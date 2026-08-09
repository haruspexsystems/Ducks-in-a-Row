using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Setup;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Alerts;

/// <summary>
/// Background service that periodically scans for expiring certificates
/// and sends alert notifications via configured channels (email, webhook).
/// Uses the AlertsSent table to prevent duplicate notifications.
///
/// The server's own HTTPS certificate is excluded (issue #105). It is issued
/// by the monitored CA like every other certificate, so it would otherwise
/// fire the whole threshold ladder for a certificate the product renews for
/// itself. <see cref="HttpsCertificateAutoRenewalService"/> owns it, and
/// speaks up on these same channels only when its renewal actually fails.
/// </summary>
public sealed class ExpiryMonitorService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ServerCertificateIdentity _serverCertificate;
    private readonly ILogger<ExpiryMonitorService> _logger;
    private readonly AlertOptions _options;

    /// <param name="serverCertificate">
    /// Required rather than optional on purpose. An optional parameter would
    /// fall back to null the day a host stops registering it, and suppression
    /// would quietly stop working while every test still passed. Missing, this
    /// fails at startup instead.
    /// </param>
    public ExpiryMonitorService(
        IServiceScopeFactory scopeFactory,
        IOptions<AlertOptions> options,
        ILogger<ExpiryMonitorService> logger,
        ServerCertificateIdentity serverCertificate)
    {
        _scopeFactory = scopeFactory;
        _serverCertificate = serverCertificate;
        _logger = logger;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("Expiry monitor service is disabled");
            return;
        }

        var interval = TimeSpan.FromMinutes(Math.Max(1, _options.CheckIntervalMinutes));

        _logger.LogInformation(
            "Expiry monitor service started (interval: {Interval} minutes, thresholds: {Thresholds})",
            interval.TotalMinutes,
            string.Join(", ", _options.ThresholdDays.Select(d => $"{d}d")));

        // Initial delay to let the app start up and cert sync run first
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckForExpiringCertificatesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Expiry monitor check failed");
            }

            try
            {
                await Task.Delay(interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("Expiry monitor service stopped");
    }

    /// <summary>
    /// Scans for certificates expiring within each threshold and sends alerts
    /// for any that haven't been notified yet.
    /// </summary>
    public async Task CheckForExpiringCertificatesAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var notifiers = scope.ServiceProvider.GetServices<IAlertNotifier>().ToList();

        var enabledNotifiers = notifiers.Where(n => n.IsEnabled).ToList();
        if (enabledNotifiers.Count == 0)
        {
            _logger.LogDebug("No alert notifiers are enabled, skipping expiry check");
            return;
        }

        var now = DateTime.UtcNow;

        // Sort thresholds descending so we process largest first (30, 14, 7, 1)
        var thresholds = _options.ThresholdDays
            .OrderByDescending(d => d)
            .ToArray();

        // A newly seen certificate is alerted once for every threshold it already falls
        // within, so the first run over an existing inventory produces a burst: a cert
        // 5 days from expiry fires the 30, 14, and 7 day thresholds in the same pass.
        // This is intentional.
        foreach (var thresholdDays in thresholds)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var cutoff = now.AddDays(thresholdDays);

            // Find certificates that:
            // 1. Are "Issued" status (don't alert on revoked/expired status)
            // 2. Expire before the cutoff
            // 3. Haven't expired yet (NotAfter > now) — we don't nag about certs that have already expired
            // 4. Haven't already been alerted for this threshold
            var expiringCerts = await db.SyncedCertificates
                .Where(c => c.Status == "Issued"
                    && c.NotAfter <= cutoff
                    && c.NotAfter > now
                    && !db.AlertsSent.Any(a => a.CertificateId == c.Id && a.ThresholdDays == thresholdDays))
                .OrderBy(c => c.NotAfter)
                .ToListAsync(cancellationToken);

            // Drop the server's own certificate. Filtered here rather than in
            // the query because matching a CA database serial against an X509
            // one needs SerialNumbers.Normalize, which SQLite cannot run. No
            // AlertsSent row is written for a suppressed certificate, so if it
            // ever stops being ours the normal ladder still fires.
            var suppressed = expiringCerts
                .RemoveAll(c => _serverCertificate.IsOwnCertificate(c.SerialNumber));
            if (suppressed > 0)
            {
                _logger.LogDebug(
                    "Suppressed the {Threshold} day expiry alert for {Count} server " +
                    "certificate(s); automatic renewal owns them",
                    thresholdDays, suppressed);
            }

            if (expiringCerts.Count == 0)
                continue;

            _logger.LogInformation(
                "Found {Count} certificates expiring within {Threshold} days that need alerting",
                expiringCerts.Count, thresholdDays);

            var certInfos = expiringCerts.Select(c => new CertificateExpiryInfo(
                c.Id,
                c.Subject,
                c.SerialNumber,
                c.TemplateName,
                c.NotAfter,
                (int)Math.Ceiling((c.NotAfter - now).TotalDays)
            )).ToList();

            var batch = new ExpiryAlertBatch(thresholdDays, certInfos);

            // Send via all enabled channels
            var channels = new List<string>();
            var allSuccess = true;
            string? lastError = null;

            foreach (var notifier in enabledNotifiers)
            {
                var result = await notifier.SendExpiryAlertAsync(batch, cancellationToken);
                channels.Add(notifier.Channel);

                if (!result.Success)
                {
                    allSuccess = false;
                    lastError = result.ErrorMessage;
                }
            }

            // Record the alert as sent for every certificate in the batch, whether the
            // send succeeded or failed. A recorded row permanently suppresses this
            // certificate and threshold: the query above does not filter on Success, so a
            // failed alert is never retried (intentional, to avoid repeat notifications).
            // Success, Channels, and ErrorMessage are aggregated across all channels, so if
            // one channel fails the row is marked failed even when another channel delivered.
            foreach (var cert in expiringCerts)
            {
                db.AlertsSent.Add(new AlertSent
                {
                    CertificateId = cert.Id,
                    ThresholdDays = thresholdDays,
                    SentAt = DateTime.UtcNow,
                    Channels = string.Join(",", channels),
                    Success = allSuccess,
                    ErrorMessage = lastError,
                });
            }

            // Delivery happens at least once: notifications are sent above, before this
            // save. If the save throws, the alerts already went out and will be sent again
            // on the next run.
            await db.SaveChangesAsync(cancellationToken);
        }
    }
}
