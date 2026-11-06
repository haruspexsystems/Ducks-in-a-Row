using System.Collections.Concurrent;
using Certus.Core.Alerts;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Modules;

/// <summary>
/// Sends the licence alerts the paid module says are due, through the existing
/// email and webhook channels (issue #494, licence design section 13.6).
///
/// <para><b>Why it is its own service.</b> The certificate and CRL monitors, and
/// every alert notifier, are on the protected surface that must never reach the
/// module host (<c>ModuleBoundaryTests.IssuancePathNeverReachesTheModuleHost</c>),
/// so the licence check cannot live inside either monitor. It lives here, on the
/// module host's side of that line, and hands the notifiers a
/// <see cref="LicenceAlert"/> that holds no contract type.</para>
///
/// <para><b>It never runs module code.</b> It reads
/// <see cref="ILicenceStatusSource.Current"/>, which is a reference the host
/// publishes under a lock. The module re-evaluates on a licence change and at
/// least hourly (<c>ModuleHost.ReevaluateAtLeastEvery</c>), so a stage reaches
/// that reference within about an hour of its moment, and this pass adds at most
/// <see cref="Interval"/>. A pass with nothing due touches neither the database
/// nor a channel.</para>
///
/// <para><b>Each (licence id, stage) is sent once.</b> The record is written
/// whether or not a channel accepted the alert, the stance the CRL alerts take
/// (Sean's decision of 2026-10-14), and is not written at all when no channel is
/// configured, so a channel added later still gets the stage that is due. Only
/// the current stage is ever sent: a server that was off at 30 days hears the
/// stage it starts in, not a backlog.</para>
///
/// <para>There is no switch to turn it off and it runs in monitor mode too: a
/// licence alert is not a write to the CA, and a paid licence lapsing with no
/// warning is the failure it exists to prevent.</para>
/// </summary>
public sealed class LicenceAlertService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILicenceStatusSource _source;
    private readonly ILogger<LicenceAlertService> _logger;
    private readonly TimeProvider _time;

    // One pass at a time, so a test that calls CheckAsync on the hosted instance
    // cannot race the loop over the same (licence id, stage).
    private readonly SemaphoreSlim _gate = new(1, 1);

    // Each problem is logged once for the life of the process, not on every pass.
    private readonly ConcurrentDictionary<string, byte> _reported = new(StringComparer.Ordinal);

    // The (licence id, stage) pairs this process has already sent or found sent.
    // The database is the record that survives a restart; this caps resends at one
    // per process if the database keeps refusing the save, which at one pass every
    // few minutes would otherwise repeat the alert on every pass.
    private readonly HashSet<(string LicenceId, string Stage)> _attempted = [];

    /// <summary>
    /// The settling delay before the first pass. The module starts once the
    /// application has, with a start budget of 10 seconds and then its first
    /// evaluation, so by a minute in the first pass normally sees a verdict.
    /// </summary>
    internal TimeSpan StartupDelay { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>How often the current verdict is read.</summary>
    internal TimeSpan Interval { get; init; } = TimeSpan.FromMinutes(5);

    public LicenceAlertService(
        IServiceScopeFactory scopeFactory,
        ILicenceStatusSource source,
        ILogger<LicenceAlertService> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = timeProvider ?? TimeProvider.System;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Licence alerting started, checking every {Interval} minute(s).", Interval.TotalMinutes);

        try
        {
            await Task.Delay(StartupDelay, _time, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // One bad pass must not end licence alerting for the life of the
                // service, the stance the certificate and CRL monitors take.
                _logger.LogError(ex, "The licence alert check failed. The next one runs as scheduled.");
            }

            try
            {
                await Task.Delay(Interval, _time, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// One pass: read the current verdict, and send the alert it says is due if
    /// it has not been sent. Public so tests drive it directly rather than through
    /// the timer.
    /// </summary>
    public async Task CheckAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await CheckOnceAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task CheckOnceAsync(CancellationToken cancellationToken)
    {
        var decision = LicenceAlertRules.Evaluate(_source.Current);

        foreach (var problem in decision.Problems)
        {
            if (_reported.TryAdd(problem.Key, 0))
                _logger.LogWarning("{Problem}", problem.Message);
        }

        if (decision.Alert is not { } alert)
            return;

        var key = (alert.LicenceId, alert.Stage);
        if (_attempted.Contains(key))
            return;

        using var scope = _scopeFactory.CreateScope();
        var services = scope.ServiceProvider;

        var notifiers = services.GetServices<IAlertNotifier>().Where(n => n.IsEnabled).ToList();
        if (notifiers.Count == 0)
        {
            // Nothing is recorded either, which is the point: an install that
            // configures a channel next week still gets the stage that is due then.
            _logger.LogDebug(
                "A licence alert is due ({Stage}), but no alert channel is configured, so nothing was sent.",
                alert.Stage);
            return;
        }

        var db = services.GetRequiredService<CertusDbContext>();
        var alreadySent = await db.LicenceAlertsSent
            .AnyAsync(a => a.LicenceId == alert.LicenceId && a.Stage == alert.Stage, cancellationToken)
            .ConfigureAwait(false);

        if (alreadySent)
        {
            _attempted.Add(key);
            return;
        }

        var channels = new List<string>(notifiers.Count);
        var allSucceeded = true;

        foreach (var notifier in notifiers)
        {
            channels.Add(notifier.Channel);
            try
            {
                var sent = await notifier.SendLicenceAlertAsync(alert, cancellationToken).ConfigureAwait(false);
                if (!sent.Success)
                {
                    allSucceeded = false;
                    _logger.LogWarning(
                        "The {Channel} channel could not deliver the licence {Stage} alert: {Error}",
                        notifier.Channel, alert.Stage, sent.ErrorMessage ?? "no detail available");
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // The service is stopping. Nothing is recorded, so the next start
                // tries this stage again rather than losing it.
                throw;
            }
            catch (Exception ex)
            {
                // A broken notifier must never stop the other channels, or the loop.
                allSucceeded = false;
                _logger.LogWarning(ex,
                    "The {Channel} channel threw while delivering the licence {Stage} alert.",
                    notifier.Channel, alert.Stage);
            }
        }

        _attempted.Add(key);

        db.LicenceAlertsSent.Add(new LicenceAlertSent
        {
            LicenceId = alert.LicenceId,
            Stage = alert.Stage,
            SentAt = _time.GetUtcNow().UtcDateTime,
            Channels = Truncate(string.Join(",", channels), 50),
            Success = allSucceeded,
        });
        await db.SaveChangesAsync(CancellationToken.None).ConfigureAwait(false);

        // The licence id, never the licensee's name: the name is personal data for
        // a sole trader, and the design keeps it out of every log. A delivery that
        // failed on any channel says so, rather than reading as sent.
        if (allSucceeded)
        {
            _logger.LogInformation(
                "Licence {Kind} alert sent for stage {Stage} of licence {LicenceId}, through {Channels}.",
                alert.Kind, alert.Stage, alert.LicenceId, string.Join(", ", channels));
        }
        else
        {
            _logger.LogWarning(
                "Licence {Kind} alert for stage {Stage} of licence {LicenceId} did not reach every channel " +
                "({Channels}). It is recorded and will not be retried; the next stage follows.",
                alert.Kind, alert.Stage, alert.LicenceId, string.Join(", ", channels));
        }
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max];
}
