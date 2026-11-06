using System.Text.Json;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Setup;

/// <summary>
/// Renews the server's own HTTPS certificate before it expires (issue #105).
/// The wizard enrolls that certificate once; without this it would simply run
/// out at the end of its template validity, the host would fall back to the
/// self signed certificate with a startup warning, and trust would break for
/// every ACME client and browser at once.
///
/// It renews only a certificate this service installed, which carries the
/// friendly name <see cref="HttpsCertificateOwnership.FriendlyName"/> (issue
/// #535). The overlay can name one somebody else installed, picked in monitor
/// mode and typically renewed by Windows autoenrolment; that one is left to
/// whoever issued it, and a pass records why. A recorded certificate missing
/// from the store is still replaced, because there is nothing left to take
/// over. See <see cref="HttpsCertificateOwnership"/>.
///
/// The renewal deliberately does not restart the host. A production service
/// must not bounce itself unannounced, so a successful renewal installs the
/// new certificate, points the settings overlay at it, and stops there. The
/// dashboard then shows the pending change with an Apply button, which is the
/// announced restart. Until that happens the process keeps serving the old
/// certificate, which is still valid: renewal runs a whole window ahead of
/// real expiry.
///
/// The superseded certificate therefore stays in the store while a restart is
/// pending. Removing it would delete its key container out from under the
/// running Kestrel endpoint. It is swept up on a later pass, once the served
/// and recorded thumbprints agree again.
///
/// Registered as a singleton and as a hosted service, so the settings API can
/// read <see cref="LastAttempt"/> off the same instance the loop writes.
/// </summary>
public sealed class HttpsCertificateAutoRenewalService : BackgroundService
{
    /// <summary>
    /// Let the host settle before the first check, and let it be short enough
    /// that an administrator who restarts to fix a failed renewal sees the
    /// retry outcome while they are still watching.
    /// </summary>
    private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(60);

    /// <summary>The smallest check interval honored, whatever is configured.</summary>
    private const int MinCheckIntervalHours = 1;

    /// <summary>
    /// What a pass records for a certificate this service did not install (issue #535).
    /// It names the friendly name, because that is what an administrator can check in
    /// certlm.msc, and change, to hand the certificate to the service.
    /// </summary>
    internal const string NotInstalledByServiceMessage =
        "The certificate does not carry the friendly name \"" + HttpsCertificateOwnership.FriendlyName +
        "\", so this service did not install it and leaves its renewal to whoever issued it. " +
        "When the renewed certificate comes from the same template, the service serves it from " +
        "its next start.";

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IHttpsCertificateStore _certificateStore;
    private readonly ServerCertificateIdentity _identity;
    private readonly CertusOptions _options;
    private readonly CertusInstanceMode _instanceMode;
    private readonly ILogger<HttpsCertificateAutoRenewalService> _logger;

    private volatile HttpsCertificateRenewalAttempt? _lastAttempt;

    public HttpsCertificateAutoRenewalService(
        IServiceScopeFactory scopeFactory,
        IHttpsCertificateStore certificateStore,
        ServerCertificateIdentity identity,
        IOptions<CertusOptions> options,
        CertusInstanceMode instanceMode,
        ILogger<HttpsCertificateAutoRenewalService> logger)
    {
        _scopeFactory = scopeFactory;
        _certificateStore = certificateStore;
        _identity = identity;
        _options = options.Value;
        _instanceMode = instanceMode;
        _logger = logger;
    }

    /// <summary>
    /// Whether automatic renewal is turned on for this install: the setting, and full
    /// mode. In monitor mode the hosted loop is not even registered (issue #470), but
    /// this instance still is, because the settings API reads it, and it has to report
    /// itself off there.
    /// </summary>
    public bool Enabled => IsActive(_options, _instanceMode);

    /// <summary>
    /// The one rule for "something renews the server's own certificate", shared with
    /// <see cref="ServerCertificateIdentity"/>, which stops keeping that certificate out
    /// of the expiry alerts the moment nothing does.
    /// </summary>
    public static bool IsActive(CertusOptions options, CertusInstanceMode instanceMode)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(instanceMode);
        return options.HttpsCertificateAutoRenewalEnabled && !instanceMode.IsMonitor;
    }

    /// <summary>The configured renewal window, before the short lifetime cap.</summary>
    public int RenewalWindowDays => Math.Max(1, _options.HttpsCertificateRenewalWindowDays);

    /// <summary>
    /// The most recent renewal attempt this process made, or null when it has
    /// not checked yet. Kept in memory on purpose: the only durable state a
    /// renewal produces is the overlay thumbprint, and the settings API
    /// derives the pending restart from that. This is the diagnostic record
    /// behind the dashboard notice, and the first check after startup
    /// repopulates it within a minute.
    /// </summary>
    public HttpsCertificateRenewalAttempt? LastAttempt => _lastAttempt;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!Enabled)
        {
            if (_instanceMode.IsMonitor)
            {
                _logger.LogInformation(
                    "Automatic HTTPS certificate renewal is off, because this server runs in monitor mode");
            }
            else
            {
                _logger.LogInformation(
                    "Automatic HTTPS certificate renewal is disabled " +
                    "(Certus:HttpsCertificateAutoRenewalEnabled=false)");
            }

            return;
        }

        var interval = TimeSpan.FromHours(
            Math.Max(MinCheckIntervalHours, _options.HttpsCertificateRenewalCheckIntervalHours));

        _logger.LogInformation(
            "Automatic HTTPS certificate renewal started (window: {Window} days, " +
            "check interval: {Interval} hours)",
            RenewalWindowDays, interval.TotalHours);

        try
        {
            await Task.Delay(StartupDelay, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // The loop outlives any single failure: the certificate is
                // still valid for a whole window, so there is time to retry.
                _logger.LogError(ex, "The HTTPS certificate renewal check failed");
                Record(HttpsCertificateRenewalOutcome.Failed, ex.Message);
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

        _logger.LogInformation("Automatic HTTPS certificate renewal stopped");
    }

    /// <summary>
    /// One renewal pass. Public so tests can drive it without the timer loop,
    /// the same shape as <c>ExpiryMonitorService.CheckForExpiringCertificatesAsync</c>.
    /// </summary>
    public async Task CheckAsync(CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            Record(HttpsCertificateRenewalOutcome.NotApplicable, _instanceMode.IsMonitor
                ? "Automatic renewal is off in monitor mode."
                : "Automatic renewal is disabled.");
            return;
        }

        using var scope = _scopeFactory.CreateScope();
        var renewal = scope.ServiceProvider.GetRequiredService<HttpsCertificateRenewalService>();

        var context = renewal.ReadContext();
        if (context.Blocker != HttpsCertificateRenewalBlocker.None)
        {
            _logger.LogDebug(
                "Skipping the HTTPS certificate renewal check: {Reason}", context.Message);
            Record(HttpsCertificateRenewalOutcome.NotApplicable, context.Message);
            return;
        }

        var recordedThumbprint = context.OverlayThumbprint;
        if (string.IsNullOrWhiteSpace(recordedThumbprint))
        {
            _logger.LogDebug(
                "Skipping the HTTPS certificate renewal check: no CA issued certificate is recorded");
            Record(HttpsCertificateRenewalOutcome.NotApplicable,
                "No CA issued certificate is recorded for this server.");
            return;
        }

        // A recorded thumbprint the process is not serving means a renewal
        // already happened and is waiting for the restart that applies it.
        // Renewing again would enroll a second certificate nobody asked for.
        var servedThumbprint = _options.HttpsCertificateThumbprint;
        if (!string.Equals(recordedThumbprint, servedThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug(
                "A renewed HTTPS certificate ({Thumbprint}) is waiting for a restart; " +
                "skipping the renewal check", recordedThumbprint);
            return;
        }

        // Served and recorded agree, so nothing is pending and any other
        // certificate we installed is superseded. This is the only safe point
        // to clean up: the certificate the process serves is the one we keep.
        SweepSuperseded(recordedThumbprint);

        using var certificate = _certificateStore.Find(recordedThumbprint);
        int? daysRemaining = null;

        if (certificate is null)
        {
            // The store no longer holds it, so the host is already on the self
            // signed fallback. Renewing is the fix, not a wait. Who installed it
            // (below) is a question only a certificate in the store can answer,
            // and a missing one leaves nothing to take over: the follower has no
            // reference to follow from either, so in full mode this enrolment is
            // the only automatic way off the fallback (issue #535).
            _logger.LogWarning(
                "The recorded HTTPS certificate {Thumbprint} is not in the machine store; " +
                "enrolling a replacement", recordedThumbprint);
        }
        else if (!HttpsCertificateOwnership.InstalledByService(certificate))
        {
            // Somebody else installed it, typically a certificate picked in monitor
            // mode that Windows autoenrolment renews (issue #535). Renewing it here
            // would enrol a replacement from an ACME template, serve that instead,
            // and leave autoenrolment renewing a certificate nothing uses. Whoever
            // issued it renews it, and the service follows that renewal at its next
            // start (HttpsCertificateFollow), so there is nothing to do here.
            _logger.LogDebug(
                "The HTTPS certificate {Thumbprint} does not carry the friendly name {FriendlyName}, " +
                "so this service did not install it and leaves its renewal to whoever issued it",
                recordedThumbprint, HttpsCertificateOwnership.FriendlyName);
            Record(HttpsCertificateRenewalOutcome.NotApplicable, NotInstalledByServiceMessage);
            return;
        }
        else
        {
            var notAfter = certificate.NotAfter.ToUniversalTime();
            var windowDays = EffectiveWindowDays(
                RenewalWindowDays, certificate.NotBefore.ToUniversalTime(), notAfter);
            daysRemaining = (int)Math.Floor((notAfter - DateTime.UtcNow).TotalDays);

            if (notAfter > DateTime.UtcNow.AddDays(windowDays))
            {
                _logger.LogDebug(
                    "The HTTPS certificate {Thumbprint} expires {NotAfter:u}, outside the " +
                    "{Window} day renewal window; nothing to do",
                    recordedThumbprint, notAfter, windowDays);
                Record(HttpsCertificateRenewalOutcome.NotApplicable,
                    $"The certificate expires {notAfter:u}, outside the {windowDays} day renewal window.");
                return;
            }

            _logger.LogInformation(
                "The HTTPS certificate {Thumbprint} expires {NotAfter:u}, inside the {Window} day " +
                "renewal window; enrolling a replacement with template {Template}",
                recordedThumbprint, notAfter, windowDays, context.Template);
        }

        HttpsCertificateRenewalResult result;
        try
        {
            result = await renewal.RenewAsync(context, currentHost: null, cancellationToken);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex,
                "Automatic HTTPS certificate renewal could not reach the certificate authority; " +
                "the current certificate stays in place");
            var attempt = Record(HttpsCertificateRenewalOutcome.Failed,
                $"The certificate authority is unavailable: {ex.Message}",
                template: context.Template);
            await SendFailureAlertAsync(
                scope, attempt, attempt.Message, daysRemaining, cancellationToken);
            return;
        }
        catch (CaAccessDeniedException ex)
        {
            // Its own arm rather than the loop's general catch (issue #336). That
            // catch keeps the service alive, which is why this was never fatal, but it
            // records no attempt and sends no alert, so a renewal blocked by a
            // withdrawn permission would go quiet until the certificate expired. This
            // is the one CA failure that does not clear on its own, so it is the one
            // that most needs the alert, and the alert carries the remediation.
            _logger.LogError(ex,
                "Automatic HTTPS certificate renewal was denied by the certificate authority; " +
                "the current certificate stays in place and this will not clear on its own");
            var attempt = Record(HttpsCertificateRenewalOutcome.Failed,
                $"The certificate authority denied access: {ex.Message}",
                template: context.Template);
            await SendFailureAlertAsync(
                scope, attempt, attempt.Message, daysRemaining, cancellationToken);
            return;
        }
        catch (JsonException ex)
        {
            // The settings overlay could not be read, or refused the record (issue
            // #553). The usual refusal, a managed key also written in the colon form
            // at the top level, is asked before the enrolment and comes back as a
            // Failed outcome below, alert included. What still lands here is a hand
            // edit made while the renewal ran, after that question was answered.
            // Made before the enrolment it is a file that no longer reads; made
            // after, the replacement may already be installed with nothing naming
            // it, and the superseded sweep removes it from the store once a pass
            // finds served and recorded agreeing. The exception cannot say which, so
            // the log does not claim either. The loop's general catch would record
            // this with no alert, and a renewal that keeps failing quietly is how the
            // certificate expires, so this arm alerts like the CA arms above.
            _logger.LogError(ex,
                "Automatic HTTPS certificate renewal stopped, because the settings overlay could " +
                "not be read or refused the record; the current certificate stays in place, and " +
                "a replacement may be in LocalMachine\\My unrecorded until the next pass removes it");
            var attempt = Record(HttpsCertificateRenewalOutcome.Failed,
                $"The settings overlay could not be read or saved: {ex.Message}",
                template: context.Template);
            await SendFailureAlertAsync(
                scope, attempt, attempt.Message, daysRemaining, cancellationToken);
            return;
        }

        if (result.Outcome == HttpsCertificateRenewalOutcome.Installed)
        {
            _logger.LogInformation(
                "The server's HTTPS certificate was renewed automatically with template " +
                "{Template}: {Thumbprint} replaces {Previous}. It is served after the next " +
                "restart; the superseded certificate stays in the store until then",
                result.Template, result.Thumbprint, result.PreviousThumbprint ?? "(none)");

            // The recorded thumbprint just changed, so anything holding the
            // old answer (expiry alert suppression) must resolve again.
            _identity.Invalidate();

            Record(result.Outcome, message: null, result.Thumbprint, result.PreviousThumbprint, result.Template);
            return;
        }

        // Every other outcome leaves the served certificate exactly as it was,
        // which is the safe state: it stays valid until its real expiry, and
        // the existing self signed fallback applies after that.
        _logger.LogWarning(
            "Automatic HTTPS certificate renewal did not complete ({Outcome}): {Message}",
            result.Outcome, result.Message ?? "no detail available");

        var failure = Record(result.Outcome, result.Message, template: result.Template);
        await SendFailureAlertAsync(
            scope, failure, result.WireMessage, daysRemaining, cancellationToken);
    }

    /// <summary>
    /// The renewal window to apply to a certificate, capped at a third of its
    /// own validity. A 30 day window against a two year certificate is the
    /// intent; against a 14 day template it would mean "always inside the
    /// window", renewing on every check and churning certificates through the
    /// CA forever.
    /// </summary>
    internal static int EffectiveWindowDays(int configuredDays, DateTime notBefore, DateTime notAfter)
    {
        var configured = Math.Max(1, configuredDays);
        var lifetimeDays = (notAfter - notBefore).TotalDays;

        // A nonsensical validity window (clock skew, a malformed certificate)
        // gives no useful cap, so fall back to the configured value.
        if (lifetimeDays <= 0)
            return configured;

        var cap = Math.Max(1, (int)Math.Floor(lifetimeDays / 3));
        return Math.Min(configured, cap);
    }

    /// <summary>
    /// Remove certificates a previous renewal superseded. Only reached when
    /// the served and recorded thumbprints agree, so the certificate in use is
    /// never a candidate. Best effort: leftovers are visible in certlm.msc and
    /// cost nothing but clutter.
    /// </summary>
    private void SweepSuperseded(string keepThumbprint)
    {
        try
        {
            var removed = _certificateStore.RemoveSuperseded(keepThumbprint);
            if (removed > 0)
            {
                _logger.LogInformation(
                    "Removed {Count} superseded HTTPS certificate(s) now that {Thumbprint} is served",
                    removed, keepThumbprint);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not remove superseded HTTPS certificates; they remain until removed by hand");
        }
    }

    /// <summary>
    /// Tell the configured alert channels that automatic renewal failed. The
    /// server certificate is excluded from the routine expiry thresholds
    /// precisely so this is the only thing they ever hear about it, and it
    /// carries the CA's own reason, which names the exact fix for a pended or
    /// denied request.
    ///
    /// <paramref name="wireDetail"/> is what the webhook may carry instead of the
    /// attempt's message (issue #485). Every caller passes it explicitly: a denial
    /// names the computer account, so its result supplies an account free form,
    /// and the three exception arms pass their own message, because what they
    /// wrap is the CA exceptions' fixed text or the overlay's, none of which names
    /// an account or a host.
    /// </summary>
    private async Task SendFailureAlertAsync(
        IServiceScope scope,
        HttpsCertificateRenewalAttempt attempt,
        string? wireDetail,
        int? daysRemaining,
        CancellationToken cancellationToken)
    {
        var notifiers = scope.ServiceProvider.GetServices<IAlertNotifier>()
            .Where(n => n.IsEnabled)
            .ToList();
        if (notifiers.Count == 0)
            return;

        var alert = new ServerCertificateAlert(
            Outcome: attempt.Outcome.ToString(),
            Detail: attempt.Message,
            Template: attempt.Template,
            DaysRemaining: daysRemaining,
            WireDetail: wireDetail);

        foreach (var notifier in notifiers)
        {
            try
            {
                var sent = await notifier.SendServerCertificateAlertAsync(alert, cancellationToken);
                if (!sent.Success)
                {
                    _logger.LogWarning(
                        "The {Channel} channel could not deliver the server certificate renewal " +
                        "alert: {Error}", notifier.Channel, sent.ErrorMessage ?? "no detail available");
                }
            }
            catch (Exception ex)
            {
                // A broken notifier must never take down the renewal loop.
                _logger.LogWarning(ex,
                    "The {Channel} channel threw while delivering the server certificate renewal alert",
                    notifier.Channel);
            }
        }
    }

    private HttpsCertificateRenewalAttempt Record(
        HttpsCertificateRenewalOutcome outcome,
        string? message,
        string? thumbprint = null,
        string? previousThumbprint = null,
        string? template = null)
    {
        var attempt = new HttpsCertificateRenewalAttempt(
            DateTime.UtcNow, outcome, message, thumbprint, previousThumbprint, template);
        _lastAttempt = attempt;
        return attempt;
    }
}

/// <summary>
/// What the last automatic renewal pass did. <see cref="Outcome"/> is
/// <see cref="HttpsCertificateRenewalOutcome.NotApplicable"/> for the ordinary
/// "nothing to do" passes, with <see cref="Message"/> saying which one.
/// </summary>
public sealed record HttpsCertificateRenewalAttempt(
    DateTime AttemptedAt,
    HttpsCertificateRenewalOutcome Outcome,
    string? Message,
    string? Thumbprint,
    string? PreviousThumbprint,
    string? Template);
