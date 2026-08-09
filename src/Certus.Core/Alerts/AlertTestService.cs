using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Alerts;

/// <summary>
/// Delivers an operator triggered test alert over every configured channel and
/// reports what each one did (issue #161).
///
/// <para>
/// <b>It persists nothing.</b> AlertsSent has no column that could mark a row as
/// a test, and it carries a unique index on (CertificateId, ThresholdDays). A
/// test row would therefore have to borrow a real certificate's slot, and the
/// expiry monitor's duplicate check does not filter on Success, so that slot
/// would be permanently consumed: the real warning for that certificate at that
/// threshold would never be sent. Writing nothing is the only safe answer. The
/// audit log line is the durable record.
/// </para>
///
/// <para>
/// The refuse before arm ordering lives here rather than in the controller. A
/// refusal for having no channel configured must not start the cooldown, or an
/// operator fixing their configuration is locked out for a minute by a send that
/// never happened. Keeping it here makes that a unit test with a fake clock
/// instead of a live sixty second window.
/// </para>
/// </summary>
public sealed class AlertTestService
{
    private readonly IReadOnlyList<IAlertNotifier> _notifiers;
    private readonly AlertTestThrottle _throttle;
    private readonly AlertOptions _options;
    private readonly ILogger<AlertTestService> _logger;

    public AlertTestService(
        IEnumerable<IAlertNotifier> notifiers,
        AlertTestThrottle throttle,
        IOptions<AlertOptions> options,
        ILogger<AlertTestService> logger)
    {
        _notifiers = notifiers.ToList();
        _throttle = throttle;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Sends a test over every enabled channel.
    ///
    /// Note that this does not consult <see cref="AlertOptions.Enabled"/>. That
    /// flag gates the expiry monitor, not the notifiers, and proving SMTP works
    /// before switching monitoring on is a reasonable thing to want to do. The
    /// dashboard is responsible for not letting a green test read as "alerting
    /// is working" while monitoring is off.
    /// </summary>
    public Task<AlertTestResult> SendAsync(string actor, CancellationToken cancellationToken = default) =>
        SendAsync(actor, candidateSmtp: null, cancellationToken);

    /// <summary>
    /// The candidate variant: when <paramref name="candidateSmtp"/> is present,
    /// the email channel sends with those values instead of the configured
    /// ones, which is how the dashboard proves a typed but unsaved (or saved
    /// but unapplied) SMTP configuration without a restart, the same
    /// candidate-in-body shape as the wizard's CA connection test. The other
    /// channels are untouched, the email channel joins the test even when the
    /// running configuration could not deliver, and the candidate's own values
    /// are redacted out of any failure text. The caller has already validated
    /// the candidate is deliverable.
    /// </summary>
    public async Task<AlertTestResult> SendAsync(
        string actor, SmtpOptions? candidateSmtp, CancellationToken cancellationToken = default)
    {
        var enabled = _notifiers
            .Where(n => n.IsEnabled || (candidateSmtp != null && n is EmailAlertNotifier))
            .ToList();

        if (enabled.Count == 0)
        {
            Audit(actor, "refused: no channel configured");
            return new AlertTestResult(AlertTestStatus.NoChannelsEnabled, [], 0);
        }

        if (!_throttle.TryAcquire(out var retryAfter))
        {
            Audit(actor, $"refused: cooling down, {retryAfter.TotalSeconds:F0}s remaining");
            return new AlertTestResult(
                AlertTestStatus.Throttled, [], (int)retryAfter.TotalSeconds);
        }

        var alert = new TestAlert(actor, DateTime.UtcNow);
        var results = new List<AlertTestChannelResult>(enabled.Count);

        // Sequential, matching ExpiryMonitorService. A notifier never throws by
        // contract, so there is no per channel try/catch here either.
        foreach (var notifier in enabled)
        {
            var result = notifier is EmailAlertNotifier email && candidateSmtp != null
                ? await email.SendTestAlertAsync(alert, candidateSmtp, cancellationToken)
                : await notifier.SendTestAlertAsync(alert, cancellationToken);

            results.Add(new AlertTestChannelResult(
                notifier.Channel,
                result.Success,
                AlertErrorRedactor.Redact(result.ErrorMessage, _options, candidateSmtp)));
        }

        var outcome = string.Join(
            ", ", results.Select(r => $"{r.Channel} {(r.Success ? "delivered" : "failed")}"));
        Audit(actor, outcome);

        return new AlertTestResult(AlertTestStatus.Sent, results, 0);
    }

    /// <summary>
    /// One structured line per attempt, refused or not, in the same shape as
    /// CertificateRevocationService.Audit. This is the only durable record that
    /// a test was ever sent, so it fires on every path.
    /// </summary>
    private void Audit(string actor, string outcome)
    {
        _logger.LogInformation(
            "Alert test send by {Actor}: outcome {Outcome}", actor, outcome);
    }
}

/// <summary>How a test send ended.</summary>
public enum AlertTestStatus
{
    /// <summary>Attempted on at least one channel. Individual channels may still have failed.</summary>
    Sent,

    /// <summary>Nothing is configured to send over, so there was nothing to test.</summary>
    NoChannelsEnabled,

    /// <summary>A test was sent too recently. Nothing was attempted.</summary>
    Throttled,
}

/// <summary>The outcome of a test send, per channel.</summary>
public sealed record AlertTestResult(
    [property: JsonPropertyName("status")] AlertTestStatus Status,
    [property: JsonPropertyName("results")] IReadOnlyList<AlertTestChannelResult> Results,
    [property: JsonPropertyName("retryAfterSeconds")] int RetryAfterSeconds);

/// <summary>What one channel did with the test.</summary>
public sealed record AlertTestChannelResult(
    [property: JsonPropertyName("channel")] string Channel,
    [property: JsonPropertyName("success")] bool Success,
    [property: JsonPropertyName("errorMessage")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ErrorMessage);
