using System.Text.Json.Serialization;
using Certus.Core.Data.Entities;

namespace Certus.Core.Alerts;

/// <summary>
/// Why a certificate is, or is not, being alerted on. Certificate wide or
/// install wide, never per threshold: every reason the expiry monitor declines
/// to alert applies to the whole certificate.
///
/// Const strings rather than an enum, so the wire contract is written down once
/// and the compiler still catches a typo at every use, matching the other
/// string vocabularies in this codebase (the domain policy audit stages, the AD
/// principal types).
/// </summary>
public static class AlertCoverage
{
    /// <summary>The expiry monitor will alert on this certificate.</summary>
    public const string Monitored = "monitored";

    /// <summary>Expiry monitoring is switched off entirely.</summary>
    public const string AlertingDisabled = "alertingDisabled";

    /// <summary>
    /// Monitoring is on but no channel is configured, so nothing is delivered
    /// and nothing is even recorded. <see cref="ExpiryMonitorService"/> returns
    /// before writing a row when no notifier reports itself enabled.
    /// </summary>
    public const string NoChannelsConfigured = "noChannelsConfigured";

    /// <summary>
    /// Revoked at the CA. Split from <see cref="NotIssued"/> because it is the
    /// only non Issued status the detail page actually renders this block for
    /// (the page suppresses every expiry affordance for a request that never
    /// became a certificate), and "not issued" is a poor description of a
    /// certificate that was issued and then withdrawn.
    /// </summary>
    public const string Revoked = "revoked";

    /// <summary>The request never became a certificate: pending, denied, failed.</summary>
    public const string NotIssued = "notIssued";

    /// <summary>Already expired. The monitor does not nag about those.</summary>
    public const string AlreadyExpired = "alreadyExpired";

    /// <summary>
    /// The server's own HTTPS certificate, suppressed on purpose (issue #105).
    /// Automatic renewal owns it and speaks up only when renewal fails.
    /// </summary>
    public const string OwnCertificate = "ownCertificate";
}

/// <summary>
/// What happened, or did not happen, at one threshold on the ladder.
/// </summary>
public static class AlertThresholdState
{
    /// <summary>A row exists and every channel accepted it.</summary>
    public const string Sent = "sent";

    /// <summary>A row exists and at least one channel failed.</summary>
    public const string Failed = "failed";

    /// <summary>
    /// The certificate crossed this threshold, the monitor has had time to act,
    /// and nothing was recorded. The one state that is an alarm.
    /// </summary>
    public const string Missing = "missing";

    /// <summary>
    /// Crossed, but not long enough ago to expect a row yet. Not an alarm.
    /// </summary>
    public const string AwaitingCheck = "awaitingCheck";

    /// <summary>Not crossed yet.</summary>
    public const string Pending = "pending";

    /// <summary>
    /// Nothing will fire, and the coverage reason says why. Distinct from
    /// <see cref="Pending"/> so the page never promises an alert that is not
    /// coming.
    /// </summary>
    public const string NotApplicable = "notApplicable";
}

/// <summary>
/// The certificate facts the ladder needs. A projection rather than the entity,
/// so the caller never has to load the certificate's DER to answer this.
/// </summary>
public sealed record CertificateAlertFacts(
    int CertificateId,
    string Status,
    string? SerialNumber,
    DateTime NotAfter,
    DateTime FirstSyncedAt);

/// <summary>
/// The install wide facts, resolved once by the caller: the alert options, which
/// notifiers report themselves enabled, and whether this serial is one of ours.
/// </summary>
public sealed record AlertLadderContext(
    bool AlertingEnabled,
    IReadOnlyList<string> EnabledChannels,
    int CheckIntervalMinutes,
    IReadOnlyList<int> ThresholdDays,
    bool IsOwnCertificate);

/// <summary>
/// Turns the recorded <see cref="AlertSent"/> rows for one certificate into the
/// full expected threshold ladder, so the detail page can show the thresholds
/// that fired, the ones that failed, and the ones that should have fired and did
/// not (issue #160).
///
/// The ladder rather than a plain list is the point. A certificate five days
/// from expiry should carry rows for 30, 14 and 7; if the service was down
/// across the 14 and 7 crossings, a list of what exists still shows an alert and
/// reads as healthy while two thresholds are silently missing.
///
/// Pure by design: no database, no clock, no configuration reads. Everything it
/// decides is decided from its arguments, so the interesting cases are unit
/// testable without a host, in the same spirit as
/// <see cref="Acme.Services.AllowedDomainsPolicy"/>.
/// </summary>
public static class CertificateAlertLadder
{
    /// <summary>
    /// Assembles the history. <paramref name="rows"/> is every
    /// <see cref="AlertSent"/> row for this certificate and no other.
    /// </summary>
    public static CertificateAlertHistory Build(
        CertificateAlertFacts certificate,
        IReadOnlyList<AlertSent> rows,
        AlertLadderContext context,
        DateTime nowUtc)
    {
        var coverage = ResolveCoverage(certificate, context, nowUtc);

        // Configured thresholds plus any threshold that actually fired. An
        // operator who alerted at 30 and later reconfigured to [60, 7] still has
        // that 30 day row, and dropping it would quietly erase the evidence this
        // whole block exists to show.
        var thresholds = context.ThresholdDays
            .Concat(rows.Select(r => r.ThresholdDays))
            .Distinct()
            .ToList();

        var entries = thresholds
            .Select(t => BuildEntry(t, certificate, rows, context, coverage, nowUtc))
            .ToList();

        return new CertificateAlertHistory
        {
            CertificateId = certificate.CertificateId,
            Coverage = coverage,
            CheckIntervalMinutes = context.CheckIntervalMinutes,
            EnabledChannels = context.EnabledChannels,
            Thresholds = Order(entries),
        };
    }

    /// <summary>
    /// Mirrors the order <see cref="ExpiryMonitorService"/> applies its own
    /// checks in, so the reason reported here is the reason the engine would act
    /// on: the service exits on the enabled flag first, then on having no
    /// notifier, and only then filters certificates.
    /// </summary>
    private static string ResolveCoverage(
        CertificateAlertFacts certificate,
        AlertLadderContext context,
        DateTime nowUtc)
    {
        if (!context.AlertingEnabled)
            return AlertCoverage.AlertingDisabled;

        if (context.EnabledChannels.Count == 0)
            return AlertCoverage.NoChannelsConfigured;

        // The monitor requires exactly "Issued", so every other status is
        // excluded. Revoked is called out on its own because it is the one the
        // detail page renders this block for.
        if (string.Equals(certificate.Status, "Revoked", StringComparison.OrdinalIgnoreCase))
            return AlertCoverage.Revoked;

        if (!string.Equals(certificate.Status, "Issued", StringComparison.OrdinalIgnoreCase))
            return AlertCoverage.NotIssued;

        if (certificate.NotAfter <= nowUtc)
            return AlertCoverage.AlreadyExpired;

        if (context.IsOwnCertificate)
            return AlertCoverage.OwnCertificate;

        return AlertCoverage.Monitored;
    }

    private static CertificateAlertThreshold BuildEntry(
        int thresholdDays,
        CertificateAlertFacts certificate,
        IReadOnlyList<AlertSent> rows,
        AlertLadderContext context,
        string coverage,
        DateTime nowUtc)
    {
        var dueAt = certificate.NotAfter.AddDays(-thresholdDays);
        var row = rows.FirstOrDefault(r => r.ThresholdDays == thresholdDays);

        var entry = new CertificateAlertThreshold
        {
            ThresholdDays = thresholdDays,
            DueAt = dueAt,
        };

        // A recorded row always wins. History stays visible after the coverage
        // reason changes, so a certificate that was alerted and later revoked
        // keeps its record instead of reading as though nothing happened.
        if (row != null)
        {
            entry.State = row.Success ? AlertThresholdState.Sent : AlertThresholdState.Failed;
            entry.SentAt = row.SentAt;
            entry.Channels = row.Channels;
            entry.ErrorMessage = row.ErrorMessage;
            return entry;
        }

        if (coverage != AlertCoverage.Monitored)
        {
            entry.State = AlertThresholdState.NotApplicable;
            return entry;
        }

        if (dueAt > nowUtc)
        {
            entry.State = AlertThresholdState.Pending;
            return entry;
        }

        // Measured from the later of the crossing and the first sync, which is
        // the load bearing half. A certificate imported today that is already
        // five days from expiry crossed its 30 day threshold 25 days ago, and
        // without the FirstSyncedAt term every threshold below 30 would read as
        // missing the instant it appeared in the inventory. That first sight
        // burst is exactly what ExpiryMonitorService documents itself doing.
        //
        // Math.Max on the interval mirrors the monitor's own floor, so a
        // nonsensical interval cannot produce a zero length grace here while the
        // engine still waits a minute between passes.
        var grace = TimeSpan.FromMinutes(Math.Max(1, context.CheckIntervalMinutes));
        var expectedBy = (dueAt > certificate.FirstSyncedAt ? dueAt : certificate.FirstSyncedAt) + grace;

        entry.State = nowUtc < expectedBy
            ? AlertThresholdState.AwaitingCheck
            : AlertThresholdState.Missing;

        return entry;
    }

    /// <summary>
    /// Most recent first, as the issue asks, without burying the real events
    /// under thresholds that have not happened yet. Anything with an outcome or
    /// an alarm comes first, newest first; the rest follows in the order it will
    /// come due.
    /// </summary>
    private static List<CertificateAlertThreshold> Order(List<CertificateAlertThreshold> entries)
    {
        static bool HasHappened(CertificateAlertThreshold e) =>
            e.State is AlertThresholdState.Sent
                or AlertThresholdState.Failed
                or AlertThresholdState.Missing
                or AlertThresholdState.AwaitingCheck;

        return entries
            .Where(HasHappened)
            .OrderByDescending(e => e.SentAt ?? e.DueAt)
            .Concat(entries
                .Where(e => !HasHappened(e))
                .OrderBy(e => e.DueAt))
            .ToList();
    }
}

/// <summary>
/// The alert history for one certificate: why it is or is not covered, and every
/// threshold on the ladder.
/// </summary>
public sealed class CertificateAlertHistory
{
    [JsonPropertyName("certificateId")]
    public int CertificateId { get; set; }

    /// <summary>One of the <see cref="AlertCoverage"/> values.</summary>
    [JsonPropertyName("coverage")]
    public string Coverage { get; set; } = AlertCoverage.Monitored;

    /// <summary>
    /// How often the monitor runs, so the page can say how long a threshold has
    /// been overdue in terms the operator configured.
    /// </summary>
    [JsonPropertyName("checkIntervalMinutes")]
    public int CheckIntervalMinutes { get; set; }

    /// <summary>
    /// The channels that would be attempted right now. Empty is what
    /// <see cref="AlertCoverage.NoChannelsConfigured"/> reports on.
    /// </summary>
    [JsonPropertyName("enabledChannels")]
    public IReadOnlyList<string> EnabledChannels { get; set; } = [];

    [JsonPropertyName("thresholds")]
    public IReadOnlyList<CertificateAlertThreshold> Thresholds { get; set; } = [];
}

/// <summary>
/// One rung of the ladder.
/// </summary>
public sealed class CertificateAlertThreshold
{
    [JsonPropertyName("thresholdDays")]
    public int ThresholdDays { get; set; }

    /// <summary>One of the <see cref="AlertThresholdState"/> values.</summary>
    [JsonPropertyName("state")]
    public string State { get; set; } = AlertThresholdState.Pending;

    /// <summary>
    /// When the certificate crosses (or crossed) this threshold. Not the same as
    /// <see cref="SentAt"/>: a certificate already inside several thresholds when
    /// it is first synced fires all of them at once, long after they came due.
    /// </summary>
    [JsonPropertyName("dueAt")]
    public DateTime DueAt { get; set; }

    /// <summary>Null unless a row exists.</summary>
    [JsonPropertyName("sentAt")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTime? SentAt { get; set; }

    /// <summary>
    /// The channels that were <em>attempted</em>, not the ones that delivered.
    /// The row aggregates the whole batch, so on a failure this does not say
    /// which channel failed and the page must not imply that it does.
    /// </summary>
    [JsonPropertyName("channels")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Channels { get; set; }

    /// <summary>
    /// The last failing channel's error, which is all the row carries.
    /// </summary>
    [JsonPropertyName("errorMessage")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ErrorMessage { get; set; }
}
