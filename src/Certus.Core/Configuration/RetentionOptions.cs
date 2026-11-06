namespace Certus.Core.Configuration;

/// <summary>
/// How long each class of data stays in the database before the daily
/// retention pass removes it (issue #637, CRA risk R18). Bound from the
/// <c>Certus:Retention</c> section.
///
/// <para>The defaults are Sean's decision of 2026-10-21 on #637: finished ACME
/// orders 90 days, deactivated accounts one year, alert history two years.
/// Each period is a number of days and <c>0</c> turns that class off, so an
/// operator who must keep everything can. The CA inventory mirror
/// (<c>SyncedCertificates</c>) is never subject to retention: it reflects what
/// the CA holds, and the sync would recreate any row removed.</para>
///
/// <para>None of these keys appear in <c>appsettings.json</c>, on purpose. A key
/// shipped there as an explicit JSON null has that null applied over the C#
/// initializer by the configuration binder (see
/// <see cref="CertusOptions.NormalizeDatabasePath"/>), so leaving them out is
/// what makes these initializers the real defaults.</para>
///
/// <para>The administrator audit trail (R07, #634) is the one class with a
/// floor: the decision fixes it at two years and never below 90 days, so a
/// configured period under 90 is raised to 90 and the pass says so. 0 still
/// keeps the trail for ever, which is above the floor.</para>
/// </summary>
public sealed class RetentionOptions
{
    public const string SectionName = "Certus:Retention";

    /// <summary>
    /// Rows removed per statement by the retention pass. Small enough that one
    /// batch holds the database for milliseconds, so ACME traffic and the
    /// dashboard never wait on housekeeping; the pass loops until a class has
    /// no more rows due.
    /// </summary>
    public const int DefaultBatchSize = 500;

    /// <summary>
    /// How many days a finished ACME order (one that reached <c>valid</c> or
    /// <c>invalid</c>) keeps its authorizations and challenges, and how long an
    /// invalid order itself is kept. A valid order's own row and its certificate
    /// record stay until this many days after the certificate expired, because
    /// renewal information (ARI), <c>replaces</c> and revoke-cert all look the
    /// certificate up through them for as long as it is live. <c>0</c> keeps
    /// finished orders for ever.
    /// </summary>
    public int FinishedOrderDays { get; set; } = 90;

    /// <summary>
    /// How many days after deactivation an ACME account's contact addresses are
    /// removed, and its row deleted once the order rule has removed its last
    /// order. <c>0</c> keeps deactivated accounts for ever.
    /// </summary>
    public int DeactivatedAccountDays { get; set; } = 365;

    /// <summary>
    /// How many days certificate, CRL and licence alert history rows are kept
    /// after they were sent. <c>0</c> keeps alert history for ever.
    /// </summary>
    public int AlertHistoryDays { get; set; } = 730;

    /// <summary>
    /// The shortest period the administrator audit trail may be kept for
    /// (issue #634): a configured value below this is raised to it, never
    /// silently applied.
    /// </summary>
    public const int AuditTrailFloorDays = 90;

    /// <summary>
    /// How many days administrator audit rows and the failed sign in counts
    /// are kept. <c>0</c> keeps them for ever; any other value below
    /// <see cref="AuditTrailFloorDays"/> is raised to the floor, see
    /// <see cref="EffectiveAuditTrailDays"/>.
    /// </summary>
    public int AuditTrailDays { get; set; } = 730;

    /// <summary>
    /// The audit trail period the pass applies: the configured value, or the
    /// floor when the value is positive and below it. 0 stays 0 (for ever).
    /// </summary>
    public int EffectiveAuditTrailDays =>
        AuditTrailDays <= 0 ? 0 : Math.Max(AuditTrailFloorDays, AuditTrailDays);

    /// <summary>True when the configured audit trail period had to be raised to the floor.</summary>
    public bool AuditTrailRaisedToFloor => AuditTrailDays > 0 && AuditTrailDays < AuditTrailFloorDays;

    /// <summary>
    /// Rows removed per statement. Values below 1 are raised to 1. Internal so a
    /// test can prove the pass loops over more than one batch; it is not a
    /// documented setting.
    /// </summary>
    public int BatchSize { get; set; } = DefaultBatchSize;

    /// <summary>The batch size the pass actually uses.</summary>
    public int EffectiveBatchSize => Math.Max(1, BatchSize);

    /// <summary>Whether a period is in force: a positive number of days.</summary>
    public static bool IsEnabled(int days) => days > 0;

    /// <summary>True when every class is turned off, so the pass has nothing to do.</summary>
    public bool EverythingDisabled =>
        !IsEnabled(FinishedOrderDays) && !IsEnabled(DeactivatedAccountDays) && !IsEnabled(AlertHistoryDays)
        && !IsEnabled(EffectiveAuditTrailDays);
}
