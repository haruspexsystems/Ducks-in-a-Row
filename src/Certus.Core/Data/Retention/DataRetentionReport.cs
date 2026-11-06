namespace Certus.Core.Data.Retention;

/// <summary>
/// What one retention pass removed, class by class (issue #637). The pass logs
/// these counts, and the tests read them to prove that a class was applied, or
/// left alone when its period is 0.
/// </summary>
public sealed class DataRetentionReport
{
    /// <summary>Invalid orders deleted, with everything under them.</summary>
    public int InvalidOrdersRemoved { get; set; }

    /// <summary>
    /// Valid orders whose certificate has been expired for the finished order
    /// period, deleted together with their certificate record.
    /// </summary>
    public int ValidOrdersRemoved { get; set; }

    /// <summary>Authorizations deleted, under finished orders of either status.</summary>
    public int AuthorizationsRemoved { get; set; }

    /// <summary>Challenges deleted, under finished orders of either status.</summary>
    public int ChallengesRemoved { get; set; }

    /// <summary>Certificate records (the issued leaf and its CA request id) deleted.</summary>
    public int CertificateRecordsRemoved { get; set; }

    /// <summary>
    /// Valid orders left alone because their stored certificate could not be
    /// parsed, so its expiry is unknown. Retention keeps what it cannot date.
    /// </summary>
    public int UnreadableCertificates { get; set; }

    /// <summary>Deactivated accounts whose contact addresses were removed.</summary>
    public int AccountContactsRemoved { get; set; }

    /// <summary>Deactivated accounts deleted, once no order referred to them.</summary>
    public int AccountsRemoved { get; set; }

    /// <summary>Certificate expiry alert history rows deleted.</summary>
    public int AlertHistoryRemoved { get; set; }

    /// <summary>CRL alert history rows deleted.</summary>
    public int CrlAlertHistoryRemoved { get; set; }

    /// <summary>Licence alert history rows deleted.</summary>
    public int LicenceAlertHistoryRemoved { get; set; }

    /// <summary>Administrator audit rows deleted (issue #634), never under the 90 day floor.</summary>
    public int AuditEntriesRemoved { get; set; }

    /// <summary>Failed sign in count rows (one per source and hour) deleted (issue #634).</summary>
    public int SignInFailuresRemoved { get; set; }

    /// <summary>How many batches the pass ran, across every class.</summary>
    public int Batches { get; set; }

    /// <summary>Whether the pass changed anything at all.</summary>
    public bool RemovedAnything =>
        InvalidOrdersRemoved + ValidOrdersRemoved + AuthorizationsRemoved + ChallengesRemoved
        + CertificateRecordsRemoved + AccountContactsRemoved + AccountsRemoved
        + AlertHistoryRemoved + CrlAlertHistoryRemoved + LicenceAlertHistoryRemoved
        + AuditEntriesRemoved + SignInFailuresRemoved > 0;
}
