using Certus.Core.Configuration;

namespace Certus.Core.ServiceRights;

/// <summary>One right, or one prerequisite, and what the check could establish about it.</summary>
/// <param name="Id">
/// Stable identifier: <c>domain</c>, <c>components</c>, <c>ca-connect</c>,
/// <c>ca-enroll</c>, <c>ca-read</c>, <c>ca-officer</c>, <c>template:&lt;name&gt;</c>,
/// <c>https-enrolment</c> or <c>challenge-egress</c>.
/// </param>
/// <param name="Group">Where the row belongs.</param>
/// <param name="Title">What the row is about, in the console's words.</param>
/// <param name="Status">What the check established.</param>
/// <param name="Basis">What that rests on.</param>
/// <param name="NeededFor">What the right is needed for.</param>
/// <param name="Detail">What was found, in plain language.</param>
/// <param name="Remedy">What to ask for or change, when there is something to do.</param>
/// <param name="Optional">
/// True for a right only an optional feature needs, today Issue and Manage
/// Certificates, which only revocation uses.
/// </param>
/// <param name="Template">The template's programmatic name, on a template row.</param>
public sealed record ServiceRightsRow(
    string Id,
    RightsGroup Group,
    string Title,
    RightsStatus Status,
    RightsBasis Basis,
    RightNeededFor NeededFor,
    string Detail,
    string? Remedy = null,
    bool Optional = false,
    string? Template = null);

/// <summary>Whose rights the report is about.</summary>
/// <param name="ProcessIdentity">The identity the service runs as, for example <c>NT AUTHORITY\SYSTEM</c>.</param>
/// <param name="IsMachineIdentity">True when that identity reaches the network as this server's computer account.</param>
/// <param name="AccountName">The account the CA sees, for example <c>CORP\DUCKS01$</c>. Null when it could not be read.</param>
/// <param name="AccountSid">That account's SID. Null when it could not be read.</param>
/// <param name="DomainName">The domain this server is joined to, when it is.</param>
/// <param name="GroupCount">How many security groups the account carries, as read.</param>
public sealed record ServiceRightsIdentity(
    string ProcessIdentity,
    bool IsMachineIdentity,
    string? AccountName,
    string? AccountSid,
    string? DomainName,
    int GroupCount);

/// <summary>The whole answer for one CA and one set of templates.</summary>
/// <param name="CaConnectionString">The CA the rows are about.</param>
/// <param name="Identity">Whose rights they are.</param>
/// <param name="Rows">One row per right, in the order a page shows them.</param>
/// <param name="Simulated">True on the dev host, whose answers describe an example estate.</param>
/// <param name="CheckedAt">When the check ran.</param>
public sealed record ServiceRightsReport(
    string CaConnectionString,
    ServiceRightsIdentity Identity,
    IReadOnlyList<ServiceRightsRow> Rows,
    bool Simulated,
    DateTimeOffset CheckedAt)
{
    /// <summary>
    /// The report as the API carries it, with every enum as its camelCase name. Given
    /// the instance mode, a row whose right only issuance or revocation uses carries
    /// <c>notNeeded: "monitorMode"</c> in monitor mode (issue #470), so the page does
    /// not send an operator to collect rights the mode never uses. The check itself is
    /// untouched and the row keeps what it measured; only what the page makes of it
    /// changes, which is the use <see cref="RightNeededFor"/> was added for.
    /// </summary>
    public ServiceRightsReportWire ToWire(CertusInstanceMode? instanceMode = null) => new(
        CaConnectionString,
        Identity,
        Rows.Select(row => new ServiceRightsRowWire(
            row.Id,
            ServiceRightsWire.Group(row.Group),
            row.Title,
            ServiceRightsWire.Status(row.Status),
            ServiceRightsWire.Basis(row.Basis),
            ServiceRightsWire.NeededFor(row.NeededFor),
            row.Detail,
            row.Remedy,
            row.Optional,
            row.Template,
            instanceMode?.IsMonitor == true && IsNotNeededInMonitorMode(row.NeededFor)
                ? ServiceRightsWire.NotNeededInMonitorMode
                : null)).ToList(),
        Simulated,
        CheckedAt);

    /// <summary>
    /// True when everything the right is needed for is something monitor mode never
    /// does. Written as "nothing outside issuance and revocation" rather than as a list
    /// of the rows it covers, so a purpose added to <see cref="RightNeededFor"/> later
    /// keeps its rows needed until someone decides otherwise. A row that lists nothing
    /// is needed for the same reason.
    /// </summary>
    public static bool IsNotNeededInMonitorMode(RightNeededFor neededFor) =>
        neededFor != RightNeededFor.None
        && (neededFor & ~(RightNeededFor.Issuance | RightNeededFor.Revocation)) == RightNeededFor.None;
}

/// <summary>The report on the wire.</summary>
/// <param name="TemplatesNotChecked">
/// How many of the template names enabled for ACME were left out because one check
/// reads at most <see cref="ServiceRightsCheck.MaxTemplates"/> (issue #478), so the
/// page can say that those templates have no rows rather than let their absence
/// read as a clean answer. Only the Settings route sets it. The wizard's route
/// refuses a longer list instead, so it always sends 0.
/// </param>
public sealed record ServiceRightsReportWire(
    string CaConnectionString,
    ServiceRightsIdentity Identity,
    IReadOnlyList<ServiceRightsRowWire> Rows,
    bool Simulated,
    DateTimeOffset CheckedAt,
    int TemplatesNotChecked = 0);

/// <summary>A row on the wire.</summary>
public sealed record ServiceRightsRowWire(
    string Id,
    string Group,
    string Title,
    string Status,
    string Basis,
    IReadOnlyList<string> NeededFor,
    string Detail,
    string? Remedy,
    bool Optional,
    string? Template,
    string? NotNeeded = null);

/// <summary>
/// What a lab measurement established about the CA's behaviour, which decides
/// how far a reading may be trusted. The rows are built against this record
/// rather than against assumptions written into each builder, so the evidence
/// sits in one place with its date, and the tests can hold both answers.
/// </summary>
/// <param name="ConnectProvesRequestCertificates">
/// True when the request interface's GetCAProperty, which is Test Connection,
/// is refused to an account without Request Certificates. A passing Test
/// Connection has then exercised that right.
/// </param>
/// <param name="CaRolesTrusted">
/// True when <c>ICertAdmin2::GetMyRoles</c> was seen to follow the CA's
/// security descriptor, so its report can back an Inferred row.
/// </param>
/// <param name="ViewOpenProvesInventory">
/// True when a view that opens was seen to show every certificate, so opening it
/// proves the inventory will be complete rather than merely readable.
/// </param>
public sealed record ServiceRightsFindings(
    bool ConnectProvesRequestCertificates,
    bool CaRolesTrusted,
    bool ViewOpenProvesInventory)
{
    /// <summary>
    /// Measured on lab 2019 (Server 2019) on 2026-09-26, running the
    /// probe as SYSTEM on the Certus host, so as the service's own computer
    /// account, through four states of that account's rights on the CA:
    ///
    /// <list type="bullet">
    /// <item>With Read and Issue and Manage (the lab's baseline) and with only the
    /// Request Certificates Authenticated Users hold, Test Connection's two
    /// property reads answered. With Read but Request Certificates denied, and
    /// with every right denied, the CA refused them with CERTSRV_E_ENROLL_DENIED.
    /// So Test Connection exercises Request Certificates, as [MS-CSRA] says.</item>
    /// <item>GetMyRoles reported 0x302 at the baseline and 0x100 with Read alone,
    /// exactly the rights held. It refused the account that held only Request
    /// Certificates, as well as the one that held nothing: [MS-CSRA] says Enroll
    /// implies Read, but the CA did not honour that for GetMyRoles, the admin
    /// interface's GetCAProperty, or the certificate view.</item>
    /// <item>With Read alone the view opened, found request 1, which the account
    /// never submitted, and counted the same issued rows as the baseline. So a
    /// view that opens is not filtered to the caller's own requests. The lab CA
    /// held one issued row, which was thin.</item>
    /// </list>
    ///
    /// Issue #469 measured the view again on lab 2025 (Server 2025)
    /// on 2026-10-03, seeded to 17 issued and 5 revoked rows from three
    /// requesters. With Read, and Request Certificates only through
    /// Authenticated Users, the view returned the same request ids as the
    /// baseline through the sync's own columns, every row with its certificate,
    /// which is what <see cref="ViewOpenProvesInventory"/> rests on.
    ///
    /// Both runs are recorded in docs/lab-runs (gitignored) and on issues #440
    /// and #469.
    /// </summary>
    public static readonly ServiceRightsFindings MeasuredOnLab2019 = new(
        ConnectProvesRequestCertificates: true,
        CaRolesTrusted: true,
        ViewOpenProvesInventory: true);
}
