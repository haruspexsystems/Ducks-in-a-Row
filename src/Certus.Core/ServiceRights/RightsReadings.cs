namespace Certus.Core.ServiceRights;

/// <summary>
/// How one reading behind the service rights check ended (issue #440).
///
/// Every reading comes back as a value rather than an exception, because the
/// check reports on each right on its own and one failure must never hide the
/// others. That is the contract the directory readers already keep (CLAUDE.md,
/// "Directory lookups"), applied to the COM readings as well.
///
/// This file is also compiled into tools/AdcsQiProbe, so the lab run reports in
/// the product's own vocabulary. Keep it to the base class library and C# 12.
/// </summary>
public enum ReadingOutcome
{
    /// <summary>The reading answered.</summary>
    Ok,

    /// <summary>The CA or the directory refused the service's account.</summary>
    AccessDenied,

    /// <summary>The CA or a domain controller could not be reached.</summary>
    Unavailable,

    /// <summary>
    /// A COM class the product needs is not registered on this server, which
    /// almost always means the RSAT-ADCS-Mgmt feature is missing.
    /// </summary>
    NotRegistered,

    /// <summary>
    /// The object asked about does not exist, such as a template name the
    /// directory does not know or a computer account it has no record of.
    /// </summary>
    NotFound,

    /// <summary>This server is not joined to a domain, so there is no directory to ask.</summary>
    NotDomainJoined,

    /// <summary>Anything else. The reading's detail says what.</summary>
    Failed,
}

/// <summary>One ADCS COM class, activated on this server without contacting the CA.</summary>
/// <param name="Name">The coclass, for example <c>CertView</c>.</param>
/// <param name="Outcome">Whether it activated.</param>
/// <param name="HResult">The failure's HRESULT, when there was one.</param>
/// <param name="Detail">A plain language reason when it did not activate.</param>
public sealed record ComponentReading(
    string Name,
    ReadingOutcome Outcome,
    int? HResult = null,
    string? Detail = null);

/// <summary>
/// The three ADCS COM classes the product uses. CertRequest comes with every
/// copy of Windows; CertView and CertAdmin come with the RSAT-ADCS-Mgmt feature,
/// which is why a check of CertRequest alone proves nothing about that feature.
/// </summary>
public sealed record ComponentsReading(IReadOnlyList<ComponentReading> Components);

/// <summary>
/// Who the service is when it reaches the CA and the directory, and which
/// groups that identity carries.
/// </summary>
/// <param name="Outcome">Ok when the account and its groups were read.</param>
/// <param name="DomainJoined">
/// Whether this server is joined to a domain, read from the local join state so
/// it is answered even when no domain controller is reachable. Null when the
/// join state itself could not be read.
/// </param>
/// <param name="DomainName">
/// The NetBIOS name of the joined domain, or the workgroup name on a host that
/// is not joined. Null when unknown.
/// </param>
/// <param name="ProcessIdentity">The Windows identity the process runs as, for example <c>NT AUTHORITY\SYSTEM</c>.</param>
/// <param name="IsMachineIdentity">
/// True when that identity reaches the network as this server's computer
/// account. LocalSystem and NetworkService do; LocalService does not.
/// </param>
/// <param name="AccountName">The account the CA sees, for example <c>CORP\DUCKS01$</c>. Null when unknown.</param>
/// <param name="AccountSid">That account's SID in string form. Null when unknown.</param>
/// <param name="GroupSids">
/// The account's security groups, transitively. For the computer account they
/// come from its <c>tokenGroups</c> in the directory, because the process token
/// of LocalSystem does not carry them. For any other identity they come from
/// the process token.
/// </param>
/// <param name="Detail">A plain language reason when the outcome is not Ok.</param>
public sealed record PrincipalReading(
    ReadingOutcome Outcome,
    bool? DomainJoined,
    string? DomainName,
    string ProcessIdentity,
    bool IsMachineIdentity,
    string? AccountName,
    string? AccountSid,
    IReadOnlyList<string> GroupSids,
    string? Detail = null);

/// <summary>
/// The CA's own answer to "which roles do I hold", from
/// <c>ICertAdmin2::GetMyRoles</c>. The CA works it out from the caller's
/// token, so groups local to the CA and deny entries count, which no directory
/// read can see.
/// </summary>
/// <param name="Outcome">Ok when the CA answered.</param>
/// <param name="RolesMask">The CA_ACCESS bit mask when the CA answered. See <see cref="CaAccessRoles"/>.</param>
/// <param name="HResult">The failure's HRESULT, when there was one.</param>
/// <param name="Detail">A plain language reason when the outcome is not Ok.</param>
public sealed record CaRolesReading(
    ReadingOutcome Outcome,
    int? RolesMask,
    int? HResult = null,
    string? Detail = null);

/// <summary>What kind of permission entry an <see cref="AclEntry"/> is, as far as the Enroll test cares.</summary>
public enum AclEntryKind
{
    /// <summary>An access allowed entry.</summary>
    Allow,

    /// <summary>An access denied entry.</summary>
    Deny,

    /// <summary>
    /// A kind the test does not evaluate, such as a conditional (callback)
    /// entry. When one of these could decide the right, the verdict is
    /// Undetermined rather than a guess.
    /// </summary>
    Unsupported,
}

/// <summary>
/// One entry of a template's permission list, reduced to what the Enroll test reads.
/// </summary>
/// <param name="Kind">Allow, deny, or a kind the test does not evaluate.</param>
/// <param name="AccessMask">The access mask as stored in the directory.</param>
/// <param name="ObjectType">
/// The extended right or property the entry is limited to, or null when it
/// applies to all of them.
/// </param>
/// <param name="InheritOnly">
/// True when the entry exists only to be inherited by child objects and does
/// not apply to the template itself.
/// </param>
/// <param name="Inherited">True when the entry was inherited from the container.</param>
/// <param name="TrusteeSid">
/// Whom the entry is about, as a SID string, or <see cref="AnyTrustee"/> for an
/// entry whose trustee could not be read.
/// </param>
public sealed record AclEntry(
    AclEntryKind Kind,
    int AccessMask,
    Guid? ObjectType,
    bool InheritOnly,
    bool Inherited,
    string TrusteeSid)
{
    /// <summary>
    /// Stands in for the trustee of an entry that could not be read. It matches
    /// every account, so an unreadable entry that could decide the right makes
    /// the verdict Undetermined instead of being silently skipped.
    /// </summary>
    public const string AnyTrustee = "*";
}

/// <summary>
/// A template's permission list as the directory returned it to the service's account.
/// </summary>
/// <param name="TemplateName">The template's programmatic name (its <c>cn</c>).</param>
/// <param name="Outcome">Ok when the list was read.</param>
/// <param name="Entries">
/// The entries in the order they are stored, which is the order Windows
/// evaluates them in. Empty unless the outcome is Ok.
/// </param>
/// <param name="Sddl">The permission list in SDDL, for the record and the lab log. Null when not read.</param>
/// <param name="Detail">A plain language reason when the outcome is not Ok.</param>
public sealed record TemplateDaclReading(
    string TemplateName,
    ReadingOutcome Outcome,
    IReadOnlyList<AclEntry> Entries,
    string? Sddl = null,
    string? Detail = null);
