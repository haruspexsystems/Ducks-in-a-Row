namespace Certus.Core.ServiceRights;

/// <summary>
/// What a row of the service rights check can say (issue #440). The five are
/// the issue's own, and the rule that matters most is that
/// <see cref="Inferred"/> is never a pass: a reading of a permission list, or
/// the CA's own report of a role, is not the right being used.
/// </summary>
public enum RightsStatus
{
    /// <summary>The right was exercised and it worked, now or by a certificate this server holds.</summary>
    Proven,

    /// <summary>Read, not exercised: from a permission list, or reported by the CA.</summary>
    Inferred,

    /// <summary>Nothing here could check it, or the check did not answer.</summary>
    Unproven,

    /// <summary>Exercised and refused, or read and definitely absent.</summary>
    Failed,

    /// <summary>Not attempted, because something it depends on failed first.</summary>
    Skipped,
}

/// <summary>What a row's status rests on.</summary>
public enum RightsBasis
{
    /// <summary>The call the right governs was made.</summary>
    Exercised,

    /// <summary>The CA reported the right for the service's account (<c>ICertAdmin2::GetMyRoles</c>).</summary>
    ReportedByCa,

    /// <summary>Read from a template's permission list, which the CA evaluates with a token that can carry more.</summary>
    ReadFromAcl,

    /// <summary>A certificate this server already holds shows the right was used.</summary>
    PriorEnrollment,

    /// <summary>Checked on this server alone.</summary>
    Local,

    /// <summary>Nothing checked it.</summary>
    NotChecked,
}

/// <summary>
/// What a right is needed for. Carried on every row so a mode that never
/// issues, the monitor mode of issues #470 and #471, can mark the issuance only
/// rows as not needed without a change to the check itself.
/// </summary>
[Flags]
public enum RightNeededFor
{
    /// <summary>Nothing listed.</summary>
    None = 0,

    /// <summary>Issuing certificates over ACME.</summary>
    Issuance = 1,

    /// <summary>The certificate inventory the dashboard shows.</summary>
    Inventory = 2,

    /// <summary>Revoking from the dashboard or through ACME revoke-cert.</summary>
    Revocation = 4,

    /// <summary>Watching the CA's revocation lists.</summary>
    CrlWatching = 8,
}

/// <summary>Where a row belongs, so a page can show the part it has the facts for.</summary>
public enum RightsGroup
{
    /// <summary>This server: its domain membership and its ADCS components.</summary>
    Host,

    /// <summary>The CA's own permissions.</summary>
    Ca,

    /// <summary>A template's permissions.</summary>
    Template,

    /// <summary>A whole path, end to end.</summary>
    EndToEnd,
}

/// <summary>
/// The camelCase names the API carries, because it serialises enums as numbers.
/// Each map throws for a member it does not name rather than falling through to
/// a default, so a member added later without a name fails a test instead of
/// reaching the wire as something it is not.
/// </summary>
public static class ServiceRightsWire
{
    public static string Status(RightsStatus status) => status switch
    {
        RightsStatus.Proven => "proven",
        RightsStatus.Inferred => "inferred",
        RightsStatus.Unproven => "unproven",
        RightsStatus.Failed => "failed",
        RightsStatus.Skipped => "skipped",
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "No wire name for this status."),
    };

    public static string Basis(RightsBasis basis) => basis switch
    {
        RightsBasis.Exercised => "exercised",
        RightsBasis.ReportedByCa => "reportedByCa",
        RightsBasis.ReadFromAcl => "readFromAcl",
        RightsBasis.PriorEnrollment => "priorEnrollment",
        RightsBasis.Local => "local",
        RightsBasis.NotChecked => "notChecked",
        _ => throw new ArgumentOutOfRangeException(nameof(basis), basis, "No wire name for this basis."),
    };

    public static string Group(RightsGroup group) => group switch
    {
        RightsGroup.Host => "host",
        RightsGroup.Ca => "ca",
        RightsGroup.Template => "template",
        RightsGroup.EndToEnd => "endToEnd",
        _ => throw new ArgumentOutOfRangeException(nameof(group), group, "No wire name for this group."),
    };

    /// <summary>The flags set in <paramref name="neededFor"/>, by name, in declaration order.</summary>
    public static IReadOnlyList<string> NeededFor(RightNeededFor neededFor)
    {
        var names = new List<string>();
        if (neededFor.HasFlag(RightNeededFor.Issuance)) names.Add("issuance");
        if (neededFor.HasFlag(RightNeededFor.Inventory)) names.Add("inventory");
        if (neededFor.HasFlag(RightNeededFor.Revocation)) names.Add("revocation");
        if (neededFor.HasFlag(RightNeededFor.CrlWatching)) names.Add("crlWatching");

        var known = RightNeededFor.Issuance | RightNeededFor.Inventory | RightNeededFor.Revocation | RightNeededFor.CrlWatching;
        if ((neededFor & ~known) != 0)
            throw new ArgumentOutOfRangeException(nameof(neededFor), neededFor, "No wire name for this flag.");
        return names;
    }
}
