namespace Certus.Core.ServiceRights;

/// <summary>What a template's permission list says about one extended right for one account.</summary>
public enum EnrollVerdict
{
    /// <summary>The first entry that applies allows the right.</summary>
    Granted,

    /// <summary>The first entry that applies denies the right.</summary>
    Denied,

    /// <summary>No entry applies to the account or any of its groups.</summary>
    NotGranted,

    /// <summary>
    /// An entry the test cannot evaluate applies before any decision, so the
    /// answer is not guessed.
    /// </summary>
    Undetermined,
}

/// <summary>The verdict and the entry that decided it.</summary>
/// <param name="Verdict">What the list says.</param>
/// <param name="DecidingSid">The trustee of the deciding entry. Null for <see cref="EnrollVerdict.NotGranted"/>.</param>
/// <param name="DecidedByInheritedEntry">True when the deciding entry was inherited from the container.</param>
public sealed record EnrollEvaluation(
    EnrollVerdict Verdict,
    string? DecidingSid = null,
    bool DecidedByInheritedEntry = false);

/// <summary>
/// Reads a certificate template's permission list the way the CA's policy module
/// does when it decides whether a requester may enroll (issue #440).
///
/// The rule is [MS-CRTD] section 2.5.1: an allowed object entry carrying
/// control access (0x100) whose object type is the Enroll right grants it, and
/// so does a plain allowed entry carrying control access, which covers every
/// extended right; the same shapes as deny entries refuse it. GENERIC_ALL
/// covers control access too, so it counts as well.
///
/// The order matters and is not "deny entries first". Windows walks a
/// permission list from the top and the first entry that applies to the right
/// decides it. In a list stored in canonical order explicit entries come before
/// inherited ones, so an explicit allow beats an inherited deny, and a check
/// that looked at every deny first would report that wrongly.
///
/// This is still a reading, not an exercise: the policy module evaluates the
/// list against the token the CA holds for the caller, which can carry groups
/// this server cannot see, so a template row built on it reads Inferred.
///
/// This file is also compiled into tools/AdcsQiProbe. Keep it to the base class
/// library and C# 12.
/// </summary>
public static class TemplateEnrollEvaluator
{
    /// <summary>The Certificate-Enrollment extended right.</summary>
    public static readonly Guid EnrollRight = new("0e10c968-78fb-11d2-90d4-00c04f79dc55");

    /// <summary>
    /// The Certificate-AutoEnrollment extended right. The service never needs
    /// it, so holding it only earns an "over granted" note.
    /// </summary>
    public static readonly Guid AutoenrollRight = new("a05b8cc2-17bc-4802-a710-e7c15ab866a2");

    /// <summary>ADS_RIGHT_DS_CONTROL_ACCESS, the bit every extended right is granted through.</summary>
    public const int ControlAccess = 0x100;

    /// <summary>GENERIC_ALL, which covers control access along with everything else.</summary>
    public const int GenericAll = 0x10000000;

    /// <summary>Everyone.</summary>
    public const string EveryoneSid = "S-1-1-0";

    /// <summary>Authenticated Users, the usual holder of Enroll on a stock template.</summary>
    public const string AuthenticatedUsersSid = "S-1-5-11";

    /// <summary>NETWORK, carried by every network logon, which is how the CA sees the service.</summary>
    public const string NetworkSid = "S-1-5-2";

    /// <summary>This Organization, carried by a logon from inside the forest.</summary>
    public const string ThisOrganizationSid = "S-1-5-15";

    /// <summary>
    /// The SIDs the CA's token for the service carries: the account, its
    /// groups, and the well known groups every network logon from inside the
    /// forest adds.
    /// </summary>
    public static IReadOnlySet<string> SidsForNetworkLogon(string accountSid, IEnumerable<string> groupSids)
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            accountSid,
            EveryoneSid,
            AuthenticatedUsersSid,
            NetworkSid,
            ThisOrganizationSid,
        };
        foreach (var sid in groupSids)
        {
            if (!string.IsNullOrWhiteSpace(sid))
                sids.Add(sid);
        }
        return sids;
    }

    /// <summary>
    /// What <paramref name="entries"/> says about <paramref name="right"/> for
    /// an account carrying <paramref name="sids"/>.
    /// </summary>
    public static EnrollEvaluation Evaluate(
        IReadOnlyList<AclEntry> entries,
        IReadOnlySet<string> sids,
        Guid right)
    {
        foreach (var entry in entries)
        {
            // An inherit only entry is there for child objects and does not
            // apply to the template itself.
            if (entry.InheritOnly)
                continue;

            if (entry.TrusteeSid != AclEntry.AnyTrustee && !sids.Contains(entry.TrusteeSid))
                continue;

            if ((entry.AccessMask & (ControlAccess | GenericAll)) == 0)
                continue;

            // An entry limited to a different extended right or property says
            // nothing about this one. No object type means every one of them.
            if (entry.ObjectType is { } objectType && objectType != right)
                continue;

            return entry.Kind switch
            {
                AclEntryKind.Allow => new EnrollEvaluation(EnrollVerdict.Granted, entry.TrusteeSid, entry.Inherited),
                AclEntryKind.Deny => new EnrollEvaluation(EnrollVerdict.Denied, entry.TrusteeSid, entry.Inherited),
                _ => new EnrollEvaluation(EnrollVerdict.Undetermined, entry.TrusteeSid, entry.Inherited),
            };
        }

        return new EnrollEvaluation(EnrollVerdict.NotGranted);
    }
}
