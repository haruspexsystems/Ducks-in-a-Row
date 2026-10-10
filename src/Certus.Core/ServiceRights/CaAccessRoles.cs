namespace Certus.Core.ServiceRights;

/// <summary>
/// The role bits <c>ICertAdmin2::GetMyRoles</c> returns (the CA_ACCESS values
/// in certadm.h), and the names the Certification Authority console gives the
/// four that appear on a CA's Security tab (issue #440).
///
/// [MS-CSRA] says the CA works these out for the caller from its own security
/// descriptor and the caller's token, so they are the CA's verdict rather than
/// our reading of an access list. They are still not an exercise of the right,
/// which is why a row built on them reads Inferred.
///
/// This file is also compiled into tools/AdcsQiProbe. Keep it to the base class
/// library and C# 12.
/// </summary>
public static class CaAccessRoles
{
    /// <summary>CA_ACCESS_ADMIN, shown as "Manage CA".</summary>
    public const int Administrator = 0x1;

    /// <summary>CA_ACCESS_OFFICER, shown as "Issue and Manage Certificates". Revocation needs it.</summary>
    public const int Officer = 0x2;

    /// <summary>CA_ACCESS_AUDITOR, a privilege on the CA server rather than a Security tab entry.</summary>
    public const int Auditor = 0x4;

    /// <summary>CA_ACCESS_OPERATOR (backup), a privilege on the CA server rather than a Security tab entry.</summary>
    public const int Operator = 0x8;

    /// <summary>CA_ACCESS_READ, shown as "Read".</summary>
    public const int Read = 0x100;

    /// <summary>CA_ACCESS_ENROLL, shown as "Request Certificates".</summary>
    public const int Enroll = 0x200;

    private static readonly (int Bit, string Name)[] Names =
    [
        (Administrator, "Manage CA"),
        (Officer, "Issue and Manage Certificates"),
        (Auditor, "Auditor"),
        (Operator, "Backup operator"),
        (Read, "Read"),
        (Enroll, "Request Certificates"),
    ];

    /// <summary>True when <paramref name="mask"/> carries every bit of <paramref name="role"/>.</summary>
    public static bool Has(int mask, int role) => (mask & role) == role;

    /// <summary>
    /// The console names of the roles in <paramref name="mask"/>, in the order
    /// the Security tab lists them, with any bit this code does not know
    /// reported as hex rather than dropped.
    /// </summary>
    public static IReadOnlyList<string> Describe(int mask)
    {
        var names = new List<string>();
        var known = 0;
        foreach (var (bit, name) in Names)
        {
            known |= bit;
            if ((mask & bit) != 0)
                names.Add(name);
        }

        var unknown = mask & ~known;
        if (unknown != 0)
            names.Add($"unknown bits 0x{unknown:X}");
        return names;
    }
}
