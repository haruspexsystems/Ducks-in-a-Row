namespace Certus.Core.ActiveDirectory;

/// <summary>
/// Principal lookup for mock mode: a small canned directory so the owner
/// picker stays demonstrable without a domain, the
/// <see cref="Setup.MockCaDiscoveryService"/> stance. The SIDs are stable
/// across restarts, so a linked owner survives a dev host restart and the
/// resolve path can be exercised end to end in tests.
/// </summary>
public sealed class MockAdPrincipalLookup : IAdPrincipalLookup
{
    // One fake domain, mirrored in every SID: S-1-5-21-<domain>-<rid>.
    private const string DomainSid = "S-1-5-21-1004336348-1177238915-682003330";
    private const string DomainDn = "DC=example,DC=com";

    private static readonly IReadOnlyList<AdPrincipal> Principals =
    [
        new AdPrincipal($"{DomainSid}-1104", "jsmith", "user",
            $"CN=Jane Smith,CN=Users,{DomainDn}"),
        new AdPrincipal($"{DomainSid}-1105", "websvc$", "service account",
            $"CN=websvc,CN=Managed Service Accounts,{DomainDn}"),
        new AdPrincipal($"{DomainSid}-1201", "WEB01$", "computer",
            $"CN=WEB01,CN=Computers,{DomainDn}"),
        new AdPrincipal($"{DomainSid}-1202", "BUILD01$", "computer",
            $"CN=BUILD01,CN=Computers,{DomainDn}"),
        new AdPrincipal($"{DomainSid}-1301", "Web Admins", "group",
            $"CN=Web Admins,OU=Groups,{DomainDn}"),
        new AdPrincipal($"{DomainSid}-1302", "Certificate Managers", "group",
            $"CN=Certificate Managers,OU=Groups,{DomainDn}"),
    ];

    public Task<IReadOnlyList<AdPrincipal>> SearchAsync(
        string query, CancellationToken cancellationToken = default)
    {
        var trimmed = query.Trim();
        if (trimmed.Length == 0)
            return Task.FromResult<IReadOnlyList<AdPrincipal>>(Array.Empty<AdPrincipal>());

        // Match the account name or the common name, the same double prefix
        // the real DirectorySearcher filter uses, so "Jane" finds jsmith
        // here exactly as it would on a domain.
        IReadOnlyList<AdPrincipal> matches = Principals
            .Where(p =>
                p.Name.StartsWith(trimmed, StringComparison.OrdinalIgnoreCase)
                || CommonNameOf(p).StartsWith(trimmed, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return Task.FromResult(matches);
    }

    public Task<AdPrincipal?> ResolveSidAsync(
        string sid, CancellationToken cancellationToken = default)
    {
        var match = Principals.FirstOrDefault(
            p => string.Equals(p.Sid, sid.Trim(), StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(match);
    }

    /// <summary>The first RDN value of the entry's DN ("CN=Jane Smith,..." gives "Jane Smith").</summary>
    private static string CommonNameOf(AdPrincipal principal)
    {
        var dn = principal.DistinguishedName;
        if (dn == null || !dn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            return string.Empty;
        var end = dn.IndexOf(',');
        return end < 0 ? dn[3..] : dn[3..end];
    }
}
