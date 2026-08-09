using System.DirectoryServices;
using System.Security.Principal;
using System.Text;
using Certus.Core.ActiveDirectory;
using Microsoft.Extensions.Logging;

namespace Certus.Adcs;

/// <summary>
/// Directory principal lookup for the EAB credential owner link, over the
/// domain's default naming context. Searches users, computers, groups, and
/// managed service accounts by <c>sAMAccountName</c> or <c>cn</c> prefix and
/// resolves a SID through the <c>LDAP://&lt;SID=...&gt;</c> binding syntax.
///
/// Modeled on <see cref="AdcsCaDiscoveryService"/> and best effort under the
/// same contract: if the host is not domain joined, AD is unreachable, or the
/// account lacks read rights, a search returns an empty list and a resolve
/// returns null. The owner link is display and audit only, so a degraded
/// directory degrades the picker, never an ACME or issuance path. Plain LDAP
/// reads; no COM interop is involved.
/// </summary>
public sealed class AdPrincipalLookup : IAdPrincipalLookup
{
    /// <summary>
    /// Cap for one search. The picker shows a short type ahead list; a
    /// broader prefix wants narrowing, not paging.
    /// </summary>
    private const int MaxResults = 20;

    /// <summary>
    /// Deadlines for one search, so a DC that stops answering mid session
    /// cannot pin a thread pool thread for the OS level TCP timeout. The
    /// picker fires a request per debounced keystroke; a search that cannot
    /// answer in seconds should fail and free the thread.
    /// </summary>
    private static readonly TimeSpan SearchClientTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan SearchServerTimeLimit = TimeSpan.FromSeconds(10);

    private static readonly string[] PrincipalProperties =
        ["sAMAccountName", "cn", "objectSid", "objectCategory", "distinguishedName"];

    private readonly ILogger<AdPrincipalLookup> _logger;

    /// <summary>
    /// The domain's default naming context, read from RootDSE once and then
    /// reused: it is fixed for the lifetime of the process, and re-reading it
    /// would double the directory round trips of every picker keystroke.
    /// Stays null (and is re-probed) until a read succeeds. Benign race: two
    /// concurrent first searches write the same value.
    /// </summary>
    private volatile string? _defaultNamingContext;

    public AdPrincipalLookup(ILogger<AdPrincipalLookup> logger)
    {
        _logger = logger;
    }

    public Task<IReadOnlyList<AdPrincipal>> SearchAsync(
        string query, CancellationToken cancellationToken = default)
    {
        var trimmed = query.Trim();
        if (trimmed.Length == 0)
            return Task.FromResult<IReadOnlyList<AdPrincipal>>(Array.Empty<AdPrincipal>());

        // System.DirectoryServices is synchronous; keep the request thread free.
        return Task.Run<IReadOnlyList<AdPrincipal>>(() =>
        {
            var result = new List<AdPrincipal>();

            try
            {
                var defaultContext = GetDefaultNamingContext();
                if (defaultContext == null)
                {
                    _logger.LogWarning(
                        "Principal search: defaultNamingContext not available; the owner " +
                        "picker shows no directory results.");
                    return result;
                }

                var escaped = EscapeFilterValue(trimmed);
                using var domainEntry = new DirectoryEntry($"LDAP://{defaultContext}");
                using var searcher = new DirectorySearcher(domainEntry)
                {
                    // objectCategory separates the kinds cleanly: computer
                    // objects carry objectClass user too, but their category
                    // is computer, not person. Managed service accounts (the
                    // archetypal ACME client identity) have their own two
                    // categories and would be invisible behind person or
                    // computer alone.
                    Filter = "(&(|(objectCategory=person)(objectCategory=computer)" +
                             "(objectCategory=group)(objectCategory=msDS-ManagedServiceAccount)" +
                             "(objectCategory=msDS-GroupManagedServiceAccount))" +
                             $"(|(sAMAccountName={escaped}*)(cn={escaped}*)))",
                    SearchScope = SearchScope.Subtree,
                    // A client side cap, no paging: the server stops at the
                    // limit and the picker never wants more than one page.
                    SizeLimit = MaxResults,
                    ClientTimeout = SearchClientTimeout,
                    ServerTimeLimit = SearchServerTimeLimit,
                };
                foreach (var property in PrincipalProperties)
                    searcher.PropertiesToLoad.Add(property);

                using var found = searcher.FindAll();
                foreach (SearchResult sr in found)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var principal = ToPrincipal(sr);
                    if (principal != null)
                        result.Add(principal);
                }

                result.Sort((a, b) =>
                    string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Principal search for '{Query}' failed; the owner picker shows no " +
                    "directory results. This is expected when the host is not domain " +
                    "joined or AD is unreachable.",
                    trimmed);
            }

            return (IReadOnlyList<AdPrincipal>)result;
        }, cancellationToken);
    }

    public Task<AdPrincipal?> ResolveSidAsync(
        string sid, CancellationToken cancellationToken = default)
    {
        // Parse before binding: the SDDL form is about to be embedded in an
        // LDAP path, so anything that is not a well formed SID stops here.
        SecurityIdentifier parsed;
        try
        {
            parsed = new SecurityIdentifier(sid.Trim());
        }
        catch (ArgumentException)
        {
            return Task.FromResult<AdPrincipal?>(null);
        }

        return Task.Run<AdPrincipal?>(() =>
        {
            try
            {
                // The <SID=...> binding resolves the object wherever it lives
                // in the domain, with no filter round trip. The bind is lazy;
                // RefreshCache is the first server contact and throws for a
                // SID that does not exist.
                using var entry = new DirectoryEntry($"LDAP://<SID={parsed.Value}>");
                entry.RefreshCache(PrincipalProperties);

                cancellationToken.ThrowIfCancellationRequested();

                var name = entry.Properties["sAMAccountName"]?.Value as string
                    ?? entry.Properties["cn"]?.Value as string;
                var type = TypeFromCategory(entry.Properties["objectCategory"]?.Value as string);
                if (name == null || type == null)
                {
                    _logger.LogWarning(
                        "Principal resolve: {Sid} exists but is not a user, computer, " +
                        "group, or managed service account; refusing the owner link.",
                        parsed.Value);
                    return null;
                }

                return new AdPrincipal(
                    parsed.Value,
                    name,
                    type,
                    entry.Properties["distinguishedName"]?.Value as string);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Principal resolve for {Sid} failed; the SID is unknown or AD is unreachable.",
                    parsed.Value);
                return null;
            }
        }, cancellationToken);
    }

    private string? GetDefaultNamingContext()
    {
        var cached = _defaultNamingContext;
        if (cached != null)
            return cached;

        using var rootDse = new DirectoryEntry("LDAP://RootDSE");
        var read = rootDse.Properties["defaultNamingContext"]?.Value as string;
        if (!string.IsNullOrEmpty(read))
            _defaultNamingContext = read;
        return _defaultNamingContext;
    }

    private static AdPrincipal? ToPrincipal(SearchResult sr)
    {
        var sidBytes = GetSingle(sr, "objectSid") as byte[];
        var name = GetSingle(sr, "sAMAccountName") as string
            ?? GetSingle(sr, "cn") as string;
        var type = TypeFromCategory(GetSingle(sr, "objectCategory") as string);
        if (sidBytes == null || name == null || type == null)
            return null;

        return new AdPrincipal(
            new SecurityIdentifier(sidBytes, 0).Value,
            name,
            type,
            GetSingle(sr, "distinguishedName") as string);
    }

    /// <summary>
    /// Maps an <c>objectCategory</c> DN ("CN=Person,CN=Schema,...") to the
    /// principal type the picker displays. The search filter only admits
    /// these categories; anything else reads as null and is skipped. The
    /// managed service account schema classes use hyphenated common names
    /// (<c>CN=ms-DS-Managed-Service-Account</c>), unlike their
    /// lDAPDisplayName. Internal for unit tests; the directory itself needs
    /// the lab domain.
    /// </summary>
    internal static string? TypeFromCategory(string? categoryDn)
    {
        if (categoryDn == null)
            return null;
        if (categoryDn.StartsWith("CN=Person,", StringComparison.OrdinalIgnoreCase))
            return "user";
        if (categoryDn.StartsWith("CN=Computer,", StringComparison.OrdinalIgnoreCase))
            return "computer";
        if (categoryDn.StartsWith("CN=Group,", StringComparison.OrdinalIgnoreCase))
            return "group";
        if (categoryDn.StartsWith("CN=ms-DS-Managed-Service-Account,", StringComparison.OrdinalIgnoreCase)
            || categoryDn.StartsWith("CN=ms-DS-Group-Managed-Service-Account,", StringComparison.OrdinalIgnoreCase))
            return "service account";
        return null;
    }

    /// <summary>
    /// Escapes one value for embedding in an LDAP filter (RFC 4515), so a
    /// typed query can never terminate or extend the filter expression.
    /// Internal for unit tests.
    /// </summary>
    internal static string EscapeFilterValue(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            switch (ch)
            {
                case '\\': sb.Append(@"\5c"); break;
                case '*': sb.Append(@"\2a"); break;
                case '(': sb.Append(@"\28"); break;
                case ')': sb.Append(@"\29"); break;
                case '\0': sb.Append(@"\00"); break;
                default: sb.Append(ch); break;
            }
        }
        return sb.ToString();
    }

    private static object? GetSingle(SearchResult sr, string property)
    {
        var values = sr.Properties[property];
        if (values == null || values.Count == 0)
            return null;
        return values[0];
    }
}
