using System.DirectoryServices;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging;

namespace Certus.Adcs;

/// <summary>
/// Discovers the enterprise CAs published in Active Directory for the setup
/// wizard's CA selection step. Enrollment services live in the Configuration
/// partition under
/// <c>CN=Enrollment Services,CN=Public Key Services,CN=Services,&lt;ConfigurationNamingContext&gt;</c>,
/// one <c>pKIEnrollmentService</c> object per CA, carrying the CA common name
/// (<c>cn</c>) and its host (<c>dNSHostName</c>) — exactly the two parts of
/// the "HostName\CaName" connection string.
///
/// Modeled on <see cref="AdcsTemplateDirectoryLookup"/> and best effort under
/// the same contract: if the host is not domain joined, AD is unreachable, or
/// the account cannot read the Configuration partition, an empty list is
/// returned and the wizard falls back to manual entry. This is a plain LDAP
/// read; no COM is involved.
/// </summary>
public sealed class AdcsCaDiscoveryService : ICaDiscoveryService
{
    /// <summary>
    /// Deadlines for the enrollment services search, so a domain controller
    /// that stops answering the search cannot pin a thread pool thread for the
    /// OS level TCP timeout while the wizard's CA step waits on it (issue
    /// #466). The project notes require both on every
    /// <see cref="DirectorySearcher"/>, and this search is paged, so the per
    /// page limit is set too. The values are
    /// <see cref="AdcsTemplateDirectoryLookup"/>'s: the wizard asks once when
    /// the step opens rather than once per keystroke like the principal
    /// picker, so it can afford the more patient pair. They bound the search
    /// only: the binds before it, RootDSE and the search root, take no
    /// deadline here or in any other reader, because a DirectoryEntry offers
    /// no control for one.
    /// </summary>
    private static readonly TimeSpan SearchClientTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan SearchServerTimeLimit = TimeSpan.FromSeconds(20);

    private readonly ILogger<AdcsCaDiscoveryService> _logger;

    public AdcsCaDiscoveryService(ILogger<AdcsCaDiscoveryService> logger)
    {
        _logger = logger;
    }

    public Task<IReadOnlyList<DiscoveredCa>> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        // System.DirectoryServices is synchronous; keep the request thread free.
        return Task.Run<IReadOnlyList<DiscoveredCa>>(() =>
        {
            var result = new List<DiscoveredCa>();

            try
            {
                using var rootDse = new DirectoryEntry("LDAP://RootDSE");
                var configContext = rootDse.Properties["configurationNamingContext"]?.Value as string;
                if (string.IsNullOrEmpty(configContext))
                {
                    _logger.LogWarning(
                        "CA discovery: configurationNamingContext not available; the setup wizard " +
                        "falls back to manual CA entry.");
                    return result;
                }

                var path = $"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,{configContext}";
                using var enrollmentEntry = new DirectoryEntry(path);
                using var searcher = CreateSearcher(enrollmentEntry);

                using var found = searcher.FindAll();
                foreach (SearchResult sr in found)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var caName = GetSingle(sr, "cn");
                    var hostName = GetSingle(sr, "dNSHostName");
                    if (string.IsNullOrWhiteSpace(caName) || string.IsNullOrWhiteSpace(hostName))
                        continue;

                    var displayName = GetSingle(sr, "displayName");
                    result.Add(new DiscoveredCa(
                        HostName: hostName,
                        CaName: caName,
                        DisplayName: string.IsNullOrWhiteSpace(displayName) ? caName : displayName,
                        ConnectionString: $"{hostName}\\{caName}"));
                }

                _logger.LogInformation("CA discovery: found {Count} enrollment service(s) in AD.", result.Count);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "CA discovery failed; the setup wizard falls back to manual CA entry. This is " +
                    "expected when the host is not domain joined or AD is unreachable.");
            }

            return (IReadOnlyList<DiscoveredCa>)result;
        }, cancellationToken);
    }

    /// <summary>
    /// Builds the one level search for the <c>pKIEnrollmentService</c> objects
    /// under the Enrollment Services container. It is apart from the read so a
    /// test can pin the deadlines without a domain: constructing a searcher, or
    /// the entry it searches from, binds nothing.
    /// </summary>
    internal static DirectorySearcher CreateSearcher(DirectoryEntry enrollmentServices)
    {
        var searcher = new DirectorySearcher(enrollmentServices)
        {
            Filter = "(objectClass=pKIEnrollmentService)",
            SearchScope = SearchScope.OneLevel,
            PageSize = 1000,
            ClientTimeout = SearchClientTimeout,
            ServerTimeLimit = SearchServerTimeLimit,
            ServerPageTimeLimit = SearchServerTimeLimit
        };
        searcher.PropertiesToLoad.Add("cn");
        searcher.PropertiesToLoad.Add("dNSHostName");
        searcher.PropertiesToLoad.Add("displayName");
        return searcher;
    }

    private static string? GetSingle(SearchResult sr, string property)
    {
        var values = sr.Properties[property];
        if (values == null || values.Count == 0)
            return null;
        return values[0]?.ToString();
    }
}
