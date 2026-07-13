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
                using var searcher = new DirectorySearcher(enrollmentEntry)
                {
                    Filter = "(objectClass=pKIEnrollmentService)",
                    SearchScope = SearchScope.OneLevel,
                    PageSize = 1000
                };
                searcher.PropertiesToLoad.Add("cn");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("displayName");

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

    private static string? GetSingle(SearchResult sr, string property)
    {
        var values = sr.Properties[property];
        if (values == null || values.Count == 0)
            return null;
        return values[0]?.ToString();
    }
}
