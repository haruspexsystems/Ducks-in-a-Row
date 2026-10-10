namespace Certus.Core.Setup;

/// <summary>
/// An enterprise CA published in Active Directory, as offered by the setup
/// wizard's discovery step.
/// </summary>
/// <param name="HostName">The CA server DNS name (AD <c>dNSHostName</c>).</param>
/// <param name="CaName">The CA common name (AD <c>cn</c>).</param>
/// <param name="DisplayName">The AD <c>displayName</c> when present, otherwise the common name.</param>
/// <param name="ConnectionString">The ready to use "HostName\CaName" connection string.</param>
public sealed record DiscoveredCa(
    string HostName,
    string CaName,
    string DisplayName,
    string ConnectionString);

/// <summary>
/// Enumerates the enterprise CAs published in the forest so the setup wizard
/// can offer a pick list when more than one CA exists. Best effort by
/// contract: any failure (host not domain joined, AD unreachable, insufficient
/// rights) returns an empty list and the wizard falls back to manual entry.
/// </summary>
public interface ICaDiscoveryService
{
    Task<IReadOnlyList<DiscoveredCa>> DiscoverAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Discovery for mock mode: one well known fake CA so the wizard flow stays
/// demonstrable without a domain.
/// </summary>
public sealed class MockCaDiscoveryService : ICaDiscoveryService
{
    public Task<IReadOnlyList<DiscoveredCa>> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<DiscoveredCa> cas =
        [
            new DiscoveredCa(
                HostName: "ca-server.corp.example.com",
                CaName: "Example Issuing CA",
                DisplayName: "Example Issuing CA",
                ConnectionString: "ca-server.corp.example.com\\Example Issuing CA"),
        ];
        return Task.FromResult(cas);
    }
}
