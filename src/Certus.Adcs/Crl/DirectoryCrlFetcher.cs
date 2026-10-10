using Certus.Core.Crl;

namespace Certus.Adcs.Crl;

/// <summary>
/// The directory half of the distribution point fetcher, bound on the host that
/// has System.DirectoryServices. The dev web host has none and never asks,
/// because the mock CA publishes no distribution point.
///
/// The timeouts are here rather than in <see cref="LdapCrlFetcher"/> so the
/// fetcher itself stays a plain function the probe can link and call.
/// </summary>
public sealed class DirectoryCrlFetcher : ILdapCrlFetcher
{
    private readonly TimeSpan _clientTimeout;
    private readonly TimeSpan _serverTimeLimit;

    public DirectoryCrlFetcher(TimeSpan clientTimeout)
    {
        _clientTimeout = clientTimeout;

        // Two thirds of the client's patience, so the server gives up first and
        // says why, the way AdPrincipalLookup and the template lookup are set.
        _serverTimeLimit = TimeSpan.FromSeconds(Math.Max(1, clientTimeout.TotalSeconds * 2 / 3));
    }

    public CrlFetchResult Fetch(LdapCdpUrl url) =>
        LdapCrlFetcher.Fetch(url, _clientTimeout, _serverTimeLimit);
}
