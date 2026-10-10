namespace Certus.Core.Crl;

/// <summary>
/// Reads one distribution point, whatever scheme it uses.
///
/// The seam exists because the two schemes live on opposite sides of a project
/// boundary: HTTP is <see cref="HttpCrlFetcher"/> here in Certus.Core, and LDAP
/// needs System.DirectoryServices, which is Windows only and lives in
/// Certus.Adcs. Certus.Core cannot reference that, and the dev web host cannot
/// reference it either, so the monitor asks through this instead.
/// </summary>
public interface ICrlDistributionPointFetcher
{
    /// <summary>
    /// Reads the CRL at <paramref name="url"/>. Never throws for anything about
    /// the distribution point itself: an unreachable one is a normal state of
    /// the world and comes back as a failed result.
    /// </summary>
    /// <param name="knownETag">The entity tag stored from the last read, for a conditional request.</param>
    /// <param name="knownLastModified">The last modified time stored from the last read.</param>
    Task<CrlFetchResult> FetchAsync(
        string url,
        string? knownETag,
        DateTimeOffset? knownLastModified,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// The directory half of the fetcher, implemented where
/// System.DirectoryServices is available.
/// </summary>
public interface ILdapCrlFetcher
{
    CrlFetchResult Fetch(LdapCdpUrl url);
}

/// <summary>
/// Routes a distribution point URL to the fetcher for its scheme.
///
/// The LDAP half is optional. On the dev web host there is none, and the mock CA
/// publishes no distribution point at all, so nothing there ever asks. A real
/// service always has it.
/// </summary>
public sealed class CrlDistributionPointFetcher : ICrlDistributionPointFetcher
{
    private readonly HttpCrlFetcher _http;
    private readonly ILdapCrlFetcher? _ldap;
    private readonly int _maxCrlBytes;

    public CrlDistributionPointFetcher(
        HttpCrlFetcher http,
        int maxCrlBytes,
        ILdapCrlFetcher? ldap = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _maxCrlBytes = maxCrlBytes;
        _ldap = ldap;
    }

    public async Task<CrlFetchResult> FetchAsync(
        string url,
        string? knownETag,
        DateTimeOffset? knownLastModified,
        CancellationToken cancellationToken = default)
    {
        if (LdapCdpUrl.TryParse(url, out var ldapUrl, out _))
        {
            return _ldap is null
                ? CrlFetchResult.Failure(
                    "This host cannot read an LDAP distribution point.")
                : _ldap.Fetch(ldapUrl!);
        }

        if (Uri.TryCreate(url, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            return await _http
                .FetchAsync(uri, _maxCrlBytes, knownETag, knownLastModified, cancellationToken)
                .ConfigureAwait(false);
        }

        // file:// and ftp:// distribution points exist. A CA writes a file URL so
        // it can publish to a share, not so clients can read from one, and
        // Microsoft's own CA refuses to fetch over FTP.
        return CrlFetchResult.Failure("Only HTTP and LDAP distribution points are read.");
    }
}
