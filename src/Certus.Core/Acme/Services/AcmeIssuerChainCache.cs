using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certus.Core.Adcs;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Caches the CA signing certificate chain as PEM for the ACME issuer endpoint,
/// the "up" link target RFC 8555 §7.4.2 requires on a certificate download.
///
/// The settings page fetches this chain fresh on every request and is right to:
/// it is AdminOnly and cold. The ACME route is neither. It is unauthenticated,
/// every client follows the "up" link after every issuance, and each fetch is a
/// COM round trip to the CA, so serving it uncached would turn an anonymous GET
/// into an amplification vector against the CA. RFC 8555 §7.4.2 calls these
/// "indefinitely cacheable resources"; a CA certificate changes only on CA
/// renewal, so an hour is generous to the CA and still picks a renewal up
/// promptly.
///
/// Single flight: a burst arriving on a cold cache collapses into one CA call
/// rather than one per request, which is the case worth defending. A CA outage
/// is deliberately never cached, so the next request retries rather than
/// serving a null for an hour.
///
/// Registered as a singleton in both hosts. IAdcsClient is a singleton in every
/// registration path (AdcsServiceExtensions and the dev host alike), so there is
/// no captive dependency.
///
/// Deliberately not IDisposable. A SemaphoreSlim only needs disposing if its
/// AvailableWaitHandle was touched, which this never does, and disposing one at
/// shutdown while a request still holds it turns a clean shutdown into an
/// ObjectDisposedException on the release. Nothing is leaked by leaving it.
/// </summary>
public sealed class AcmeIssuerChainCache
{
    /// <summary>How long a fetched chain is served before the CA is asked again.</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromHours(1);

    private readonly IAdcsClient _adcsClient;
    private readonly ILogger<AcmeIssuerChainCache> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>
    /// One immutable reference rather than a string and a timestamp side by side,
    /// so the unlocked fast path reads both halves as one atomic reference and
    /// cannot pair a new chain with an old fetch time.
    /// </summary>
    private sealed record CachedChain(string Pem, DateTimeOffset FetchedAt);

    private CachedChain? _cached;

    public AcmeIssuerChainCache(
        IAdcsClient adcsClient,
        ILogger<AcmeIssuerChainCache> logger,
        TimeProvider? timeProvider = null)
    {
        _adcsClient = adcsClient;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// The chain as PEM, issuing CA first and self signed root last (the order
    /// <see cref="IAdcsClient.GetCaCertificateChainAsync"/> documents), or null
    /// when the CA is unavailable.
    /// </summary>
    public async Task<string?> GetPemChainAsync(CancellationToken cancellationToken = default)
    {
        if (ReadFresh() is { } cached)
            return cached;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            // Another caller may have filled it while this one waited on the gate.
            if (ReadFresh() is { } filled)
                return filled;

            IReadOnlyList<byte[]> derChain;
            try
            {
                derChain = await _adcsClient.GetCaCertificateChainAsync(cancellationToken);
            }
            catch (CaUnavailableException ex)
            {
                _logger.LogWarning(ex,
                    "The ACME issuer certificate endpoint could not read the CA signing chain");
                return null;
            }

            // Append('\n'), not AppendLine, matching CaCertificatesController's chain
            // download. ExportCertificatePem emits LF endings, so AppendLine would
            // splice a CRLF between blocks on Windows and hand out a chain with mixed
            // line endings.
            var builder = new StringBuilder();
            foreach (var der in derChain)
            {
                using var certificate = X509CertificateLoader.LoadCertificate(der);
                builder.Append(certificate.ExportCertificatePem()).Append('\n');
            }

            var pem = builder.ToString();
            _cached = new CachedChain(pem, _timeProvider.GetUtcNow());
            return pem;
        }
        finally
        {
            _gate.Release();
        }
    }

    private string? ReadFresh()
    {
        var cached = _cached;
        return cached != null && _timeProvider.GetUtcNow() - cached.FetchedAt < Ttl
            ? cached.Pem
            : null;
    }
}
