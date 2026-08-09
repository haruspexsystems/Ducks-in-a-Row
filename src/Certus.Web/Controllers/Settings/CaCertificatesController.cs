using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certus.Core.Adcs;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.Settings;

/// <summary>
/// CA trust anchor downloads for the settings page: the connected CA's
/// signing certificate chain (root and any intermediates) as individual DER
/// or PEM files, and the whole chain bundled as PEM or PKCS#7 (.p7b). Admin
/// only like the rest of the settings surface — the admin downloads and
/// distributes the anchors. All endpoints are GET, so plain anchor tags work
/// with Negotiate and the CSRF header guard does not apply.
///
/// The chain comes from the DI bound <see cref="IAdcsClient"/> (the
/// configured CA after setup; the mock in the dev host), fetched fresh per
/// request — CA certificates change only on CA renewal, and this surface is
/// too cold to justify a cache.
/// </summary>
[ApiController]
[Route("api/settings/ca-certificates")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class CaCertificatesController : ControllerBase
{
    private const string PemMediaType = "application/x-pem-file";
    private const string DerMediaType = "application/pkix-cert";
    private const string Pkcs7MediaType = "application/x-pkcs7-certificates";

    private readonly IAdcsClient _adcsClient;
    private readonly ILogger<CaCertificatesController> _logger;

    public CaCertificatesController(IAdcsClient adcsClient, ILogger<CaCertificatesController> logger)
    {
        _adcsClient = adcsClient;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/settings/ca-certificates — the chain as JSON metadata,
    /// ordered issuing CA first, root last, for the settings page list.
    /// </summary>
    [HttpGet("")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var chain = await FetchChainAsync(ct);
        if (chain is null)
            return CaUnavailable();

        try
        {
            var entries = chain.Select((certificate, index) => new
            {
                position = index,
                role = Role(certificate, index),
                subject = certificate.Subject,
                issuer = certificate.Issuer,
                notBefore = certificate.NotBefore,
                notAfter = certificate.NotAfter,
                thumbprint = certificate.Thumbprint,
            }).ToList();
            return Ok(entries);
        }
        finally
        {
            DisposeAll(chain);
        }
    }

    /// <summary>
    /// GET /api/settings/ca-certificates/{thumbprint}/der — one certificate
    /// of the chain as a binary .cer download.
    /// </summary>
    [HttpGet("{thumbprint}/der")]
    public async Task<IActionResult> DownloadDer(string thumbprint, CancellationToken ct)
    {
        var chain = await FetchChainAsync(ct);
        if (chain is null)
            return CaUnavailable();

        try
        {
            var certificate = FindByThumbprint(chain, thumbprint);
            if (certificate is null)
                return NotFound(new { error = "No certificate with that thumbprint is in the CA chain" });

            return File(certificate.RawData, DerMediaType, FileName(certificate) + ".cer");
        }
        finally
        {
            DisposeAll(chain);
        }
    }

    /// <summary>
    /// GET /api/settings/ca-certificates/{thumbprint}/pem — one certificate
    /// of the chain as a PEM text download.
    /// </summary>
    [HttpGet("{thumbprint}/pem")]
    public async Task<IActionResult> DownloadPem(string thumbprint, CancellationToken ct)
    {
        var chain = await FetchChainAsync(ct);
        if (chain is null)
            return CaUnavailable();

        try
        {
            var certificate = FindByThumbprint(chain, thumbprint);
            if (certificate is null)
                return NotFound(new { error = "No certificate with that thumbprint is in the CA chain" });

            var pem = certificate.ExportCertificatePem() + "\n";
            return File(Encoding.ASCII.GetBytes(pem), PemMediaType, FileName(certificate) + ".pem");
        }
        finally
        {
            DisposeAll(chain);
        }
    }

    /// <summary>
    /// GET /api/settings/ca-certificates/chain/pem — the whole chain as one
    /// PEM file, issuing CA first, root last.
    /// </summary>
    [HttpGet("chain/pem")]
    public async Task<IActionResult> DownloadChainPem(CancellationToken ct)
    {
        var chain = await FetchChainAsync(ct);
        if (chain is null)
            return CaUnavailable();

        try
        {
            var sb = new StringBuilder();
            foreach (var certificate in chain)
                sb.Append(certificate.ExportCertificatePem()).Append('\n');

            return File(Encoding.ASCII.GetBytes(sb.ToString()), PemMediaType, "ca-chain.pem");
        }
        finally
        {
            DisposeAll(chain);
        }
    }

    /// <summary>
    /// GET /api/settings/ca-certificates/chain/p7b — the whole chain as a
    /// PKCS#7 certificate bundle, the format the Windows certificate import
    /// wizard and Group Policy expect.
    /// </summary>
    [HttpGet("chain/p7b")]
    public async Task<IActionResult> DownloadChainP7b(CancellationToken ct)
    {
        var chain = await FetchChainAsync(ct);
        if (chain is null)
            return CaUnavailable();

        try
        {
            var collection = new X509Certificate2Collection();
            foreach (var certificate in chain)
                collection.Add(certificate);

            var bytes = collection.Export(X509ContentType.Pkcs7)
                ?? throw new InvalidOperationException("PKCS#7 export produced no data");
            return File(bytes, Pkcs7MediaType, "ca-chain.p7b");
        }
        finally
        {
            DisposeAll(chain);
        }
    }

    /// <summary>
    /// Fetch and parse the chain, or null when the CA is unavailable (the
    /// caller answers 503). Any other failure propagates as a 500, which is
    /// right: a CA that answers with an unparseable chain is a real fault.
    /// </summary>
    private async Task<List<X509Certificate2>?> FetchChainAsync(CancellationToken ct)
    {
        IReadOnlyList<byte[]> derChain;
        try
        {
            derChain = await _adcsClient.GetCaCertificateChainAsync(ct);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "CA certificate download: the CA is unavailable");
            return null;
        }

        return derChain.Select(der => X509CertificateLoader.LoadCertificate(der)).ToList();
    }

    private ObjectResult CaUnavailable() => StatusCode(503, new
    {
        error = true,
        message = "The certificate authority is unavailable. Try again shortly.",
    });

    private static void DisposeAll(IEnumerable<X509Certificate2> certificates)
    {
        foreach (var certificate in certificates)
            certificate.Dispose();
    }

    private static X509Certificate2? FindByThumbprint(
        IEnumerable<X509Certificate2> chain, string thumbprint)
    {
        return chain.FirstOrDefault(c =>
            string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// root when self signed, issuing for the CA's own certificate at the
    /// front of the chain, intermediate for anything between.
    /// </summary>
    private static string Role(X509Certificate2 certificate, int position)
    {
        if (string.Equals(certificate.Subject, certificate.Issuer, StringComparison.Ordinal))
            return "root";
        return position == 0 ? "issuing" : "intermediate";
    }

    /// <summary>
    /// A download file name from the certificate CN, with characters invalid
    /// in file names stripped. Falls back to a generic name when nothing
    /// usable remains.
    /// </summary>
    private static string FileName(X509Certificate2 certificate)
    {
        var cn = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        if (string.IsNullOrWhiteSpace(cn))
            return "ca-certificate";

        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(cn.Where(c => !invalid.Contains(c)).ToArray()).Trim();
        return string.IsNullOrWhiteSpace(cleaned) ? "ca-certificate" : cleaned;
    }
}
