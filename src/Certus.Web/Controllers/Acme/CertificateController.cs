using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME certificate download endpoint.
/// Returns the issued certificate chain in PEM format.
/// RFC 8555 §7.4.2
/// </summary>
[ApiController]
[EnableRateLimiting("acme-general")]
public sealed class CertificateController : AcmeControllerBase
{
    private readonly OrderService _orderService;
    private readonly AccountService _accountService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;

    public CertificateController(
        OrderService orderService,
        AccountService accountService,
        NonceService nonceService,
        JwsService jwsService)
    {
        _orderService = orderService;
        _accountService = accountService;
        _nonceService = nonceService;
        _jwsService = jwsService;
    }

    /// <summary>
    /// POST /acme/{template}/cert/{certId} — download certificate (POST-as-GET).
    /// Returns the full PEM certificate chain.
    /// RFC 8555 §7.4.2
    /// </summary>
    [HttpPost("/acme/{template}/cert/{certId}")]
    [Consumes("application/jose+json")]
    public async Task<IActionResult> DownloadCertificate(
        string template, string certId, CancellationToken ct)
    {
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        var cert = await _orderService.GetCertificateAsync(certId, ct);
        if (cert == null)
            return AcmeError(404, AcmeErrorType.Malformed, "Certificate not found.");

        // Verify the certificate belongs to this account
        if (cert.Order.AccountId != auth.Account!.Id)
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "Certificate does not belong to this account.");

        // Return PEM certificate chain
        // Content-Type: application/pem-certificate-chain per RFC 8555
        return Content(cert.CertificatePem, "application/pem-certificate-chain");
    }
}
