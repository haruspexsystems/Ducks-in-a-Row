using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME certificate download endpoint.
/// Returns the issued certificate chain in PEM format.
/// RFC 8555 §7.4.2
/// </summary>
[ApiController]
[EnableRateLimiting(AcmeRateLimitPolicies.General)]
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

        // The order has to agree that this is the certificate it issued, and that it
        // issued one at all (issue #318). Deliberately after the ownership check, so a
        // caller who does not own the row never learns anything about its order. See
        // OrderService.MayServe for why "valid" is the whole set and why this exists
        // even though no path in the product can currently fail it.
        if (!OrderService.MayServe(cert))
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "The order for this certificate is not valid, so the certificate is " +
                "not available for download.");

        // RFC 8555 §7.4.2: the response MUST carry at least one "up" link pointing at
        // where the issuing CA certificate can be retrieved.
        var issuerUrl = AcmeUrl($"/acme/{template}/issuer-cert");
        Response.Headers.Append("Link", $"<{issuerUrl}>;rel=\"up\"");

        // Return PEM certificate chain
        // Content-Type: application/pem-certificate-chain per RFC 8555
        return Content(cert.CertificatePem, "application/pem-certificate-chain");
    }
}
