using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME certificate revocation endpoint.
/// Accepts a JWS signed with either the owning account key (kid) or the certificate's own
/// key pair (jwk), revokes the certificate at the CA, and records the revocation.
/// RFC 8555 §7.6
/// </summary>
[ApiController]
[EnableRateLimiting(AcmeRateLimitPolicies.General)]
public sealed class RevokeCertController : AcmeControllerBase
{
    // Permitted CRL revocation reason codes (RFC 5280 §5.3.1). Value 7 is unused. A request
    // with any other reason is rejected with badRevocationReason (RFC 8555 §7.6).
    private static readonly HashSet<int> PermittedReasons = new() { 0, 1, 2, 3, 4, 5, 6, 8, 9, 10 };

    private readonly OrderService _orderService;
    private readonly AccountService _accountService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;

    public RevokeCertController(
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
    /// POST /acme/{template}/revoke-cert — revoke a certificate.
    /// RFC 8555 §7.6
    /// </summary>
    [HttpPost("/acme/{template}/revoke-cert")]
    [Consumes("application/jose+json")]
    public async Task<IActionResult> RevokeCert(string template, CancellationToken ct)
    {
        var auth = await AuthenticateRevocationJwsAsync(
            _jwsService, _nonceService, _accountService, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        // Parse the payload: { "certificate": "<base64url DER>", "reason": <int optional> }
        RevokeCertRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<RevokeCertRequest>(auth.PayloadBytes ?? Array.Empty<byte>());
        }
        catch (JsonException)
        {
            return AcmeError(400, AcmeErrorType.Malformed, "Invalid revocation request JSON.");
        }

        if (request == null || string.IsNullOrEmpty(request.Certificate))
            return AcmeError(400, AcmeErrorType.Malformed,
                "The revocation request must include a 'certificate'.");

        X509Certificate2 submitted;
        try
        {
            var der = JwsService.Base64UrlDecode(request.Certificate);
            submitted = X509CertificateLoader.LoadCertificate(der);
        }
        catch (Exception)
        {
            return AcmeError(400, AcmeErrorType.Malformed, "Could not parse the certificate to revoke.");
        }

        using (submitted)
        {
            // Validate the reason (absent means unspecified).
            var reason = request.Reason ?? 0;
            if (!PermittedReasons.Contains(reason))
                return AcmeError(400, AcmeErrorType.BadRevocationReason,
                    $"Revocation reason {reason} is not permitted.");

            // Locate the stored certificate by serial. The payload carries the certificate
            // itself (RFC 8555 §7.6), so we match on the leaf serial, not a certificate ID.
            var cert = await _orderService.FindCertificateBySerialAsync(submitted.SerialNumber, ct);
            if (cert == null)
                return AcmeError(404, AcmeErrorType.Malformed, "Unknown certificate.");

            // Bind the request to the certificate we actually issued. A serial number is not a
            // secret and is attacker chosen in a crafted certificate, so a serial match alone is
            // not enough: require the submitted bytes to equal the stored leaf. This is also what
            // makes the jwk possession proof below meaningful, because it then checks the key of
            // the issued certificate rather than a payload the caller fully controls.
            X509Certificate2 storedLeaf;
            try
            {
                storedLeaf = X509Certificate2.CreateFromPem(cert.CertificatePem);
            }
            catch (Exception)
            {
                return AcmeError(500, AcmeErrorType.ServerInternal,
                    "The stored certificate could not be read.");
            }

            using (storedLeaf)
            {
                if (!submitted.RawData.AsSpan().SequenceEqual(storedLeaf.RawData))
                    return AcmeError(404, AcmeErrorType.Malformed, "Unknown certificate.");

                // Authorize the signer (RFC 8555 §7.6):
                //  - account key (kid): the account must own the certificate.
                //  - certificate key (jwk): the key must be the issued certificate's own key.
                if (auth.Account != null)
                {
                    if (cert.Order.AccountId != auth.Account.Id)
                        return AcmeError(403, AcmeErrorType.Unauthorized,
                            "The account does not own this certificate.");
                }
                else if (auth.JwkJson == null ||
                         !JwsService.JwkMatchesCertificatePublicKey(auth.JwkJson, storedLeaf))
                {
                    return AcmeError(403, AcmeErrorType.Unauthorized,
                        "The signing key is not the certificate's key pair.");
                }

                // Revoke at the CA and persist. A second attempt is rejected as alreadyRevoked.
                try
                {
                    var outcome = await _orderService.RevokeCertificateAsync(cert, reason, ct);
                    if (outcome == RevokeOutcome.AlreadyRevoked)
                        return AcmeError(400, AcmeErrorType.AlreadyRevoked,
                            "The certificate has already been revoked.");
                }
                catch (CaUnavailableException)
                {
                    return AcmeError(503, AcmeErrorType.ServiceUnavailable,
                        "The ADCS Certificate Authority is unavailable. Try again shortly.");
                }
                catch (CaAccessDeniedException)
                {
                    // The service account lacks permission to revoke on the CA. That is a server
                    // configuration issue, not a client error; the remediation is logged.
                    return AcmeError(500, AcmeErrorType.ServerInternal,
                        "The server could not revoke the certificate at the CA.");
                }

                // RFC 8555 §7.6: a successful revocation returns an empty 200.
                return Ok();
            }
        }
    }
}
