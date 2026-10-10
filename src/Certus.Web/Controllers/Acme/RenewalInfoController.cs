using System.Globalization;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME Renewal Information (RFC 9773): the suggested renewal window for one
/// certificate this server issued, addressed by the identifier the client
/// builds from the leaf's Authority Key Identifier and serial number (§4.1).
///
/// Plain GET and unauthenticated like the issuer certificate (§4.1 makes the
/// fetch an explicit exception to POST-as-GET), and template scoped the same
/// way, so it inherits the fail closed template policy and the ACME rate
/// limiter. The lookup itself is CA wide by serial, the same stance
/// revoke-cert takes: a certificate is not required to have been issued under
/// the template in the URL, because the serial names it uniquely at the CA and
/// the window is a fact about the certificate, not about a template.
///
/// Only certificates issued through ACME answer. The inventory the sync
/// mirrors from the CA is never confirmed to exist: the one thing read from it
/// is the revocation instant of a certificate already matched as ACME issued,
/// because a revocation done at the CA itself reaches only that side of the
/// bridge and the renew now window exists precisely for that case.
///
/// Nothing here logs per request at Information: the endpoint is anonymous and
/// polled, so that would hand unauthenticated callers a log volume dial.
///
/// Polled, but deliberately not on the acme-poll budget that authorization and
/// order polling share (issue #263). That budget is for polling a client paces
/// itself, where the request count follows how long validation takes; this
/// endpoint sets its own cadence through the Retry-After above, so it cannot
/// drain a budget the same way. It is also anonymous, where both members of the
/// poll budget are JWS authenticated, and the poll budget is the more generous
/// of the two.
/// </summary>
[ApiController]
[EnableRateLimiting(AcmeRateLimitPolicies.General)]
public sealed class RenewalInfoController : AcmeControllerBase
{
    private readonly TemplateService _templateService;
    private readonly OrderService _orderService;

    public RenewalInfoController(
        TemplateService templateService,
        OrderService orderService)
    {
        _templateService = templateService;
        _orderService = orderService;
    }

    // HEAD is declared explicitly for the same reason the directory declares it:
    // the ACME protocol fallback is an unconstrained catch all that always accepts
    // the method, so ASP.NET never falls back to answering HEAD from this GET and
    // a HEAD on a live resource would be reported as missing (issue #147).
    [HttpGet("/acme/{template}/renewalInfo/{certId}")]
    [HttpHead("/acme/{template}/renewalInfo/{certId}")]
    public async Task<IActionResult> GetRenewalInfo(
        string template, string certId, CancellationToken cancellationToken)
    {
        var (_, error) = await ResolveTemplateAsync(_templateService, template, cancellationToken);
        if (error != null)
            return error;

        if (!AriCertificateId.TryParse(certId, out var keyIdentifier, out var serialNumber))
            return AcmeError(400, AcmeErrorType.Malformed,
                "Invalid ARI certificate identifier.");

        // One answer for every way this can miss (no row, an unreadable
        // stored leaf, octets that name a different issuer's certificate):
        // the identifier does not address a certificate here.
        var match = await _orderService.FindCertificateByAriOctetsAsync(
            keyIdentifier, serialNumber, cancellationToken);
        if (match == null)
            return AcmeError(404, AcmeErrorType.Malformed, "Unknown certificate.");

        using var leaf = match.Leaf;

        var (start, end) = RenewalWindowPolicy.GetWindow(
            leaf.NotBefore.ToUniversalTime(),
            leaf.NotAfter.ToUniversalTime(),
            match.RevokedAt,
            serialNumber);

        // RFC 9773 §4.3: the desired polling interval rides the Retry-After
        // header, never the body.
        Response.Headers.RetryAfter =
            ((int)RenewalWindowPolicy.RetryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);

        return Ok(new RenewalInfoResponse
        {
            SuggestedWindow = new RenewalInfoSuggestedWindow
            {
                Start = AcmeTimestamps.Format(start),
                End = AcmeTimestamps.Format(end)
            }
        });
    }
}
