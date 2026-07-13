using Certus.Core.Acme.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME nonce endpoints.
/// RFC 8555 §7.2 — clients get a fresh nonce before each POST.
/// </summary>
[ApiController]
[EnableRateLimiting("acme-general")]
public sealed class NonceController : AcmeControllerBase
{
    private readonly NonceService _nonceService;

    public NonceController(NonceService nonceService)
    {
        _nonceService = nonceService;
    }

    /// <summary>
    /// HEAD /acme/{template}/new-nonce — returns a fresh nonce in the Replay-Nonce header.
    /// Preferred by clients since it has no response body.
    /// </summary>
    [HttpHead("/acme/{template}/new-nonce")]
    public IActionResult HeadNonce(string template)
    {
        // Replay-Nonce is the payload here. Cache-Control: no-store is added to every
        // /acme/ response by SecurityHeadersMiddleware and AcmeNonceMiddleware.
        Response.Headers["Replay-Nonce"] = _nonceService.GenerateNonce();
        return Ok();
    }

    /// <summary>
    /// GET /acme/{template}/new-nonce — same as HEAD but returns 204 No Content.
    /// RFC 8555 §7.2: "If a client sends a GET request ... the server MUST ... return a 204 response."
    /// </summary>
    [HttpGet("/acme/{template}/new-nonce")]
    public IActionResult GetNonce(string template)
    {
        Response.Headers["Replay-Nonce"] = _nonceService.GenerateNonce();
        return NoContent();
    }
}
