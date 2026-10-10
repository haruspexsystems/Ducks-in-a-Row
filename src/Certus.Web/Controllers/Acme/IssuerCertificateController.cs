using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// The "up" link target of a certificate download (RFC 8555 §7.4.2): the CA
/// signing certificate chain a client needs to build a path from the leaf it
/// just downloaded to a trust anchor.
///
/// The resource answers on two methods, and the difference between them is the
/// whole design. GET and HEAD are anonymous and cacheable, because §7.4.2
/// describes the "up" target as a resource the client retrieves rather than an
/// ACME resource it POSTs to, and the content is a public CA certificate with
/// nothing to authorize. POST is the POST-as-GET §7.1 tells a client to use on
/// an ACME URL, and it is authenticated and uncacheable like every other
/// POST-as-GET in the product.
///
/// POST exists because a conforming client that follows the "up" link the way
/// the RFC describes could not reach this resource at all: it answered 405 and
/// issuance failed after validation had already succeeded, with Caddy (acmez)
/// and Apache mod_md both dying at the same hop (issue #373). Serving only the
/// anonymous GET was a bet that no client walks the chain, and two of them do.
///
/// Both methods are template scoped and both call ResolveTemplateAsync, so each
/// inherits the fail closed template policy (issue #101) and the ACME rate
/// limiter. AuthenticateKidJwsAsync deliberately does not gate the template
/// despite taking one, so the POST arm would bypass that policy if it leaned on
/// authentication alone. The chain itself is CA wide and identical under every
/// template.
///
/// The CA round trip is cached by <see cref="AcmeIssuerChainCache"/>, which is
/// what keeps an anonymous GET from being an amplification vector against the
/// CA. Both arms read through it, so adding POST adds no CA load.
/// </summary>
[ApiController]
[EnableRateLimiting(AcmeRateLimitPolicies.General)]
public sealed class IssuerCertificateController : AcmeControllerBase
{
    private readonly TemplateService _templateService;
    private readonly AcmeIssuerChainCache _chainCache;
    private readonly AccountService _accountService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;

    public IssuerCertificateController(
        TemplateService templateService,
        AcmeIssuerChainCache chainCache,
        AccountService accountService,
        NonceService nonceService,
        JwsService jwsService)
    {
        _templateService = templateService;
        _chainCache = chainCache;
        _accountService = accountService;
        _nonceService = nonceService;
        _jwsService = jwsService;
    }

    // HEAD is declared explicitly for the same reason the directory declares it:
    // the ACME protocol fallback is an unconstrained catch all that always accepts
    // the method, so ASP.NET never falls back to answering HEAD from this GET and
    // a HEAD on a live resource would be reported as missing (issue #147).
    [HttpGet("/acme/{template}/issuer-cert")]
    [HttpHead("/acme/{template}/issuer-cert")]
    public async Task<IActionResult> GetIssuerCertificate(
        string template, CancellationToken cancellationToken)
    {
        var (_, error) = await ResolveTemplateAsync(_templateService, template, cancellationToken);
        if (error != null)
            return error;

        var (pem, chainError) = await ReadChainAsync(cancellationToken);
        if (chainError != null)
            return chainError;

        // Only the anonymous fetch is cacheable. AcmeNonceMiddleware and
        // SecurityHeadersMiddleware both skip their no-store stamp for exactly this
        // method and path shape, so nothing downstream contradicts this header.
        Response.Headers.CacheControl =
            $"public, max-age={(int)AcmeIssuerChainCache.Ttl.TotalSeconds}";

        return Content(pem!, "application/pem-certificate-chain");
    }

    /// <summary>
    /// POST /acme/{template}/issuer-cert — the same chain by POST-as-GET (RFC 8555 §7.1).
    /// Authenticated with a kid JWS like every other POST-as-GET here, because §6.3 has
    /// the server verify the JWS on a POST rather than treat it as an anonymous fetch.
    /// Deliberately sets no Cache-Control of its own: an authenticated response carries a
    /// fresh Replay-Nonce (§6.5) and both middlewares stamp it no-store, which is the
    /// opposite of the GET arm above and is why their exemptions are gated on the method.
    /// </summary>
    [HttpPost("/acme/{template}/issuer-cert")]
    [Consumes("application/jose+json")]
    public async Task<IActionResult> PostIssuerCertificate(
        string template, CancellationToken cancellationToken)
    {
        // The template gate runs first, matching the GET arm on the same route, so one
        // resource cannot be fail closed on one method and open on the other.
        var (_, error) = await ResolveTemplateAsync(_templateService, template, cancellationToken);
        if (error != null)
            return error;

        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, cancellationToken);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        var (pem, chainError) = await ReadChainAsync(cancellationToken);
        if (chainError != null)
            return chainError;

        return Content(pem!, "application/pem-certificate-chain");
    }

    /// <summary>
    /// Reads the cached PEM chain. A CA outage is never cached, so recovery is immediate;
    /// both arms answer it the same way the rest of the ACME surface answers one.
    /// </summary>
    private async Task<(string? Pem, IActionResult? Error)> ReadChainAsync(
        CancellationToken cancellationToken)
    {
        var pem = await _chainCache.GetPemChainAsync(cancellationToken);
        if (pem == null)
            return (null, AcmeError(503, AcmeErrorType.ServiceUnavailable,
                "The ADCS Certificate Authority is unavailable. Try again shortly."));

        return (pem, null);
    }
}
