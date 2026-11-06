using Certus.Core.Acme.Services;
using Certus.Web.Routing;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Certus.Web.Middleware;

/// <summary>
/// Injects a Replay-Nonce header on every ACME response.
/// RFC 8555 §7.2 — every response from the ACME server includes a fresh nonce.
///
/// <para>
/// Sits after routing and after the rate limiter since issue #632 (CRA R04),
/// and stamps only a response that a controller action produced. A nonce is a
/// stored entry, so every response that mints one is work an unauthenticated
/// caller can make the server do: the rate limiter's 429 never reaches this
/// middleware now, and the protocol fallback's 404, 405 and 415 match no
/// controller action, so none of them stores a nonce. RFC 8555 §6.5 makes a
/// nonce a MUST on a successful POST response only, and a client that needs one
/// after a refusal asks new-nonce, which is a controller action and still
/// stamps. The badNonce answer keeps its fresh nonce the same way: it comes
/// from the controller.
/// </para>
/// </summary>
public sealed class AcmeNonceMiddleware
{
    private readonly RequestDelegate _next;

    public AcmeNonceMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, NonceService nonceService)
    {
        // Only add nonces to ACME protocol paths, which always carry a
        // template segment (/acme/{template}/...). Bare /acme is the
        // dashboard's ACME tab (issue #129): stamping it would burn a stored
        // nonce per page load that no client ever consumes, and force
        // no-store on the SPA shell.
        // The issuer certificate endpoint is excluded for the same reason bare
        // /acme is: a nonce no client consumes is a stored nonce burned per
        // request, and here the no-store that rides along would also overwrite
        // the Cache-Control that makes the "up" target cacheable. That holds
        // for the anonymous fetch only, so the exclusion is gated on GET and
        // HEAD (issue #373). The same path also answers POST-as-GET, which is
        // authenticated, and RFC 8555 §6.5 requires a Replay-Nonce on every
        // successful response to a POST: that arm must be stamped, and the
        // no-store riding with it is correct there rather than harmful,
        // because an authenticated response is not the cacheable "up" target.
        // The renewal info endpoint (RFC 9773) is excluded for the nonce half
        // of that reason only: it is an unauthenticated GET clients poll, so a
        // stamp is a stored nonce per poll, but it keeps the no-store the
        // security headers middleware stamps, so a revocation driven window
        // change is never served stale. Its exclusion is gated on GET and
        // HEAD, the only methods the resource defines, to match the issuer
        // certificate gate; an errant POST at the same shape is answered by
        // the protocol fallback, which the action gate below leaves unstamped
        // either way (issue #632).
        var isExemptIssuerCertificateFetch =
            ProtocolPaths.IsAcmeIssuerCertificatePath(context.Request.Path)
            && (HttpMethods.IsGet(context.Request.Method)
                || HttpMethods.IsHead(context.Request.Method));
        var isExemptRenewalInfoFetch =
            ProtocolPaths.IsAcmeRenewalInfoPath(context.Request.Path)
            && (HttpMethods.IsGet(context.Request.Method)
                || HttpMethods.IsHead(context.Request.Method));
        // Routing has run, so the matched endpoint says whether a controller
        // action will answer. The protocol fallback is a MapFallback endpoint
        // and carries no action descriptor; an unrouted request (none exists
        // under /acme/{template}/, but the test is cheap) carries no endpoint.
        var answeredByAnAction = context.GetEndpoint()?.Metadata
            .GetMetadata<ControllerActionDescriptor>() is not null;

        if (ProtocolPaths.IsAcmeProtocolPath(context.Request.Path)
            && answeredByAnAction
            && !isExemptIssuerCertificateFetch
            && !isExemptRenewalInfoFetch)
        {
            context.Response.OnStarting(() =>
            {
                if (!context.Response.Headers.ContainsKey("Replay-Nonce"))
                {
                    context.Response.Headers["Replay-Nonce"] = nonceService.GenerateNonce();
                }

                // ACME responses must include Cache-Control: no-store
                context.Response.Headers["Cache-Control"] = "no-store";

                return Task.CompletedTask;
            });
        }

        await _next(context);
    }
}
