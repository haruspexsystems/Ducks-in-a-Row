using Certus.Core.Acme.Services;
using Certus.Web.Routing;

namespace Certus.Web.Middleware;

/// <summary>
/// Injects a Replay-Nonce header on every ACME response.
/// RFC 8555 §7.2 — every response from the ACME server includes a fresh nonce.
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
        // HEAD, the only methods the resource defines: an errant POST at the
        // same shape is an error a client may harvest its next nonce from
        // (RFC 8555 §7.2), so it keeps the stamp.
        var isExemptIssuerCertificateFetch =
            ProtocolPaths.IsAcmeIssuerCertificatePath(context.Request.Path)
            && (HttpMethods.IsGet(context.Request.Method)
                || HttpMethods.IsHead(context.Request.Method));
        var isExemptRenewalInfoFetch =
            ProtocolPaths.IsAcmeRenewalInfoPath(context.Request.Path)
            && (HttpMethods.IsGet(context.Request.Method)
                || HttpMethods.IsHead(context.Request.Method));
        if (ProtocolPaths.IsAcmeProtocolPath(context.Request.Path)
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
