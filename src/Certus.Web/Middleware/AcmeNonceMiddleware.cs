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
        if (ProtocolPaths.IsAcmeProtocolPath(context.Request.Path))
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
