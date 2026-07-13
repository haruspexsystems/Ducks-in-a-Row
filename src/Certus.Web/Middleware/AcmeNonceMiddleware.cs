using Certus.Core.Acme.Services;

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
        // Only add nonces to ACME paths
        if (context.Request.Path.StartsWithSegments("/acme"))
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
