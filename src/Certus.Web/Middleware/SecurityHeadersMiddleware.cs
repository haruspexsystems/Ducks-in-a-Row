namespace Certus.Web.Middleware;

/// <summary>
/// Adds security headers to all responses:
/// - X-Content-Type-Options: nosniff
/// - X-Frame-Options: DENY
/// - X-XSS-Protection: 0 (modern browsers don't need it)
/// - Referrer-Policy: strict-origin-when-cross-origin
/// - Content-Security-Policy: locks scripts to same origin (the dashboard XSS backstop)
/// - Cache-Control: no-store for API responses
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    // Content Security Policy for the React dashboard and the API surface.
    //   script-src 'self'      : the real cross site scripting backstop. The Vite build emits
    //                            external module scripts only and React attaches no inline
    //                            handlers, so no 'unsafe-inline' is needed for scripts.
    //   style-src 'unsafe-inline' : required by React inline style attributes (style={{...}}).
    //                            Style injection is far less severe than script injection, so
    //                            this concession does not undermine the script backstop.
    //   img-src data:          : Vite inlines small assets as data URIs; the favicon is same origin.
    //   font-src 'self'        : the @fontsource fonts ship bundled, served from this origin.
    //   connect-src 'self'     : /api, /acme, and /health are all same origin.
    //   frame-ancestors 'none' : the modern equivalent of the X-Frame-Options: DENY above.
    // No report-uri / report-to: a violation sink would phone home, which the no-telemetry
    // invariant forbids.
    private const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "frame-ancestors 'none'; " +
        "form-action 'self'";

    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["X-XSS-Protection"] = "0";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["Content-Security-Policy"] = ContentSecurityPolicy;

        // API responses should not be cached
        var path = context.Request.Path.Value ?? string.Empty;
        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/acme/", StringComparison.OrdinalIgnoreCase))
        {
            headers["Cache-Control"] = "no-store";
            headers["Pragma"] = "no-cache";
        }

        await _next(context);
    }
}
