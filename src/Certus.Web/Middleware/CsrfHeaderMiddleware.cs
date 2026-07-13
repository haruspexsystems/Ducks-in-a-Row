using Certus.Web.Authentication;

namespace Certus.Web.Middleware;

/// <summary>
/// Requires the X-Certus-Csrf custom request header (any value) on
/// state-changing /api/ requests, returning 403 when absent. With ambient
/// Windows authentication the browser attaches the user's credentials to any
/// same-origin request, so a malicious intranet page could otherwise drive
/// authenticated POSTs. A custom header cannot be set cross-origin without a
/// CORS preflight, and Certus exposes no permissive CORS policy. The /acme/
/// surface is exempt: it is not browser-driven and authenticates with JWS.
/// </summary>
public sealed class CsrfHeaderMiddleware
{
    private readonly RequestDelegate _next;

    public CsrfHeaderMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public Task InvokeAsync(HttpContext context)
    {
        if (RequiresHeader(context.Request) &&
            !context.Request.Headers.ContainsKey(CertusPolicies.CsrfHeaderName))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return context.Response.WriteAsJsonAsync(new
            {
                error = $"Missing required request header {CertusPolicies.CsrfHeaderName}"
            });
        }

        return _next(context);
    }

    private static bool RequiresHeader(HttpRequest request)
    {
        var method = request.Method;
        var isMutating =
            HttpMethods.IsPost(method) ||
            HttpMethods.IsPut(method) ||
            HttpMethods.IsPatch(method) ||
            HttpMethods.IsDelete(method);

        return isMutating && request.Path.StartsWithSegments("/api");
    }
}
