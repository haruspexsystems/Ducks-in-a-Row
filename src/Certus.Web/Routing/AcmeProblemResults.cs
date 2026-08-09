using System.Globalization;
using System.Threading.RateLimiting;
using Certus.Core.Acme.Models;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Routing;

/// <summary>
/// ACME problem documents for responses produced outside a controller action.
/// AcmeControllerBase.AcmeError covers everything an action returns, but the
/// pipeline also refuses requests before any action runs: endpoint routing
/// settles method and media type errors, and the rate limiter rejects on its
/// own. Those responses were bodiless (issue #147), which reads as "no such
/// resource" rather than the actual fault. The envelope is kept identical to
/// the controller one so a client sees a single error shape across the whole
/// /acme surface.
/// </summary>
public static class AcmeProblemResults
{
    /// <summary>
    /// The RFC 8555 §6.7 problem document media type, matching the
    /// ContentTypes set on every AcmeControllerBase.AcmeError result.
    /// </summary>
    public const string ProblemContentType = "application/problem+json";

    /// <summary>
    /// Builds an ACME problem document result. RFC 8555 §6.7 defines no error
    /// code for a method, media type, or unknown resource fault, so all three
    /// use "malformed", which is the registry's general purpose code and what
    /// other ACME servers return for the same conditions.
    /// </summary>
    public static IResult Problem(int statusCode, string errorType, string detail)
    {
        var error = new AcmeError
        {
            Type = errorType,
            Detail = detail,
            Status = statusCode
        };

        return Results.Json(error, contentType: ProblemContentType, statusCode: statusCode);
    }

    /// <summary>
    /// Writes an ACME problem document for a rate limited request, and a
    /// Retry-After header whenever the lease reports one (RFC 8555 §6.6). Only
    /// the /acme surface gets a body: the dashboard has its own error handling
    /// and its 429 is left exactly as it was. Assign this to
    /// RateLimiterOptions.OnRejected in both hosts; without it the limiter
    /// answers a bare status code with no indication of what went wrong.
    /// </summary>
    public static ValueTask OnRateLimitRejected(
        OnRejectedContext context, CancellationToken cancellationToken)
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter =
                ((int)retryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        if (!ProtocolPaths.IsAcmeProtocolPath(context.HttpContext.Request.Path))
            return ValueTask.CompletedTask;

        var response = context.HttpContext.Response;
        response.ContentType = ProblemContentType;

        var error = new AcmeError
        {
            Type = AcmeErrorType.RateLimited,
            Detail = "Too many requests. Wait for the interval in the Retry-After header and retry.",
            Status = response.StatusCode
        };

        return new ValueTask(response.WriteAsJsonAsync(
            error, options: null, contentType: ProblemContentType, cancellationToken));
    }
}
