using System.Globalization;
using System.Threading.RateLimiting;
using Certus.Core.Acme.Models;
using Certus.Core.Security;
using Certus.Web.Security;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

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
    /// Writes an ACME problem document straight to a response, for a caller
    /// that holds an <see cref="HttpContext"/> rather than returning an
    /// endpoint result. <see cref="Problem"/> is the endpoint shaped sibling.
    ///
    /// Executing an <see cref="IResult"/> would not do here. The result
    /// <see cref="Results.Json{TValue}"/> hands back resolves an
    /// <c>ILoggerFactory</c> out of <c>HttpContext.RequestServices</c> with
    /// <c>GetRequiredService</c>, and a middleware driven from a bare
    /// <c>DefaultHttpContext</c> has no request services at all. This is the
    /// shape <see cref="OnRateLimitRejected"/> already needed and wrote inline;
    /// it is lifted out here so the URL character guard becomes a second caller
    /// rather than a second copy.
    /// </summary>
    public static Task WriteProblemAsync(
        HttpContext context,
        int statusCode,
        string errorType,
        string detail,
        CancellationToken cancellationToken = default)
    {
        var response = context.Response;
        response.StatusCode = statusCode;
        response.ContentType = ProblemContentType;

        var error = new AcmeError
        {
            Type = errorType,
            Detail = detail,
            Status = statusCode
        };

        return response.WriteAsJsonAsync(
            error, options: null, contentType: ProblemContentType, cancellationToken);
    }

    /// <summary>
    /// Writes an ACME problem document for a rate limited request, naming the
    /// policy that refused it, plus a Retry-After header and an optional help
    /// link (RFC 8555 section 6.6). Only the /acme surface gets a body: the
    /// dashboard has its own error handling and its 429 is left exactly as it
    /// was. Assign this to RateLimiterOptions.OnRejected in both hosts; without
    /// it the limiter answers a bare status code with no indication of what went
    /// wrong.
    ///
    /// Naming the policy is the substance of issue #263. Four policies shared one
    /// "Too many requests" string and nothing wrote a log line, so a refused
    /// client and its operator were told that some limit had been reached and
    /// never which, leaving no way to pick the right knob.
    /// </summary>
    public static ValueTask OnRateLimitRejected(
        OnRejectedContext context, CancellationToken cancellationToken)
    {
        var http = context.HttpContext;

        // The rate limiting middleware picks the policy off the endpoint the same
        // way, and GetMetadata returns the last match, so an action level
        // attribute wins over its controller's exactly as it does there.
        var policyName = http.GetEndpoint()?.Metadata
            .GetMetadata<EnableRateLimitingAttribute>()?.PolicyName;

        var options = http.RequestServices?
            .GetService<IOptions<AcmeRateLimitOptions>>()?.Value;

        var retryAfter = ResolveRetryAfterSeconds(context, options);
        if (retryAfter is { } seconds)
        {
            http.Response.Headers.RetryAfter =
                seconds.ToString(CultureInfo.InvariantCulture);
        }

        // RFC 8555 section 6.6: the server MAY point at documentation for the
        // specific limit that was hit. Off unless an operator supplies a URL, so
        // the product ships no outbound pointer of its own.
        if (!string.IsNullOrWhiteSpace(options?.HelpUrl) && policyName is not null)
        {
            http.Response.Headers.Link =
                $"<{options.HelpUrl}#{policyName}>; rel=\"help\"";
        }

        http.RequestServices?.GetService<AcmeRateLimitRejectionLog>()?.Record(
            policyName,
            http.Request.Method,
            http.Request.Path.Value ?? string.Empty,
            http.Connection.RemoteIpAddress?.ToString(),
            retryAfter);

        if (!ProtocolPaths.IsAcmeProtocolPath(http.Request.Path))
            return ValueTask.CompletedTask;

        var response = http.Response;
        response.ContentType = ProblemContentType;

        var error = new AcmeError
        {
            Type = AcmeErrorType.RateLimited,
            Detail = $"Too many {AcmeRateLimitPolicies.Describe(policyName)}. " +
                     "Wait for the interval in the Retry-After header and retry.",
            Status = response.StatusCode
        };

        return new ValueTask(response.WriteAsJsonAsync(
            error, options: null, contentType: ProblemContentType, cancellationToken));
    }

    /// <summary>
    /// The Retry-After value to report, in whole seconds.
    ///
    /// The limiter is asked first, because an implementation that reports its own
    /// figure knows better than we do. SlidingWindowRateLimiter reports nothing
    /// (verified against .NET 10, unlike FixedWindowRateLimiter which reports the
    /// whole window), so in practice the configured fallback is what is sent; see
    /// AcmeRateLimitOptions.RetryAfterSeconds for why one segment is the right
    /// figure. Null only when the options cannot be resolved, in which case the
    /// header is omitted rather than guessed at.
    /// </summary>
    private static int? ResolveRetryAfterSeconds(
        OnRejectedContext context, AcmeRateLimitOptions? options)
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var leaseRetryAfter))
            return Math.Max(1, (int)Math.Ceiling(leaseRetryAfter.TotalSeconds));

        return options?.RetryAfterSeconds;
    }
}
