using Certus.Core.Acme.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Net.Http.Headers;

namespace Certus.Web.Routing;

/// <summary>
/// Path tests shared by everything that has to tell the ACME protocol surface
/// apart from the rest of the app. Bare /acme is the dashboard's ACME tab (a
/// SPA route, issue #129); every protocol URL carries a template segment after
/// it, so a second segment is what distinguishes the two.
/// </summary>
public static class ProtocolPaths
{
    /// <summary>The first path segment of the ACME protocol surface.</summary>
    public const string AcmeSegment = "acme";

    /// <summary>The first path segment of the dashboard admin API.</summary>
    public const string ApiSegment = "api";

    /// <summary>
    /// True for an ACME protocol URL, false for bare /acme and for everything
    /// outside the protocol namespace.
    /// </summary>
    public static bool IsAcmeProtocolPath(PathString path)
    {
        return path.StartsWithSegments("/" + AcmeSegment, out var remaining) &&
               remaining.HasValue && remaining.Value!.Length > 1;
    }

    /// <summary>
    /// True for /acme/{template}/issuer-cert, the one ACME protocol path that has
    /// to stay cacheable. It is the "up" link target RFC 8555 §7.4.2 requires on a
    /// certificate download, and §7.4.2 describes it as an indefinitely cacheable
    /// resource. The no-store rule in §6.1 is about responses carrying a
    /// Replay-Nonce and the anonymous fetch carries none: it is a GET returning a
    /// public CA certificate. Both middlewares that stamp no-store on the ACME
    /// surface consult this so the response does not contradict itself.
    ///
    /// This answers on the path alone, so both callers gate it on GET and HEAD
    /// themselves (issue #373). The same path also answers an authenticated
    /// POST-as-GET, and that arm is an ordinary ACME response: it takes a fresh
    /// Replay-Nonce under §6.5 and the no-store that rides with it, so neither
    /// middleware may exempt it.
    ///
    /// Matched on the exact route shape rather than a suffix test, so a certificate
    /// whose id happened to be "issuer-cert" cannot slip a download response past
    /// the no-store rule.
    /// </summary>
    public static bool IsAcmeIssuerCertificatePath(PathString path)
    {
        return MatchesAcmeRoute(path, segmentCount: 3, thirdSegment: "issuer-cert");
    }

    /// <summary>
    /// True for /acme/{template}/renewalInfo/{certID}, the ARI resource
    /// (RFC 9773 §4.1) and the other anonymous GET on the protocol surface.
    /// Only the nonce middleware consults this, and only for GET and HEAD: an
    /// unauthenticated poll must not burn a stored nonce per request that no
    /// client will ever consume. Unlike the issuer certificate the response
    /// deliberately stays under no-store (the security headers middleware
    /// does not consult this), so a revocation driven window change reaches
    /// clients with no cache latency.
    /// </summary>
    public static bool IsAcmeRenewalInfoPath(PathString path)
    {
        return MatchesAcmeRoute(path, segmentCount: 4, thirdSegment: "renewalInfo");
    }

    /// <summary>
    /// Matches on the exact route shape rather than a suffix test, so a
    /// certificate or template whose name happens to equal a special
    /// segment cannot slip a response past the rules keyed on these
    /// predicates.
    /// </summary>
    private static bool MatchesAcmeRoute(PathString path, int segmentCount, string thirdSegment)
    {
        var segments = path.Value?.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments?.Length == segmentCount
            && segments[0].Equals(AcmeSegment, StringComparison.OrdinalIgnoreCase)
            && segments[2].Equals(thirdSegment, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Why a request that reached a protocol fallback did not match a real endpoint.
/// </summary>
internal enum ProtocolRouteVerdict
{
    /// <summary>No registered route has this shape.</summary>
    NotFound,

    /// <summary>A route has this shape but does not accept the request method.</summary>
    MethodNotAllowed,

    /// <summary>A route accepts the method but not the request media type.</summary>
    UnsupportedMediaType
}

/// <summary>
/// A verdict plus the methods to advertise in the Allow header, which RFC 9110
/// §15.5.6 makes mandatory on a 405.
/// </summary>
internal sealed record ProtocolRouteMatch(
    ProtocolRouteVerdict Verdict,
    IReadOnlyList<string> AllowedMethods)
{
    public static readonly ProtocolRouteMatch NotFound =
        new(ProtocolRouteVerdict.NotFound, []);
}

/// <summary>
/// Classifies a request that fell through to a protocol fallback.
///
/// ASP.NET only answers 405 or 415 when every candidate endpoint is
/// invalidated. The protocol fallbacks are catch-alls with no method metadata
/// and no [Consumes], so they stay valid candidates, the rejection endpoints
/// are never created, and the fallback answers 404 for a wrong method or a
/// wrong media type alike (issue #147). Removing the fallbacks does not help:
/// MapFallbackToFile is an unconstrained catch-all too, so the SPA shell would
/// take over the protocol namespace and undo issue #27. So the fallback stays
/// and works out the real fault here, once, for a request that already failed
/// to match anything else.
///
/// The table is snapshotted on first use rather than at map time, because the
/// endpoint data sources are still being populated while the pipeline is built.
/// </summary>
internal sealed class ProtocolRouteTable
{
    private readonly Lazy<IReadOnlyList<Entry>> _routes;

    public ProtocolRouteTable(IEndpointRouteBuilder builder, string firstSegment)
    {
        _routes = new Lazy<IReadOnlyList<Entry>>(() => Snapshot(builder, firstSegment));
    }

    public ProtocolRouteMatch Classify(HttpContext context)
    {
        var segments = Tokenize(context.Request.Path);
        if (segments is null)
            return ProtocolRouteMatch.NotFound;

        var matched = _routes.Value.Where(route => Matches(route.Pattern, segments)).ToList();
        if (matched.Count == 0)
            return ProtocolRouteMatch.NotFound;

        // An entry with no method metadata accepts every method, mirroring how
        // HttpMethodMatcherPolicy treats one.
        var byMethod = matched
            .Where(route => route.Methods.Count == 0 || Allows(route.Methods, context.Request.Method))
            .ToList();

        if (byMethod.Count == 0)
        {
            var allowed = matched
                .SelectMany(route => route.Methods)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return new ProtocolRouteMatch(ProtocolRouteVerdict.MethodNotAllowed, allowed);
        }

        // An empty union means no endpoint restricted the media type.
        var accepted = byMethod.SelectMany(route => route.ContentTypes).ToList();
        if (accepted.Count > 0 && !AcceptsRequestContentType(accepted, context.Request.ContentType))
            return new ProtocolRouteMatch(ProtocolRouteVerdict.UnsupportedMediaType, []);

        // The request looks well formed against the route table, so whatever
        // stopped routing selecting the real endpoint is outside what this
        // classifier models. 404 is the conservative answer, and it is the one
        // the fallback gave before it classified anything.
        return ProtocolRouteMatch.NotFound;
    }

    /// <summary>
    /// Splits the path the way routing does, or returns null when routing
    /// could not have matched any literal or plain parameter route at all.
    /// The leading slash always yields an empty first element and routing
    /// tolerates exactly one trailing slash, but no literal or plain parameter
    /// segment matches an empty string, so a doubled slash matches nothing.
    /// Dropping empty entries wholesale instead would collapse
    /// /acme/{template}//new-order onto the real new-order route and answer
    /// 405 for a URL that has no resource behind it at all.
    /// </summary>
    private static string[]? Tokenize(PathString path)
    {
        var value = path.Value;
        if (string.IsNullOrEmpty(value))
            return [];

        var parts = value.Split('/');
        var start = parts[0].Length == 0 ? 1 : 0;
        var end = parts.Length > start && parts[^1].Length == 0 ? parts.Length - 1 : parts.Length;

        var segments = parts[start..end];
        return Array.Exists(segments, string.IsNullOrEmpty) ? null : segments;
    }

    /// <summary>
    /// A HEAD request is served by a GET endpoint unless a HEAD specific one
    /// exists, so HEAD must not be reported as disallowed where GET is allowed.
    /// </summary>
    private static bool Allows(IReadOnlyList<string> methods, string requestMethod)
    {
        if (methods.Contains(requestMethod, StringComparer.OrdinalIgnoreCase))
            return true;

        return HttpMethods.IsHead(requestMethod) &&
               methods.Contains(HttpMethods.Get, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Compares media types only, so a charset or other parameter on an
    /// otherwise correct Content-Type still passes. A request with no
    /// Content-Type at all fails, matching how [Consumes] treats one.
    /// </summary>
    private static bool AcceptsRequestContentType(
        IReadOnlyList<string> accepted, string? requestContentType)
    {
        if (string.IsNullOrEmpty(requestContentType) ||
            !MediaTypeHeaderValue.TryParse(requestContentType, out var parsed) ||
            !parsed.MediaType.HasValue)
        {
            return false;
        }

        return accepted.Any(candidate =>
            MediaTypeHeaderValue.TryParse(candidate, out var allowed) &&
            allowed.MediaType.Equals(parsed.MediaType, StringComparison.OrdinalIgnoreCase));
    }

    private static bool Matches(RoutePattern pattern, string[] segments)
    {
        if (pattern.PathSegments.Count != segments.Length)
            return false;

        for (var i = 0; i < segments.Length; i++)
        {
            // Snapshot only keeps single part segments, so the first part is
            // the whole segment: a literal to compare, or a parameter that
            // accepts any non empty segment.
            if (pattern.PathSegments[i].Parts[0] is RoutePatternLiteralPart literal &&
                !string.Equals(literal.Content, segments[i], StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static IReadOnlyList<Entry> Snapshot(IEndpointRouteBuilder builder, string firstSegment)
    {
        return builder.DataSources
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Where(endpoint =>
                StartsWith(endpoint.RoutePattern, firstSegment) &&
                IsSupportedShape(endpoint.RoutePattern))
            .Select(endpoint => new Entry(
                endpoint.RoutePattern,
                endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods ?? [],
                endpoint.Metadata.GetMetadata<ConsumesAttribute>()?.ContentTypes ?? []))
            .ToList();
    }

    private static bool StartsWith(RoutePattern pattern, string firstSegment)
    {
        return pattern.PathSegments.Count > 0 &&
               pattern.PathSegments[0].Parts is [RoutePatternLiteralPart literal] &&
               string.Equals(literal.Content, firstSegment, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// One literal, or one plain parameter, per segment. That is what lets
    /// Matches compare segment by segment without running the routing
    /// constraint machinery, so anything the comparison cannot decide is
    /// excluded rather than guessed at:
    ///
    /// - a catch-all matches a variable number of segments, and excluding it is
    ///   also what keeps the fallbacks themselves and the SPA fallback out of
    ///   the table;
    /// - an optional parameter makes the segment count ambiguous;
    /// - a constrained parameter such as {id:int} would match a segment here
    ///   that routing itself would reject, turning a genuine 404 into a 405.
    ///
    /// A dropped route simply keeps its old bodiless 404. Every ACME route is
    /// in shape today, and a guard test in Certus.Web.Tests fails if one that
    /// is not gets added.
    /// </summary>
    private static bool IsSupportedShape(RoutePattern pattern)
    {
        return pattern.PathSegments.All(segment => segment.Parts switch
        {
            [RoutePatternLiteralPart] => true,
            [RoutePatternParameterPart
                { IsCatchAll: false, IsOptional: false, ParameterPolicies.Count: 0 }] => true,
            _ => false
        });
    }

    private sealed record Entry(
        RoutePattern Pattern,
        IReadOnlyList<string> Methods,
        IReadOnlyList<string> ContentTypes);
}

/// <summary>
/// The /api and /acme fallbacks, shared by both hosts (Certus.Service and
/// Certus.Web) for the same reason CertusAuthExtensions is: the two Program.cs
/// pipelines are near duplicates, and only Certus.Web is covered by the
/// integration tests, so wiring that lives in one host only is wiring nobody
/// checks.
/// </summary>
public static class ProtocolFallbackExtensions
{
    /// <summary>
    /// Maps the ACME protocol fallback. Unknown protocol paths must never reach
    /// the SPA shell, because index.html would mask the 404 (issue #27), and a
    /// wrong method or media type must answer the status RFC 8555 asks for with
    /// a problem document rather than a bare 404 (issue #147). Map after
    /// MapControllers and before the SPA fallback.
    /// </summary>
    public static WebApplication MapAcmeProtocolFallback(this WebApplication app)
    {
        var table = new ProtocolRouteTable(app, ProtocolPaths.AcmeSegment);

        // The template segment is required because every ACME protocol URL has
        // one; bare /acme is the dashboard's ACME tab and falls through to the
        // SPA shell.
        app.MapFallback("/acme/{template}/{**path}", (HttpContext context) =>
        {
            var match = table.Classify(context);

            switch (match.Verdict)
            {
                case ProtocolRouteVerdict.MethodNotAllowed:
                    context.Response.Headers.Allow = string.Join(", ", match.AllowedMethods);
                    return AcmeProblemResults.Problem(
                        StatusCodes.Status405MethodNotAllowed, AcmeErrorType.Malformed,
                        $"The method {context.Request.Method} is not allowed on this ACME " +
                        "resource. RFC 8555 reads resources with POST-as-GET. Allowed: " +
                        $"{string.Join(", ", match.AllowedMethods)}.");

                case ProtocolRouteVerdict.UnsupportedMediaType:
                    return AcmeProblemResults.Problem(
                        StatusCodes.Status415UnsupportedMediaType, AcmeErrorType.Malformed,
                        "An ACME request body is a JWS object, so its Content-Type must be " +
                        "'application/jose+json' (RFC 8555 section 6.2).");

                default:
                    return AcmeProblemResults.Problem(
                        StatusCodes.Status404NotFound, AcmeErrorType.Malformed,
                        "No ACME resource exists at this URL. Fetch the directory to " +
                        "discover the resources this server offers.");
            }
        }).AllowAnonymous();

        return app;
    }

    /// <summary>
    /// Maps the dashboard admin API fallback, which shares the ACME fallback's
    /// routing defect and so gets the same classification: an unknown /api path
    /// keeps its bodiless 404, but a wrong method now answers 405 instead.
    /// Deliberately carries no [AllowAnonymous]: the global deny by default
    /// fallback policy applies to this endpoint, which is what makes an
    /// anonymous caller get 401 rather than a 404 that would confirm which
    /// admin routes exist (issue #27).
    /// </summary>
    public static WebApplication MapApiFallback(this WebApplication app)
    {
        var table = new ProtocolRouteTable(app, ProtocolPaths.ApiSegment);

        app.MapFallback("/api/{**path}", (HttpContext context) =>
        {
            var match = table.Classify(context);

            switch (match.Verdict)
            {
                case ProtocolRouteVerdict.MethodNotAllowed:
                    context.Response.Headers.Allow = string.Join(", ", match.AllowedMethods);
                    return Results.Problem(
                        statusCode: StatusCodes.Status405MethodNotAllowed,
                        detail: $"The method {context.Request.Method} is not allowed on this " +
                                $"resource. Allowed: {string.Join(", ", match.AllowedMethods)}.");

                case ProtocolRouteVerdict.UnsupportedMediaType:
                    return Results.Problem(statusCode: StatusCodes.Status415UnsupportedMediaType);

                default:
                    return Results.NotFound();
            }
        });

        return app;
    }
}
