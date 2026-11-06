using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests.MonitorMode;

/// <summary>
/// Turns every mapped route under a path prefix into concrete requests, one per method
/// it declares, so a test of the monitor mode gates (issue #470) covers a route added
/// later without anyone adding it to a list. Shared with Certus.Service.Tests as a
/// source link, the way the synthetic attestation builders are, so both hosts are
/// sampled the same way.
/// </summary>
internal static class ProtocolRouteSamples
{
    /// <summary>The template every sample addresses, the one the test hosts enable.</summary>
    public const string Template = "WebServer";

    /// <summary>
    /// (method, path) for every route whose pattern starts with <paramref name="prefix"/>
    /// (no leading slash, for example <c>acme/</c>). The template parameter becomes
    /// <see cref="Template"/>, a catch all becomes <c>anything</c>, and every other
    /// parameter <c>1</c>. A route with no method metadata, such as a fallback, is
    /// sampled with GET and POST.
    /// </summary>
    public static IReadOnlyList<(string Method, string Path)> For(IServiceProvider services, string prefix)
    {
        var samples = new List<(string, string)>();
        var endpoints = services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>();

        foreach (var endpoint in endpoints)
        {
            var raw = endpoint.RoutePattern.RawText?.TrimStart('/');
            if (raw is null || !raw.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                continue;

            var path = "/" + string.Join('/', endpoint.RoutePattern.PathSegments.Select(Concrete));
            var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;
            foreach (var method in methods is { Count: > 0 } ? methods : [HttpMethods.Get, HttpMethods.Post])
                samples.Add((method, path));
        }

        return samples.Distinct().ToList();
    }

    private static string Concrete(RoutePatternPathSegment segment) =>
        string.Concat(segment.Parts.Select(part => part switch
        {
            RoutePatternLiteralPart literal => literal.Content,
            RoutePatternSeparatorPart separator => separator.Content,
            RoutePatternParameterPart { IsCatchAll: true } => "anything",
            RoutePatternParameterPart { Name: "template" } => Template,
            RoutePatternParameterPart => "1",
            _ => string.Empty,
        }));
}
