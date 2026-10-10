using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Errors raised before an ACME action runs. A wrong Content-Type and a
/// disallowed method are both settled by endpoint routing, so they never reach
/// a controller and never pass through AcmeControllerBase.AcmeError. Certus-QA
/// phase 6.95 measured both as a bodiless 404 (issue #147): the ACME protocol
/// fallback is an unconstrained catch-all, so it stays a valid candidate,
/// ASP.NET never synthesizes its 405/415 rejection endpoint, and the fallback
/// answers instead. These tests pin the statuses RFC 8555 asks for and the
/// problem document that must come with them.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class AcmeProtocolErrorIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public AcmeProtocolErrorIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    // ── The two conditions issue #147 reported ──────────────────────────

    [Fact]
    public async Task WrongContentType_OnAcmePost_Returns415ProblemDocument()
    {
        // RFC 8555 §6.2: a request that is not application/jose+json MUST be
        // refused with 415, not reported as a missing resource.
        var content = new StringContent("{}", Encoding.UTF8, "application/json");
        var response = await _client.PostAsync("/acme/WebServer/new-account", content);

        response.StatusCode.Should().Be(HttpStatusCode.UnsupportedMediaType);

        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.Malformed);
        error.Status.Should().Be(415);
        error.Detail.Should().Contain("application/jose+json");

        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "an ACME protocol response carries a nonce even when it is an error");
    }

    [Fact]
    public async Task PlainGet_OnPostOnlyAcmeResource_Returns405ProblemDocument()
    {
        // RFC 8555 §6.3: reads are POST-as-GET, so a plain GET on a POST-only
        // resource is a method error. RFC 9110 §15.5.6 requires the Allow header.
        var response = await _client.GetAsync("/acme/WebServer/new-order");

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
        response.Content.Headers.Allow.Should().Contain("POST");

        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.Malformed);
        error.Status.Should().Be(405);
        error.Detail.Should().NotBeNullOrEmpty();

        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "an ACME protocol response carries a nonce even when it is an error");
    }

    // ── The rest of the surface behaves the same way ────────────────────

    [Theory]
    [InlineData("/acme/WebServer/new-account")]
    [InlineData("/acme/WebServer/revoke-cert")]
    [InlineData("/acme/WebServer/key-change")]
    [InlineData("/acme/WebServer/acct/some-account")]
    [InlineData("/acme/WebServer/acct/some-account/orders")]
    [InlineData("/acme/WebServer/order/some-order")]
    [InlineData("/acme/WebServer/order/some-order/finalize")]
    [InlineData("/acme/WebServer/authz/some-authz")]
    [InlineData("/acme/WebServer/chall/some-challenge")]
    [InlineData("/acme/WebServer/cert/some-cert")]
    public async Task Get_OnEveryPostOnlyAcmeResource_Returns405(string path)
    {
        var response = await _client.GetAsync(path);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed,
            $"{path} is POST only");
        response.Content.Headers.Allow.Should().Contain("POST");
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Theory]
    [InlineData("/acme/WebServer/directory")]
    [InlineData("/acme/WebServer/new-nonce")]
    [InlineData("/acme/WebServer/renewalInfo/some-cert-id")]
    public async Task Post_OnReadOnlyAcmeResource_Returns405(string path)
    {
        var content = new StringContent("{}", Encoding.UTF8, "application/jose+json");
        var response = await _client.PostAsync(path, content);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed,
            $"{path} is not written to");
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task Head_OnTheDirectory_IsServed()
    {
        // ASP.NET serves HEAD from a GET endpoint on its own, but only when no
        // candidate accepts the method, and the protocol fallback is an
        // unconstrained catch all that always does. So the directory carries an
        // explicit [HttpHead]; without it a HEAD on a live resource reaches the
        // fallback and is reported as missing. Assert the status, not merely
        // that it is not a 405: a 404 would satisfy the weaker check and is
        // exactly the bug.
        var request = new HttpRequestMessage(HttpMethod.Head, "/acme/WebServer/directory");
        var response = await _client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DoubledSlash_IsNotCollapsedOntoARealResource()
    {
        // No literal or plain parameter route segment matches an empty string,
        // so routing rejects this path outright and there is no resource
        // behind it. The classifier must not fold the empty segment away and
        // report the method error of the route it would otherwise resemble.
        var response = await _client.GetAsync("/acme/WebServer//new-order");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Content.Headers.Allow.Should().BeEmpty(
            "there is no resource here, so there is nothing to advertise");
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task MissingContentType_OnAcmePost_Returns415()
    {
        // [Consumes] refuses a POST with no Content-Type at all, so the
        // classifier has to reach the same verdict rather than call it a 404.
        var request = new HttpRequestMessage(HttpMethod.Post, "/acme/WebServer/new-account")
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes("{}"))
        };
        request.Content.Headers.ContentType = null;

        var response = await _client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.UnsupportedMediaType);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task ContentTypeWithCharset_OnAcmePost_IsAccepted()
    {
        // A parameter on an otherwise correct Content-Type must not be read as
        // a different media type. The body is not a valid JWS, so this gets as
        // far as the action and fails there with 400 rather than 415.
        var content = new StringContent("{}", Encoding.UTF8, "application/jose+json");
        var response = await _client.PostAsync("/acme/WebServer/new-account", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "charset is a parameter, so the media type still matches and the " +
            "request reaches the ACME handler");
    }

    [Fact]
    public async Task UnknownAcmePath_Returns404ProblemDocument()
    {
        // RFC 8555 §6.7 asks for a problem document on any error status, so the
        // whole protocol surface answers one, not only 405 and 415.
        var response = await _client.GetAsync("/acme/WebServer/nonexistent");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);

        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.Malformed);
        error.Status.Should().Be(404);

        response.Headers.Contains("Replay-Nonce").Should().BeTrue();
    }

    /// <summary>
    /// The classifier compares route patterns segment by segment and drops any
    /// route it cannot decide that way, which means a dropped route silently
    /// keeps the old bodiless 404 instead of a 405. Every ACME route is in
    /// shape today; this fails the moment one is added that is not, rather than
    /// letting the coverage quietly lapse.
    /// </summary>
    [Fact]
    public void EveryAcmeRoute_HasAShapeTheClassifierSupports()
    {
        var acmeRoutes = _factory.Services.GetRequiredService<EndpointDataSource>()
            .Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText?
                .TrimStart('/').StartsWith("acme/", StringComparison.OrdinalIgnoreCase) == true)
            // The fallback is a catch-all by design and is the classifier, not
            // one of the routes it classifies against.
            .Where(endpoint => !endpoint.RoutePattern.RawText!.Contains("**"))
            .ToList();

        acmeRoutes.Should().NotBeEmpty("the ACME controllers must be mapped");

        foreach (var endpoint in acmeRoutes)
        {
            foreach (var segment in endpoint.RoutePattern.PathSegments)
            {
                segment.Parts.Should().ContainSingle(
                    $"{endpoint.RoutePattern.RawText} must be one part per segment");

                if (segment.Parts[0] is RoutePatternParameterPart parameter)
                {
                    parameter.IsCatchAll.Should().BeFalse(
                        $"{endpoint.RoutePattern.RawText} must not use a catch-all");
                    parameter.IsOptional.Should().BeFalse(
                        $"{endpoint.RoutePattern.RawText} must not use an optional parameter");
                    parameter.ParameterPolicies.Should().BeEmpty(
                        $"{endpoint.RoutePattern.RawText} must not constrain a parameter, " +
                        "because the classifier cannot evaluate a constraint and would " +
                        "report 405 where routing means 404");
                }
            }
        }
    }

    private static async Task<AcmeError> ReadErrorAsync(HttpResponseMessage response)
    {
        response.Content.Headers.ContentType?.MediaType
            .Should().Be("application/problem+json");
        return JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync())!;
    }
}
