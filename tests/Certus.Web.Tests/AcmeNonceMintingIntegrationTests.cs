using System.Net;
using System.Text;

namespace Certus.Web.Tests;

/// <summary>
/// Which ACME responses mint a Replay-Nonce since issue #632 (CRA R04): the
/// ones a controller action produces, success or error, and no other. A nonce
/// is a stored entry, so every response that mints one is work an
/// unauthenticated caller can make the server do; the fallback's refusals and
/// the rate limiter's 429 cost the server nothing and store nothing. The 429
/// half is pinned in AcmeRateLimitIntegrationTests, which owns a throttled host.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class AcmeNonceMintingIntegrationTests
{
    private readonly HttpClient _client;

    public AcmeNonceMintingIntegrationTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task NewNonce_StillMints()
    {
        var response = await _client.GetAsync("/acme/WebServer/new-nonce");

        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "new-nonce is the resource a client fetches a nonce from (RFC 8555 section 7.2)");
    }

    [Fact]
    public async Task AControllerError_StillMints()
    {
        // A JWS the action refuses as malformed is an action's answer, and
        // RFC 8555 section 7.2 lets a client harvest its next nonce from any
        // response, so the SHOULD on error responses holds where an action
        // answered.
        var content = new StringContent("{}", Encoding.UTF8, "application/jose+json");
        var response = await _client.PostAsync("/acme/WebServer/new-account", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Headers.Contains("Replay-Nonce").Should().BeTrue();
    }

    [Theory]
    [InlineData("GET", "/acme/WebServer/nonexistent")]        // 404, no such resource
    [InlineData("GET", "/acme/WebServer/new-order")]          // 405, POST only
    [InlineData("PUT", "/acme/WebServer/new-account")]        // 405
    public async Task TheProtocolFallback_MintsNothing(string method, string path)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (method != "GET")
            request.Content = new StringContent("{}", Encoding.UTF8, "application/jose+json");

        var response = await _client.SendAsync(request);

        response.IsSuccessStatusCode.Should().BeFalse();
        response.Headers.Contains("Replay-Nonce").Should().BeFalse($"{method} {path}");
        response.Headers.CacheControl?.NoStore.Should().BeTrue(
            "the security headers middleware still stamps no-store on the whole surface");
    }
}
