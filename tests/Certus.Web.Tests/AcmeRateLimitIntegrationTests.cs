using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// A throttled ACME client used to get a bare 429 with no body, because the
/// limiter was configured with a rejection status and nothing else (issue
/// #147). RFC 8555 §6.6 has an error code for exactly this condition and asks
/// for a Retry-After header, so the rejection now carries both. The dashboard
/// is deliberately left alone: only the protocol surface gets a body.
/// </summary>
[Trait("Category", "Integration")]
public class AcmeRateLimitIntegrationTests
    : IClassFixture<AcmeRateLimitIntegrationTests.ThrottledFactory>
{
    private readonly ThrottledFactory _factory;

    public AcmeRateLimitIntegrationTests(ThrottledFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task RateLimitedAcmeRequest_Returns429ProblemDocument()
    {
        var client = _factory.CreateClient();
        var content = () => new StringContent("{}", Encoding.UTF8, "application/jose+json");

        // The window permits one request, so the second is refused. The first
        // is expected to fail on its body; only the status of the second matters.
        await client.PostAsync("/acme/WebServer/new-account", content());
        var response = await client.PostAsync("/acme/WebServer/new-account", content());

        response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());

        error.Should().NotBeNull();
        error!.Type.Should().Be(AcmeErrorType.RateLimited);
        error.Status.Should().Be(429);
        error.Detail.Should().NotBeNullOrEmpty();

        response.Headers.RetryAfter.Should().NotBeNull(
            "RFC 8555 §6.6 asks the server to tell the client when to retry");
        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "an ACME protocol response carries a nonce even when it is an error");
    }

    /// <summary>
    /// The shared factory turns rate limiting off so the rest of the suite can
    /// hammer the endpoints; this one turns it back on with a window of one.
    /// </summary>
    public sealed class ThrottledFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.UseSetting("Certus:RateLimiting:Enabled", "true");
            builder.UseSetting("Certus:RateLimiting:NewAccountLimit", "1");
            builder.UseSetting("Certus:RateLimiting:WindowSeconds", "60");
        }
    }
}
