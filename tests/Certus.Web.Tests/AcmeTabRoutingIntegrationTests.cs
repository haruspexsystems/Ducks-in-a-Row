using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.FileProviders;

namespace Certus.Web.Tests;

/// <summary>
/// The /acme URL space is shared by two different things: the dashboard's
/// ACME tab lives at bare /acme (a SPA route, issue #129), while every ACME
/// protocol URL sits under /acme/{template}/... and must keep its issue #27
/// guarantee that unknown paths return 404 rather than the SPA shell. These
/// tests pin the split. The factory swaps the web root file provider for one
/// holding a sentinel index.html, because the real wwwroot is a gitignored
/// frontend build output that need not exist in a fresh checkout.
/// </summary>
[Trait("Category", "Integration")]
public class AcmeTabRoutingIntegrationTests : IDisposable
{
    private sealed class SentinelWebRootFactory : CertusWebApplicationFactory
    {
        public const string Sentinel = "spa-shell-sentinel";

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            // UseWebRoot does not reach a minimal hosting app through the
            // test factory (the builder computed its web root long before),
            // but the static file middleware resolves the environment's
            // WebRootFileProvider when the pipeline is built, so swapping
            // the provider on the environment instance does apply.
            builder.ConfigureServices((context, _) =>
            {
                var webRoot = Path.Combine(TempDataDir, "wwwroot");
                Directory.CreateDirectory(webRoot);
                File.WriteAllText(Path.Combine(webRoot, "index.html"),
                    $"<!doctype html><title>{Sentinel}</title>");
                context.HostingEnvironment.WebRootFileProvider =
                    new PhysicalFileProvider(webRoot);
            });
        }
    }

    private readonly SentinelWebRootFactory _factory = new();
    private readonly HttpClient _client;

    public AcmeTabRoutingIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Fact]
    public async Task BareAcmePath_ServesTheSpaShell()
    {
        var response = await _client.GetAsync("/acme");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.Should().Be("text/html");
        (await response.Content.ReadAsStringAsync())
            .Should().Contain(SentinelWebRootFactory.Sentinel,
                "the ACME dashboard tab is a SPA route, so a hard refresh " +
                "or bookmark must get the shell, not the protocol 404");

        // The nonce middleware serves protocol paths only; stamping the SPA
        // shell would burn a stored nonce per dashboard load and force
        // no-store on it.
        response.Headers.Contains("Replay-Nonce").Should().BeFalse(
            "the dashboard tab is not an ACME protocol response");
    }

    [Fact]
    public async Task AcmeProtocolPaths_NeverFallBackToTheSpaShell()
    {
        // One segment (a template with no resource) and a deep unknown path
        // both stay on the protocol fallback and answer 404 (issue #27).
        foreach (var path in new[] { "/acme/WebServer", "/acme/WebServer/nonexistent" })
        {
            var response = await _client.GetAsync(path);

            response.StatusCode.Should().Be(HttpStatusCode.NotFound,
                $"{path} is protocol namespace");
            (await response.Content.ReadAsStringAsync())
                .Should().NotContain(SentinelWebRootFactory.Sentinel,
                    $"{path} must not be masked by the SPA shell");
            response.Headers.Contains("Replay-Nonce").Should().BeTrue(
                $"{path} is an ACME protocol response (RFC 8555 §7.2)");
        }
    }
}
