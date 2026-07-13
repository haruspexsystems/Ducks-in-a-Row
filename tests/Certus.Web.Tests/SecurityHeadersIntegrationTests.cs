using System.Net;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests verifying that the SecurityHeadersMiddleware
/// applies the correct security headers to all responses.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class SecurityHeadersIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public SecurityHeadersIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Response_ContainsXContentTypeOptions()
    {
        var response = await _client.GetAsync("/health");

        response.Headers.TryGetValues("X-Content-Type-Options", out var values)
            .Should().BeTrue();
        values.Should().Contain("nosniff");
    }

    [Fact]
    public async Task Response_ContainsXFrameOptions()
    {
        var response = await _client.GetAsync("/health");

        response.Headers.TryGetValues("X-Frame-Options", out var values)
            .Should().BeTrue();
        values.Should().Contain("DENY");
    }

    [Fact]
    public async Task Response_ContainsXXssProtection()
    {
        var response = await _client.GetAsync("/health");

        response.Headers.TryGetValues("X-XSS-Protection", out var values)
            .Should().BeTrue();
        values.Should().Contain("0");
    }

    [Fact]
    public async Task Response_ContainsReferrerPolicy()
    {
        var response = await _client.GetAsync("/health");

        response.Headers.TryGetValues("Referrer-Policy", out var values)
            .Should().BeTrue();
        values.Should().Contain("strict-origin-when-cross-origin");
    }

    [Fact]
    public async Task Response_ContainsContentSecurityPolicy()
    {
        var response = await _client.GetAsync("/health");

        response.Headers.TryGetValues("Content-Security-Policy", out var values)
            .Should().BeTrue();

        var csp = string.Join(' ', values!);
        csp.Should().Contain("default-src 'self'");
        csp.Should().Contain("script-src 'self'");
        csp.Should().Contain("object-src 'none'");
        csp.Should().Contain("frame-ancestors 'none'");
    }

    [Fact]
    public async Task ApiResponse_ContainsContentSecurityPolicy()
    {
        // The CSP backstop must also cover the API surface, not just the SPA shell.
        var response = await _client.GetAsync("/api/certificates?skip=0&take=1");

        response.Headers.TryGetValues("Content-Security-Policy", out var values)
            .Should().BeTrue();
        string.Join(' ', values!).Should().Contain("default-src 'self'");
    }

    [Fact]
    public void Hsts_IsConfiguredWithOneYearAndSubDomains()
    {
        // The header itself only emits over HTTPS outside Development (UseCertusTransportSecurity),
        // so assert the hardened options that app.UseHsts() consumes rather than the wire header.
        var options = _factory.Services.GetRequiredService<IOptions<HstsOptions>>().Value;

        options.MaxAge.Should().Be(TimeSpan.FromDays(365));
        options.IncludeSubDomains.Should().BeTrue();
    }

    [Fact]
    public async Task AcmeResponse_ContainsCacheControlNoStore()
    {
        var response = await _client.GetAsync("/acme/WebServer/directory");

        response.Headers.CacheControl?.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task ApiResponse_ContainsCacheControlNoStore()
    {
        var response = await _client.GetAsync("/api/certificates?skip=0&take=1");

        response.Headers.CacheControl?.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task AllResponses_ContainSecurityHeaders()
    {
        // Verify that even ACME directory endpoints get all the security headers
        var response = await _client.GetAsync("/acme/WebServer/directory");

        response.Headers.TryGetValues("X-Content-Type-Options", out var xCto)
            .Should().BeTrue();
        xCto.Should().Contain("nosniff");

        response.Headers.TryGetValues("X-Frame-Options", out var xfo)
            .Should().BeTrue();
        xfo.Should().Contain("DENY");
    }
}
