using System.Net;
using System.Text.Json;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests verifying the /health endpoint
/// returns proper status and data from CertusHealthCheck.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class HealthCheckIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public HealthCheckIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task HealthEndpoint_Returns200()
    {
        var response = await _client.GetAsync("/health");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsHealthyStatus()
    {
        var response = await _client.GetAsync("/health");
        var content = await response.Content.ReadAsStringAsync();

        // The health check response should indicate healthy status
        content.Should().Contain("Healthy");
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsTextContentType()
    {
        // ASP.NET Core's default health check response format is text/plain
        var response = await _client.GetAsync("/health");

        response.Content.Headers.ContentType?.MediaType
            .Should().Be("text/plain");
    }

    [Fact]
    public async Task LivenessEndpoint_Returns200_WithoutRunningChecks()
    {
        // /health/live runs no checks (no DB or CA probe) and should return 200.
        var response = await _client.GetAsync("/health/live");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Contain("Healthy");
    }
}
