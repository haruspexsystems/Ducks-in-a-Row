using System.Net;
using System.Text;
using System.Text.Json;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the wizard's TLS certificate provisioning endpoints
/// and the suggested external URL. The dev host runs the mock CA, whose
/// provisioning guard refuses before any store or CA call — the full
/// enrollment flow is covered at the unit level (TlsCertificateEnrollerTests)
/// and on the lab CA, because the Certus.Web host cannot carry a real ADCS
/// client. Own factory instance: the shared "ACME Integration" collection
/// completes setup, which would flip these endpoints to the SEC-G1 lock.
/// </summary>
[Trait("Category", "Integration")]
public class TlsCertificateIntegrationTests : IDisposable
{
    private readonly CertusWebApplicationFactory _factory = new();
    private readonly HttpClient _client;

    public TlsCertificateIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task GetConfig_SuggestsAnExternalUrl()
    {
        var response = await _client.GetAsync("/api/setup/config");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        var suggested = body.GetProperty("suggestedExternalUrl").GetString();

        suggested.Should().NotBeNullOrEmpty();
        var uri = new Uri(suggested!, UriKind.Absolute);
        uri.Scheme.Should().BeOneOf("http", "https");
        uri.Host.Should().NotBeNullOrEmpty();
        suggested.Should().Contain($":{uri.Port}",
            "the port must be explicit so ACME clients are never sent to the scheme default");
    }

    [Fact]
    public async Task ProvisionTlsCertificate_WithTheMockCa_IsRefused()
    {
        var response = await _client.PostAsync("/api/setup/tls-certificate", JsonContent(new
        {
            caConnectionString = "mockca.example.com\\Mock Certificate Authority",
            templateName = "WebServer",
            externalUrl = "https://certus.example.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ParseJsonAsync(response);
        body.GetProperty("error").GetString().Should().Contain("mock");
    }

    [Theory]
    [InlineData("/api/setup/tls-certificate/apply")]
    [InlineData("/api/setup/tls-certificate/discard")]
    public async Task ApplyAndDiscard_WithTheMockCa_AreRefused(string route)
    {
        var response = await _client.PostAsync(route, JsonContent(new
        {
            caConnectionString = "mockca.example.com\\Mock Certificate Authority",
            templateName = "WebServer",
            externalUrl = "https://certus.example.com:5001",
            thumbprint = "AA11BB22",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ParseJsonAsync(response);
        body.GetProperty("error").GetString().Should().Contain("mock");
    }
}
