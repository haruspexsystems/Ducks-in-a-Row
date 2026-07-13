using System.Net;
using System.Text;
using System.Text.Json;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the Setup Wizard API endpoints.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class SetupIntegrationTests
{
    private readonly HttpClient _client;

    public SetupIntegrationTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task GetStatus_Returns200()
    {
        var response = await _client.GetAsync("/api/setup/status");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.TryGetProperty("setupCompleted", out _).Should().BeTrue();
        // SEC-F2: status is anonymous and must not expose CA configuration.
        body.TryGetProperty("caConnectionString", out _).Should().BeFalse();
    }

    private static StringContent CandidateCa() => new(
        JsonSerializer.Serialize(new { caConnectionString = "mockca.example.com\\Mock Certificate Authority" }),
        Encoding.UTF8, "application/json");

    [Fact]
    public async Task DiscoverCas_Returns200WithList()
    {
        var response = await _client.GetAsync("/api/setup/discover-cas");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.ValueKind.Should().Be(JsonValueKind.Array);
        body.GetArrayLength().Should().BeGreaterThan(0);
        body[0].TryGetProperty("connectionString", out _).Should().BeTrue();
    }

    [Fact]
    public async Task TestConnection_WithCandidateCa_Returns200WithResult()
    {
        var response = await _client.PostAsync("/api/setup/test-connection", CandidateCa());

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        // MockAdcsClient should report success
        body.GetProperty("success").GetBoolean().Should().BeTrue();
        body.TryGetProperty("caName", out _).Should().BeTrue();
    }

    [Fact]
    public async Task TestConnection_WithoutCandidateCa_Returns400()
    {
        var empty = new StringContent(
            JsonSerializer.Serialize(new { caConnectionString = "" }),
            Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/api/setup/test-connection", empty);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task GetTemplates_WithCandidateCa_Returns200()
    {
        var response = await _client.PostAsync("/api/setup/templates", CandidateCa());

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("templates").ValueKind.Should().Be(JsonValueKind.Array);
        body.GetProperty("templates").GetArrayLength().Should().BeGreaterThan(0);
        body.GetProperty("excludedCount").GetInt32().Should().BeGreaterThanOrEqualTo(0);
    }

    [Fact]
    public async Task ValidateUrl_ValidHttps_ReturnsValid()
    {
        var content = new StringContent(
            JsonSerializer.Serialize(new { url = "https://certus.example.com" }),
            Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/api/setup/validate-url", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("valid").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task ValidateUrl_Http_ReturnsValidWithWarnings()
    {
        var content = new StringContent(
            JsonSerializer.Serialize(new { url = "http://certus.example.com" }),
            Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/api/setup/validate-url", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("valid").GetBoolean().Should().BeTrue();
        body.GetProperty("warnings").GetArrayLength().Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task ValidateUrl_MockHost_SkipsTheReachabilityProbe()
    {
        // The integration host runs UseMockCa=true: a demo walkthrough must
        // never dial out or be blocked by the reachability probe (issue #89).
        var content = new StringContent(
            JsonSerializer.Serialize(new { url = "https://certus.example.com", templateName = "WebServer" }),
            Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/api/setup/validate-url", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("valid").GetBoolean().Should().BeTrue();
        body.GetProperty("probe").GetProperty("attempted").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task ValidateUrl_Empty_Returns400()
    {
        var content = new StringContent(
            JsonSerializer.Serialize(new { url = "" }),
            Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/api/setup/validate-url", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task CompleteSetup_ValidatesThenCompletesThenLocks()
    {
        // One sequential test: completion mutates shared factory state (the
        // setup status file), and the completion lock (SEC-G1) makes separate
        // facts order-dependent.

        // Invalid payload first: no templates selected.
        var noTemplates = new StringContent(
            JsonSerializer.Serialize(new
            {
                caConnectionString = "ca\\CA",
                enabledTemplates = Array.Empty<string>(),
                externalUrl = "https://certus.example.com",
            }),
            Encoding.UTF8, "application/json");

        var rejected = await _client.PostAsync("/api/setup/complete", noTemplates);
        rejected.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // Valid payload completes setup.
        StringContent ValidPayload() => new(
            JsonSerializer.Serialize(new
            {
                caConnectionString = "ca.contoso.com\\Contoso-CA",
                enabledTemplates = new[] { "WebServer" },
                externalUrl = "https://certus.contoso.com",
            }),
            Encoding.UTF8, "application/json");

        var completed = await _client.PostAsync("/api/setup/complete", ValidPayload());
        completed.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(completed);
        body.GetProperty("setupCompleted").GetBoolean().Should().BeTrue();

        // Repeat completion is locked once setup is done (SEC-G1).
        var locked = await _client.PostAsync("/api/setup/complete", ValidPayload());
        locked.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }
}
