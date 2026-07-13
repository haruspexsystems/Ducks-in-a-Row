using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Configuration;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the webserver HTTPS certificate settings API: the
/// certificate report and the renewal guards. The dev host runs the mock CA
/// and the no op certificate store, so these cover the read path and every
/// refusal; a real enrollment is exercised at the unit level and in the lab.
/// Own factory per test class, like SettingsIntegrationTests, so state never
/// couples to run order.
/// </summary>
[Trait("Category", "Integration")]
public class HttpsCertificateIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public HttpsCertificateIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private string OverlayPath => Path.Combine(_factory.DataDir, "settings.json");

    private void SeedCompletedSetup()
    {
        new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = DateTime.UtcNow,
            EnabledTemplates = ["WebServer"],
            ExternalUrl = "https://certus.example.com:5001",
        }.Save(Path.Combine(_factory.DataDir, SetupStatus.FileName));
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task GetHttpsCertificate_NothingConfigured_ReportsNotConfigured()
    {
        var response = await _client.GetAsync("/api/settings/https-certificate");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("configured").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task GetHttpsCertificate_OverlayThumbprint_ReportsDetailsAndRenewTemplate()
    {
        SeedCompletedSetup();
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(
                null, "https://certus.example.com:5001",
                HttpsCertificateThumbprint: "AA11BB22CC33",
                HttpsCertificateTemplate: "WebServerV2"),
            OverlayPath);

        var body = await ParseJsonAsync(await _client.GetAsync("/api/settings/https-certificate"));

        body.GetProperty("configured").GetBoolean().Should().BeTrue();
        body.GetProperty("thumbprint").GetString().Should().Be("AA11BB22CC33");
        // The dev host store holds nothing, so the certificate is reported
        // as configured but absent — a state, not an error.
        body.GetProperty("inStore").GetBoolean().Should().BeFalse();
        body.GetProperty("template").GetString().Should().Be("WebServerV2");
        body.GetProperty("renewTemplate").GetString().Should().Be("WebServerV2");
    }

    [Fact]
    public async Task GetHttpsCertificate_NoRecordedTemplate_FallsBackToFirstEnabled()
    {
        SeedCompletedSetup();
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(
                null, null, HttpsCertificateThumbprint: "AA11BB22CC33"),
            OverlayPath);

        var body = await ParseJsonAsync(await _client.GetAsync("/api/settings/https-certificate"));

        body.GetProperty("template").ValueKind.Should().Be(JsonValueKind.Null);
        body.GetProperty("renewTemplate").GetString().Should().Be("WebServer");
    }

    [Fact]
    public async Task RenewHttpsCertificate_BeforeSetup_Returns409()
    {
        var response = await _client.PostAsync(
            "/api/settings/https-certificate/renew",
            new StringContent("{}", Encoding.UTF8, "application/json"));

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task RenewHttpsCertificate_MockCa_Returns400()
    {
        SeedCompletedSetup();

        var response = await _client.PostAsync(
            "/api/settings/https-certificate/renew",
            new StringContent("{}", Encoding.UTF8, "application/json"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ParseJsonAsync(response);
        body.GetProperty("error").GetString().Should().Contain("mock");
    }
}
