using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Configuration;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the wizard draft endpoint and the resume fields on
/// GET /api/setup/config: the wizard step recorded in the draft and the
/// state of an already configured TLS certificate. Uses its own factory
/// instance per test class rather than the shared "ACME Integration"
/// collection, whose completion test locks setup and would make these facts
/// order dependent.
/// </summary>
[Trait("Category", "Integration")]
public class SetupDraftIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public SetupDraftIntegrationTests()
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
    public async Task SaveDraft_PersistsAndConfigEchoesTheResumePoint()
    {
        var saved = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            caConnectionString = "ca.contoso.com\\Contoso-CA",
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            wizardStep = "url",
        }));
        saved.StatusCode.Should().Be(HttpStatusCode.OK);

        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));
        config.GetProperty("wizardStep").GetString().Should().Be("url");
        config.GetProperty("caConnectionString").GetString().Should().Be("ca.contoso.com\\Contoso-CA");
        config.GetProperty("externalUrl").GetString().Should().Be("https://certus.contoso.com:5001");
        // No overlay thumbprint was written, so no certificate is reported.
        config.GetProperty("tlsCertificate").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task SaveDraft_AfterCompletedSetup_Returns409()
    {
        // The dev host runs the mock CA, so a completed wizard status file
        // alone makes setup effectively complete (SEC-G1 lock territory).
        new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = DateTime.UtcNow,
            EnabledTemplates = ["WebServer"],
            ExternalUrl = "https://certus.contoso.com:5001",
        }.Save(Path.Combine(_factory.DataDir, SetupStatus.FileName));

        var response = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            wizardStep = "welcome",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task GetConfig_ReportsAConfiguredButUninstalledCertificate()
    {
        // A thumbprint in the overlay whose certificate is not in the store
        // (the dev host store finds nothing) must read as configured but not
        // installed, never as an error.
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(null, null, "AA11BB22CC33"),
            Path.Combine(_factory.DataDir, "settings.json"));

        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));

        var cert = config.GetProperty("tlsCertificate");
        cert.GetProperty("thumbprint").GetString().Should().Be("AA11BB22CC33");
        cert.GetProperty("installed").GetBoolean().Should().BeFalse();
    }
}
