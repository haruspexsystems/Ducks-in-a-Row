using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Setup;

namespace Certus.Web.Tests.MonitorMode;

/// <summary>
/// The setup wizard's completion in monitor mode (issue #471): it finishes without a
/// template, and refuses one. A factory per test, because completion locks setup.
/// </summary>
[Trait("Category", "Integration")]
public class MonitorModeSetupIntegrationTests : IDisposable
{
    private sealed class Factory : MonitorModeWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public MonitorModeSetupIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private string StatusPath => Path.Combine(_factory.DataDir, SetupStatus.FileName);

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    [Fact]
    public async Task Completion_without_a_template_completes_and_records_none()
    {
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = Array.Empty<string>(),
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        SetupStatus.Load(StatusPath).SetupCompleted.Should().BeTrue();
        SetupStatus.Load(StatusPath).EnabledTemplates.Should().BeEmpty();

        // The wizard does not ask about binding in monitor mode and sends no
        // choice, so the server records the fresh install default: a server
        // later switched to full starts with binding required (issue #631).
        SetupStatus.Load(StatusPath).EabEnforcement.Should().Be("required");

        // A monitor mode server never awaits a template, so the dashboard opens.
        var status = await ParseJsonAsync(await _client.GetAsync("/api/setup/status"));
        status.GetProperty("setupCompleted").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task Completion_with_a_template_is_refused_and_records_nothing()
    {
        // A template recorded here would go live for ACME the moment a local
        // administrator switches the server to full, without anyone choosing it.
        var before = File.ReadAllText(StatusPath);

        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("monitor mode");
        File.ReadAllText(StatusPath).Should().Be(before);
    }

    [Fact]
    public async Task A_draft_carrying_a_template_is_refused()
    {
        var response = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            wizardStep = "url",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task A_draft_without_a_template_is_saved()
    {
        var response = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            enabledTemplates = Array.Empty<string>(),
            externalUrl = "https://certus.contoso.com:5001",
            wizardStep = "review",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Config_reports_monitor_mode_and_no_reopen()
    {
        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));

        config.GetProperty("mode").GetString().Should().Be("monitor");
        config.GetProperty("reopenReason").ValueKind.Should().Be(JsonValueKind.Null);
    }
}
