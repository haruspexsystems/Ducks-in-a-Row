using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// A server that finished setup in monitor mode and was then switched to full by a
/// local administrator (issue #471). No template is recorded, so the wizard reopens
/// at the Templates step with the CA it already has, and nothing it carried, such as
/// the EAB mode and the revocation scope, is lost on the way through. A factory per
/// test, because completion locks setup.
/// </summary>
[Trait("Category", "Integration")]
public class ReopenForIssuanceIntegrationTests : IDisposable
{
    private const string Ca = "ca.contoso.com\\Contoso-CA";

    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public ReopenForIssuanceIntegrationTests()
    {
        _client = _factory.CreateClient();

        // What monitor mode completion leaves behind, with settings an
        // administrator chose since, which the reopened wizard must carry.
        new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = DateTime.UtcNow,
            CaConnectionString = Ca,
            EnabledTemplates = [],
            ExternalUrl = "https://certus.contoso.com:5001",
            EabEnforcement = "required",
            RevocationScope = "custom",
            RevocableTemplates = ["WebServer"],
        }.Save(StatusPath);
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
    public async Task Setup_reads_as_incomplete_so_the_dashboard_sends_the_administrator_to_the_wizard()
    {
        var status = await ParseJsonAsync(await _client.GetAsync("/api/setup/status"));

        status.GetProperty("setupCompleted").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task The_wizard_resumes_at_templates_with_the_ca_prefilled_and_says_why()
    {
        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));

        config.GetProperty("mode").GetString().Should().Be("full");
        config.GetProperty("wizardStep").GetString().Should().Be("templates");
        config.GetProperty("reopenReason").GetString().Should().Be("issuanceEnabled");
        config.GetProperty("caConnectionString").GetString().Should().Be(Ca);
        config.GetProperty("wizardCompleted").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task Draft_then_completion_carries_the_eab_mode_and_revocation_scope_forward()
    {
        // The draft is no longer locked: the reopened wizard is a wizard.
        var draft = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            caConnectionString = Ca,
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            wizardStep = "domains",
        }));
        draft.StatusCode.Should().Be(HttpStatusCode.OK);
        SetupStatus.Load(StatusPath).SetupCompleted.Should().BeFalse();

        var complete = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            caConnectionString = Ca,
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
        }));
        complete.StatusCode.Should().Be(HttpStatusCode.OK);

        var status = SetupStatus.Load(StatusPath);
        status.SetupCompleted.Should().BeTrue();
        status.EnabledTemplates.Should().Equal("WebServer");
        status.EabEnforcement.Should().Be("required");
        status.RevocationScope.Should().Be("custom");
        status.RevocableTemplates.Should().Equal("WebServer");

        var after = await ParseJsonAsync(await _client.GetAsync("/api/setup/status"));
        after.GetProperty("setupCompleted").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task Completion_in_full_mode_still_requires_a_template()
    {
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            caConnectionString = Ca,
            enabledTemplates = Array.Empty<string>(),
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Be("At least one template must be enabled");
    }
}
