using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// Pins the external account binding default of issue #631 across the wizard's
/// endpoints and the ACME directory: a fresh install that completes without a
/// binding choice serves <c>externalAccountRequired: true</c> on the very next
/// directory fetch, an explicit off is honoured, a mode that is not one is
/// refused, and an install upgraded from before the field existed stays off,
/// both at the directory and in the prefill a reopened wizard reads. Own factory
/// instance per test because completion locks setup.
/// </summary>
[Trait("Category", "Integration")]
public class EabSetupIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public EabSetupIntegrationTests()
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

    private async Task<bool> DirectoryRequiresBindingAsync()
    {
        var response = await _client.GetAsync("/acme/WebServer/directory");
        response.EnsureSuccessStatusCode();
        var directory = JsonSerializer.Deserialize<AcmeDirectory>(
            await response.Content.ReadAsStringAsync());
        return directory!.Meta!.ExternalAccountRequired;
    }

    [Fact]
    public async Task FreshInstall_CompletedWithoutAChoice_DirectoryRequiresBinding()
    {
        // The wizard prefills the server's fresh install default, and an API
        // caller that predates the choice sends no eabEnforcement at all.
        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));
        config.GetProperty("eabEnforcement").GetString().Should().Be("required");

        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.example.com:5001",
        }));
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        SetupStatus.Load(StatusPath).EabEnforcement.Should().Be("required");
        (await DirectoryRequiresBindingAsync()).Should().BeTrue();
    }

    [Fact]
    public async Task FreshInstall_ExplicitOff_IsHonoured()
    {
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.example.com:5001",
            eabEnforcement = "off",
        }));
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        SetupStatus.Load(StatusPath).EabEnforcement.Should().Be("off");
        (await DirectoryRequiresBindingAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task Complete_ModeThatIsNotOne_Returns400_AndCompletesNothing()
    {
        // A typo is refused rather than read as off, which would quietly drop
        // the protection the administrator meant to keep.
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.example.com:5001",
            eabEnforcement = "requried",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("off, optional or required");
        SetupStatus.Load(StatusPath).SetupCompleted.Should().BeFalse();
    }

    [Fact]
    public async Task Draft_ModeThatIsNotOne_Returns400()
    {
        var response = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            wizardStep = "url",
            eabEnforcement = "sometimes",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Draft_RoundTripsTheBindingChoice_AndCompletionKeepsIt()
    {
        // The wizard drafts the choice at each step, so a reload or the mid
        // wizard TLS restart comes back with binding switched off as chosen.
        var saved = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            caConnectionString = "ca.example.com\\Example-CA",
            enabledTemplates = new[] { "WebServer" },
            wizardStep = "url",
            eabEnforcement = "off",
        }));
        saved.StatusCode.Should().Be(HttpStatusCode.OK);

        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));
        config.GetProperty("eabEnforcement").GetString().Should().Be("off");

        var completed = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.example.com:5001",
        }));
        completed.StatusCode.Should().Be(HttpStatusCode.OK);
        (await DirectoryRequiresBindingAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task UpgradedInstall_StatusFileWithoutTheField_StaysOff()
    {
        // A file a release before the field existed completed: the upgrade
        // path keeps binding off, and the wizard's prefill says so outright.
        new SetupStatus
        {
            SetupCompleted = true,
            EnabledTemplates = ["WebServer"],
            ExternalUrl = "https://certus.example.com:5001",
        }.Save(StatusPath);

        (await DirectoryRequiresBindingAsync()).Should().BeFalse();

        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));
        config.GetProperty("eabEnforcement").GetString().Should().Be("off");
    }
}
