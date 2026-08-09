using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the allowed domain fields on the setup wizard
/// endpoints: completion validates and persists them (with the same rules as
/// the settings PUT), the old request shape without the fields still
/// completes unrestricted, and drafts round trip the choice through GET
/// /api/setup/config. Uses its own factory instance per test because
/// completion locks setup.
/// </summary>
[Trait("Category", "Integration")]
public class AllowedDomainsSetupIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public AllowedDomainsSetupIntegrationTests()
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

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task Complete_WithAllowedDomains_PersistsTheNormalizedFields()
    {
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            allowedDomainsEnabled = true,
            allowedDomains = new[] { " Home.Local. ", "corp" },
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var status = SetupStatus.Load(StatusPath);
        status.SetupCompleted.Should().BeTrue();
        status.AllowedDomainsEnabled.Should().BeTrue();
        status.AllowedDomains.Should().Equal("home.local", "corp");
    }

    [Fact]
    public async Task Complete_EnabledWithEmptyList_Returns400()
    {
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            allowedDomainsEnabled = true,
            allowedDomains = Array.Empty<string>(),
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ParseJsonAsync(response);
        body.GetProperty("error").GetString().Should().Contain("at least one allowed domain");
    }

    [Fact]
    public async Task Complete_InvalidEntry_Returns400WithTheReason()
    {
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            allowedDomainsEnabled = true,
            allowedDomains = new[] { "*.home.local" },
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ParseJsonAsync(response);
        body.GetProperty("error").GetString().Should().Contain("included automatically");
    }

    [Fact]
    public async Task Complete_WithoutTheNewFields_CompletesUnrestricted()
    {
        // The pre feature request shape must keep working: an older wizard
        // (or a scripted call) completes with the restriction off.
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var status = SetupStatus.Load(StatusPath);
        status.SetupCompleted.Should().BeTrue();
        status.AllowedDomainsEnabled.Should().BeFalse();
        status.AllowedDomains.Should().BeEmpty();
    }

    [Fact]
    public async Task Draft_RoundTripsTheAllowedDomainChoice()
    {
        var saved = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            caConnectionString = "ca.contoso.com\\Contoso-CA",
            enabledTemplates = new[] { "WebServer" },
            allowedDomainsEnabled = true,
            allowedDomains = new[] { "home.local" },
            wizardStep = "url",
        }));
        saved.StatusCode.Should().Be(HttpStatusCode.OK);

        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));
        config.GetProperty("allowedDomainsEnabled").GetBoolean().Should().BeTrue();
        config.GetProperty("allowedDomains").EnumerateArray()
            .Select(d => d.GetString()).Should().Equal("home.local");
        // Present on every config response; the value depends on whether the
        // test machine is domain joined.
        config.TryGetProperty("suggestedAllowedDomain", out _).Should().BeTrue();
    }
}
