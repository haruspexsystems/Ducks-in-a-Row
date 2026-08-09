using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for GET and PUT /api/settings/allowed-domains: read the
/// policy fresh from the wizard status file, validate and normalize entries
/// on save, refuse the enabled flag without at least one usable entry, and
/// refuse writes before setup completion. Uses its own factory instance per
/// test, following the SettingsIntegrationTests pattern, so setup state
/// never couples these facts to run order.
/// </summary>
[Trait("Category", "Integration")]
public class AllowedDomainsSettingsIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public AllowedDomainsSettingsIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private string StatusPath => Path.Combine(_factory.DataDir, SetupStatus.FileName);

    private void SeedCompletedSetup()
    {
        new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = DateTime.UtcNow,
            EnabledTemplates = ["WebServer"],
            ExternalUrl = "https://certus.contoso.com:5001",
        }.Save(StatusPath);
    }

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task GetAllowedDomains_DefaultsToDisabled_AndCarriesTheAdDomainSuggestion()
    {
        SeedCompletedSetup();

        var response = await _client.GetAsync("/api/settings/allowed-domains");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("enabled").GetBoolean().Should().BeFalse();
        body.GetProperty("domains").GetArrayLength().Should().Be(0);
        // The value depends on whether the test machine is domain joined;
        // the contract is that the key is always present (string or null).
        body.TryGetProperty("adDomain", out _).Should().BeTrue();
    }

    [Fact]
    public async Task UpdateAllowedDomains_BeforeSetup_Returns409()
    {
        var response = await _client.PutAsync("/api/settings/allowed-domains",
            JsonContent(new { enabled = true, domains = new[] { "home.local" } }));

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task UpdateAllowedDomains_NormalizesDedupesAndPersists()
    {
        SeedCompletedSetup();

        var response = await _client.PutAsync("/api/settings/allowed-domains",
            JsonContent(new
            {
                enabled = true,
                domains = new[] { " Home.Local. ", "home.local", "corp" },
            }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("enabled").GetBoolean().Should().BeTrue();
        body.GetProperty("domains").EnumerateArray().Select(d => d.GetString())
            .Should().Equal("home.local", "corp");
        body.GetProperty("message").GetString().Should().Contain("immediately");

        // The GET reads the file fresh, so the save is visible right away.
        var readBack = await ParseJsonAsync(
            await _client.GetAsync("/api/settings/allowed-domains"));
        readBack.GetProperty("enabled").GetBoolean().Should().BeTrue();
        readBack.GetProperty("domains").EnumerateArray().Select(d => d.GetString())
            .Should().Equal("home.local", "corp");

        // And the file carries the new fields with the wizard state intact.
        using var file = JsonDocument.Parse(File.ReadAllText(StatusPath));
        file.RootElement.GetProperty("allowedDomainsEnabled").GetBoolean().Should().BeTrue();
        file.RootElement.GetProperty("allowedDomains").EnumerateArray()
            .Select(d => d.GetString()).Should().Equal("home.local", "corp");
        file.RootElement.GetProperty("enabledTemplates").EnumerateArray()
            .Select(t => t.GetString()).Should().Equal("WebServer");
        file.RootElement.GetProperty("setupCompleted").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task UpdateAllowedDomains_EnabledWithEmptyList_Returns400()
    {
        SeedCompletedSetup();

        var response = await _client.PutAsync("/api/settings/allowed-domains",
            JsonContent(new { enabled = true, domains = Array.Empty<string>() }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ParseJsonAsync(response);
        body.GetProperty("error").GetString().Should().Contain("Add at least one domain");
    }

    [Fact]
    public async Task UpdateAllowedDomains_InvalidEntries_Returns400WithPerEntryReasons()
    {
        SeedCompletedSetup();

        var response = await _client.PutAsync("/api/settings/allowed-domains",
            JsonContent(new
            {
                enabled = true,
                domains = new[] { "https://x.y", "1.2.3.4", "*.x.y", "a b.local" },
            }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await ParseJsonAsync(response);
        var invalid = body.GetProperty("invalidEntries").EnumerateArray().ToList();
        invalid.Should().HaveCount(4);
        invalid.Select(e => e.GetProperty("entry").GetString())
            .Should().Equal("https://x.y", "1.2.3.4", "*.x.y", "a b.local");
        invalid.Should().OnlyContain(e =>
            !string.IsNullOrEmpty(e.GetProperty("reason").GetString()));
    }

    [Fact]
    public async Task UpdateAllowedDomains_TurningOff_NeedsNoDomains()
    {
        SeedCompletedSetup();

        var enable = await _client.PutAsync("/api/settings/allowed-domains",
            JsonContent(new { enabled = true, domains = new[] { "home.local" } }));
        enable.StatusCode.Should().Be(HttpStatusCode.OK);

        var disable = await _client.PutAsync("/api/settings/allowed-domains",
            JsonContent(new { enabled = false }));

        disable.StatusCode.Should().Be(HttpStatusCode.OK);
        var readBack = await ParseJsonAsync(
            await _client.GetAsync("/api/settings/allowed-domains"));
        readBack.GetProperty("enabled").GetBoolean().Should().BeFalse();
    }
}
