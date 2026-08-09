using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Configuration;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the settings API (issue #93): change the external
/// URL after setup, preserving the rest of the overlay, and report which
/// configuration layer supplies the value.
///
/// Uses its own factory instance per test rather than the shared "ACME
/// Integration" collection, whose tests complete setup and would couple these
/// facts to run order. The dev host runs the mock CA, so the wizard status
/// file alone makes setup effectively complete, and the save probe is
/// skipped by design (the 422 confirm flow is covered at the unit level; a
/// real CA connection string is refused by the Certus.Web host guard).
/// </summary>
[Trait("Category", "Integration")]
public class SettingsIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public SettingsIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private const string SeededCa = "ca.seeded.example.com\\Seeded-CA";
    private const string OldUrl = "https://old.example.com:5001";
    private const string NewUrl = "https://new.example.com:5001";

    private string OverlayPath => Path.Combine(_factory.DataDir, "settings.json");

    /// <summary>
    /// Put the install in the shape it has after setup: wizard status
    /// complete and an overlay holding a CA connection string next to the
    /// URL (the real service install shape), so the tests can assert the
    /// update rewrites only the URL. The overlay is never loaded into the
    /// dev host's configuration, so the seeded CA string stays inert.
    /// </summary>
    private void SeedCompletedSetup()
    {
        new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = DateTime.UtcNow,
            EnabledTemplates = ["WebServer"],
            ExternalUrl = OldUrl,
        }.Save(Path.Combine(_factory.DataDir, SetupStatus.FileName));

        SettingsOverlay.Save(new SettingsOverlay.OverlaySettings(SeededCa, OldUrl), OverlayPath);
    }

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task GetExternalUrl_ReportsTheOverlayValueAndPendingRestart()
    {
        SeedCompletedSetup();

        var response = await _client.GetAsync("/api/settings/external-url");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("overlayUrl").GetString().Should().Be(OldUrl);
        // The dev host never loads the overlay into configuration, so the
        // saved value is never in effect there and always reads as pending.
        body.GetProperty("restartPending").GetBoolean().Should().BeTrue();
        body.TryGetProperty("effectiveSource", out var source).Should().BeTrue();
        source.GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task UpdateExternalUrl_SavesTheUrlAndPreservesTheSeededCa()
    {
        SeedCompletedSetup();

        var response = await _client.PutAsync(
            "/api/settings/external-url", JsonContent(new { url = NewUrl }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("externalUrl").GetString().Should().Be(NewUrl);
        // NoOpServiceRestarter in the dev host: saved, manual restart needed.
        body.GetProperty("restartScheduled").GetBoolean().Should().BeFalse();

        using var overlay = JsonDocument.Parse(File.ReadAllText(OverlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.GetProperty("ExternalUrl").GetString().Should().Be(NewUrl);
        section.GetProperty("CaConnectionString").GetString().Should().Be(SeededCa,
            "changing the URL must not touch the CA connection string");
    }

    [Fact]
    public async Task UpdateExternalUrl_RefreshesTheWizardPrefill()
    {
        SeedCompletedSetup();

        await _client.PutAsync("/api/settings/external-url", JsonContent(new { url = NewUrl }));

        var config = await ParseJsonAsync(await _client.GetAsync("/api/setup/config"));
        config.GetProperty("externalUrl").GetString().Should().Be(NewUrl);
    }

    [Fact]
    public async Task UpdateExternalUrl_InvalidUrl_Returns400()
    {
        SeedCompletedSetup();

        var response = await _client.PutAsync(
            "/api/settings/external-url", JsonContent(new { url = "not-a-url" }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task UpdateExternalUrl_EmptyUrl_Returns400()
    {
        SeedCompletedSetup();

        var response = await _client.PutAsync(
            "/api/settings/external-url", JsonContent(new { url = "" }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task UpdateExternalUrl_BeforeSetup_Returns409()
    {
        // No seeding: the wizard is the single write path until setup is
        // effectively complete (the inverse of the SEC-G1 completion lock).
        var response = await _client.PutAsync(
            "/api/settings/external-url", JsonContent(new { url = NewUrl }));

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task GetExternalUrl_CorruptOverlay_Returns500NamingTheFile()
    {
        SeedCompletedSetup();
        File.WriteAllText(OverlayPath, "{ this is not json");

        var response = await _client.GetAsync("/api/settings/external-url");

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        var body = await ParseJsonAsync(response);
        body.GetProperty("error").GetString().Should().Contain("settings.json",
            "the admin must learn which file to fix by hand");
    }

    [Fact]
    public async Task UpdateExternalUrl_CorruptOverlay_Returns500AndDoesNotRewriteIt()
    {
        SeedCompletedSetup();
        File.WriteAllText(OverlayPath, "{ this is not json");

        var response = await _client.PutAsync(
            "/api/settings/external-url", JsonContent(new { url = NewUrl }));

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        File.ReadAllText(OverlayPath).Should().Be("{ this is not json",
            "a rewrite from an empty record would silently drop the CA connection string");
    }

    [Fact]
    public async Task GetExternalUrl_OverlayWithUnknownSiblingKeys_StillWorks()
    {
        // The configuration provider tolerates keys outside the Certus
        // section, so the settings surface must too.
        SeedCompletedSetup();
        File.WriteAllText(OverlayPath,
            """{ "comment": "hand edited", "Certus": { "ExternalUrl": "https://old.example.com:5001" } }""");

        var response = await _client.GetAsync("/api/settings/external-url");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("overlayUrl").GetString().Should().Be(OldUrl);
    }

    /// <summary>
    /// Issue #112. The build stamps the commit onto AssemblyInformationalVersion
    /// as SemVer build metadata, and this endpoint splits it back out so the
    /// Settings page shows a clean version with the sha as its own field.
    ///
    /// Deliberately asserts the payload shape, not a sha: the stamp is absent
    /// on a plain `dotnet build` and on a build from the release source
    /// snapshot, both of which must keep this suite green. The assertion that a
    /// shipped binary really carries a sha lives in build.ps1, which is the
    /// only place the expected value is known.
    ///
    /// The load bearing assertion here is that "commit" is present at all: that
    /// is what fails if the endpoint is ever reverted to returning the raw
    /// informational version. The "no +" assertion only bites on a stamped
    /// build, so it is a guard for a developer running this against build.ps1
    /// output, not something CI can catch. The splitting itself is covered
    /// exhaustively by BuildVersionInfoTests.
    /// </summary>
    [Fact]
    public async Task GetInfo_ReportsACleanVersionAndACommitField()
    {
        var response = await _client.GetAsync("/api/settings/info");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);

        var version = body.GetProperty("version").GetString();
        version.Should().NotBeNullOrWhiteSpace();
        version.Should().NotContain("+",
            "the build metadata belongs in the commit field, not the version the page shows");

        body.TryGetProperty("commit", out var commit).Should().BeTrue(
            "the dashboard reads this field and must not have to guess whether it exists");
        commit.ValueKind.Should().BeOneOf(JsonValueKind.String, JsonValueKind.Null);
        if (commit.ValueKind == JsonValueKind.String)
        {
            commit.GetString().Should().NotBeNullOrWhiteSpace();
        }
    }
}
