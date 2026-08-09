using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// The revocation scope settings API: GET serves the defaults and the stored
/// values, PUT strict parses the mode, validates template names for the
/// characters the ADCS attribute rules refuse while accepting names the CA
/// does not currently publish, allows the empty custom list (dashboard
/// revocation disabled, fails safe), and refuses before setup completes.
/// Uses its own factory instance per test so setup state never couples these
/// facts to run order.
/// </summary>
[Trait("Category", "Integration")]
public class RevocationScopeSettingsIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public RevocationScopeSettingsIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private string StatusPath => Path.Combine(_factory.DataDir, SetupStatus.FileName);

    private void SeedCompletedSetup() => new SetupStatus
    {
        SetupCompleted = true,
        CompletedAt = DateTime.UtcNow,
        EnabledTemplates = ["WebServer"],
        ExternalUrl = "https://certus.contoso.com:5001",
    }.Save(StatusPath);

    private Task<HttpResponseMessage> PutScopeAsync(object payload) =>
        _client.PutAsync(
            "/api/settings/revocation-scope",
            new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    [Fact]
    public async Task Get_FreshInstall_ServesTheDucksManagedDefault()
    {
        SeedCompletedSetup();

        var response = await _client.GetAsync("/api/settings/revocation-scope");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await BodyAsync(response);
        body.GetProperty("mode").GetString().Should().Be("ducks-managed");
        body.GetProperty("customTemplates").GetArrayLength().Should().Be(0);
        body.GetProperty("enabledTemplates").EnumerateArray()
            .Select(e => e.GetString()).Should().Contain("WebServer");
    }

    [Theory]
    [InlineData("ducks-managed")]
    [InlineData("custom")]
    [InlineData("all")]
    public async Task Put_EachMode_PersistsAndEchoes(string mode)
    {
        SeedCompletedSetup();

        var response = await PutScopeAsync(new { mode, customTemplates = new[] { "WebServer" } });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await BodyAsync(response);
        body.GetProperty("mode").GetString().Should().Be(mode);
        body.GetProperty("message").GetString().Should().Contain("immediately");

        var stored = SetupStatus.Load(StatusPath);
        stored.RevocationScope.Should().Be(mode);
        stored.RevocableTemplates.Should().Equal("WebServer");
    }

    [Fact]
    public async Task Put_TypoMode_Returns400()
    {
        SeedCompletedSetup();

        var response = await PutScopeAsync(new { mode = "duck-managed" });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await BodyAsync(response)).GetProperty("error").GetString()
            .Should().Contain("ducks-managed, custom, all");
        SetupStatus.Load(StatusPath).RevocationScope.Should().BeNull();
    }

    [Fact]
    public async Task Put_TemplateNameWithControlCharacter_Returns400Naming()
    {
        // The same character rules the ADCS attribute string enforces (issue
        // #175): a name that could smuggle a second attribute is refused
        // with the entry echoed in the structured body.
        SeedCompletedSetup();

        var response = await PutScopeAsync(new
        {
            mode = "custom",
            customTemplates = new[] { "Web\nServer" },
        });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await BodyAsync(response);
        body.GetProperty("error").GetString().Should().Contain("template names");
        body.GetProperty("invalidEntries").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task Put_UnpublishedTemplateName_IsStoredAsGiven()
    {
        // The CA may be unreachable at save time, and a list that only
        // accepted currently published names would not survive an outage.
        SeedCompletedSetup();

        var response = await PutScopeAsync(new
        {
            mode = "custom",
            customTemplates = new[] { "NotPublishedAnywhere" },
        });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        SetupStatus.Load(StatusPath).RevocableTemplates
            .Should().Equal("NotPublishedAnywhere");
    }

    [Fact]
    public async Task Put_CustomWithEmptyList_IsAllowed()
    {
        // Custom with nothing ticked disables dashboard revocation
        // entirely, which fails safe, so the API allows it rather than
        // forcing the admin through a fake entry.
        SeedCompletedSetup();

        var response = await PutScopeAsync(new { mode = "custom", customTemplates = Array.Empty<string>() });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        SetupStatus.Load(StatusPath).RevocationScope.Should().Be("custom");
    }

    [Fact]
    public async Task Put_BeforeSetupCompletes_Returns409()
    {
        var response = await PutScopeAsync(new { mode = "all" });

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await BodyAsync(response)).GetProperty("error").GetString()
            .Should().Contain("Setup has not been completed");
    }
}
