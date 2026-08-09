using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The setup wizard must not accept a CA connection string that could forge
/// entries in the service log (issue #220). Unlike a template name this cannot
/// smuggle an ADCS request attribute — the connection string is its own Submit
/// parameter — but it is written verbatim on every CA call, and the wizard is
/// the only path that records it. The refusal therefore has to happen before
/// the value reaches the status file. Uses its own factory instance per test
/// because completion locks setup.
/// </summary>
[Trait("Category", "Integration")]
public class CaConnectionStringInjectionIntegrationTests : IDisposable
{
    /// <summary>
    /// Runs the host unconfigured rather than on the mock CA. The shared
    /// factory sets UseMockCa, and the two TLS provisioning endpoints refuse a
    /// mock CA in <c>GuardTlsProvisioning</c> before they ever look at the
    /// request body, so on the shared factory those endpoints could not be
    /// shown to refuse the connection string itself. Unconfigured also makes
    /// completion record the value for real (a mock install discards it), so
    /// the "ordinary value still saves" tests assert on what was written.
    /// UseMockCa is flipped through PostConfigure rather than UseSetting
    /// because appsettings.json sets the key and would outrank host
    /// configuration.
    /// </summary>
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services =>
                services.PostConfigure<CertusOptions>(o => o.UseMockCa = false));
        }
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public CaConnectionStringInjectionIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
        GC.SuppressFinalize(this);
    }

    private string StatusPath => Path.Combine(_factory.DataDir, SetupStatus.FileName);

    /// <summary>
    /// A connection string shaped like a forged log entry: the line feed closes
    /// the real line and what follows reads as a separate event.
    /// </summary>
    private const string ForgedLogLine =
        "ca01.contoso.local\\Contoso-CA\n[FTL] Certificate issued to Administrator";

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task TestConnection_ConnectionStringCarryingALineFeed_Returns400()
    {
        var response = await _client.PostAsync("/api/setup/test-connection", JsonContent(new
        {
            caConnectionString = ForgedLogLine,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var error = (await ParseJsonAsync(response)).GetProperty("error").GetString();
        error.Should().Contain("control character");
        // The refusal must not echo the payload back out of the API, or the
        // response body carries the forged line onward.
        error.Should().NotContain("[FTL]");
    }

    [Fact]
    public async Task Templates_ConnectionStringCarryingALineFeed_Returns400()
    {
        var response = await _client.PostAsync("/api/setup/templates", JsonContent(new
        {
            caConnectionString = ForgedLogLine,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("control character");
    }

    [Fact]
    public async Task Complete_ConnectionStringCarryingALineFeed_Returns400AndRecordsNothing()
    {
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            caConnectionString = ForgedLogLine,
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var error = (await ParseJsonAsync(response)).GetProperty("error").GetString();
        error.Should().Contain("control character");
        error.Should().NotContain("[FTL]");

        SetupStatus.Load(StatusPath).SetupCompleted.Should().BeFalse();
    }

    [Fact]
    public async Task Complete_ConnectionStringCarryingABidiOverride_Returns400()
    {
        // A right to left override cannot forge a line, but it makes the
        // recorded CA display as a different host wherever it is echoed.
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            caConnectionString = "ca01.contoso.local\\Contoso" + (char)0x202E + "AC-osotnoC",
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("formatting character");

        SetupStatus.Load(StatusPath).SetupCompleted.Should().BeFalse();
    }

    [Fact]
    public async Task Draft_ConnectionStringCarryingALineFeed_Returns400AndRecordsNothing()
    {
        // The draft is a second writer to the same field completion writes, so
        // guarding only completion would leave the value recordable anyway.
        var response = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            caConnectionString = ForgedLogLine,
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            wizardStep = "url",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (SetupStatus.Load(StatusPath).CaConnectionString ?? string.Empty)
            .Should().NotContain("[FTL]");
    }

    [Fact]
    public async Task TlsCertificate_ConnectionStringCarryingALineFeed_Returns400()
    {
        var response = await _client.PostAsync("/api/setup/tls-certificate", JsonContent(new
        {
            caConnectionString = ForgedLogLine,
            templateName = "WebServer",
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("control character");
    }

    [Fact]
    public async Task TlsCertificateApply_ConnectionStringCarryingALineFeed_Returns400()
    {
        // Apply is refused on the connection string before the thumbprint is
        // looked up, so no certificate has to exist for this to be the answer.
        var response = await _client.PostAsync("/api/setup/tls-certificate/apply", JsonContent(new
        {
            caConnectionString = ForgedLogLine,
            templateName = "WebServer",
            externalUrl = "https://certus.contoso.com:5001",
            thumbprint = "0000000000000000000000000000000000000000",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("control character");
    }

    [Fact]
    public async Task Draft_OrdinaryConnectionString_StillSaves()
    {
        // The guard must not narrow what a legitimate install can record: a CA
        // common name with spaces and punctuation is normal.
        var response = await _client.PostAsync("/api/setup/draft", JsonContent(new
        {
            caConnectionString = "ca01.contoso.local\\Contoso Issuing CA 01",
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            wizardStep = "url",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        SetupStatus.Load(StatusPath).CaConnectionString
            .Should().Be("ca01.contoso.local\\Contoso Issuing CA 01");
    }

    [Fact]
    public async Task Complete_OrdinaryConnectionString_StillCompletes()
    {
        // The external URL probe is live here because this factory turns the
        // mock off, and a test host cannot reach certus.contoso.com, so the
        // confirmation flag stands in for the administrator behind a reverse
        // proxy. Nothing about it touches the connection string guard, which
        // has already run by the time the URL is probed.
        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            caConnectionString = "ca01.contoso.local\\Contoso Issuing CA 01",
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
            confirmUnreachableExternalUrl = true,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var status = SetupStatus.Load(StatusPath);
        status.SetupCompleted.Should().BeTrue();
        status.CaConnectionString.Should().Be("ca01.contoso.local\\Contoso Issuing CA 01");
    }
}
