using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The service rights check over HTTP, issue #440: the wizard's route with a
/// candidate CA, the Settings routes with the configured one, and the refusals
/// in front of both. The dev host runs the simulated probe, so the report is
/// the example estate's, marked as simulated.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class ServiceRightsIntegrationTests
{
    private static readonly string[] Statuses = ["proven", "inferred", "unproven", "failed", "skipped"];

    private readonly HttpClient _client;

    public ServiceRightsIntegrationTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    private static StringContent Json(object payload) =>
        new(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    private static JsonElement Row(JsonElement body, string id) =>
        body.GetProperty("rows").EnumerateArray().Single(r => r.GetProperty("id").GetString() == id);

    [Fact]
    public async Task TheWizardRoute_ReturnsAReportWithNamedStatuses()
    {
        var response = await _client.PostAsync("/api/setup/service-rights",
            Json(new { caConnectionString = @"mockca.example.com\Mock Certificate Authority", templates = new[] { "WebServer" } }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);

        body.GetProperty("simulated").GetBoolean().Should().BeTrue();
        body.GetProperty("identity").GetProperty("accountName").GetString().Should().Be(@"CORP\DUCKS01$");
        body.GetProperty("rows").EnumerateArray()
            .Select(r => r.GetProperty("status").GetString())
            .Should().OnlyContain(s => Statuses.Contains(s));
        Row(body, "template:WebServer").GetProperty("status").GetString().Should().Be("inferred");
        Row(body, "https-enrolment").GetProperty("status").GetString().Should().Be("skipped");
        Row(body, "ca-read").GetProperty("neededFor").EnumerateArray().Select(e => e.GetString())
            .Should().Equal("inventory");
    }

    [Fact]
    public async Task TheWizardRoute_WithNoTemplates_ChecksTheCaAlone()
    {
        var response = await _client.PostAsync("/api/setup/service-rights",
            Json(new { caConnectionString = @"mockca.example.com\Mock Certificate Authority" }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("rows").EnumerateArray()
            .Should().NotContain(r => r.GetProperty("group").GetString() == "template");
    }

    [Theory]
    [InlineData("")]
    // The same guard test-connection applies: a character that could forge a
    // log line, since the connection string is written to the log.
    [InlineData("ca.example.com\\Example CA\nforged line")]
    public async Task TheWizardRoute_RefusesAnUnusableCa(string ca)
    {
        var response = await _client.PostAsync("/api/setup/service-rights", Json(new { caConnectionString = ca }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task TheWizardRoute_RefusesATemplateNameCarryingAControlCharacter()
    {
        var response = await _client.PostAsync("/api/setup/service-rights",
            Json(new { caConnectionString = @"mockca.example.com\Mock Certificate Authority", templates = new[] { "Web\nServer" } }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task TheWizardRoute_RefusesMoreTemplatesThanTheLimit()
    {
        var many = Enumerable.Range(0, 17).Select(i => $"Template{i}").ToArray();

        var response = await _client.PostAsync("/api/setup/service-rights",
            Json(new { caConnectionString = @"mockca.example.com\Mock Certificate Authority", templates = many }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task TheSettingsRoutes_CheckTheConfiguredCaAndTemplates()
    {
        var kept = await _client.GetAsync("/api/settings/service-rights");
        kept.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ParseJsonAsync(kept)).GetProperty("simulated").GetBoolean().Should().BeTrue();

        var fresh = await _client.PostAsync("/api/settings/service-rights/check", Json(new { }));
        fresh.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(fresh);
        // The factory's seeded status file enables WebServer.
        Row(body, "template:WebServer").GetProperty("status").GetString().Should().Be("inferred");
    }

    [Fact]
    public async Task TheSettingsRoutes_AnswerConflict_WhenNoCaIsConfigured()
    {
        using var factory = new UnconfiguredFactory();
        var client = factory.CreateClient();

        var response = await client.GetAsync("/api/settings/service-rights");

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    /// <summary>
    /// The mock turned off and no CA string: the unconfigured install the
    /// wizard exists for. PostConfigure, because the dev host's appsettings
    /// sets UseMockCa and a plain setting would lose to it.
    /// </summary>
    private sealed class UnconfiguredFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services =>
                services.PostConfigure<CertusOptions>(options =>
                {
                    options.UseMockCa = false;
                    options.CaConnectionString = null;
                }));
        }
    }
}
