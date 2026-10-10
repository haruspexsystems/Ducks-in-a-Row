using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Certus.Core.Adcs;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The wire contract for the wizard's template reporting, issues #235 and #292.
/// The wizard's
/// DTOs are hand written on both sides with no code generation, so a casing or
/// naming drift between the C# record and the TypeScript interface is silent:
/// the checklist item would simply never render and the wizard would look like
/// it had nothing to say about a broken template. These tests pin the exact
/// JSON property names the frontend reads.
///
/// The dashboard's own GET /api/templates is pinned here too rather than in a
/// file of its own, because both endpoints compose their warning through the
/// single SetupTemplateNameWarning.From. Two shapes drifting apart is the
/// failure that sharing one composer exists to prevent, and it is only visible
/// with both read side by side.
/// </summary>
[Trait("Category", "Integration")]
public class SetupTemplateNameWarningIntegrationTests
    : IClassFixture<SetupTemplateNameWarningIntegrationTests.DirtyTemplateFactory>
{
    private readonly HttpClient _client;

    public SetupTemplateNameWarningIntegrationTests(DirtyTemplateFactory factory)
    {
        _client = factory.CreateClient();
    }

    private async Task<JsonElement> ListTemplatesAsync()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/setup/templates", new { caConnectionString = "ca.contoso.com\\Contoso CA" });

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    [Fact]
    public async Task DisplayNameWarning_IsCarriedWithTheNamesTheFrontendReads()
    {
        var root = await ListTemplatesAsync();

        var template = root.GetProperty("templates").EnumerateArray()
            .Single(t => t.GetProperty("name").GetString() == "WebServer");

        var warning = template.GetProperty("displayNameWarning");
        warning.ValueKind.Should().NotBe(JsonValueKind.Null);
        warning.GetProperty("kind").GetString().Should().Be("formatting");
        warning.GetProperty("codePoint").GetInt32().Should().Be(0x00AD);
        warning.GetProperty("position").GetInt32().Should().Be(3);
    }

    [Fact]
    public async Task UnusableNameCount_IsCarriedAlongsideExcludedCount()
    {
        var root = await ListTemplatesAsync();

        // The template whose programmatic name carries a line feed is hidden,
        // and counted twice over: once in the total, once in the subset whose
        // fix is to duplicate the template rather than change a setting.
        //
        // One template of the three, and only that one. The template with the
        // deceptive OID is listed and adds to neither count, which is the whole
        // of the issue #292 policy read off the wire: reported, never withheld.
        root.GetProperty("excludedCount").GetInt32().Should().Be(1);
        root.GetProperty("unusableNameCount").GetInt32().Should().Be(1);

        var names = root.GetProperty("templates").EnumerateArray()
            .Select(t => t.GetProperty("name").GetString())
            .ToList();
        names.Should().BeEquivalentTo(new[] { "WebServer", "WebServerOid" });
    }

    [Fact]
    public async Task ACleanTemplateCarriesANullWarningRatherThanAMissingKey()
    {
        // The frontend tests `template.displayNameWarning` for truthiness, so
        // null and absent both work, but a null is what the serializer emits
        // today and a change to that is worth noticing.
        var root = await ListTemplatesAsync();

        var clean = root.GetProperty("templates").EnumerateArray()
            .Single(t => t.GetProperty("name").GetString() == "WebServer");

        clean.TryGetProperty("displayNameWarning", out _).Should().BeTrue();
    }

    [Fact]
    public async Task OidWarning_IsCarriedWithTheNamesTheFrontendReads()
    {
        var root = await ListTemplatesAsync();

        var template = root.GetProperty("templates").EnumerateArray()
            .Single(t => t.GetProperty("name").GetString() == "WebServerOid");

        var warning = template.GetProperty("oidWarning");
        warning.ValueKind.Should().NotBe(JsonValueKind.Null);
        warning.GetProperty("kind").GetString().Should().Be("formatting");
        warning.GetProperty("codePoint").GetInt32().Should().Be(0x00AD);
        warning.GetProperty("position").GetInt32().Should().Be(5);

        // The OID itself is still served, because nothing here strips. The
        // warning beside it must not repeat the characters, or the object that
        // reports the fault becomes a second copy of it.
        warning.GetRawText().Should().NotContain(char.ConvertFromUtf32(0x00AD));
        template.GetProperty("displayNameWarning").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task ACleanTemplateCarriesANullOidWarningRatherThanAMissingKey()
    {
        var root = await ListTemplatesAsync();

        var clean = root.GetProperty("templates").EnumerateArray()
            .Single(t => t.GetProperty("name").GetString() == "WebServer");

        clean.TryGetProperty("oidWarning", out var warning).Should().BeTrue();
        warning.ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task TheDashboardTemplatesEndpoint_CarriesTheSameOidWarning()
    {
        var response = await _client.GetAsync("/api/templates");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var root = JsonDocument.Parse(await response.Content.ReadAsStringAsync())
            .RootElement.Clone();

        var dirty = root.EnumerateArray()
            .Single(t => t.GetProperty("name").GetString() == "WebServerOid");

        var warning = dirty.GetProperty("oidWarning");
        warning.GetProperty("kind").GetString().Should().Be("formatting");
        warning.GetProperty("codePoint").GetInt32().Should().Be(0x00AD);
        warning.GetProperty("position").GetInt32().Should().Be(5);

        // The template with the soft hyphen in its display name answers null
        // here. This endpoint reports on the OID and nothing else, so a fault
        // in another value must not arrive under this key.
        var dirtyDisplayName = root.EnumerateArray()
            .Single(t => t.GetProperty("name").GetString() == "WebServer");
        dirtyDisplayName.GetProperty("oidWarning").ValueKind.Should().Be(JsonValueKind.Null);

        // Unlike the wizard's list, this one is not filtered by what can be
        // enrolled, so the template whose programmatic name carries a line feed
        // is served here as well.
        root.GetArrayLength().Should().Be(3);
    }

    /// <summary>
    /// Serves a CA whose published list carries one template with a soft hyphen
    /// in its display name (listed, warned about), one with a line feed in its
    /// programmatic name (hidden, counted), and one with a soft hyphen in its
    /// OID (listed, noted, counted nowhere). The mock's own default list is
    /// deliberately left alone: other suites count it.
    /// </summary>
    public sealed class DirtyTemplateFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existingFactory = services.SingleOrDefault(
                    d => d.ServiceType == typeof(IAdcsClientFactory));
                if (existingFactory != null)
                    services.Remove(existingFactory);

                services.AddSingleton<IAdcsClientFactory>(new DirtyTemplateClientFactory());

                // Both registrations, because the two endpoints reach the CA by
                // different routes: the wizard builds a client per candidate
                // connection string through the factory, while TemplateService
                // behind GET /api/templates takes the singleton IAdcsClient.
                // Replacing only the factory leaves the dashboard talking to a
                // different CA than the wizard, which is a fixture that cannot
                // show the two disagreeing.
                var existingClient = services.SingleOrDefault(
                    d => d.ServiceType == typeof(IAdcsClient));
                if (existingClient != null)
                    services.Remove(existingClient);

                services.AddSingleton<IAdcsClient>(
                    new DirtyTemplateClientFactory().Create("test"));
            });
        }
    }

    private sealed class DirtyTemplateClientFactory : IAdcsClientFactory
    {
        // Built from numeric code points rather than written literally: a soft
        // hyphen pasted into source is invisible to the next reader too.
        private static string With(int codePoint, string before, string after) =>
            before + char.ConvertFromUtf32(codePoint) + after;

        public IAdcsClient Create(string caConnectionString) =>
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo(
                    "WebServer", With(0x00AD, "Web", " Server"), "1.3.6.1.4.1.311.21.8.1",
                    new[] { "1.3.6.1.5.5.7.3.1" }),
                new TemplateInfo(
                    With(0x0A, "Web", "Server2"), "Web Server 2", "1.3.6.1.4.1.311.21.8.2",
                    new[] { "1.3.6.1.5.5.7.3.1" }),
                new TemplateInfo(
                    "WebServerOid", "Web Server Oid",
                    With(0x00AD, "1.3.6", ".1.4.1.311.21.8.3"),
                    new[] { "1.3.6.1.5.5.7.3.1" }),
            });
    }
}
