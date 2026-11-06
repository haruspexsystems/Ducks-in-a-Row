using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Crl;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Modules;
using Certus.Core.Services;
using Certus.Core.ServiceRights;
using Certus.Core.Setup;
using Certus.Web.Controllers.Dashboard;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Certus.Web.Tests.MonitorMode;

/// <summary>
/// The development host in monitor mode (issue #470): no ACME on either surface, no
/// issuance worker, and every dashboard endpoint that would write to the CA refuses by
/// name. The production host is proven the same way in Certus.Service.Tests; this file
/// also covers what only the dashboard reads, such as the service rights marking.
/// </summary>
[Trait("Category", "Integration")]
public class MonitorModeIntegrationTests : IClassFixture<MonitorModeWebApplicationFactory>
{
    private readonly MonitorModeWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public MonitorModeIntegrationTests(MonitorModeWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public void TheIssuanceWorkers_AreNotRegistered_AndTheReadersAre()
    {
        var hosted = _factory.Services.GetServices<IHostedService>().Select(s => s.GetType()).ToList();

        hosted.Should().NotContain(typeof(ChallengeValidationService));
        hosted.Should().NotContain(typeof(PendingIssuanceService));
        hosted.Should().NotContain(typeof(HttpsCertificateAutoRenewalService));
        hosted.Should().Contain(typeof(CertificateSyncService));
        hosted.Should().Contain(typeof(ExpiryMonitorService));
        hosted.Should().Contain(typeof(CrlMonitorService));
        hosted.Should().Contain(typeof(LicenceAlertService), "a licence alert is not a write to the CA");

        // The singleton stays, because the settings page reads it, and says it is off.
        _factory.Services.GetRequiredService<HttpsCertificateAutoRenewalService>().Enabled.Should().BeFalse();
    }

    [Fact]
    public void TheCaClientAndItsFactory_AreGuarded()
    {
        _factory.Services.GetRequiredService<IAdcsClient>().Should().BeOfType<MonitorModeAdcsClient>();
        _factory.Services.GetRequiredService<IAdcsClientFactory>().Should().BeOfType<MonitorModeAdcsClientFactory>();
    }

    [Fact]
    public async Task EveryAcmeProtocolRoute_Answers404_WithNoNonce()
    {
        var samples = ProtocolRouteSamples.For(_factory.Services, "acme/");

        // The writes and the way in to them, by name, so a sampler that silently
        // stopped finding routes cannot pass this test by sampling nothing.
        samples.Select(s => s.Path).Should().Contain(
        [
            "/acme/WebServer/directory",
            "/acme/WebServer/new-nonce",
            "/acme/WebServer/new-order",
            "/acme/WebServer/order/1/finalize",
            "/acme/WebServer/revoke-cert",
            "/acme/WebServer/key-change",
            "/acme/WebServer/anything",
        ]);

        foreach (var (method, path) in samples)
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path);
            if (method != HttpMethods.Get && method != HttpMethods.Head)
                request.Content = new StringContent("{}", Encoding.UTF8, "application/jose+json");

            var response = await _client.SendAsync(request);

            response.StatusCode.Should().Be(HttpStatusCode.NotFound, $"{method} {path}");
            response.Headers.Contains("Replay-Nonce").Should().BeFalse(
                $"{method} {path} must not cost a stored nonce");
            if (method != HttpMethods.Head)
            {
                (await response.Content.ReadAsStringAsync()).Should().Contain("monitor mode", $"{method} {path}");
            }
        }
    }

    [Fact]
    public async Task EveryAcmeAdministrationRoute_Answers404_WithTheMonitorModeType()
    {
        var samples = ProtocolRouteSamples.For(_factory.Services, "api/acme").ToList();
        samples.Should().Contain(s => s.Path == "/api/acme/accounts");
        samples.Add((HttpMethods.Get, "/api/acme/no-such-route"));

        foreach (var (method, path) in samples)
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path);
            if (method != HttpMethods.Get && method != HttpMethods.Head)
                request.Content = new StringContent("{}", Encoding.UTF8, "application/json");

            var response = await _client.SendAsync(request);

            response.StatusCode.Should().Be(HttpStatusCode.NotFound, $"{method} {path}");
            if (method != HttpMethods.Head)
                (await TypeOf(response)).Should().Be(DashboardProblemType.MonitorMode, $"{method} {path}");
        }
    }

    [Fact]
    public async Task DashboardRevoke_IsRefused_AndTheRowStaysIssued()
    {
        var (id, serial) = await SeedIssuedRowAsync();

        var detail = await _client.GetAsync($"/api/certificates/{id}");
        var body = await BodyAsync(detail);
        body.GetProperty("revocationBlocked").GetString().Should().Be(RevocationEligibilityService.MonitorModeKind);

        var response = await _client.PostAsync($"/api/certificates/{id}/revoke",
            Json(new { reason = 0, serialNumber = serial }));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await TypeOf(response)).Should().Be(DashboardProblemType.MonitorMode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        (await db.SyncedCertificates.FindAsync(id))!.Status.Should().Be("Issued");
    }

    [Fact]
    public async Task WizardEnrolment_IsRefused_BeforeTheMockCaGuard()
    {
        // The dev host runs the mock CA, whose own refusal is a 400. Monitor mode
        // answers first, so it is the reason the operator reads.
        var response = await _client.PostAsync("/api/setup/tls-certificate", Json(new
        {
            caConnectionString = @"mockca.example.com\Mock Certificate Authority",
            templateName = "WebServer",
            externalUrl = "https://ducks.example.com",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await TypeOf(response)).Should().Be(DashboardProblemType.MonitorMode);
    }

    [Fact]
    public async Task SettingsRenewal_IsRefused()
    {
        var response = await _client.PostAsync("/api/settings/https-certificate/renew", Json(new { }));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await TypeOf(response)).Should().Be(DashboardProblemType.MonitorMode);
    }

    [Fact]
    public async Task SettingsInfo_ReportsMonitorMode()
    {
        var body = await BodyAsync(await _client.GetAsync("/api/settings/info"));

        body.GetProperty("mode").GetString().Should().Be("monitor");
    }

    [Fact]
    public async Task ServiceRights_MarkOnlyTheRowsMonitorModeNeverUses()
    {
        var response = await _client.PostAsync("/api/setup/service-rights", Json(new
        {
            caConnectionString = @"mockca.example.com\Mock Certificate Authority",
            templates = new[] { "WebServer" },
        }));
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var rows = (await BodyAsync(response)).GetProperty("rows").EnumerateArray().ToList();

        foreach (var row in rows)
        {
            var neededFor = row.GetProperty("neededFor").EnumerateArray().Select(e => e.GetString()).ToList();
            var expected = neededFor.Count > 0 && neededFor.All(n => n is "issuance" or "revocation");
            row.GetProperty("notNeeded").GetString().Should().Be(
                expected ? ServiceRightsWire.NotNeededInMonitorMode : null,
                row.GetProperty("id").GetString());
        }

        rows.Should().Contain(r => r.GetProperty("id").GetString() == "template:WebServer"
            && r.GetProperty("notNeeded").GetString() == ServiceRightsWire.NotNeededInMonitorMode);
        rows.Should().Contain(r => r.GetProperty("id").GetString() == "ca-read"
            && r.GetProperty("notNeeded").ValueKind == JsonValueKind.Null);
    }

    private async Task<(int Id, string Serial)> SeedIssuedRowAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var entity = new SyncedCertificate
        {
            RequestId = Random.Shared.Next(70_000_000, 80_000_000),
            SerialNumber = $"0dc0ffee{Random.Shared.Next(0x1000, 0xFFFF):x8}",
            Subject = $"CN=monitor-mode-{Guid.NewGuid():N}",
            TemplateName = "WebServer",
            Status = "Issued",
            RequestDate = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow,
            NotAfter = DateTime.UtcNow.AddYears(1),
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1",
            KeyUsage = 160,
        };
        db.SyncedCertificates.Add(entity);
        await db.SaveChangesAsync();
        return (entity.Id, entity.SerialNumber);
    }

    private static StringContent Json(object payload) =>
        new(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    private static async Task<string?> TypeOf(HttpResponseMessage response) =>
        (await BodyAsync(response)).GetProperty("type").GetString();
}

/// <summary>
/// The administration API gate behind the real authorization stack: an anonymous caller
/// and a non admin get the same 401 and 403 as on any other /api path, so monitor mode
/// tells nobody outside the admin group which routes exist.
/// </summary>
[Trait("Category", "Integration")]
public class MonitorModeAuthIntegrationTests : IClassFixture<MonitorModeAuthWebApplicationFactory>
{
    private readonly MonitorModeAuthWebApplicationFactory _factory;

    public MonitorModeAuthIntegrationTests(MonitorModeAuthWebApplicationFactory factory) => _factory = factory;

    [Theory]
    [InlineData("/api/acme/accounts")]
    [InlineData("/api/acme/no-such-route")]
    public async Task Anonymous_Gets401_NotTheGate(string path)
    {
        var response = await Client().GetAsync(path);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task NonAdmin_Gets403_NotTheGate()
    {
        var response = await Client("alice").GetAsync("/api/acme/accounts");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Admin_Gets404()
    {
        var response = await Client(TestAuthHandler.AdminUser).GetAsync("/api/acme/accounts");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    private HttpClient Client(string? user = null)
    {
        var client = _factory.CreateClient();
        if (user is not null)
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        return client;
    }
}
