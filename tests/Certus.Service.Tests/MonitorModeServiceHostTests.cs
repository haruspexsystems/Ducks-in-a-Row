using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Crl;
using Certus.Core.Modules;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Web.Controllers.Dashboard;
using Certus.Web.Tests.MonitorMode;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Certus.Service.Tests;

/// <summary>The production host booted in monitor mode (issue #470).</summary>
public sealed class MonitorModeServiceHostFactory : ServiceHostFactory
{
    protected override string? InstanceMode => CertusInstanceMode.MonitorValue;
}

/// <summary>
/// The acceptance criteria of issue #470, proven on the real service host rather than the
/// development host: no issuance worker, a guarded CA client and factory, no ACME on
/// either surface, and the two dashboard endpoints that write to the CA refused by name.
/// </summary>
public class MonitorModeServiceHostTests : IClassFixture<MonitorModeServiceHostFactory>
{
    private readonly MonitorModeServiceHostFactory _factory;
    private readonly HttpClient _client;

    public MonitorModeServiceHostTests(MonitorModeServiceHostFactory factory)
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
        samples.Select(s => s.Path).Should().Contain(
            ["/acme/WebServer/order/1/finalize", "/acme/WebServer/revoke-cert", "/acme/WebServer/anything"]);

        foreach (var (method, path) in samples)
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path);
            if (method != HttpMethods.Get && method != HttpMethods.Head)
                request.Content = new StringContent("{}", Encoding.UTF8, "application/jose+json");

            var response = await _client.SendAsync(request);

            response.StatusCode.Should().Be(HttpStatusCode.NotFound, $"{method} {path}");
            response.Headers.Contains("Replay-Nonce").Should().BeFalse($"{method} {path}");
        }
    }

    [Fact]
    public async Task TheAcmeAdministrationApi_Answers404()
    {
        var response = await _client.GetAsync("/api/acme/accounts");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await TypeOf(response)).Should().Be(DashboardProblemType.MonitorMode);
    }

    [Theory]
    [InlineData("/api/certificates/1/revoke")]
    [InlineData("/api/settings/https-certificate/renew")]
    [InlineData("/api/setup/tls-certificate")]
    public async Task TheEndpointsThatWriteToTheCa_Refuse(string path)
    {
        var response = await _client.PostAsync(path, new StringContent(
            JsonSerializer.Serialize(new
            {
                reason = 0,
                serialNumber = "0dc0ffee",
                caConnectionString = @"mockca.example.com\Mock Certificate Authority",
                templateName = ServiceHostFactory.Template,
                externalUrl = "https://ducks.example.com",
            }),
            Encoding.UTF8, "application/json"));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await TypeOf(response)).Should().Be(DashboardProblemType.MonitorMode);
    }

    [Fact]
    public async Task SettingsInfo_ReportsMonitorMode()
    {
        var body = JsonSerializer.Deserialize<JsonElement>(
            await _client.GetStringAsync("/api/settings/info"));

        body.GetProperty("mode").GetString().Should().Be("monitor");
    }

    private static async Task<string?> TypeOf(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync())
            .GetProperty("type").GetString();
}

/// <summary>
/// The instance mode is never something the settings overlay can supply (issue #470), and
/// a value that cannot be honoured stops the service with the reason in its log file.
/// </summary>
public class InstanceModeStartupTests
{
    // Host configuration from the environment ranks below the overlay, so the overlay's
    // value would win if the host resolved the mode after adding it. See
    // DataDirectoryOverlayTests for why the factory's UseSetting cannot be used here.
    private const string WeakSource = "DOTNET_Certus__Development__Mode";

    [Fact]
    public void TheOverlayCannotSetTheMode()
    {
        var factory = new OverlayNamingMonitorMode();
        Environment.SetEnvironmentVariable(WeakSource, CertusInstanceMode.FullValue);
        try
        {
            var services = factory.Services;

            // The positive control: the overlay was read and wins in configuration, so a
            // host that resolved the mode from configuration after adding it would be in
            // monitor mode now.
            services.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>()[CertusInstanceMode.DevelopmentKey]
                .Should().Be(CertusInstanceMode.MonitorValue);
            services.GetRequiredService<CertusInstanceMode>().IsMonitor.Should().BeFalse();
            services.GetServices<IHostedService>().Select(s => s.GetType())
                .Should().Contain(typeof(ChallengeValidationService));
        }
        finally
        {
            Environment.SetEnvironmentVariable(WeakSource, null);
            factory.Dispose();
        }
    }

    [Fact]
    public async Task AValueThatCannotBeHonoured_StopsTheHost_AndTheReasonReachesTheLogFile()
    {
        using var factory = new ModeFactory("observe");

        // Bounded, so a host that hung instead of stopping fails here rather than
        // holding the run; a timeout is not the refusal, so it is not accepted as one.
        var boot = Task.Run(() => factory.CreateClient());
        var thrown = await FluentActions.Awaiting(() => boot.WaitAsync(TimeSpan.FromSeconds(60)))
            .Should().ThrowAsync<Exception>();
        thrown.Which.Should().NotBeOfType<TimeoutException>();

        var log = Directory.EnumerateFiles(Path.Combine(factory.DataDirectory, "logs"), "ducks-*.log")
            .Select(ReadShared)
            .Should().ContainSingle().Subject;
        log.Should().Contain("observe").And.Contain("'monitor'").And.Contain("'full'");
    }

    private static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private sealed class ModeFactory(string mode) : ServiceHostFactory
    {
        protected override string? InstanceMode => mode;
    }

    private sealed class OverlayNamingMonitorMode : ServiceHostFactory
    {
        // The weak environment variable is the only source besides the overlay, so
        // the factory's own setting, which would outrank both, is left out.
        protected override string? InstanceMode => null;

        protected override void SeedDataDirectory(string dataDirectory)
        {
            // Nested the way the configuration provider reads it: Certus:Development:Mode.
            var overlay = new { Certus = new { Development = new { Mode = CertusInstanceMode.MonitorValue } } };
            File.WriteAllText(
                Path.Combine(dataDirectory, CertusPaths.SettingsOverlayFileName),
                JsonSerializer.Serialize(overlay));
        }
    }
}
