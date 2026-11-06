using System.Net;
using System.Security.Cryptography;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Crl;
using Certus.Core.Modules;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Core.Tests.Acme.Attestation;
using Certus.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Certus.Service.Tests;

/// <summary>
/// The service host boots under test, writes only where the test says, and issues a
/// certificate end to end (issue #413, P0). Every later claim about the service host,
/// that issuance carries on whatever state a paid module is in above all, rests on these.
/// </summary>
public class ServiceHostTests : IClassFixture<ServiceHostFactory>
{
    private const string Serial = "SN-SERVICE-0001";
    private const string Udid = "00008030-000A1B2C3D4E5F61";

    private static readonly TimeSpan ValidationTimeout = TimeSpan.FromSeconds(30);

    private readonly ServiceHostFactory _factory;

    public ServiceHostTests(ServiceHostFactory factory) => _factory = factory;

    [Fact]
    public void ItIsTheServiceHost_NotTheDevelopmentHost()
    {
        // The development host registers the no-op restarter; only the service restarts itself.
        _factory.Services.GetRequiredService<IServiceRestarter>().Should().BeOfType<WindowsServiceRestarter>();
    }

    [Fact]
    public void FullMode_RegistersEveryWorker_AndLeavesTheCaClientUnguarded()
    {
        // The counterpart of MonitorModeServiceHostTests (issue #470): with no mode
        // configured the host is exactly what it was before monitor mode existed.
        _factory.Services.GetRequiredService<CertusInstanceMode>().Mode.Should().Be(InstanceMode.Full);
        _factory.Services.GetServices<IHostedService>().Select(s => s.GetType()).Should().Contain(
        [
            typeof(ChallengeValidationService),
            typeof(PendingIssuanceService),
            typeof(HttpsCertificateAutoRenewalService),
            typeof(CertificateSyncService),
            typeof(ExpiryMonitorService),
            typeof(CrlMonitorService),
            typeof(LicenceAlertService),
        ]);
        _factory.Services.GetRequiredService<IAdcsClient>().Should().NotBeOfType<MonitorModeAdcsClient>();
        _factory.Services.GetRequiredService<IAdcsClientFactory>().Should().NotBeOfType<MonitorModeAdcsClientFactory>();
    }

    [Fact]
    public void TheExternalUrlProbeResolves_WithTheInstanceMode()
    {
        // The probe's typed client is activated with the instance mode since issue
        // #532; a registration that could not supply it would fail only here, at the
        // first setup request.
        using var scope = _factory.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<IExternalUrlProbe>().Should().BeOfType<ExternalUrlProbe>();
        scope.ServiceProvider.GetRequiredService<SetupService>().Should().NotBeNull();
    }

    [Fact]
    public void TheWebhookClient_CarriesNoFactoryLogger()
    {
        // The HTTP client factory's loggers write each request URI at Information
        // with the path whole, where Slack, Discord and Teams connector URLs carry
        // their secret. The CRL client keeps them, which proves the walk sees them.
        static IReadOnlyList<string> Chain(IServiceProvider services, string client)
        {
            var names = new List<string>();
            HttpMessageHandler? handler =
                services.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(client);
            for (; handler is DelegatingHandler delegating; handler = delegating.InnerHandler)
                names.Add(delegating.GetType().Name);
            return names;
        }

        Chain(_factory.Services, nameof(HttpCrlFetcher)).Should().Contain(n => n.Contains("Logg"));
        Chain(_factory.Services, nameof(WebhookAlertNotifier)).Should().NotContain(n => n.Contains("Logg"));
    }

    [Fact]
    public void TheFactorysSettingsOutrankTheServicesOwnAppSettings()
    {
        // appsettings.json says Negotiate and true. Had it won, the host could not have
        // started at all, since the Negotiate handler cannot run under TestServer.
        var auth = _factory.Services.GetRequiredService<IOptions<AuthOptions>>().Value;

        auth.Mode.Should().Be(AuthOptions.ModeDisabled);
        auth.RequireHttps.Should().BeFalse();
    }

    [Fact]
    public void TheHostWritesUnderTheTestDataDirectory()
    {
        var certus = _factory.Services.GetRequiredService<IOptions<CertusOptions>>().Value;

        certus.DatabasePath.Should().Be(_factory.DatabasePath);
        File.Exists(_factory.DatabasePath).Should().BeTrue("startup migrates the database");
        Directory.EnumerateFiles(Path.Combine(_factory.DataDirectory, "logs"), "ducks-*.log").Should().NotBeEmpty(
            "the file log goes to the data directory");
    }

    /// <summary>
    /// The self signed fallback is loaded when Kestrel asks for its options
    /// (issue #635), which TestServer never does, so the test asks for them.
    /// That runs the host's own ConfigureKestrel delegate, keyring lookup
    /// included, against the ephemeral provider the factory registers.
    /// </summary>
    [Fact]
    public void TheSelfSignedFallbackIsKeyringEncryptedAndHoldsNoFixedPassword()
    {
        var kestrel = _factory.Services
            .GetRequiredService<IOptions<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>>().Value;
        kestrel.Should().NotBeNull();

        var path = Path.Combine(_factory.DataDirectory, SelfSignedHttpsCertificate.FileName);
        File.Exists(path).Should().BeTrue(
            "with no certificate configured the service generates one in its data directory");
        File.Exists(Path.Combine(_factory.DataDirectory, SelfSignedHttpsCertificate.LegacyFileName))
            .Should().BeFalse("the fixed password PFX is gone");

        // Not a PKCS#12 (which starts with an ASN.1 SEQUENCE), and not readable
        // with any password: it is a Data Protection payload.
        var bytes = File.ReadAllBytes(path);
        bytes[0].Should().NotBe(0x30);
        var open = () => System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(
            bytes, "certus-dev", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.EphemeralKeySet);
        open.Should().Throw<CryptographicException>();
    }

    [Fact]
    public async Task TheDeployedHost_MintsANonceForAnAction_AndNoneForTheFallback()
    {
        // The nonce middleware sits below the rate limiter and stamps only an
        // action's answer (issue #632). The Web host's order is pinned by
        // AcmeNonceMintingIntegrationTests; this is the same pin on the host
        // that ships, because wiring checked in one host only is wiring nobody
        // checks (issue #263).
        using var http = _factory.CreateClient();

        var minted = await http.GetAsync($"/acme/{ServiceHostFactory.Template}/new-nonce");
        minted.Headers.Contains("Replay-Nonce").Should().BeTrue();

        var fallback = await http.GetAsync($"/acme/{ServiceHostFactory.Template}/nonexistent");
        fallback.StatusCode.Should().Be(HttpStatusCode.NotFound);
        fallback.Headers.Contains("Replay-Nonce").Should().BeFalse();
    }

    [Fact]
    public async Task DeviceAttestation_OpenMode_IssuesThroughTheServiceHost()
    {
        using var root = SyntheticAttestationBuilder.CreateRoot();
        await _factory.SeedOpenDeviceProfileAsync(root);

        using var http = _factory.CreateClient();
        using var acme = new AcmeTestClient(http, ServiceHostFactory.Template);
        await acme.CreateAccountAsync();

        var (orderPath, order) = await acme.NewDeviceOrderAsync(Serial);
        var authzPath = new Uri(order.Authorizations.Single()).AbsolutePath;
        var challenge = (await acme.GetAuthorizationAsync(authzPath)).Challenges.Single();

        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = SyntheticAttestationBuilder.CreateLeaf(
            root, Serial, Udid, SyntheticAttestationBuilder.NonceFor(challenge.Token), key: deviceKey);
        var attObj = SyntheticAttestationBuilder.ToChallengePayload(
            SyntheticAttestationBuilder.BuildAttestationObject("apple", [leaf]));

        var posted = await acme.PostAsync(new Uri(challenge.Url).AbsolutePath, new { attObj });
        posted.StatusCode.Should().Be(HttpStatusCode.OK, await posted.Content.ReadAsStringAsync());

        var authz = await AcmeTestClient.PollAsync(
            () => acme.GetAuthorizationAsync(authzPath), a => a.Status != "pending", ValidationTimeout);
        authz.Status.Should().Be("valid", authz.Challenges[0].Error?.Detail);

        var ready = await AcmeTestClient.PollAsync(
            () => acme.GetOrderAsync(orderPath), o => o.Status == "ready", ValidationTimeout);
        ready.Status.Should().Be("ready");

        var finalized = await acme.FinalizeAsync(
            new Uri(order.Finalize).AbsolutePath, DeviceCsrBuilder.Build(deviceKey, $"CN={Serial}"));
        finalized.StatusCode.Should().Be(HttpStatusCode.OK, await finalized.Content.ReadAsStringAsync());

        var issued = await acme.GetOrderAsync(orderPath);
        issued.Status.Should().Be("valid");
        issued.Certificate.Should().NotBeNullOrEmpty();
    }
}
