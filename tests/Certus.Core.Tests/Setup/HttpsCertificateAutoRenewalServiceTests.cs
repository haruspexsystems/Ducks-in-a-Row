using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Certus.Core.Tests.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Certus.Core.Tests.Setup;

/// <summary>
/// Automatic renewal of the server's own HTTPS certificate (issue #105): when
/// it fires, when it stays out of the way, what it persists, and the load
/// bearing promise that a failure never disturbs the certificate the host is
/// currently serving.
/// </summary>
public class HttpsCertificateAutoRenewalServiceTests : IDisposable
{
    private const string TestCa = "ca.home.local\\Home-CA";
    private const string ExternalHost = "certus.home.local";
    private const string ExternalUrl = "https://certus.home.local:5001";
    private const string InstalledThumbprint = "AA11BB22";
    private const string RenewedThumbprint = "CC33DD44";

    private readonly string _tempDir = Path.Combine(
        Path.GetTempPath(), "certus-renewal-tests-" + Guid.NewGuid().ToString("N"));

    private readonly IAdcsClient _client = Substitute.For<IAdcsClient>();
    private readonly IAdcsClientFactory _clientFactory = Substitute.For<IAdcsClientFactory>();
    private readonly IHttpsCertificateStore _store = Substitute.For<IHttpsCertificateStore>();
    private readonly IAlertNotifier _notifier = Substitute.For<IAlertNotifier>();
    private readonly CertusOptions _options;
    private readonly ServiceProvider _provider;

    private byte[]? _submittedCsr;

    public HttpsCertificateAutoRenewalServiceTests()
    {
        Directory.CreateDirectory(_tempDir);

        _options = new CertusOptions
        {
            CaConnectionString = TestCa,
            ExternalUrl = ExternalUrl,
            DatabasePath = Path.Combine(_tempDir, "ducks.db"),
            SettingsOverlayPath = Path.Combine(_tempDir, "settings.json"),
            HttpsCertificateThumbprint = InstalledThumbprint,
        };

        _clientFactory.Create(Arg.Any<string>()).Returns(_client);

        // The enroller resolves the recorded template against the CA's own
        // published list before it submits, so the CA has to publish the
        // template these cases renew with. Distinct programmatic and display
        // names, as a real CA has them.
        _client.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo> { new("WebServer", "Web Server", "oid1") });

        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(),
                Arg.Do<byte[]>(csr => _submittedCsr = csr),
                Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(7, SubmitStatus.Issued));
        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns(_ => new CertificateResult(7, CertificateStatus.Issued, IssueFromSubmittedCsr()));
        _store.Install(Arg.Any<X509Certificate2>()).Returns(RenewedThumbprint);

        _notifier.Channel.Returns("test");
        _notifier.IsEnabled.Returns(true);
        _notifier.SendServerCertificateAlertAsync(
                Arg.Any<ServerCertificateAlert>(), Arg.Any<CancellationToken>())
            .Returns(new AlertNotificationResult(true));

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Options.Create(_options));
        services.AddSingleton(_clientFactory);
        services.AddSingleton(_store);
        services.AddSingleton(Substitute.For<ICaDiscoveryService>());
        services.AddSingleton(Substitute.For<IExternalUrlProbe>());
        services.AddScoped<IAlertNotifier>(_ => _notifier);
        services.AddScoped<SetupService>();
        services.AddScoped<TlsCertificateEnroller>();
        services.AddScoped<HttpsCertificateRenewalService>();
        services.AddSingleton(CertusInstanceMode.Full);
        _provider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _provider.Dispose();
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: a stray temp folder is harmless.
        }
    }

    private HttpsCertificateAutoRenewalService CreateService(CertusInstanceMode? instanceMode = null) =>
        new(_provider.GetRequiredService<IServiceScopeFactory>(),
            _store,
            new ServerCertificateIdentity(
                _store, Options.Create(_options), instanceMode ?? CertusInstanceMode.Full,
                NullLogger<ServerCertificateIdentity>.Instance),
            Options.Create(_options),
            instanceMode ?? CertusInstanceMode.Full,
            NullLogger<HttpsCertificateAutoRenewalService>.Instance);

    /// <summary>Wizard state a configured, completed install has.</summary>
    private void SeedCompletedSetup(string? template = "WebServer")
    {
        new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = DateTime.UtcNow,
            CaConnectionString = TestCa,
            EnabledTemplates = template is null ? [] : [template],
            ExternalUrl = ExternalUrl,
        }.Save(SetupStatus.GetStatusPath(_options));
    }

    /// <summary>The overlay as the wizard's TLS provisioning leaves it.</summary>
    private void SeedOverlay(string? thumbprint = InstalledThumbprint, string? template = "WebServer")
    {
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(
                TestCa, ExternalUrl,
                HttpsCertificateThumbprint: thumbprint,
                HttpsCertificateTemplate: template),
            _options.SettingsOverlayPath!);
    }

    private SettingsOverlay.OverlaySettings ReadOverlay() =>
        SettingsOverlay.Load(_options.SettingsOverlayPath!);

    /// <summary>
    /// A self signed stand in for the certificate in LocalMachine\My, valid
    /// for <paramref name="lifetimeDays"/> and expiring in
    /// <paramref name="daysToExpiry"/>.
    /// </summary>
    private static X509Certificate2 MakeCertificate(double daysToExpiry, double lifetimeDays = 730)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={ExternalHost}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(daysToExpiry);
        return request.CreateSelfSigned(notAfter.AddDays(-lifetimeDays), notAfter);
    }

    /// <summary>
    /// The store answers <paramref name="thumbprint"/> with a fresh copy of
    /// <paramref name="certificate"/> on every call, because the caller disposes what
    /// it is given. The copy carries the friendly name the service gives every
    /// certificate it installs unless <paramref name="installedByService"/> is false,
    /// which is a certificate somebody else put in the store (issue #535).
    /// </summary>
    private void StoreHolds(string thumbprint, X509Certificate2 certificate, bool installedByService = true) =>
        _store.Find(thumbprint).Returns(_ =>
        {
            var copy = X509CertificateLoader.LoadCertificate(certificate.RawData);
            if (installedByService)
                copy.FriendlyName = HttpsCertificateOwnership.FriendlyName;
            return copy;
        });

    /// <summary>Sign the captured CSR the way an ADCS CA honoring the request would.</summary>
    private byte[] IssueFromSubmittedCsr()
    {
        var loaded = CertificateRequest.LoadSigningRequest(
            _submittedCsr!,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pkcs1);

        using var caKey = RSA.Create(2048);
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using var cert = loaded.Create(
            new X500DistinguishedName("CN=Test Issuing CA"),
            X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(2),
            serial);
        return cert.Export(X509ContentType.Cert);
    }

    [Fact]
    public async Task CheckAsync_InsideTheWindow_RenewsAndSwapsTheOverlayThumbprint()
    {
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Installed);
        sut.LastAttempt.Thumbprint.Should().Be(RenewedThumbprint);
        sut.LastAttempt.PreviousThumbprint.Should().Be(InstalledThumbprint);

        var overlay = ReadOverlay();
        overlay.HttpsCertificateThumbprint.Should().Be(RenewedThumbprint);
        overlay.HttpsCertificateTemplate.Should().Be("WebServer");
        overlay.CaConnectionString.Should().Be(TestCa, "the rest of the overlay must survive the swap");
        overlay.ExternalUrl.Should().Be(ExternalUrl);
    }

    [Fact]
    public async Task CheckAsync_InsideTheWindow_KeepsTheKeysAnAdministratorAddedByHand()
    {
        // The one overlay writer no administrator triggers (issue #550): before the
        // fix, a renewal on its timer took the admin group, the private range block
        // and the webhook with it, and the next restart fell back on all three.
        SeedCompletedSetup();
        SeedOverlay();
        HandEditedOverlay.AddTo(_options.SettingsOverlayPath!);
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Installed);
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(RenewedThumbprint);
        HandEditedOverlay.ShouldStillBeInForce(_options.SettingsOverlayPath!);
    }

    [Fact]
    public async Task CheckAsync_InsideTheWindow_LeavesTheCertificateItServesInTheStore()
    {
        // The running process is still serving the old certificate, and
        // removing it from the store deletes its key container out from under
        // Kestrel. The sweep that runs earlier in the pass names it as the one
        // to keep, so it protects that certificate rather than removing it.
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);

        await CreateService().CheckAsync(CancellationToken.None);

        _store.DidNotReceive().Remove(InstalledThumbprint);
        _store.DidNotReceive().RemoveSuperseded(RenewedThumbprint);
    }

    [Fact]
    public async Task CheckAsync_OutsideTheWindow_DoesNothing()
    {
        SeedCompletedSetup();
        SeedOverlay();
        using var healthy = MakeCertificate(daysToExpiry: 200);
        StoreHolds(InstalledThumbprint, healthy);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.NotApplicable);
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(InstalledThumbprint);
    }

    [Fact]
    public async Task CheckAsync_ShortLivedTemplate_DoesNotRenewOnEveryCheck()
    {
        // A 14 day certificate against the 30 day default would always be
        // "inside the window", churning a fresh certificate every check.
        SeedCompletedSetup();
        SeedOverlay();
        using var shortLived = MakeCertificate(daysToExpiry: 9, lifetimeDays: 14);
        StoreHolds(InstalledThumbprint, shortLived);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.NotApplicable);
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
    }

    [Theory]
    // A two year certificate takes the configured window unchanged.
    [InlineData(30, 730, 30)]
    // A 14 day certificate is capped to a third of its life.
    [InlineData(30, 14, 4)]
    // The cap never falls below a day, however short the certificate.
    [InlineData(30, 1, 1)]
    // A configured window smaller than the cap wins.
    [InlineData(7, 730, 7)]
    public void EffectiveWindowDays_CapsAtAThirdOfTheCertificateLifetime(
        int configured, int lifetimeDays, int expected)
    {
        var notAfter = DateTime.UtcNow.AddDays(5);
        var notBefore = notAfter.AddDays(-lifetimeDays);

        HttpsCertificateAutoRenewalService
            .EffectiveWindowDays(configured, notBefore, notAfter)
            .Should().Be(expected);
    }

    [Fact]
    public async Task CheckAsync_Disabled_DoesNotEnroll()
    {
        _options.HttpsCertificateAutoRenewalEnabled = false;
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 3);
        StoreHolds(InstalledThumbprint, expiring);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.NotApplicable);
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
    }

    /// <summary>
    /// Issue #470. In monitor mode the loop is not even registered, but the instance is,
    /// because the settings API reads it: it must report itself off, and a direct call
    /// must still not enroll, with renewal switched on in the configuration.
    /// </summary>
    [Fact]
    public async Task CheckAsync_MonitorMode_ReportsOffAndDoesNotEnroll()
    {
        _options.HttpsCertificateAutoRenewalEnabled = true;
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 3);
        StoreHolds(InstalledThumbprint, expiring);

        var sut = CreateService(CertusInstanceMode.Monitor);
        await sut.CheckAsync(CancellationToken.None);

        sut.Enabled.Should().BeFalse();
        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.NotApplicable);
        sut.LastAttempt.Message.Should().Contain("monitor mode");
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
    }

    [Fact]
    public async Task CheckAsync_MockCa_DoesNotEnroll()
    {
        _options.UseMockCa = true;
        _options.CaConnectionString = null;
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 3);
        StoreHolds(InstalledThumbprint, expiring);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.NotApplicable);
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
    }

    [Fact]
    public async Task CheckAsync_NoRecordedThumbprint_DoesNothing()
    {
        SeedCompletedSetup();
        SeedOverlay(thumbprint: null);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.NotApplicable);
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
    }

    /// <summary>
    /// Issue #535. The overlay names a certificate this service did not install: in
    /// monitor mode the wizard offers the certificates already in the store, and the
    /// usual pick is one Windows autoenrolment renews. After a switch to full mode the
    /// renewal used to enrol a replacement from the first ACME template, serve it, and
    /// leave autoenrolment renewing a certificate nothing used. Inside the window is
    /// the case that matters, because that is where it used to act.
    /// </summary>
    [Fact]
    public async Task CheckAsync_CertificateTheServiceDidNotInstall_LeavesItToWhoeverIssuedIt()
    {
        SeedCompletedSetup();
        SeedOverlay(template: null);
        using var autoenrolled = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, autoenrolled, installedByService: false);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.NotApplicable);
        sut.LastAttempt.Message.Should().Contain(HttpsCertificateOwnership.FriendlyName,
            "the friendly name is what an administrator can check, and change, in certlm.msc");
        sut.LastAttempt.Message.Should().Contain("did not install");

        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
        _store.DidNotReceiveWithAnyArgs().Install(default!);
        _store.DidNotReceive().Remove(InstalledThumbprint);
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(InstalledThumbprint);
        ReadOverlay().HttpsCertificateTemplate.Should().BeNull(
            "nothing may be recorded against a certificate the service left alone");

        // A routine "nothing to do" pass, not a failure, so no administrator alert.
        await _notifier.DidNotReceiveWithAnyArgs()
            .SendServerCertificateAlertAsync(default!, default);
    }

    /// <summary>
    /// The friendly name is compared exactly, like the store's own sweep. A near miss
    /// is somebody else's certificate, and an expired one is no exception: the renewal
    /// replaces only what the service installed, however urgent.
    /// </summary>
    [Theory]
    [InlineData("ducks in a row https")]
    [InlineData("Ducks in a Row HTTPS ")]
    [InlineData("")]
    public async Task CheckAsync_FriendlyNameThatIsNotExactlyOurs_IsLeftAlone(string friendlyName)
    {
        SeedCompletedSetup();
        SeedOverlay();
        using var expired = MakeCertificate(daysToExpiry: -1);
        _store.Find(InstalledThumbprint).Returns(_ =>
        {
            var copy = X509CertificateLoader.LoadCertificate(expired.RawData);
            copy.FriendlyName = friendlyName;
            return copy;
        });

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.NotApplicable);
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
    }

    [Fact]
    public async Task CheckAsync_CertificateMissingFromTheStore_RenewsImmediately()
    {
        // The host is already on the self signed fallback; waiting for a
        // window that can never be measured would leave it there forever.
        // Who installed it cannot be asked of a certificate that is gone, and
        // nothing is left to take over, so the issue #535 rule does not stop
        // this: in full mode it is the only automatic way off the fallback.
        SeedCompletedSetup();
        SeedOverlay();
        _store.Find(InstalledThumbprint).Returns((X509Certificate2?)null);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Installed);
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(RenewedThumbprint);
    }

    [Fact]
    public async Task CheckAsync_RenewalAwaitingRestart_SkipsWithoutEnrollingAgain()
    {
        // The overlay names the renewed certificate, the process still serves
        // the old one. Renewing again would enroll a third certificate.
        SeedCompletedSetup();
        SeedOverlay(thumbprint: RenewedThumbprint);
        using var expiring = MakeCertificate(daysToExpiry: 3);
        StoreHolds(RenewedThumbprint, expiring);

        await CreateService().CheckAsync(CancellationToken.None);

        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
        _store.DidNotReceiveWithAnyArgs().RemoveSuperseded(default!);
    }

    [Fact]
    public async Task CheckAsync_RenewalApplied_SweepsTheSupersededCertificate()
    {
        // Served and recorded agree again, so the certificate a previous
        // renewal replaced is finally safe to remove.
        SeedCompletedSetup();
        SeedOverlay();
        using var healthy = MakeCertificate(daysToExpiry: 400);
        StoreHolds(InstalledThumbprint, healthy);
        _store.RemoveSuperseded(InstalledThumbprint).Returns(1);

        await CreateService().CheckAsync(CancellationToken.None);

        _store.Received(1).RemoveSuperseded(InstalledThumbprint);
    }

    [Fact]
    public async Task CheckAsync_Denied_KeepsTheCurrentCertificateAndAlerts()
    {
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(0, SubmitStatus.Denied, "Denied by Policy Module"));

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Denied);
        sut.LastAttempt.Message.Should().Contain("Enroll permission");
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(
            InstalledThumbprint, "a failed renewal must never disturb the served certificate");

        await _notifier.Received(1).SendServerCertificateAlertAsync(
            Arg.Is<ServerCertificateAlert>(a =>
                a.Outcome == "Denied" && a.DaysRemaining == 9),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CheckAsync_Denied_TheWebhookPayloadNamesNoAccount()
    {
        // Issue #485. The denial names the computer account and its domain, which is
        // the fix an administrator needs, so the alert mail keeps it: that goes to the
        // operator's own recipients. The webhook POSTs to whatever relay the operator
        // configured, so it carries the reason and the remedy without the account, the
        // line issue #336 drew for the ACME wire. Driven through the real enroller and
        // the real webhook notifier, so a change on either side of the alert record
        // that lets the account back onto the wire fails here.
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(
                0, SubmitStatus.Denied, "Denied by Policy Module", CaStatusCode.TemplateDenied));
        ServerCertificateAlert? raised = null;
        _notifier.SendServerCertificateAlertAsync(
                Arg.Do<ServerCertificateAlert>(a => raised = a), Arg.Any<CancellationToken>())
            .Returns(new AlertNotificationResult(true));

        await CreateService().CheckAsync(CancellationToken.None);

        var captured = new CapturedBody();
        var webhook = new WebhookAlertNotifier(
            Options.Create(new AlertOptions
            {
                Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" },
            }),
            new HttpClient(new CapturingHandler(captured)),
            NullLogger<WebhookAlertNotifier>.Instance);
        (await webhook.SendServerCertificateAlertAsync(raised!)).Success.Should().BeTrue();

        var account = TlsCertificateEnroller.DescribeServiceAccount();
        raised!.Detail.Should().Contain(account, "the alert mail is where the operator reads the fix");

        captured.Body.Should().NotContain(Environment.MachineName + "$")
            .And.NotContain(account);
        var payload = JsonSerializer.Deserialize<JsonElement>(captured.Body!);
        payload.GetProperty("event").GetString().Should().Be("server.certificate.renewal_failed");
        payload.GetProperty("detail").GetString().Should()
            .Contain("Denied by Policy Module", "the CA's own reason may go on the wire")
            .And.Contain("Enroll on the Security tab of the WebServer template",
                "the remedy is still the whole value of the alert");
    }

    [Fact]
    public async Task CheckAsync_Pending_KeepsTheCurrentCertificateAndAlerts()
    {
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(42, SubmitStatus.Pending, "Taken under submission"));

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Pending);
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(InstalledThumbprint);
        await _notifier.Received(1).SendServerCertificateAlertAsync(
            Arg.Is<ServerCertificateAlert>(a =>
                a.WireDetail != null && a.WireDetail == a.Detail && a.WireDetail.Contains("42")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CheckAsync_CaUnavailable_KeepsTheCurrentCertificateAndAlerts()
    {
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);

        // A CA that cannot answer a submission cannot answer a template listing
        // either, so refuse both. That order matters: the template resolution
        // runs first, and a list it could not read must leave the enrollment on
        // the recorded name rather than refuse it as unpublished, or a CA
        // outage would be reported as a configuration error (issue #194).
        _client.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns<IReadOnlyList<TemplateInfo>>(
                _ => throw new CaUnavailableException("The RPC server is unavailable"));
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns<SubmitResult>(_ => throw new CaUnavailableException("The RPC server is unavailable"));

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Failed);
        sut.LastAttempt.Message.Should().Contain("unavailable");
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(InstalledThumbprint);
        await _notifier.Received(1).SendServerCertificateAlertAsync(
            Arg.Is<ServerCertificateAlert>(a => a.WireDetail != null && a.WireDetail == a.Detail),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CheckAsync_CaDeniesAccess_KeepsTheCurrentCertificateAndAlerts()
    {
        // Issue #336. Its own arm rather than the worker loop's general catch, which
        // kept the service alive but recorded no attempt and sent no alert. This is
        // the one CA failure that does not clear on its own, so silence here means a
        // renewal blocked by a withdrawn permission goes unnoticed until the
        // certificate expires, which is the failure this service exists to prevent.
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);

        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns<SubmitResult>(_ => throw new CaAccessDeniedException(
                CaAccessDeniedException.EnrollPermissionMessage,
                new UnauthorizedAccessException("simulated E_ACCESSDENIED")));

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Failed);
        sut.LastAttempt.Message.Should().Contain("denied");
        sut.LastAttempt.Message.Should().Contain("Request Certificates",
            "the alert is read by an administrator and the remediation is its whole value");
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(InstalledThumbprint);

        // The message constant names the right and no account, so the webhook carries
        // it whole (issue #485); a null here would send the remediation nowhere.
        await _notifier.Received(1).SendServerCertificateAlertAsync(
            Arg.Is<ServerCertificateAlert>(a =>
                a.WireDetail != null && a.WireDetail == a.Detail
                && a.WireDetail.Contains("Request Certificates")),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The colon form key issue #553 is about, added at the top level of the overlay
    /// the way docs/hardening.md writes nested keys. Seeded beside a section that
    /// records no template, so the file itself loads, and the renewal falls back to
    /// the first enabled template, which it then records, setting the key twice.
    /// </summary>
    private void AddColonFormTemplateKey()
    {
        var path = _options.SettingsOverlayPath!;
        var root = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        root["Certus:HttpsCertificateTemplate"] = "WebServer";
        File.WriteAllText(path, root.ToJsonString());
    }

    /// <summary>
    /// Issue #553. The record of a renewed certificate is refused by an overlay that
    /// would then set a key twice (issue #550). The refusal used to land after the
    /// enrolment, so every check inside the window had the CA issue a certificate and
    /// the store install it, with nothing recording it and no alert, because the
    /// refusal fell to the loop's general catch. It is asked first now, and comes back
    /// as a failed pass with the alert.
    /// </summary>
    [Fact]
    public async Task CheckAsync_OverlayThatWouldRefuseTheRecord_RefusesBeforeEnrollingAndAlerts()
    {
        SeedCompletedSetup();
        SeedOverlay(template: null);
        AddColonFormTemplateKey();
        var before = File.ReadAllText(_options.SettingsOverlayPath!);
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
        _store.DidNotReceiveWithAnyArgs().Install(default!);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Failed);
        sut.LastAttempt.Message.Should().Contain("Certus:HttpsCertificateTemplate",
            "the alert is read by an administrator, and the key is what they have to fix");
        sut.LastAttempt.Message.Should().Contain("Nothing was enrolled");
        File.ReadAllText(_options.SettingsOverlayPath!).Should().Be(before);

        await _notifier.Received(1).SendServerCertificateAlertAsync(
            Arg.Is<ServerCertificateAlert>(a =>
                a.Outcome == "Failed" && a.DaysRemaining == 9 && a.WireDetail == a.Detail),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// Issue #553, the Renew button's half: the settings page calls the same renewal,
    /// and gets the refusal back as a failed outcome whose message it shows, with
    /// nothing enrolled.
    /// </summary>
    [Fact]
    public async Task RenewAsync_OverlayThatWouldRefuseTheRecord_RefusesBeforeEnrolling()
    {
        SeedCompletedSetup();
        SeedOverlay(template: null);
        AddColonFormTemplateKey();

        using var scope = _provider.CreateScope();
        var result = await scope.ServiceProvider.GetRequiredService<HttpsCertificateRenewalService>()
            .RenewAsync(currentHost: ExternalHost, CancellationToken.None);

        result.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Failed);
        result.Message.Should().Contain("Certus:HttpsCertificateTemplate");
        result.Message.Should().Contain(_options.SettingsOverlayPath!);
        result.PreviousThumbprint.Should().Be(InstalledThumbprint);
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
        _store.DidNotReceiveWithAnyArgs().Install(default!);
    }

    /// <summary>
    /// What the question asked before the enrolment cannot rule out: a hand edit
    /// landing while the renewal runs. The record is then refused after the store
    /// installed the replacement, and that refusal reached the loop's general catch,
    /// which records it with no alert. It alerts like the CA failures now.
    /// </summary>
    [Fact]
    public async Task CheckAsync_OverlayEditedWhileRenewing_RecordsTheFailureAndAlerts()
    {
        SeedCompletedSetup();
        SeedOverlay(template: null);
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);
        _store.Install(Arg.Any<X509Certificate2>()).Returns(_ =>
        {
            AddColonFormTemplateKey();
            return RenewedThumbprint;
        });

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Failed);
        sut.LastAttempt.Message.Should().Contain("Certus:HttpsCertificateTemplate");
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(InstalledThumbprint);
        await _notifier.Received(1).SendServerCertificateAlertAsync(
            Arg.Is<ServerCertificateAlert>(a =>
                a.Outcome == "Failed" && a.WireDetail != null && a.WireDetail == a.Detail),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The issue #194 defect end to end. An overlay recording the display name
    /// is legal (EnabledTemplatesPolicy documents the both forms contract and
    /// the ACME path issues against it happily), but ADCS matches
    /// CertificateTemplate: against the programmatic name alone, so every
    /// renewal denied with 0x80094800 while ACME kept issuing. The renewal now
    /// resolves before submitting, and records what it submitted, so the
    /// install converges on the name ADCS actually matches.
    /// </summary>
    [Fact]
    public async Task CheckAsync_OverlayRecordsTheDisplayName_SubmitsAndRecordsTheProgrammaticName()
    {
        SeedCompletedSetup(template: "Web Server");
        SeedOverlay(template: "Web Server");
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Installed);
        sut.LastAttempt.Template.Should().Be("WebServer");

        await _client.Received(1).SubmitCertificateRequestAsync(
            "WebServer", Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
        await _client.DidNotReceive().SubmitCertificateRequestAsync(
            "Web Server", Arg.Any<byte[]>(), Arg.Any<CancellationToken>());

        ReadOverlay().HttpsCertificateTemplate.Should().Be("WebServer",
            "the next renewal must not have to resolve the same display name again");
    }

    [Fact]
    public async Task CheckAsync_IssuedNamesMissTheExternalHost_DiscardsAndKeepsTheCurrentOne()
    {
        // The CA built the subject from AD instead of honoring the request.
        // Applying that certificate would break the external URL outright.
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);
        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns(_ => new CertificateResult(7, CertificateStatus.Issued, IssueWithOverriddenName()));

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.SanMismatch);
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(InstalledThumbprint);
        _store.Received(1).Remove(RenewedThumbprint);
        _store.DidNotReceive().Remove(InstalledThumbprint);
    }

    /// <summary>
    /// The settings page's Renew button removes the certificate it superseded, because
    /// it restarts straight away and nothing serves that certificate afterwards. That
    /// holds for one the service installed.
    /// </summary>
    [Fact]
    public void TryRemoveSuperseded_CertificateTheServiceInstalled_IsRemoved()
    {
        using var previous = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, previous);

        using var scope = _provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<HttpsCertificateRenewalService>()
            .TryRemoveSuperseded(InstalledThumbprint);

        _store.Received(1).Remove(InstalledThumbprint);
    }

    /// <summary>
    /// Issue #535. Pressing Renew on a certificate somebody else installed hands its
    /// renewal to the service, by Sean's decision of 2026-10-12, but the certificate
    /// stays theirs. Before this the button removed it from LocalMachine\My and
    /// deleted its private key with it.
    /// </summary>
    [Fact]
    public void TryRemoveSuperseded_CertificateSomebodyElseInstalled_StaysInTheStore()
    {
        using var previous = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, previous, installedByService: false);

        using var scope = _provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<HttpsCertificateRenewalService>()
            .TryRemoveSuperseded(InstalledThumbprint);

        _store.DidNotReceiveWithAnyArgs().Remove(default!);
    }

    [Fact]
    public void TryRemoveSuperseded_StoreCannotBeRead_LeavesTheCertificateAndDoesNotThrow()
    {
        // The overlay already names the new certificate by the time this runs, so a
        // store failure must not stop the restart that applies it.
        _store.Find(InstalledThumbprint).Returns<X509Certificate2?>(
            _ => throw new CryptographicException("The store could not be opened"));

        using var scope = _provider.CreateScope();
        var act = () => scope.ServiceProvider.GetRequiredService<HttpsCertificateRenewalService>()
            .TryRemoveSuperseded(InstalledThumbprint);

        act.Should().NotThrow();
        _store.DidNotReceiveWithAnyArgs().Remove(default!);
    }

    /// <summary>Sign the request with the CA's own idea of the subject name.</summary>
    private byte[] IssueWithOverriddenName()
    {
        var loaded = CertificateRequest.LoadSigningRequest(
            _submittedCsr!,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pkcs1);

        var toSign = new CertificateRequest(
            new X500DistinguishedName("CN=machine.home.local"),
            loaded.PublicKey,
            HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("machine.home.local");
        toSign.CertificateExtensions.Add(san.Build());

        using var caKey = RSA.Create(2048);
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using var cert = toSign.Create(
            new X500DistinguishedName("CN=Test Issuing CA"),
            X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(2),
            serial);
        return cert.Export(X509ContentType.Cert);
    }

    private sealed class CapturedBody
    {
        public string? Body { get; set; }
    }

    /// <summary>Records the body a webhook POSTs and answers 200.</summary>
    private sealed class CapturingHandler(CapturedBody captured) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            captured.Body = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        }
    }
}
