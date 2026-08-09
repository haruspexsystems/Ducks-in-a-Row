using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Setup;
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

    private HttpsCertificateAutoRenewalService CreateService() =>
        new(_provider.GetRequiredService<IServiceScopeFactory>(),
            _store,
            new ServerCertificateIdentity(
                _store, Options.Create(_options), NullLogger<ServerCertificateIdentity>.Instance),
            Options.Create(_options),
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

    private void StoreHolds(string thumbprint, X509Certificate2 certificate) =>
        _store.Find(thumbprint).Returns(_ => X509CertificateLoader.LoadCertificate(certificate.RawData));

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

    [Fact]
    public async Task CheckAsync_CertificateMissingFromTheStore_RenewsImmediately()
    {
        // The host is already on the self signed fallback; waiting for a
        // window that can never be measured would leave it there forever.
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
            Arg.Any<ServerCertificateAlert>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CheckAsync_CaUnavailable_KeepsTheCurrentCertificateAndAlerts()
    {
        SeedCompletedSetup();
        SeedOverlay();
        using var expiring = MakeCertificate(daysToExpiry: 10);
        StoreHolds(InstalledThumbprint, expiring);
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns<SubmitResult>(_ => throw new CaUnavailableException("The RPC server is unavailable"));

        var sut = CreateService();
        await sut.CheckAsync(CancellationToken.None);

        sut.LastAttempt!.Outcome.Should().Be(HttpsCertificateRenewalOutcome.Failed);
        sut.LastAttempt.Message.Should().Contain("unavailable");
        ReadOverlay().HttpsCertificateThumbprint.Should().Be(InstalledThumbprint);
        await _notifier.Received(1).SendServerCertificateAlertAsync(
            Arg.Any<ServerCertificateAlert>(), Arg.Any<CancellationToken>());
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
}
