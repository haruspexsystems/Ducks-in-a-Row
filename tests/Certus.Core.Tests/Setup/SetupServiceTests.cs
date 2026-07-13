using System.Text.Json;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Certus.Core.Tests.Setup;

public class SetupServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _overlayPath;
    private readonly IAdcsClient _mockClient;
    private readonly IAdcsClientFactory _clientFactory;
    private readonly ICaDiscoveryService _caDiscovery;
    private readonly IExternalUrlProbe _probe;
    private readonly SetupService _sut;

    public SetupServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _overlayPath = Path.Combine(_tempDir, "settings.json");

        _mockClient = Substitute.For<IAdcsClient>();
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns(new CaInfo("Contoso-CA", "ca.contoso.com", "Contoso Root CA", true));
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "1.3.6.1.4.1.311.21.8.1"),
                new("CodeSigning", "Code Signing", "1.3.6.1.4.1.311.21.8.2"),
            });

        _clientFactory = Substitute.For<IAdcsClientFactory>();
        _clientFactory.Create(Arg.Any<string>()).Returns(_mockClient);

        _caDiscovery = Substitute.For<ICaDiscoveryService>();
        _caDiscovery.DiscoverAsync(Arg.Any<CancellationToken>())
            .Returns(new List<DiscoveredCa>
            {
                new("ca.contoso.com", "Contoso-CA", "Contoso Root CA", "ca.contoso.com\\Contoso-CA"),
            });

        _probe = Substitute.For<IExternalUrlProbe>();
        _probe.ProbeAsync(Arg.Any<Uri>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(call => new ExternalUrlProbeResult(
                Attempted: true,
                Reachable: true,
                DialedAuthority: $"{call.Arg<Uri>().Host}:{call.Arg<Uri>().Port}",
                HttpStatusCode: 200));

        _sut = CreateSut(new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "certus.db"),
            SettingsOverlayPath = _overlayPath,
        });
    }

    private SetupService CreateSut(CertusOptions options)
    {
        return new SetupService(
            _clientFactory,
            _caDiscovery,
            _probe,
            Options.Create(options),
            NullLogger<SetupService>.Instance);
    }

    private const string TestCa = "ca.contoso.com\\Contoso-CA";

    [Fact]
    public void GetStatus_NoFile_ReturnsNotCompleted()
    {
        var status = _sut.GetStatus();

        status.SetupCompleted.Should().BeFalse();
        status.CompletedAt.Should().BeNull();
    }

    [Fact]
    public async Task DiscoverCas_ReturnsDiscoveredCas()
    {
        var cas = await _sut.DiscoverCasAsync();

        cas.Should().ContainSingle();
        cas[0].ConnectionString.Should().Be(TestCa);
    }

    [Fact]
    public async Task TestConnectivity_CaAccessible_ReturnsSuccess()
    {
        var result = await _sut.TestConnectivityAsync(TestCa);

        result.Success.Should().BeTrue();
        result.CaName.Should().Be("Contoso-CA");
        result.CaDnsName.Should().Be("ca.contoso.com");
        result.CaDisplayName.Should().Be("Contoso Root CA");
    }

    [Fact]
    public async Task TestConnectivity_ProbesTheCandidateString_NotTheDiClient()
    {
        await _sut.TestConnectivityAsync("other.contoso.com\\Other-CA");

        _clientFactory.Received(1).Create("other.contoso.com\\Other-CA");
    }

    [Fact]
    public async Task TestConnectivity_CaNotAccessible_ReturnsFailure()
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns(new CaInfo("Contoso-CA", "ca.contoso.com", null, false));

        var result = await _sut.TestConnectivityAsync(TestCa);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task TestConnectivity_CaThrows_ReturnsFailure()
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns<CaInfo>(_ => throw new InvalidOperationException("DCOM connection refused"));

        var result = await _sut.TestConnectivityAsync(TestCa);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("DCOM connection refused");
    }

    [Fact]
    public async Task GetSetupTemplates_EkuVerified_FiltersToServerAuthOnly()
    {
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1", new[] { SetupService.ServerAuthEku }),
                new("CodeSigning", "Code Signing", "oid2", new[] { "1.3.6.1.5.5.7.3.3" }),
                new("Smartcard", "Smartcard Logon", "oid3", Array.Empty<string>()),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().ContainSingle();
        result.Templates[0].Name.Should().Be("WebServer");
        result.Templates[0].HasServerAuthEku.Should().BeTrue();
        result.Templates[0].EkuVerified.Should().BeTrue();
        result.ExcludedCount.Should().Be(2);
    }

    [Fact]
    public async Task GetSetupTemplates_ServerAuthWithClientAuth_IsNotExcluded()
    {
        // A template carrying both Server Authentication and Client Authentication
        // (the common mutual TLS shape) must remain selectable.
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServerMtls", "Web Server mTLS", "oid1",
                    new[] { SetupService.ServerAuthEku, "1.3.6.1.5.5.7.3.2" }),
                new("ClientOnly", "Client Auth", "oid2", new[] { "1.3.6.1.5.5.7.3.2" }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().ContainSingle();
        result.Templates[0].Name.Should().Be("WebServerMtls");
        result.Templates[0].HasServerAuthEku.Should().BeTrue();
        result.ExcludedCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSetupTemplates_SubjectBuiltFromAd_IsHiddenAndCounted()
    {
        // Domain Controller, Machine, and Kerberos Authentication carry the
        // server authentication EKU but build their subject from AD, so ACME
        // clients could never get the names they ask for. Those are hidden.
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1",
                    new[] { SetupService.ServerAuthEku },
                    new TemplateAcmeViability(false, false, SubjectSuppliedInRequest: true, "RSA", 2048)),
                new("DomainController", "Domain Controller", "oid2",
                    new[] { SetupService.ServerAuthEku, "1.3.6.1.5.5.7.3.2" },
                    new TemplateAcmeViability(false, false, SubjectSuppliedInRequest: false, "RSA", 2048)),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().ContainSingle();
        result.Templates[0].Name.Should().Be("WebServer");
        result.ExcludedCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSetupTemplates_SubjectFlagUnreadable_IsKept()
    {
        // A null subject flag means "could not verify", and unverified never
        // hides a template; only a definite "built from AD" does.
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1",
                    new[] { SetupService.ServerAuthEku },
                    new TemplateAcmeViability(false, false, SubjectSuppliedInRequest: null, "RSA", 2048)),
                new("NoViabilityRow", "No Viability Row", "oid2",
                    new[] { SetupService.ServerAuthEku }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().HaveCount(2);
        result.ExcludedCount.Should().Be(0);
    }

    [Fact]
    public async Task GetSetupTemplates_AllUnverified_ReturnsAllFlagged()
    {
        // The constructor seeds templates with null EKU (e.g. AD was unreachable).
        // None can be verified, so the wizard receives all of them flagged unverified.
        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().HaveCount(2);
        result.Templates.Should().OnlyContain(t => !t.EkuVerified);
        result.Templates.Should().OnlyContain(t => !t.HasServerAuthEku);
        result.ExcludedCount.Should().Be(0);
    }

    [Fact]
    public void ValidateExternalUrl_ValidHttps_ReturnsValid()
    {
        var result = _sut.ValidateExternalUrl("https://certus.contoso.com");

        result.Valid.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();
    }

    [Fact]
    public void ValidateExternalUrl_Http_ReturnsValidWithWarning()
    {
        var result = _sut.ValidateExternalUrl("http://certus.contoso.com");

        result.Valid.Should().BeTrue();
        result.Warnings.Should().NotBeNull();
        result.Warnings.Should().Contain(w => w.Contains("not recommended"));
    }

    [Fact]
    public void ValidateExternalUrl_Localhost_ReturnsValidWithWarning()
    {
        var result = _sut.ValidateExternalUrl("https://localhost:5000");

        result.Valid.Should().BeTrue();
        result.Warnings.Should().NotBeNull();
        result.Warnings.Should().Contain(w => w.Contains("localhost"));
    }

    [Fact]
    public void ValidateExternalUrl_InvalidFormat_ReturnsInvalid()
    {
        var result = _sut.ValidateExternalUrl("not-a-url");

        result.Valid.Should().BeFalse();
        result.ErrorMessage.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateExternalUrl_Empty_ReturnsInvalid()
    {
        var result = _sut.ValidateExternalUrl("");

        result.Valid.Should().BeFalse();
    }

    [Fact]
    public void ValidateExternalUrl_PortlessUrl_WarnsAboutTheDefaultPort()
    {
        // The issue #89 trap: https://<host> sends clients to port 443, which
        // the service does not listen on unless a proxy forwards it.
        var result = _sut.ValidateExternalUrl("https://certus.contoso.com");

        result.Valid.Should().BeTrue();
        result.Warnings.Should().NotBeNull();
        result.Warnings.Should().Contain(w => w.Contains("certus.contoso.com:443"));
    }

    [Fact]
    public void ValidateExternalUrl_ExplicitPort_DoesNotWarnAboutThePort()
    {
        var result = _sut.ValidateExternalUrl("https://certus.contoso.com:5001");

        result.Valid.Should().BeTrue();
        (result.Warnings ?? Array.Empty<string>())
            .Should().NotContain(w => w.Contains("No port"));
    }

    [Fact]
    public async Task ValidateExternalUrlAsync_Reachable_AttachesTheProbeOutcome()
    {
        var result = await _sut.ValidateExternalUrlAsync("https://certus.contoso.com:5001", "WebServer");

        result.Valid.Should().BeTrue();
        result.Probe.Should().NotBeNull();
        result.Probe!.Attempted.Should().BeTrue();
        result.Probe.Reachable.Should().BeTrue();
        result.Probe.DialedAuthority.Should().Be("certus.contoso.com:5001");
    }

    [Fact]
    public async Task ValidateExternalUrlAsync_PortlessUrlNothingOn443_WarnsAndNamesTheDialedPort()
    {
        // The issue #89 shape: nothing listens on the default port. The URL
        // stays valid; the probe outcome drives the wizard's warn and confirm
        // path instead of a hard block.
        _probe.ProbeAsync(Arg.Any<Uri>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(new ExternalUrlProbeResult(
                Attempted: true,
                Reachable: false,
                DialedAuthority: "certus.contoso.com:443",
                FailureKind: ExternalUrlProbeFailure.ConnectionRefused,
                FailureDetail: "Connection refused at certus.contoso.com:443."));

        var result = await _sut.ValidateExternalUrlAsync("https://certus.contoso.com", "WebServer");

        result.Valid.Should().BeTrue();
        result.Probe!.Reachable.Should().BeFalse();
        result.Probe.FailureKind.Should().Be(ExternalUrlProbeFailure.ConnectionRefused);
        result.Probe.DialedAuthority.Should().Be("certus.contoso.com:443");
        result.Warnings.Should().Contain(w => w.Contains("certus.contoso.com:443"));
    }

    [Fact]
    public async Task ValidateExternalUrlAsync_UnresolvableHost_SurfacesTheDnsFailure()
    {
        _probe.ProbeAsync(Arg.Any<Uri>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(new ExternalUrlProbeResult(
                Attempted: true,
                Reachable: false,
                DialedAuthority: "no-such-host.contoso.com:5001",
                FailureKind: ExternalUrlProbeFailure.DnsFailure,
                FailureDetail: "The host name no-such-host.contoso.com could not be resolved from this server."));

        var result = await _sut.ValidateExternalUrlAsync("https://no-such-host.contoso.com:5001", "WebServer");

        result.Valid.Should().BeTrue();
        result.Probe!.FailureKind.Should().Be(ExternalUrlProbeFailure.DnsFailure);
    }

    [Fact]
    public async Task ValidateExternalUrlAsync_CertificateWarning_StaysOnTheProbeOnly()
    {
        // The wizard renders the certificate warning as its own panel (with
        // the enroll offer); folding it into the generic warnings list would
        // show it twice.
        _probe.ProbeAsync(Arg.Any<Uri>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(new ExternalUrlProbeResult(
                Attempted: true,
                Reachable: true,
                DialedAuthority: "certus.contoso.com:5001",
                HttpStatusCode: 200,
                CertificateWarning: "The TLS certificate does not validate from here."));

        var result = await _sut.ValidateExternalUrlAsync("https://certus.contoso.com:5001", "WebServer");

        result.Probe!.Reachable.Should().BeTrue();
        result.Probe.CertificateWarning.Should().Contain("certificate");
        (result.Warnings ?? Array.Empty<string>())
            .Should().NotContain(w => w.Contains("certificate"));
    }

    [Fact]
    public async Task ValidateExternalUrlAsync_MockMode_SkipsTheProbe()
    {
        // The demo walkthrough must never dial out or be slowed by a probe.
        var sut = CreateSut(new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "certus.db"),
            SettingsOverlayPath = _overlayPath,
            UseMockCa = true,
        });

        var result = await sut.ValidateExternalUrlAsync("https://certus.contoso.com", "WebServer");

        result.Valid.Should().BeTrue();
        result.Probe.Should().NotBeNull();
        result.Probe!.Attempted.Should().BeFalse();
        await _probe.DidNotReceiveWithAnyArgs().ProbeAsync(default!, default, default);
    }

    [Fact]
    public async Task ValidateExternalUrlAsync_InvalidFormat_DoesNotProbe()
    {
        var result = await _sut.ValidateExternalUrlAsync("not-a-url", "WebServer");

        result.Valid.Should().BeFalse();
        await _probe.DidNotReceiveWithAnyArgs().ProbeAsync(default!, default, default);
    }

    [Fact]
    public void CompleteSetup_PersistsStatusToFile()
    {
        var config = new SetupConfiguration(
            TestCa,
            new[] { "WebServer", "CodeSigning" },
            "https://certus.contoso.com");

        var status = _sut.CompleteSetup(config);

        status.SetupCompleted.Should().BeTrue();
        status.CompletedAt.Should().NotBeNull();
        status.CaConnectionString.Should().Be(TestCa);
        status.EnabledTemplates.Should().BeEquivalentTo(new[] { "WebServer", "CodeSigning" });
        status.ExternalUrl.Should().Be("https://certus.contoso.com");

        // Verify persisted to disk
        var loaded = _sut.GetStatus();
        loaded.SetupCompleted.Should().BeTrue();
        loaded.CaConnectionString.Should().Be(TestCa);
    }

    [Fact]
    public void CompleteSetup_WritesTheSettingsOverlay()
    {
        var config = new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com");

        _sut.CompleteSetup(config);

        File.Exists(_overlayPath).Should().BeTrue();
        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.GetProperty("CaConnectionString").GetString().Should().Be(TestCa);
        section.GetProperty("ExternalUrl").GetString().Should().Be("https://certus.contoso.com");
    }

    [Fact]
    public void CompleteSetup_InMockMode_OmitsTheCaConnectionString()
    {
        // UseMockCa and a CA connection string are mutually exclusive at
        // startup; a mock walkthrough must not write a string that would stop
        // the next start.
        var sut = CreateSut(new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "certus.db"),
            SettingsOverlayPath = _overlayPath,
            UseMockCa = true,
        });

        sut.CompleteSetup(new SetupConfiguration(
            "mockca.example.com\\Mock CA", new[] { "WebServer" }, "https://certus.contoso.com"));

        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.TryGetProperty("CaConnectionString", out _).Should().BeFalse();
        section.GetProperty("ExternalUrl").GetString().Should().Be("https://certus.contoso.com");
    }

    [Fact]
    public void EffectiveCompleteness_WizardDoneButNoCa_ReportsIncomplete()
    {
        // The stranded install shape: the wizard file says complete (written
        // by a version whose wizard configured nothing) while the service has
        // no CA in effect. It must re-enter the wizard.
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        _sut.IsSetupEffectivelyComplete().Should().BeFalse();
        _sut.CaMode.Should().Be("unconfigured");
    }

    [Fact]
    public void EffectiveCompleteness_WizardDoneAndCaConfigured_ReportsComplete()
    {
        var sut = CreateSut(new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "certus.db"),
            SettingsOverlayPath = _overlayPath,
            CaConnectionString = TestCa,
        });

        sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        sut.IsSetupEffectivelyComplete().Should().BeTrue();
        sut.CaMode.Should().Be("real");
    }

    [Fact]
    public void UpdateExternalUrl_PreservesOverlayCaConnectionString()
    {
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        _sut.UpdateExternalUrl("https://new.contoso.com:5001");

        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.GetProperty("CaConnectionString").GetString().Should().Be(TestCa);
        section.GetProperty("ExternalUrl").GetString().Should().Be("https://new.contoso.com:5001");
    }

    [Fact]
    public void UpdateExternalUrl_MockMode_KeepsCaConnectionStringAbsent()
    {
        // The deliberate absence of the connection string in a mock install
        // must survive the round trip, or the next start refuses to run
        // (UseMockCa and a connection string are mutually exclusive).
        var sut = CreateSut(new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "certus.db"),
            SettingsOverlayPath = _overlayPath,
            UseMockCa = true,
        });
        sut.CompleteSetup(new SetupConfiguration(
            string.Empty, new[] { "WebServer" }, "https://certus.contoso.com"));

        sut.UpdateExternalUrl("https://new.contoso.com:5001");

        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.TryGetProperty("CaConnectionString", out _).Should().BeFalse();
        section.GetProperty("ExternalUrl").GetString().Should().Be("https://new.contoso.com:5001");
    }

    [Fact]
    public void UpdateExternalUrl_WhenOverlayMissing_WritesUrlOnly()
    {
        _sut.UpdateExternalUrl("https://new.contoso.com:5001");

        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.TryGetProperty("CaConnectionString", out _).Should().BeFalse();
        section.GetProperty("ExternalUrl").GetString().Should().Be("https://new.contoso.com:5001");
    }

    [Fact]
    public void UpdateExternalUrl_DoesNotCopyOptionsCaIntoOverlay()
    {
        // The options value can come from an environment variable; writing it
        // into the overlay would freeze a higher precedence value into the
        // file and corrupt the layering.
        var sut = CreateSut(new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "certus.db"),
            SettingsOverlayPath = _overlayPath,
            CaConnectionString = TestCa,
        });

        sut.UpdateExternalUrl("https://new.contoso.com:5001");

        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.TryGetProperty("CaConnectionString", out _).Should().BeFalse();
    }

    [Fact]
    public void UpdateExternalUrl_WhenStatusUnreadable_LeavesTheStatusFileAlone()
    {
        // SetupStatus.Load swallows read errors and returns a fresh record;
        // rewriting the file from that would wipe the wizard state and drop
        // the enabled template restriction. The guard must leave it be.
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));
        var statusPath = _sut.GetSetupStatusPath();
        File.WriteAllText(statusPath, "{ torn write");

        _sut.UpdateExternalUrl("https://new.contoso.com:5001");

        File.ReadAllText(statusPath).Should().Be("{ torn write",
            "an unreadable status file must not be replaced with a fresh record");
        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        overlay.RootElement.GetProperty("Certus").GetProperty("ExternalUrl").GetString()
            .Should().Be("https://new.contoso.com:5001", "the overlay update still happens");
    }

    [Fact]
    public void UpdateExternalUrl_RefreshesStatusFile()
    {
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer", "CodeSigning" }, "https://certus.contoso.com"));

        _sut.UpdateExternalUrl("https://new.contoso.com:5001");

        var status = _sut.GetStatus();
        status.ExternalUrl.Should().Be("https://new.contoso.com:5001",
            "the wizard prefill must show the current URL");
        status.SetupCompleted.Should().BeTrue();
        status.CaConnectionString.Should().Be(TestCa);
        status.EnabledTemplates.Should().BeEquivalentTo(new[] { "WebServer", "CodeSigning" },
            "only the URL changes; the rest of the wizard state stays intact");
    }

    [Fact]
    public void CompleteSetup_PreservesTheHttpsCertificateThumbprint()
    {
        // The wizard's TLS provisioning writes the thumbprint before setup
        // completes. A CompleteSetup that rewrote the overlay from scratch
        // would drop it, and the completion restart would silently fall back
        // to the self signed certificate.
        _sut.SetHttpsCertificateThumbprint("ABCDEF0123456789");

        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.GetProperty("HttpsCertificateThumbprint").GetString().Should().Be("ABCDEF0123456789");
        section.GetProperty("CaConnectionString").GetString().Should().Be(TestCa);
        section.GetProperty("ExternalUrl").GetString().Should().Be("https://certus.contoso.com");
    }

    [Fact]
    public void SetHttpsCertificateThumbprint_PreservesTheRestOfTheOverlay()
    {
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        _sut.SetHttpsCertificateThumbprint("ABCDEF0123456789");

        using var overlay = JsonDocument.Parse(File.ReadAllText(_overlayPath));
        var section = overlay.RootElement.GetProperty("Certus");
        section.GetProperty("CaConnectionString").GetString().Should().Be(TestCa);
        section.GetProperty("ExternalUrl").GetString().Should().Be("https://certus.contoso.com");
        section.GetProperty("HttpsCertificateThumbprint").GetString().Should().Be("ABCDEF0123456789");
    }

    [Fact]
    public void SaveWizardDraft_PersistsSelectionsWithoutCompleting()
    {
        // The draft prefills a wizard reopened after the TLS certificate
        // restart (possibly at a different origin). It must never mark setup
        // complete: only CompleteSetup does that.
        _sut.SaveWizardDraft(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com:5001"));

        var status = _sut.GetStatus();
        status.SetupCompleted.Should().BeFalse();
        status.CaConnectionString.Should().Be(TestCa);
        status.EnabledTemplates.Should().BeEquivalentTo(new[] { "WebServer" });
        status.ExternalUrl.Should().Be("https://certus.contoso.com:5001");
        _sut.IsSetupEffectivelyComplete().Should().BeFalse();
    }

    [Fact]
    public void SaveWizardDraft_RecordsTheWizardStep()
    {
        _sut.SaveWizardDraft(
            new SetupConfiguration(TestCa, new[] { "WebServer" }, "https://certus.contoso.com:5001"),
            wizardStep: "url");

        _sut.GetStatus().WizardStep.Should().Be("url");
    }

    [Fact]
    public void CompleteSetup_ClearsTheWizardStep()
    {
        // Completion writes a fresh status; a lingering resume point would
        // make a reopened wizard (stranded install recovery) jump into the
        // middle of a flow that already finished once.
        _sut.SaveWizardDraft(
            new SetupConfiguration(TestCa, new[] { "WebServer" }, "https://certus.contoso.com:5001"),
            wizardStep: "review");

        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com:5001"));

        _sut.GetStatus().WizardStep.Should().BeNull();
    }

    [Fact]
    public void SetHttpsCertificateThumbprint_RecordsTheTemplate()
    {
        _sut.SetHttpsCertificateThumbprint("AA11BB22", "WebServerV2");

        var overlay = SettingsOverlay.Load(_overlayPath);
        overlay.HttpsCertificateThumbprint.Should().Be("AA11BB22");
        overlay.HttpsCertificateTemplate.Should().Be("WebServerV2");
    }

    [Fact]
    public void SetHttpsCertificateThumbprint_NullTemplate_KeepsTheRecordedOne()
    {
        // A caller that only knows the thumbprint must never erase which
        // template the certificate came from; renewal depends on it.
        _sut.SetHttpsCertificateThumbprint("AA11BB22", "WebServerV2");

        _sut.SetHttpsCertificateThumbprint("CC33DD44");

        var overlay = SettingsOverlay.Load(_overlayPath);
        overlay.HttpsCertificateThumbprint.Should().Be("CC33DD44");
        overlay.HttpsCertificateTemplate.Should().Be("WebServerV2");
    }

    [Fact]
    public async Task GetSetupTemplates_CarriesTheViabilitySignals()
    {
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1",
                    new[] { SetupService.ServerAuthEku },
                    new TemplateAcmeViability(
                        RequiresManagerApproval: true,
                        RequiresRaSignatures: false,
                        SubjectSuppliedInRequest: true,
                        KeyAlgorithm: "RSA",
                        MinimalKeySize: 2048)),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().ContainSingle();
        result.Templates[0].Viability.Should().NotBeNull();
        result.Templates[0].Viability!.RequiresManagerApproval.Should().BeTrue();
        result.Templates[0].Viability!.KeyAlgorithm.Should().Be("RSA");
    }

    [Fact]
    public void EffectiveCompleteness_WizardDoneInMockMode_ReportsComplete()
    {
        var sut = CreateSut(new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "certus.db"),
            SettingsOverlayPath = _overlayPath,
            UseMockCa = true,
        });

        sut.CompleteSetup(new SetupConfiguration(
            string.Empty, new[] { "WebServer" }, "https://certus.contoso.com"));

        sut.IsSetupEffectivelyComplete().Should().BeTrue();
        sut.CaMode.Should().Be("mock");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); }
        catch { /* cleanup best effort */ }
    }
}
