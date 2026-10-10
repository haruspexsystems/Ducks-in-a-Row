using System.Text.Json;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Core.Tests.Security;
using Microsoft.Extensions.Logging;
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
        return CreateSut(options, NullLogger<SetupService>.Instance);
    }

    private SetupService CreateSut(CertusOptions options, ILogger<SetupService> logger)
    {
        return new SetupService(
            _clientFactory,
            _caDiscovery,
            _probe,
            Options.Create(options),
            logger);
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
        result.FailureKind.Should().Be(ConnectivityFailureKind.Other);
    }

    [Fact]
    public async Task TestConnectivity_CaNotAccessible_SaysSoByKind()
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns(new CaInfo("Contoso-CA", "ca.contoso.com", null, false));

        var result = await _sut.TestConnectivityAsync(TestCa);

        result.FailureKind.Should().Be(ConnectivityFailureKind.NotAccessible);
    }

    [Fact]
    public async Task TestConnectivity_CaRefusesTheAccount_NamesTheRightRatherThanTheNetwork()
    {
        // Issue #440: the CA answered and refused, which no firewall or DNS
        // check would ever fix, so the wizard must not send the operator there.
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns<CaInfo>(_ => throw new CaAccessDeniedException(
                CaAccessDeniedException.ConnectPermissionMessage,
                new UnauthorizedAccessException()));

        var result = await _sut.TestConnectivityAsync(TestCa);

        result.Success.Should().BeFalse();
        result.FailureKind.Should().Be(ConnectivityFailureKind.AccessDenied);
        result.ErrorMessage.Should().Contain("Request Certificates");
    }

    [Fact]
    public async Task TestConnectivity_CaUnreachable_GivesTheRpcHint()
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns<CaInfo>(_ => throw new CaUnavailableException("unreachable"));

        var result = await _sut.TestConnectivityAsync(TestCa);

        result.Success.Should().BeFalse();
        result.FailureKind.Should().Be(ConnectivityFailureKind.Unavailable);
        result.ErrorMessage.Should().Contain("TCP 135");
    }

    [Theory]
    [InlineData(unchecked((int)0x80040154))]
    [InlineData(unchecked((int)0x80020003))]
    public async Task TestConnectivity_ComponentsMissing_NamesRsat(int hresult)
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns<CaInfo>(_ => throw new System.Runtime.InteropServices.COMException("missing", hresult));

        var result = await _sut.TestConnectivityAsync(TestCa);

        result.Success.Should().BeFalse();
        result.FailureKind.Should().Be(ConnectivityFailureKind.ComponentsMissing);
        result.ErrorMessage.Should().Contain("RSAT-ADCS-Mgmt");
    }

    [Fact]
    public async Task TestConnectivity_Passing_CarriesNoFailureKind()
    {
        var result = await _sut.TestConnectivityAsync(TestCa);

        result.Success.Should().BeTrue();
        result.FailureKind.Should().BeNull();
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

    // Built from a numeric code point, never written literally: a soft hyphen
    // pasted into source is invisible to the next reader of this file too.
    private const int SoftHyphen = 0x00AD;

    private static string With(int codePoint, string before, string after) =>
        before + char.ConvertFromUtf32(codePoint) + after;

    [Fact]
    public async Task GetSetupTemplates_DisplayNameCarriesASoftHyphen_IsStillListedWithAWarning()
    {
        // The template enrolls perfectly well. Only the ACME addressing form
        // issue #17 added is lost, so hiding it would take away a working
        // template (issue #235).
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", With(SoftHyphen, "Web", " Server"), "oid1",
                    new[] { SetupService.ServerAuthEku }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().ContainSingle();
        result.ExcludedCount.Should().Be(0);
        result.UnusableNameCount.Should().Be(0);

        var warning = result.Templates[0].DisplayNameWarning;
        warning.Should().NotBeNull();
        warning!.Kind.Should().Be("formatting");
        warning.CodePoint.Should().Be(SoftHyphen);
        warning.Position.Should().Be(3);
    }

    [Fact]
    public async Task GetSetupTemplates_CleanTemplate_CarriesNoNameWarning()
    {
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1", new[] { SetupService.ServerAuthEku }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates[0].DisplayNameWarning.Should().BeNull();
    }

    [Fact]
    public async Task GetSetupTemplates_ProgrammaticNameCarriesAControlCharacter_IsHiddenAndCounted()
    {
        // AdcsRequestAttributes refuses to build a request attribute string
        // from such a name, so nothing can be enrolled against this template on
        // any path, and completion would refuse to record it at the last click.
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1", new[] { SetupService.ServerAuthEku }),
                new(With(0x0A, "Web", "Server2"), "Web Server 2", "oid2",
                    new[] { SetupService.ServerAuthEku }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().ContainSingle();
        result.Templates[0].Name.Should().Be("WebServer");
        result.ExcludedCount.Should().Be(1);
        result.UnusableNameCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSetupTemplates_ProgrammaticNameFault_IsHiddenEvenWhenNoEkuCouldBeVerified()
    {
        // The unverified fallback exists because AD could not be read. The
        // programmatic name comes from the CA's own published list, so "could
        // not be checked" never applies to it and the fallback must not carry
        // an unenrollable template through.
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1"),
                new(With(SoftHyphen, "Web", "Server2"), "Web Server 2", "oid2"),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().ContainSingle();
        result.Templates.Should().OnlyContain(t => !t.EkuVerified);
        result.ExcludedCount.Should().Be(1);
        result.UnusableNameCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSetupTemplates_DisplayNameEqualsProgrammaticName_IsNotCountedTwice()
    {
        // The shape AdcsClient leaves behind when the AD lookup could not run.
        var name = With(SoftHyphen, "Web", "Server");
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo> { new(name, name, "oid1") });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().BeEmpty();
        result.UnusableNameCount.Should().Be(1);
        result.ExcludedCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSetupTemplates_DisplayNameWarning_CarriesNoNameText()
    {
        // The warning travels into a browser. Carrying the name would hand the
        // very characters the guard refuses to the page that reports them.
        var displayName = With(SoftHyphen, "Web", " Server");
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", displayName, "oid1", new[] { SetupService.ServerAuthEku }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        var warning = result.Templates[0].DisplayNameWarning!;
        warning.Kind.Should().NotContain(displayName);
        warning.ToString().Should().NotContain(displayName);
    }

    [Fact]
    public async Task GetSetupTemplates_OidCarriesASoftHyphen_IsListedUnchangedWithANote()
    {
        // Weaker than the display name case above, deliberately. Nothing routes
        // on the OID, so this template is not hidden, not counted, and not
        // limited in any way: the note exists only because the wizard prints
        // the OID on the row (issue #292).
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", With(SoftHyphen, "1.3.6", ".1"),
                    new[] { SetupService.ServerAuthEku }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates.Should().ContainSingle();
        result.ExcludedCount.Should().Be(0);
        result.UnusableNameCount.Should().Be(
            0, "a deceptive OID is not a reason to withhold a template that issues");
        result.Templates[0].DisplayNameWarning.Should().BeNull();

        var warning = result.Templates[0].OidWarning;
        warning.Should().NotBeNull();
        warning!.Kind.Should().Be("formatting");
        warning.CodePoint.Should().Be(SoftHyphen);
        warning.Position.Should().Be(5);
    }

    [Fact]
    public async Task GetSetupTemplates_CleanTemplate_CarriesNoOidWarning()
    {
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "1.3.6.1", new[] { SetupService.ServerAuthEku }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        result.Templates[0].OidWarning.Should().BeNull();
    }

    [Fact]
    public async Task GetSetupTemplates_OidWarning_CarriesNoOidText()
    {
        // Same reason as the display name warning: it travels into a browser,
        // and handing it the value would put the characters it reports on into
        // the page reporting them.
        var oid = With(SoftHyphen, "1.3.6.1.4.1.311", ".21.8.99999");
        _mockClient.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", oid, new[] { SetupService.ServerAuthEku }),
            });

        var result = await _sut.GetSetupTemplatesAsync(TestCa);

        var warning = result.Templates[0].OidWarning!;
        warning.ToString().Should().NotContain(oid);
        warning.ToString().Should().NotContain("21.8.99999");
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
    public void UpdateEabEnforcement_PersistsTheMode()
    {
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        _sut.UpdateEabEnforcement(EabEnforcementMode.Optional).Should().BeTrue();

        _sut.GetStatus().EabEnforcement.Should().Be("optional");
    }

    [Fact]
    public void UpdateEabEnforcement_BeforeSetupCompletes_IsRefused()
    {
        _sut.UpdateEabEnforcement(EabEnforcementMode.Required).Should().BeFalse();

        _sut.GetStatus().EabEnforcement.Should().BeNull();
    }

    [Fact]
    public void SaveWizardDraft_CarriesTheEabEnforcementModeForward()
    {
        // A stranded install recovery reopens the wizard and saves drafts.
        // The draft rewrites the whole status file, and the mode is not
        // wizard state, so the draft writer must carry it forward or the
        // subsequent completion carry-forward reads an already wiped value.
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));
        _sut.UpdateEabEnforcement(EabEnforcementMode.Required).Should().BeTrue();

        _sut.SaveWizardDraft(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        _sut.GetStatus().EabEnforcement.Should().Be("required");
    }

    [Fact]
    public void CompleteSetup_CarriesTheEabEnforcementModeForward()
    {
        // The EAB mode is not part of the wizard's configuration, so a re-run
        // of setup (the stranded install recovery path) writes a fresh status
        // record that must carry the mode forward, not reset it to off.
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));
        _sut.UpdateEabEnforcement(EabEnforcementMode.Required).Should().BeTrue();

        var status = _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        status.EabEnforcement.Should().Be("required");
        _sut.GetStatus().EabEnforcement.Should().Be("required");
    }

    [Fact]
    public void CompleteSetup_UntrustedPriorStatusFile_WarnsRatherThanResettingSilently()
    {
        // Issue #489: an untrusted ducks-setup.json reads as absent, so the EAB mode
        // and revocation scope reset to their defaults on a wizard re-run. That reset
        // must not be silent, the same invariant the unreadable arm protects. A box
        // compromised before the fix is exactly this: the status file is writable by a
        // standard user, so it is not trusted.
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));
        _sut.UpdateEabEnforcement(EabEnforcementMode.Required).Should().BeTrue();
        FileAcl.GrantEveryoneWrite(_sut.GetSetupStatusPath());

        var logger = new CapturingLogger();
        var sut = CreateSut(
            new CertusOptions { DatabasePath = Path.Combine(_tempDir, "certus.db"), SettingsOverlayPath = _overlayPath },
            logger);
        var status = sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        // The reset happened (the untrusted "required" could not be carried forward)...
        status.EabEnforcement.Should().BeNull();
        // ...but it was not silent.
        logger.Warnings.Should().ContainMatch("*not trusted*carried forward*");
    }

    [Fact]
    public void CompleteSetup_TrustedCarryForward_DoesNotWarn()
    {
        // The control: a trusted prior file carries forward with no warning, so the
        // warning above is the untrusted case and not noise on every re-run.
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));
        _sut.UpdateEabEnforcement(EabEnforcementMode.Required).Should().BeTrue();

        var logger = new CapturingLogger();
        var sut = CreateSut(
            new CertusOptions { DatabasePath = Path.Combine(_tempDir, "certus.db"), SettingsOverlayPath = _overlayPath },
            logger);
        var status = sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        status.EabEnforcement.Should().Be("required");
        logger.Warnings.Should().NotContainMatch("*not trusted*");
    }

    [Fact]
    public void UpdateRevocationScope_PersistsModeAndList()
    {
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        _sut.UpdateRevocationScope(
            RevocationScopeMode.Custom, ["WebServer", "AcmeClient"]).Should().BeTrue();

        var status = _sut.GetStatus();
        status.RevocationScope.Should().Be("custom");
        status.RevocableTemplates.Should().Equal("WebServer", "AcmeClient");
    }

    [Fact]
    public void UpdateRevocationScope_BeforeSetupCompletes_IsRefused()
    {
        _sut.UpdateRevocationScope(RevocationScopeMode.All, []).Should().BeFalse();

        _sut.GetStatus().RevocationScope.Should().BeNull();
    }

    [Fact]
    public void SaveWizardDraft_CarriesTheRevocationScopeForward()
    {
        // The same trap as the EAB mode above: the scope is not wizard
        // state, and a draft that rewrites the file must not reset it.
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));
        _sut.UpdateRevocationScope(RevocationScopeMode.Custom, ["WebServer"]).Should().BeTrue();

        _sut.SaveWizardDraft(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        var status = _sut.GetStatus();
        status.RevocationScope.Should().Be("custom");
        status.RevocableTemplates.Should().Equal("WebServer");
    }

    [Fact]
    public void CompleteSetup_CarriesTheRevocationScopeForward()
    {
        _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));
        _sut.UpdateRevocationScope(RevocationScopeMode.All, []).Should().BeTrue();

        var status = _sut.CompleteSetup(new SetupConfiguration(
            TestCa, new[] { "WebServer" }, "https://certus.contoso.com"));

        status.RevocationScope.Should().Be("all");
        _sut.GetStatus().RevocationScope.Should().Be("all");
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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SetHttpsCertificateThumbprint_BlankThumbprint_ThrowsAndWritesNothing(string? blank)
    {
        // A blank thumbprint would persist as an empty overlay value, which
        // every reader treats as no certificate configured, so the next start
        // would quietly serve the self signed certificate instead. Refusing it
        // must also leave the recorded certificate alone: a guard that threw
        // after writing would be worse than no guard at all.
        _sut.SetHttpsCertificateThumbprint("AA11BB22", "WebServerV2");

        var act = () => _sut.SetHttpsCertificateThumbprint(blank!, "WebServerV2");

        act.Should().Throw<ArgumentException>().WithParameterName("thumbprint");
        var overlay = SettingsOverlay.Load(_overlayPath);
        overlay.HttpsCertificateThumbprint.Should().Be("AA11BB22");
        overlay.HttpsCertificateTemplate.Should().Be("WebServerV2");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void SetHttpsCertificateThumbprint_BlankTemplate_KeepsTheRecordedOne(string blank)
    {
        // The empty string counterpart of the null case above. It matters on
        // its own: renewal reads the recorded template ?? the first enabled
        // one, so an empty string is not null, the fallback never runs, and
        // the install blocks on NoTemplate instead of renewing.
        _sut.SetHttpsCertificateThumbprint("AA11BB22", "WebServerV2");

        _sut.SetHttpsCertificateThumbprint("CC33DD44", blank);

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

    /// <summary>
    /// Template name resolution for the wizard's TLS enrollment (issue #175).
    /// The enrolled name is interpolated into the ADCS request attribute string,
    /// so the wizard's request body value must only ever select a template; the
    /// CA's own published name is what gets submitted.
    /// </summary>
    [Fact]
    public async Task ResolvePublishedTemplateName_ProgrammaticName_ReturnsIt()
    {
        var resolved = await _sut.ResolvePublishedTemplateNameAsync(TestCa, "WebServer");

        resolved.Should().Be("WebServer");
    }

    [Fact]
    public async Task ResolvePublishedTemplateName_DisplayName_ReturnsTheProgrammaticName()
    {
        // ADCS matches the CertificateTemplate attribute against the
        // programmatic name, so the display form must be translated, never
        // forwarded.
        var resolved = await _sut.ResolvePublishedTemplateNameAsync(TestCa, "Web Server");

        resolved.Should().Be("WebServer");
    }

    [Fact]
    public async Task ResolvePublishedTemplateName_DiffersOnlyByCase_ReturnsTheCanonicalCasing()
    {
        var resolved = await _sut.ResolvePublishedTemplateNameAsync(TestCa, "wEbSeRvEr");

        resolved.Should().Be("WebServer");
    }

    [Fact]
    public async Task ResolvePublishedTemplateName_UnpublishedName_ReturnsNull()
    {
        var resolved = await _sut.ResolvePublishedTemplateNameAsync(TestCa, "NotOnThisCa");

        resolved.Should().BeNull();
    }

    [Fact]
    public async Task ResolvePublishedTemplateName_CertiGhostPayload_ReturnsNull()
    {
        // The attribute smuggling payload never matches a published template, so
        // it is refused here, one step before the AdcsRequestAttributes guard
        // that would also catch it.
        var resolved = await _sut.ResolvePublishedTemplateNameAsync(
            TestCa, "WebServer\ncdc:evil.attacker.example\nrmd:DC01.contoso.com");

        resolved.Should().BeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ResolvePublishedTemplateName_MissingName_ReturnsNull(string? templateName)
    {
        var resolved = await _sut.ResolvePublishedTemplateNameAsync(TestCa, templateName!);

        resolved.Should().BeNull();
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); }
        catch { /* cleanup best effort */ }
    }

    /// <summary>Records the rendered text of every warning, so a test can assert one fired.</summary>
    private sealed class CapturingLogger : ILogger<SetupService>
    {
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
                Warnings.Add(formatter(state, exception));
        }
    }
}
