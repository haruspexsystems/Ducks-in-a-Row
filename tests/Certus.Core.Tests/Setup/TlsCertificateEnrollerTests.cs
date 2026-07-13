using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Certus.Core.Tests.Setup;

/// <summary>
/// The one click TLS certificate enrollment: CSR shape, disposition handling
/// with actionable failure messages, store installation, and the SAN
/// coverage the wizard bases its restart and mismatch decisions on.
/// </summary>
public class TlsCertificateEnrollerTests
{
    private const string TestCa = "ca.home.local\\Home-CA";
    private const string ExternalHost = "certus.home.local";
    private const string ExternalUrl = "https://certus.home.local:5001";

    private readonly IAdcsClient _client = Substitute.For<IAdcsClient>();
    private readonly IAdcsClientFactory _factory = Substitute.For<IAdcsClientFactory>();
    private readonly IHttpsCertificateStore _store = Substitute.For<IHttpsCertificateStore>();
    private readonly TlsCertificateEnroller _sut;

    private byte[]? _submittedCsr;
    private X509Certificate2? _installedCertificate;

    public TlsCertificateEnrollerTests()
    {
        _factory.Create(Arg.Any<string>()).Returns(_client);
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(),
                Arg.Do<byte[]>(csr => _submittedCsr = csr),
                Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(7, SubmitStatus.Issued));
        _store.Install(Arg.Do<X509Certificate2>(c => _installedCertificate = new X509Certificate2(c)))
            .Returns("AA11BB22");

        _sut = new TlsCertificateEnroller(
            _factory, _store, NullLogger<TlsCertificateEnroller>.Instance);
    }

    /// <summary>
    /// Sign the captured CSR like an ADCS CA honoring "supply in the
    /// request" would: same public key, requested subject and extensions.
    /// With <paramref name="overrideName"/> it mimics an AD built subject
    /// template instead: same key, but the CA's own idea of the name.
    /// </summary>
    private byte[] IssueFromSubmittedCsr(string? overrideName = null)
    {
        var loaded = CertificateRequest.LoadSigningRequest(
            _submittedCsr!,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pkcs1);

        var toSign = loaded;
        if (overrideName is not null)
        {
            toSign = new CertificateRequest(
                new X500DistinguishedName($"CN={overrideName}"),
                loaded.PublicKey,
                HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(overrideName);
            toSign.CertificateExtensions.Add(san.Build());
        }

        using var caKey = RSA.Create(2048);
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using var cert = toSign.Create(
            new X500DistinguishedName("CN=Test Issuing CA"),
            X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1),
            serial);
        return cert.Export(X509ContentType.Cert);
    }

    private void RespondWithIssuedCertificate(string? overrideName = null)
    {
        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns(_ => new CertificateResult(
                7, CertificateStatus.Issued, IssueFromSubmittedCsr(overrideName)));
    }

    [Fact]
    public async Task EnrollAsync_Issued_InstallsWithThePrivateKeyAndReportsCoverage()
    {
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, currentHost: "localhost");

        result.Status.Should().Be(TlsEnrollmentStatus.Installed);
        result.Thumbprint.Should().Be("AA11BB22");
        result.RequestId.Should().Be(7);
        result.IssuedNames.Should().Contain(ExternalHost);
        result.ExternalHostCovered.Should().BeTrue();
        result.CurrentHostCovered.Should().BeFalse("the certificate names only the external host");

        _factory.Received(1).Create(TestCa);
        _installedCertificate!.HasPrivateKey.Should().BeTrue(
            "Kestrel cannot serve a certificate without its key");
    }

    [Fact]
    public async Task EnrollAsync_SubjectBuiltFromAd_InstallsButReportsTheMismatch()
    {
        // The CA ignored the requested names (no ENROLLEE_SUPPLIES_SUBJECT)
        // and issued for its own idea of the identity. The certificate is
        // usable, so it is installed, but configuring it is the wizard's
        // explicit decision.
        RespondWithIssuedCertificate(overrideName: "machine.home.local");

        var result = await _sut.EnrollAsync(TestCa, "Machine", ExternalUrl, currentHost: null);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed);
        result.ExternalHostCovered.Should().BeFalse();
        result.CurrentHostCovered.Should().BeNull();
        result.IssuedNames.Should().Contain("machine.home.local");
    }

    [Fact]
    public async Task EnrollAsync_Pending_NamesTheRequestAndTheApprovalFix()
    {
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(42, SubmitStatus.Pending, "Taken under submission"));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Pending);
        result.RequestId.Should().Be(42);
        result.Message.Should().Contain("manager approval").And.Contain("42");
        _store.DidNotReceiveWithAnyArgs().Install(default!);
    }

    [Fact]
    public async Task EnrollAsync_Denied_NamesTheComputerAccountAndTheTemplate()
    {
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(43, SubmitStatus.Denied, "Denied by Policy Module"));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Denied);
        result.Message.Should()
            .Contain(Environment.MachineName + "$", "the fix must name the exact account")
            .And.Contain("WebServer")
            .And.Contain("Denied by Policy Module");
        _store.DidNotReceiveWithAnyArgs().Install(default!);
    }

    [Fact]
    public async Task EnrollAsync_RetrievalFailsAfterIssue_Fails()
    {
        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns(new CertificateResult(7, CertificateStatus.Failed));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        result.Message.Should().Contain("7");
        _store.DidNotReceiveWithAnyArgs().Install(default!);
    }

    [Fact]
    public async Task EnrollAsync_InvalidExternalUrl_FailsWithoutSubmitting()
    {
        var result = await _sut.EnrollAsync(TestCa, "WebServer", "not a url", null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
    }

    [Fact]
    public async Task BuildCsr_CarriesTheHostAsCnAndSan()
    {
        // Round trip: the CSR the enroller builds, signed as submitted, must
        // yield a certificate whose names cover the external host.
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.IssuedNames.Should().ContainSingle().Which.Should().Be(ExternalHost);
        _installedCertificate!.Subject.Should().Contain($"CN={ExternalHost}");
    }

    [Fact]
    public async Task BuildCsr_IpLiteralHostBecomesAnIpSan()
    {
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "WebServer", "https://192.168.2.132:5001", null);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed);
        result.IssuedNames.Should().Contain("192.168.2.132");
        result.ExternalHostCovered.Should().BeTrue();
    }

    [Theory]
    [InlineData("certus.home.local", "certus.home.local", true)]
    [InlineData("CERTUS.HOME.LOCAL", "certus.home.local", true)]
    [InlineData("*.home.local", "certus.home.local", true)]
    [InlineData("*.home.local", "a.b.home.local", false)] // single label only
    [InlineData("*.home.local", "home.local", false)]
    [InlineData("other.home.local", "certus.home.local", false)]
    [InlineData("192.168.2.132", "192.168.2.132", true)]
    [InlineData("192.168.2.132", "192.168.2.133", false)]
    public void CoversHost_MatchesLikeATlsVerifier(string name, string host, bool expected)
    {
        TlsCertificateEnroller.CoversHost(new[] { name }, host).Should().Be(expected);
    }

    [Fact]
    public void GetSubjectNames_FallsBackToTheCnWithoutASanExtension()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=bare.home.local", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

        TlsCertificateEnroller.GetSubjectNames(cert)
            .Should().ContainSingle().Which.Should().Be("bare.home.local");
    }

    private void RespondWithTemplate(string? keyAlgorithm, int? minimalKeySize)
    {
        _client.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1",
                    new[] { SetupService.ServerAuthEku },
                    new TemplateAcmeViability(false, false, true, keyAlgorithm, minimalKeySize)),
            });
    }

    [Fact]
    public async Task EnrollAsync_TemplateMinimumKeySize_DrivesTheRsaKeySize()
    {
        RespondWithTemplate("RSA", 3072);
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed);
        using var publicKey = _installedCertificate!.GetRSAPublicKey();
        publicKey!.KeySize.Should().Be(3072, "the CSR key must satisfy the template minimum");
    }

    [Fact]
    public async Task EnrollAsync_EcdsaTemplate_GeneratesAMatchingKeyWithoutKeyEncipherment()
    {
        RespondWithTemplate("ECDSA_P256", 256);
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed);
        _installedCertificate!.HasPrivateKey.Should().BeTrue();
        using var publicKey = _installedCertificate.GetECDsaPublicKey();
        publicKey!.KeySize.Should().Be(256);

        var keyUsage = _installedCertificate.Extensions.OfType<X509KeyUsageExtension>().Single();
        keyUsage.KeyUsages.Should().Be(
            X509KeyUsageFlags.DigitalSignature,
            "EC keys do not encipher and some policy modules reject the claim");
    }

    [Fact]
    public async Task EnrollAsync_EcdsaP384Template_UsesTheMatchingCurve()
    {
        RespondWithTemplate("ECDSA_P384", 384);
        RespondWithIssuedCertificate();

        await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        using var publicKey = _installedCertificate!.GetECDsaPublicKey();
        publicKey!.KeySize.Should().Be(384);
    }

    [Fact]
    public async Task EnrollAsync_TemplateLookupFails_DefaultsToRsa2048()
    {
        _client.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns<IReadOnlyList<TemplateInfo>>(_ => throw new InvalidOperationException("AD unreachable"));
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed,
            "an AD read failure must not block enrollment");
        using var publicKey = _installedCertificate!.GetRSAPublicKey();
        publicKey!.KeySize.Should().Be(2048);
    }

    [Theory]
    [InlineData(null, null, "RSA", 2048)]
    [InlineData("RSA", null, "RSA", 2048)]
    [InlineData("RSA", 4096, "RSA", 4096)]
    [InlineData("RSA", 1024, "RSA", 2048)] // never below the floor
    [InlineData("ECDSA_P256", null, "ECDsa", 256)]
    [InlineData("ECDSA_P384", null, "ECDsa", 384)]
    [InlineData("ECDSA_P521", null, "ECDsa", 521)]
    [InlineData("ECDSA", 384, "ECDsa", 384)] // curve from the size when the name has none
    [InlineData("DSA", 2048, "RSA", 2048)] // unknown algorithms fall back to RSA
    public void CreateKey_MatchesTheTemplateRequirements(
        string? keyAlgorithm, int? minimalKeySize, string expectedType, int expectedSize)
    {
        using var key = TlsCertificateEnroller.CreateKey(keyAlgorithm, minimalKeySize);

        (key is ECDsa ? "ECDsa" : "RSA").Should().Be(expectedType);
        key.KeySize.Should().Be(expectedSize);
    }
}
