using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging;
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

        // Every enrollment resolves the configured template against the CA's
        // published list first, so a case that does not care about resolution
        // still needs a CA that publishes the template it enrolls with. An
        // unstubbed substitute answers an empty list, which is the CA saying
        // "I do not publish that" and refuses before submitting. The pairs
        // mirror MockAdcsClient's defaults, where the programmatic and display
        // names differ as they do on a real CA.
        _client.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServer", "Web Server", "oid1"),
                new("Machine", "Computer", "oid2"),
            });

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

    #region Issue #362: the CA's message is sanitized before it is rendered

    [Fact]
    public async Task EnrollAsync_Denied_SanitizesTheCaMessageBeforeRenderingIt()
    {
        // The enroller is a writer of CA authored text to a wizard screen and a
        // settings screen, so it sanitizes on its own account rather than trusting
        // whichever IAdcsClient handed it the value. A bidirectional override in a
        // denial makes an operator read a host that was never refused, and React
        // escaping does nothing about it.
        const char rlo = (char)0x202e;
        const char lineSep = (char)0x2028;
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(43, SubmitStatus.Denied,
                "Denied for " + rlo + "moc.elpmaxe" + lineSep + "FATAL forged"));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Denied);
        result.Message.Should()
            .Contain("Denied for moc.elpmaxeFATAL forged")
            .And.NotContain(rlo.ToString())
            .And.NotContain(lineSep.ToString());
    }

    [Fact]
    public async Task EnrollAsync_Denied_BoundsAnOverLongCaMessage()
    {
        // The CA schema allows 8192 characters for this column and nothing between
        // the CA and this screen bounds it.
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(43, SubmitStatus.Denied, new string('x', 8192)));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        // The cut spends one character of the budget on an ellipsis, so a value
        // that was 8192 x's arrives as 1999 of them and that marker.
        result.Message.Should().NotBeNull();
        result.Message!.Should()
            .NotContain(new string('x', CertificateTextSanitizer.MaxDispositionMessageLength + 1))
            .And.Contain(((char)0x2026).ToString());
    }

    [Fact]
    public async Task EnrollAsync_Error_SanitizesTheCaMessageBeforeRenderingIt()
    {
        // The default arm of the same switch. An Error disposition renders the
        // CA's words too, so it needs the same guard as the denial above.
        const char esc = (char)0x1b;
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(0, SubmitStatus.Error,
                esc + "[31mThe request could not be decoded"));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        result.Message.Should()
            .Contain("[31mThe request could not be decoded")
            .And.NotContain(esc.ToString());
    }

    [Fact]
    public async Task EnrollAsync_Denied_BlankCaMessageFallsBackToNoReasonGiven()
    {
        // The sanitizer answers null for a blank value, which is what makes the
        // fallback fire. An empty string is not null, so before issue #362 this
        // rendered "The CA denied the request: ." instead.
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(43, SubmitStatus.Denied, "   "));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Message.Should().Contain("no reason given");
    }

    #endregion

    #region Issue #356: a denial says why, not only that

    [Fact]
    public async Task EnrollAsync_DeniedWithAStatusCode_ExplainsTheCodeBesideTheCaMessage()
    {
        // The whole of issue #356 on the surface that meets it most. Before this the
        // wizard rendered "The CA denied the request: Denied by Policy Module." and an
        // administrator was told a decision had been made and nothing about why, for
        // the one CA condition they could actually go and fix.
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(
                44, SubmitStatus.Denied, "Denied by Policy Module",
                CaStatusCode.TemplateDenied));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Denied);
        result.Message.Should()
            .Contain("Denied by Policy Module",
                "the CA's own account still leads; the explanation travels beside it " +
                "rather than in place of it, so a policy module that does explain " +
                "itself keeps its own words")
            .And.Contain("0x80094012",
                "the operator needs the value to search for and to hand to certutil -error")
            .And.Contain("do not allow the current user to enroll");

        // Stated positively on purpose. Written as a NotContain over the run together
        // string, this would pass the moment either half was reworded, because the
        // string it forbids could then no longer occur under any code path at all.
        result.Message.Should().Contain("certificate. The service enrolls",
            "the explanation has to finish its sentence before the remedy starts, or " +
            "the wizard renders two sentences run together");
    }

    [Fact]
    public async Task EnrollAsync_DeniedWithAnUnmappedStatusCode_StillNamesTheCode()
    {
        // A third party policy module may record a code nobody has described. The
        // fallback is why a partial map is worth having: the operator still gets a
        // value they can search for, which is more than the bare message gave.
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(
                45, SubmitStatus.Denied, "Denied by Policy Module",
                unchecked((int)0x8009FFFF)));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Message.Should().Contain("0x8009FFFF");
    }

    [Fact]
    public async Task EnrollAsync_ErrorDispositionWithAStatusCode_ExplainsItToo()
    {
        // The Error arm gets the explanation as well. It gets no remedy, because an
        // Error disposition is not a permissions problem and sending an operator to a
        // Security tab for it would misdirect, which is the same split the ACME
        // finalize makes.
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(
                46, SubmitStatus.Error, "The request could not be processed.",
                CaStatusCode.BadRequestSubject));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        result.Message.Should()
            .Contain("0x80094001")
            .And.Contain("subject name is invalid or too long");
        result.Message.Should().NotContain("Enroll permission",
            "the remedy belongs to a denial, not to every refusal");
    }

    #endregion

    #region Issue #326: the caller's token stops at the submit

    [Fact]
    public async Task EnrollAsync_CallerGoesAwayMidEnrollment_StillCollectsTheCertificate()
    {
        // Issue #326. The wizard tab closes, or a service stops, while the CSR is
        // at the CA. Before this the fetch on the next line threw, the certificate
        // stayed live at the CA, and the request id went with the stack.
        //
        // The stand in for a client that hung up: a CA that honours the token it
        // is handed. The real COM client does not, which is exactly why the token
        // this enroller passes cannot be read off the outcome any other way.
        using var hungUp = new CancellationTokenSource();
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(),
                Arg.Do<byte[]>(csr => { _submittedCsr = csr; hungUp.Cancel(); }),
                Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(7, SubmitStatus.Issued));
        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                call.Arg<CancellationToken>().ThrowIfCancellationRequested();
                return new CertificateResult(
                    7, CertificateStatus.Issued, IssueFromSubmittedCsr());
            });

        var result = await _sut.EnrollAsync(
            TestCa, "WebServer", ExternalUrl, currentHost: null, hungUp.Token);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed,
            "the CA had already issued, so abandoning the fetch could only lose it");
        result.RequestId.Should().Be(7);
        _store.ReceivedWithAnyArgs(1).Install(default!);
    }

    [Fact]
    public async Task EnrollAsync_CallerAlreadyGoneBeforeTheSubmit_RefusesWithoutReachingTheCa()
    {
        // The other half of the boundary. Passing none to the submit must not mean
        // submitting for a caller who is already gone: up to that line abandoning
        // is free, so the token is still read.
        using var gone = new CancellationTokenSource();
        gone.Cancel();

        var enroll = async () => await _sut.EnrollAsync(
            TestCa, "WebServer", ExternalUrl, currentHost: null, gone.Token);

        await enroll.Should().ThrowAsync<OperationCanceledException>();
        await _client.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
        _store.DidNotReceiveWithAnyArgs().Install(default!);
    }

    [Fact]
    public async Task EnrollAsync_CollectionThrowsAfterTheCaIssued_NamesTheRequestIdSoItCanBeFound()
    {
        // Nothing about an enrollment reaches the database, so this log line is the
        // only record joining a certificate at the CA to the host it was meant for.
        // That makes the line the deliverable rather than decoration.
        var log = new RecordingLogger();
        var sut = new TlsCertificateEnroller(_factory, _store, log);
        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns<CertificateResult>(_ =>
                throw new CaUnavailableException("The RPC server is unavailable"));

        var enroll = async () => await sut.EnrollAsync(
            TestCa, "WebServer", ExternalUrl, currentHost: null);

        // Rethrown rather than folded into a Failed result: both controllers and the
        // auto renewal service build their 503 and their alert on this exception.
        await enroll.Should().ThrowAsync<CaUnavailableException>();

        var strand = log.Entries.Should().ContainSingle(e => e.Level == LogLevel.Error).Subject;
        strand.Message.Should().Contain("7").And.Contain("WebServer").And.Contain("revoke");
    }

    [Fact]
    public async Task EnrollAsync_CaDeniesAccess_PropagatesRatherThanFoldingIntoAResult()
    {
        // Issue #336. The second CA exception the enroller propagates, and it must
        // travel exactly as the outage above does: the wizard, the settings page and
        // the automatic renewal all build their 503 and their alert on catching it.
        // Folded into a Failed result instead, it would reach the wizard as an
        // ordinary enrollment failure, on the surface most likely to meet it.
        var sut = new TlsCertificateEnroller(_factory, _store, NullLogger<TlsCertificateEnroller>.Instance);
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns<SubmitResult>(_ => throw new CaAccessDeniedException(
                CaAccessDeniedException.EnrollPermissionMessage,
                new UnauthorizedAccessException("simulated E_ACCESSDENIED")));

        var enroll = async () => await sut.EnrollAsync(
            TestCa, "WebServer", ExternalUrl, currentHost: null);

        await enroll.Should().ThrowAsync<CaAccessDeniedException>();
        _store.DidNotReceiveWithAnyArgs().Install(default!);
    }

    [Fact]
    public async Task EnrollAsync_CaDeniesTheRequest_IsStillADeniedResultNotAnException()
    {
        // The other side of the same coin, pinned so the two do not get merged. A CA
        // that refuses through its policy module has decided, and a decision is a
        // result: it is the commonest permissions failure by far and it carries the
        // guidance the wizard renders. Only a refusal of the call itself throws.
        var sut = new TlsCertificateEnroller(_factory, _store, NullLogger<TlsCertificateEnroller>.Instance);
        _client.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(
                42, SubmitStatus.Denied, "Denied by Policy Module",
                CaStatusCode.TemplateDenied));

        var result = await sut.EnrollAsync(
            TestCa, "WebServer", ExternalUrl, currentHost: null);

        result.Status.Should().Be(TlsEnrollmentStatus.Denied);
        result.Message.Should().Contain("Enroll").And.Contain("Security",
            "the wizard's audience is an administrator, who is told what to go and fix");
        _store.DidNotReceiveWithAnyArgs().Install(default!);
    }

    #endregion

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

        // A list that could not be read says nothing about the template, so the
        // configured name goes to the CA unchanged, exactly as it did before
        // the resolution existed. Refusing here would turn a CA or AD outage
        // into a configuration error on an install that is set up correctly.
        await _client.Received(1).SubmitCertificateRequestAsync(
            "WebServer", Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The issue #194 defect. ADCS matches CertificateTemplate: against the
    /// programmatic name alone, so a configuration holding the display name
    /// (which EnabledTemplatesPolicy accepts and the ACME path issues against
    /// happily) must be resolved before it reaches the CA.
    /// </summary>
    [Fact]
    public async Task EnrollAsync_TemplateAddressedByDisplayName_SubmitsTheProgrammaticName()
    {
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "Web Server", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed);
        await _client.Received(1).SubmitCertificateRequestAsync(
            "WebServer", Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
        await _client.DidNotReceive().SubmitCertificateRequestAsync(
            "Web Server", Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
        result.TemplateName.Should().Be("WebServer",
            "the caller records what reached the CA, so the install converges on it");
    }

    /// <summary>
    /// Resolution has to happen before the key requirements are read, not only
    /// before the submission: that lookup matched the programmatic name alone,
    /// so a display name silently missed it and produced an RSA key for an
    /// ECDSA only template, which the CA denies for a different reason.
    /// </summary>
    [Fact]
    public async Task EnrollAsync_EcdsaTemplateAddressedByDisplayName_StillGeneratesAnEcKey()
    {
        _client.GetTemplatesAsync(Arg.Any<CancellationToken>())
            .Returns(new List<TemplateInfo>
            {
                new("WebServerEc", "Web Server EC", "oid3",
                    new[] { SetupService.ServerAuthEku },
                    new TemplateAcmeViability(false, false, true, "ECDSA_P384", 384)),
            });
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "Web Server EC", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed);
        using var publicKey = _installedCertificate!.GetECDsaPublicKey();
        publicKey!.KeySize.Should().Be(384);
    }

    [Fact]
    public async Task EnrollAsync_TemplateTheCaDoesNotPublish_IsRefusedWithoutSubmitting()
    {
        var result = await _sut.EnrollAsync(TestCa, "WebServerAcme", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        result.Message.Should().Contain("WebServerAcme").And.Contain("programmatic name",
            "an operator needs to know which name failed and why, not 0x80094800");
        await _client.DidNotReceive().SubmitCertificateRequestAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The refusals above name the configured template back to the caller, and
    /// that text reaches a log line and an HTTP response body, so this class
    /// guards the name itself rather than trusting every caller to have done it
    /// (issue #175).
    /// </summary>
    [Fact]
    public async Task EnrollAsync_TemplateNameCarryingAControlCharacter_IsRefusedBeforeAnyCaCall()
    {
        var result = await _sut.EnrollAsync(
            TestCa, "WebServer\ncdc:evil.example.com", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        result.Message.Should().Contain("control character");
        _factory.DidNotReceive().Create(Arg.Any<string>());
    }

    [Theory]
    [InlineData(null, null, "RSA", 2048)]
    [InlineData("", null, "RSA", 2048)]
    [InlineData("RSA", null, "RSA", 2048)]
    [InlineData("RSA", 4096, "RSA", 4096)]
    [InlineData("RSA", 1024, "RSA", 2048)] // never below the floor
    [InlineData("ECDSA_P256", null, "ECDsa", 256)]
    [InlineData("ECDSA_P384", null, "ECDsa", 384)]
    [InlineData("ECDSA_P521", null, "ECDsa", 521)]
    [InlineData("ECDSA", 384, "ECDsa", 384)] // curve from the size when the name has none
    // An ECDH template names the same curves and gets the same key (#277). A
    // PKCS#10 is self signed, so the signing key on that curve is the only key
    // anything could put in a request for such a template, and RFC 5480 encodes
    // both identically. Verified against the lab CA on 2026-08-15, which issued
    // against a template recording ECDH_P256.
    [InlineData("ECDH_P256", null, "ECDsa", 256)]
    [InlineData("ECDH_P384", null, "ECDsa", 384)]
    [InlineData("ECDH_P521", null, "ECDsa", 521)]
    [InlineData("ECDH", 384, "ECDsa", 384)]
    [InlineData("  ecdh_p384  ", null, "ECDsa", 384)] // trimmed and case folded like the rest
    public void CreateKey_MatchesTheTemplateRequirements(
        string? keyAlgorithm, int? minimalKeySize, string expectedType, int expectedSize)
    {
        using var key = TlsCertificateEnroller.CreateKey(keyAlgorithm, minimalKeySize);

        (key is ECDsa ? "ECDsa" : "RSA").Should().Be(expectedType);
        key.KeySize.Should().Be(expectedSize);
    }

    /// <summary>
    /// An algorithm the template names but this server cannot generate is
    /// refused, not quietly turned into RSA. Substituting one algorithm for
    /// another is the shape of issue #213: a CA that enforces its template
    /// denies with nothing naming the cause, and a CA that does not issues a
    /// certificate contradicting its own template.
    /// </summary>
    /// <remarks>
    /// Bare <c>DH</c> is the regression guard for the ECDH prefix test added
    /// for issue #277. It shares four letters with <c>ECDH</c> and means
    /// something this server genuinely cannot answer, so it has to keep
    /// failing while <c>ECDH_P256</c> succeeds.
    /// </remarks>
    [Theory]
    [InlineData("DSA")]
    [InlineData("DH")]
    [InlineData("ML-DSA-65")]
    public void CreateKey_AnAlgorithmItCannotGenerate_IsRefusedByName(string keyAlgorithm)
    {
        var act = () => TlsCertificateEnroller.CreateKey(keyAlgorithm, 2048);

        act.Should().Throw<NotSupportedException>()
            .WithMessage($"*{keyAlgorithm}*")
            .And.Message.Should().Contain("ECDSA_P256",
                "the message has to say what would work, not only what does not");
    }

    /// <summary>
    /// The predicate the enroller warns on. The substitution always works, so
    /// this is the only thing that tells an administrator their template is
    /// recording an encryption only algorithm.
    /// </summary>
    [Theory]
    [InlineData("ECDH_P256", true)]
    [InlineData("ecdh_p521", true)]
    [InlineData("  ECDH  ", true)]
    [InlineData("ECDSA_P256", false)]
    [InlineData("RSA", false)]
    [InlineData("DH", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsEcdhAlgorithm_NamesOnlyTheEncryptionOnlyCurveAlgorithms(
        string? keyAlgorithm, bool expected)
    {
        TlsCertificateEnroller.IsEcdhAlgorithm(keyAlgorithm).Should().Be(expected);
    }

    [Fact]
    public async Task EnrollAsync_TemplateAlgorithmItCannotGenerate_IsRefusedWithoutSubmitting()
    {
        RespondWithTemplate("DSA", 2048);

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        result.Message.Should().Contain("DSA").And.Contain("Cryptography tab");
        await _client.DidNotReceive().SubmitCertificateRequestAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// An ECDH template enrolls, on the curve its name carries (issue #277).
    /// The lab CA issued against exactly such a template on 2026-08-15, beside
    /// a control that left the template attribute as the only variable, and a
    /// PKCS#10 could not carry an encryption only key in any case.
    /// </summary>
    [Fact]
    public async Task EnrollAsync_EcdhTemplate_EnrollsOnTheMatchingCurve()
    {
        RespondWithTemplate("ECDH_P384", 384);
        RespondWithIssuedCertificate();

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Installed);
        using var publicKey = _installedCertificate!.GetECDsaPublicKey();
        publicKey!.KeySize.Should().Be(384);
        await _client.Received().SubmitCertificateRequestAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The CA is not a reliable backstop for its own template. Issue #213 was
    /// observed on two labs at once: one CA denied the wrongly keyed request
    /// and the other issued it, leaving a working certificate whose key type
    /// contradicted the template and nothing anywhere saying so. Refuse the
    /// leaf here rather than install it.
    /// </summary>
    [Fact]
    public async Task EnrollAsync_CaIssuesALeafWhoseKeyDoesNotMatchTheRequest_IsRefused()
    {
        RespondWithTemplate("RSA", 2048);
        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns(_ => new CertificateResult(7, CertificateStatus.Issued, IssueWithSubstitutedKey()));

        var result = await _sut.EnrollAsync(TestCa, "WebServer", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        result.Message.Should().Contain("ECDSA 256").And.Contain("RSA 2048")
            .And.Contain("not installed");
        _store.DidNotReceive().Install(Arg.Any<X509Certificate2>());
    }

    /// <summary>
    /// TlsEnrollmentResult.TemplateName is null only on a refusal that never
    /// reached the CA (issue #194). Every refusal past the submit carries the
    /// resolved name, so the renewal service records and alerts on the name
    /// ADCS actually matched rather than falling back to the configured one.
    /// </summary>
    [Fact]
    public async Task EnrollAsync_RefusalsAfterSubmitting_CarryTheResolvedTemplateName()
    {
        RespondWithTemplate("RSA", 2048);

        // Addressed by display name, so a fallback to the configured value
        // would be visible as "Web Server" instead of "WebServer".
        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns(_ => new CertificateResult(7, CertificateStatus.Issued, IssueWithSubstitutedKey()));
        var mismatch = await _sut.EnrollAsync(TestCa, "Web Server", ExternalUrl, null);
        mismatch.TemplateName.Should().Be("WebServer");

        _client.GetCertificateAsync(7, Arg.Any<CancellationToken>())
            .Returns(new CertificateResult(7, CertificateStatus.Denied, null));
        var unretrievable = await _sut.EnrollAsync(TestCa, "Web Server", ExternalUrl, null);
        unretrievable.Status.Should().Be(TlsEnrollmentStatus.Failed);
        unretrievable.TemplateName.Should().Be("WebServer");
    }

    /// <summary>
    /// The other half of the same contract: a refusal raised before anything
    /// was submitted has no name to report, so it must stay null rather than
    /// echo back a template the CA never saw.
    /// </summary>
    [Fact]
    public async Task EnrollAsync_RefusalsBeforeSubmitting_CarryNoTemplateName()
    {
        RespondWithTemplate("DSA", 2048);

        var result = await _sut.EnrollAsync(TestCa, "Web Server", ExternalUrl, null);

        result.Status.Should().Be(TlsEnrollmentStatus.Failed);
        result.TemplateName.Should().BeNull();
    }

    /// <summary>
    /// A leaf carrying a key the enroller did not generate: same subject and
    /// SAN as the request, different key entirely. This is what lab 2019's CA
    /// effectively produced, and before the guard it reached
    /// <c>CopyWithPrivateKey</c> and threw an unhandled ArgumentException.
    /// </summary>
    private byte[] IssueWithSubstitutedKey()
    {
        var loaded = CertificateRequest.LoadSigningRequest(
            _submittedCsr!,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pkcs1);

        using var substitute = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var toSign = new CertificateRequest(
            loaded.SubjectName, substitute, HashAlgorithmName.SHA256);
        foreach (var extension in loaded.CertificateExtensions)
            toSign.CertificateExtensions.Add(extension);

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

    /// <summary>
    /// Captures what the enroller logged, so a test can assert on a line that is
    /// the only record of something. Everything else here uses NullLogger.
    /// </summary>
    private sealed class RecordingLogger : ILogger<TlsCertificateEnroller>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
