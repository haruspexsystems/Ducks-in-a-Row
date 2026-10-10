using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for MockAdcsClient — verifies it produces realistic X.509 certificates
/// and behaves according to the IAdcsClient contract.
/// </summary>
public class MockAdcsClientTests : IDisposable
{
    private readonly MockAdcsClient _client;

    public MockAdcsClientTests()
    {
        _client = new MockAdcsClient("TestCA");
    }

    [Fact]
    public async Task GetCaInfo_ReturnsAccessibleCa()
    {
        var info = await _client.GetCaInfoAsync();

        info.Name.Should().Be("TestCA");
        info.DnsName.Should().NotBeNullOrEmpty();
        info.IsAccessible.Should().BeTrue();
    }

    [Fact]
    public async Task GetTemplates_ReturnsDefaultTemplates()
    {
        var templates = await _client.GetTemplatesAsync();

        templates.Should().NotBeEmpty();
        templates.Should().Contain(t => t.Name == "WebServer");
        templates.Should().Contain(t => t.Name == "Machine");
        templates.Should().Contain(t => t.Name == "CodeSigning");
    }

    [Fact]
    public async Task GetCaCertificateChain_ReturnsTheSelfSignedRootAlone()
    {
        var chain = await _client.GetCaCertificateChainAsync();

        chain.Should().ContainSingle();
        using var root = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(chain[0]);
        root.Subject.Should().Contain("TestCA");
        root.Subject.Should().Be(root.Issuer, "the mock CA is a one tier, self signed root");
    }

    #region Issue #309: the CA can be named anything a CA can be named

    [Fact]
    public async Task Constructor_CaNameWithAComma_BuildsTheSelfSignedRoot()
    {
        // Issue #309. new X509Name("CN=Corp, Inc CA") reads the comma as a
        // component separator, the trailing fragment carries no equals sign, and
        // the constructor refuses the whole string. The client then failed to
        // construct at all, which is why no dev host could hold a comma bearing
        // name and why the comma bearing subject that triggered issue #294 was
        // unreachable in a browser.
        var client = new MockAdcsClient("Corp, Inc CA");

        var chain = await client.GetCaCertificateChainAsync();

        chain.Should().ContainSingle();
        using var root = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(chain[0]);
        root.Subject.Should().Be("CN=\"Corp, Inc CA\"",
            "the Windows quoted form is what a live CA name renders as");
        root.Subject.Should().Be(root.Issuer, "the mock CA is a one tier, self signed root");
        DistinguishedNameParser.CommonName(root.Subject).Should().Be("Corp, Inc CA");
    }

    [Theory]
    // The comma is the reported defect.
    [InlineData("Corp, Inc CA", "CN=\"Corp, Inc CA\"")]
    // A leading hash and a leading backslash are the two shapes that pin the
    // choice of encoder. BouncyCastle's list of oids and list of values
    // constructor, which the issue suggested, refuses the first as hex encoded
    // DER and silently drops the backslash from the second. Reading either back
    // through GetValueList echoes the input unchanged, so only the DER, which is
    // what these rows measure, shows that it happened.
    [InlineData("#1 CA", "CN=\"#1 CA\"")]
    [InlineData("\\Corp CA", "CN=\\Corp CA")]
    // The ordinary name, unchanged from before.
    [InlineData("MockCA", "CN=MockCA")]
    public async Task Constructor_CaNameWithGrammarCharacters_KeepsTheValueVerbatim(
        string caName, string expectedSubject)
    {
        var client = new MockAdcsClient(caName);

        var chain = await client.GetCaCertificateChainAsync();

        using var root = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(chain[0]);
        root.Subject.Should().Be(expectedSubject);
        DistinguishedNameParser.CommonName(root.Subject).Should().Be(caName,
            "whatever the render, the name has to come back out as it went in");
    }

    [Fact]
    public void Constructor_EmptyCaName_IsRefused()
    {
        // A certificate authority whose common name is the empty string is not a
        // shape any CA can have. It used to construct; the guard names this
        // parameter rather than the inner one belonging to the encoder.
        var construct = () => new MockAdcsClient(string.Empty);

        construct.Should().Throw<ArgumentException>().WithParameterName("caName");
    }

    #endregion

    #region Issue #295: the leaf carries the names the request asked for

    [Fact]
    public async Task IssueFromCsr_CarriesTheRequestedSansOntoTheLeafAndIntoTheProjection()
    {
        // Issue #295. The mock copied only the subject and the public key, so no
        // certificate it had ever issued carried a subject alternative name. An
        // ACME run against the dev host therefore succeeded and handed back a
        // leaf every modern TLS client rejects, because common name fallback for
        // hostname verification is long gone. The subject is empty here on
        // purpose: that is the shape a modern ACME client sends.
        var csr = GenerateCsrWithSans(
            string.Empty,
            new[] { "web01.example.com", "alt.example.com" },
            new[] { "10.0.0.5" });

        var submit = await _client.SubmitCertificateRequestAsync("WebServer", csr);
        var issued = await _client.GetCertificateAsync(submit.RequestId);

        using var leaf = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(issued.CertificateDer!);
        var san = leaf.Extensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .Should().ContainSingle("the leaf itself carries the extension, not just the projection")
            .Subject;
        san.EnumerateDnsNames().Should().Contain(new[] { "web01.example.com", "alt.example.com" });

        // The configured leaf extensions still land beside it rather than being
        // displaced: the generator refuses a second extension under an OID it
        // already holds, so copying more than the SAN would throw.
        leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Should().ContainSingle();
        leaf.Extensions.OfType<X509KeyUsageExtension>().Should().ContainSingle();

        var results = await _client.QueryCertificatesAsync(new CertificateQuery());
        results.Single(c => c.RequestId == submit.RequestId)
            .SubjectAlternativeNames.Should()
            .Be("dns:web01.example.com, dns:alt.example.com, ip:10.0.0.5",
                "the projection now reads the parse instead of a hardcoded null");
    }

    [Fact]
    public async Task IssueFromCsr_PermanentIdentifierOtherName_CrossesByteForByte()
    {
        // The device attestation guarantee CLAUDE.md records for the real CA, now
        // held by the mock the device tests actually run against: ADCS forwards
        // the PermanentIdentifier otherName untouched, so this must too.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = Acme.Attestation.DeviceCsrBuilder.Build(key, "CN=SN-DEVICE-1", "SN-DEVICE-1");

        var submit = await _client.SubmitCertificateRequestAsync("WebServer", csr);
        var issued = await _client.GetCertificateAsync(submit.RequestId);

        var requested = CertificateRequest
            .LoadSigningRequest(
                csr, HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions)
            .CertificateExtensions.Single(e => e.Oid?.Value == "2.5.29.17");
        using var leaf = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(issued.CertificateDer!);

        leaf.Extensions["2.5.29.17"]!.RawData.Should().Equal(requested.RawData);

        // The projection stays null for it, which is not a regression of the line
        // above: the stored format spells dns and ip entries only, and AdcsClient
        // answers null for the same certificate.
        var results = await _client.QueryCertificatesAsync(new CertificateQuery());
        results.Single(c => c.RequestId == submit.RequestId)
            .SubjectAlternativeNames.Should().BeNull();
    }

    [Fact]
    public async Task IssueFromCsr_RequestWithNoSan_LeafCarriesNone()
    {
        // A CA does not invent a subject alternative name from the common name,
        // and neither may this. Without it the fix could pass the tests above by
        // fabricating names, which is the failure mode issue #240 was about.
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateWindowsCsr("CN=bare.example.com"));
        var issued = await _client.GetCertificateAsync(submit.RequestId);

        using var leaf = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(issued.CertificateDer!);
        leaf.Extensions["2.5.29.17"].Should().BeNull();

        var results = await _client.QueryCertificatesAsync(new CertificateQuery());
        results.Single(c => c.RequestId == submit.RequestId)
            .SubjectAlternativeNames.Should().BeNull();
    }

    #endregion

    #region Issue #332: a request the CA cannot read is refused

    [Theory]
    // The five shapes a malformed request arrives in, all measured against
    // BouncyCastle 2.6.2 rather than assumed. Four raise a type the narrowed
    // filter names. The empty one does not: a zero length input reads back as a
    // null Asn1Object and the CertificationRequest constructor dereferences it,
    // so it answers NullReferenceException and is refused ahead of the parse.
    [InlineData("an empty request", new byte[] { })]
    [InlineData("garbage bytes", new byte[] { 1, 2, 3 })]
    [InlineData("a bare DER null", new byte[] { 0x05, 0x00 })]
    [InlineData("an empty SEQUENCE", new byte[] { 0x30, 0x00 })]
    [InlineData("a truncated SEQUENCE", new byte[] { 0x30, 0x82, 0x01, 0x00 })]
    public async Task SubmitCsr_ThatCannotBeDecoded_IsRefusedAndIssuesNothing(
        string shape, byte[] csrDer)
    {
        // Issue #332. The whole issuance sat inside a bare catch that returned a
        // self signed certificate under a freshly generated key pair, so a request
        // the mock could not read came back Issued carrying a public key the
        // requester did not hold. No certificate authority behaves that way.
        var result = await _client.SubmitCertificateRequestAsync("WebServer", csrDer);

        result.Status.Should().Be(SubmitStatus.Error,
            $"{shape} is not a request this CA can issue from, AdcsClient maps a " +
            "disposition it does not recognize to Error, and Denied carries an " +
            "Enroll permission remedy that would misdirect for this");
        result.Message.Should().Contain("could not be decoded");

        // Nothing was issued to anyone, which is the half that matters: the old
        // behaviour left a signed certificate in the request row.
        var stored = await _client.QueryCertificatesAsync(new CertificateQuery());
        stored.Should().BeEmpty();
    }

    [Fact]
    public async Task SubmitCsr_ThatCannotBeDecoded_IsRefusedRatherThanPended()
    {
        // The parse runs ahead of the AutoApprove branch, so a request this CA
        // could never issue from never becomes a row waiting on a CA manager,
        // which is what a real CA does. Without this the refusal could be written
        // at issuance time only and the pending path would still hold garbage.
        _client.AutoApprove = false;

        var result = await _client.SubmitCertificateRequestAsync(
            "WebServer", new byte[] { 1, 2, 3 });

        result.Status.Should().Be(SubmitStatus.Error);
        result.RequestId.Should().Be(0, "no request row was created for it");

        var stored = await _client.QueryCertificatesAsync(new CertificateQuery());
        stored.Should().BeEmpty();
    }

    [Fact]
    public async Task IssueFromCsr_LeafCarriesTheKeyTheRequestAskedFor()
    {
        // The invariant the issue title names, held whichever route reached the
        // mock. A leaf whose SubjectPublicKeyInfo is not the request's is a
        // certificate for a key nobody holds, and the substituted certificate
        // failed exactly here.
        var csr = GenerateWindowsCsr("CN=keyed.example.com");

        var submit = await _client.SubmitCertificateRequestAsync("WebServer", csr);
        var issued = await _client.GetCertificateAsync(submit.RequestId);

        var requestedSpki = CertificateRequest
            .LoadSigningRequest(csr, HashAlgorithmName.SHA256)
            .PublicKey.ExportSubjectPublicKeyInfo();
        using var leaf = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);

        leaf.PublicKey.ExportSubjectPublicKeyInfo().Should().Equal(requestedSpki);
    }

    [Fact]
    public async Task SubmitCsr_WithAMisconfiguredLeafOid_FaultsRatherThanIssuingQuietly()
    {
        // What pins "narrow the try, not the catch list". A value that is not an
        // OID makes AddLeafExtensions throw FormatException, which the bare catch
        // used to swallow: the mock then issued a leaf with no extended key usage
        // at all, and the TLS capability ceiling refused it for a reason nothing
        // to do with what the test had set. A wider catch would pass every other
        // test in this region and fail this one.
        _client.LeafEkuOids = new[] { "not-an-oid" };

        var submit = async () => await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateWindowsCsr("CN=misconfigured.example.com"));

        await submit.Should().ThrowAsync<FormatException>();
    }

    #endregion

    [Fact]
    public async Task GetTemplates_WithCustomTemplates_ReturnsOnlyThose()
    {
        var custom = new List<TemplateInfo>
        {
            new("CustomTLS", "Custom TLS", "1.2.3.4.5")
        };

        var client = new MockAdcsClient("TestCA", custom);
        var templates = await client.GetTemplatesAsync();

        templates.Should().HaveCount(1);
        templates[0].Name.Should().Be("CustomTLS");
    }

    [Fact]
    public async Task SubmitCsr_WithValidTemplate_ReturnsIssued()
    {
        var csrDer = GenerateTestCsr("CN=test.example.com");

        var result = await _client.SubmitCertificateRequestAsync("WebServer", csrDer);

        result.Status.Should().Be(SubmitStatus.Issued);
        result.RequestId.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task SubmitCsr_WithInvalidTemplate_ReturnsDenied()
    {
        var csrDer = GenerateTestCsr("CN=test.example.com");

        var result = await _client.SubmitCertificateRequestAsync("NonExistentTemplate", csrDer);

        result.Status.Should().Be(SubmitStatus.Denied);
        result.Message.Should().Contain("not found");
    }

    [Fact]
    public async Task SubmitCsr_AutoApproveOff_ReturnsPending()
    {
        _client.AutoApprove = false;
        var csrDer = GenerateTestCsr("CN=test.example.com");

        var result = await _client.SubmitCertificateRequestAsync("WebServer", csrDer);

        result.Status.Should().Be(SubmitStatus.Pending);
    }

    [Fact]
    public async Task SubmitCsr_AutoApproveOff_ThenApprove_ReturnsIssued()
    {
        _client.AutoApprove = false;
        var csrDer = GenerateTestCsr("CN=test.example.com");

        var result = await _client.SubmitCertificateRequestAsync("WebServer", csrDer);
        result.Status.Should().Be(SubmitStatus.Pending);

        _client.ApproveRequest(result.RequestId);

        var cert = await _client.GetCertificateAsync(result.RequestId);
        cert.Status.Should().Be(CertificateStatus.Issued);
        cert.CertificateDer.Should().NotBeNullOrEmpty();
        cert.CertificatePem.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetCertificate_AfterSubmit_ReturnsDerAndPem()
    {
        var csrDer = GenerateTestCsr("CN=test.example.com");
        var submitResult = await _client.SubmitCertificateRequestAsync("WebServer", csrDer);

        var certResult = await _client.GetCertificateAsync(submitResult.RequestId);

        certResult.Status.Should().Be(CertificateStatus.Issued);
        certResult.CertificateDer.Should().NotBeNullOrEmpty();
        certResult.CertificatePem.Should().NotBeNullOrEmpty();
        certResult.CertificatePem.Should().Contain("BEGIN CERTIFICATE");
    }

    [Fact]
    public async Task GetCertificate_IsValidX509()
    {
        var csrDer = GenerateTestCsr("CN=test.example.com");
        var submitResult = await _client.SubmitCertificateRequestAsync("WebServer", csrDer);
        var certResult = await _client.GetCertificateAsync(submitResult.RequestId);

        // Parse the DER back into an X.509 certificate
        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        var cert = parser.ReadCertificate(certResult.CertificateDer);

        cert.Should().NotBeNull();
        cert.SubjectDN.ToString().Should().Contain("test.example.com");
        cert.NotBefore.Should().BeBefore(DateTime.UtcNow.AddMinutes(1));
        cert.NotAfter.Should().BeAfter(DateTime.UtcNow);
        cert.IssuerDN.ToString().Should().Contain("TestCA");
    }

    [Fact]
    public async Task GetCertificate_NonExistentRequest_ReturnsFailed()
    {
        var result = await _client.GetCertificateAsync(9999);

        result.Status.Should().Be(CertificateStatus.Failed);
        result.CertificateDer.Should().BeNull();
    }

    [Fact]
    public async Task QueryCertificates_ReturnsIssuedCerts()
    {
        // Submit a few certs
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=web1.example.com"));
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=web2.example.com"));
        await _client.SubmitCertificateRequestAsync("Machine", GenerateTestCsr("CN=srv1.example.com"));

        var results = await _client.QueryCertificatesAsync(new CertificateQuery());

        results.Should().HaveCount(3);
    }

    [Fact]
    public async Task QueryCertificates_FilterByTemplate_ReturnsOnlyMatching()
    {
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=web1.example.com"));
        await _client.SubmitCertificateRequestAsync("Machine", GenerateTestCsr("CN=srv1.example.com"));

        var results = await _client.QueryCertificatesAsync(
            new CertificateQuery(TemplateName: "WebServer"));

        results.Should().HaveCount(1);
        results[0].TemplateName.Should().Be("WebServer");
    }

    [Fact]
    public async Task QueryCertificates_FilterByStatus_ReturnsOnlyMatching()
    {
        _client.AutoApprove = false;
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=web1.example.com"));

        _client.AutoApprove = true;
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=web2.example.com"));

        var pendingResults = await _client.QueryCertificatesAsync(
            new CertificateQuery(Status: CertificateStatus.Pending));
        var issuedResults = await _client.QueryCertificatesAsync(
            new CertificateQuery(Status: CertificateStatus.Issued));

        pendingResults.Should().HaveCount(1);
        issuedResults.Should().HaveCount(1);
    }

    #region Issue #365: the CA's record of one request

    [Fact]
    public async Task GetRequestStatus_DeniedRequest_CarriesTheCaAccountOfIt()
    {
        // The read the pending issuance sweep makes to say why an order failed.
        // CERTSRV_E_ADMIN_DENIED_REQUEST is what ADCS records for a denial by hand,
        // as against the policy module codes the submit path meets.
        _client.AutoApprove = false;
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateTestCsr("CN=denied.example.com"));
        _client.DenyRequest(submit.RequestId);

        var status = await _client.GetRequestStatusAsync(submit.RequestId);

        status.Should().NotBeNull();
        status!.Status.Should().Be(CertificateStatus.Denied);
        status.DispositionMessage.Should().Be(MockAdcsClient.ManagerDenialMessage);
        status.StatusCode.Should().Be(CaStatusCode.AdminDeniedRequest);
    }

    [Fact]
    public async Task GetRequestStatus_IssuedRequest_WithholdsTheExplanationColumns()
    {
        // The same gate the real client applies. An issued row carries "Issued" and
        // a zero status code, so reporting them would hand a caller noise it would
        // then put in an error message.
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateTestCsr("CN=issued.example.com"));

        var status = await _client.GetRequestStatusAsync(submit.RequestId);

        status.Should().NotBeNull();
        status!.Status.Should().Be(CertificateStatus.Issued);
        status.DispositionMessage.Should().BeNull();
        status.StatusCode.Should().BeNull();
    }

    [Fact]
    public async Task GetRequestStatus_ApprovalClearsWhatThePendingRowSaid()
    {
        // A real CA overwrites its account of a request when the request is
        // decided. An approved row that still said it was waiting would be read
        // back as a stale explanation.
        _client.AutoApprove = false;
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateTestCsr("CN=approved.example.com"));
        (await _client.GetRequestStatusAsync(submit.RequestId))!
            .DispositionMessage.Should().Be(MockAdcsClient.PendingApprovalMessage);

        _client.ApproveRequest(submit.RequestId);

        (await _client.GetRequestStatusAsync(submit.RequestId))!
            .DispositionMessage.Should().BeNull();
    }

    [Fact]
    public async Task GetRequestStatus_UnknownRequest_IsNull()
    {
        // What a database restored against a different CA looks like from here.
        // The caller must fall back to its own wording rather than treat this as
        // an explanation.
        (await _client.GetRequestStatusAsync(4242)).Should().BeNull();
    }

    [Fact]
    public async Task GetRequestStatus_ExplicitlyNoReason_CarriesNeitherHalf()
    {
        // The CA that explains nothing, which every caller's fallback exists for.
        _client.AutoApprove = false;
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateTestCsr("CN=silent.example.com"));
        _client.DenyRequest(submit.RequestId, dispositionMessage: null, statusCode: null);

        var status = await _client.GetRequestStatusAsync(submit.RequestId);

        status!.Status.Should().Be(CertificateStatus.Denied);
        status.DispositionMessage.Should().BeNull();
        status.StatusCode.Should().BeNull();
    }

    [Fact]
    public async Task QueryCertificates_DeniedRow_CarriesTheSameExplanationColumns()
    {
        // The inventory sync's view of the same row. These were hardcoded null
        // before issue #365, so the dev host's dashboard showed a denied request
        // with no reason where a live CA shows one.
        _client.AutoApprove = false;
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateTestCsr("CN=denied-row.example.com"));
        _client.DenyRequest(submit.RequestId);

        var results = await _client.QueryCertificatesAsync(
            new CertificateQuery(Status: CertificateStatus.Denied));

        results.Should().ContainSingle();
        results[0].DispositionMessage.Should().Be(MockAdcsClient.ManagerDenialMessage);
        results[0].StatusCode.Should().Be(CaStatusCode.AdminDeniedRequest);
    }

    #endregion

    [Fact]
    public async Task QueryCertificates_Pagination_RespectsSkipAndTake()
    {
        for (var i = 0; i < 5; i++)
        {
            await _client.SubmitCertificateRequestAsync("WebServer",
                GenerateTestCsr($"CN=cert{i}.example.com"));
        }

        var page1 = await _client.QueryCertificatesAsync(
            new CertificateQuery(Skip: 0, Take: 2));
        var page2 = await _client.QueryCertificatesAsync(
            new CertificateQuery(Skip: 2, Take: 2));

        page1.Should().HaveCount(2);
        page2.Should().HaveCount(2);
    }

    [Fact]
    public async Task QueryCertificates_SubjectContainsWithPaging_CountsFilteredResults()
    {
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=match-a.example.com"));
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=match-b.example.com"));
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=match-c.example.com"));
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=other.example.com"));

        // Three subjects contain "match". Skip and Take must page the filtered
        // results, not the raw rows, so Skip 1 / Take 1 returns exactly one match.
        var page = await _client.QueryCertificatesAsync(
            new CertificateQuery(SubjectContains: "match", Skip: 1, Take: 1));

        page.Should().HaveCount(1);
        page[0].Subject.Should().Contain("match");
    }

    // ── Subject rendering (issue #240) ──────────────────────────────────

    // A name both encoders spell the same way, one whose component count is
    // where a separator or an ordering difference would show, and the
    // adversarial one a requester chooses on an enrollee supplies subject
    // template. All three are inputs the platform encoder is already known to
    // accept; see DistinguishedNameParserTests.
    [Theory]
    [InlineData("CN=plain.example.com")]
    [InlineData("CN=leaf.example.com, OU=IT, O=Example")]
    [InlineData("CN=\"evil, O=Trusted Corp\", O=Real Org")]
    public async Task QueryCertificates_SubjectIsTheWindowsRenderingOfItsOwnDer(string subjectDn)
    {
        // The invariant the mock has to hold, rather than a spelling it happens
        // to produce today (issue #240). Every other producer of a
        // CertificateInfo.Subject renders through X509Certificate2, so the mock
        // reading back its own signed DER the same way is what makes a mock
        // backed test measure the shape a live host carries. Asserted against
        // the row's own RawCertificate rather than a hand written expected
        // string, so there is no second spelling here to drift from the first,
        // and no claim about which direction the encoders read a name in.
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateWindowsCsr(subjectDn));

        var results = await _client.QueryCertificatesAsync(new CertificateQuery());

        results.Should().ContainSingle();
        var info = results[0];
        info.RawCertificate.Should().NotBeNull();
        using var leaf = X509CertificateLoader.LoadCertificate(info.RawCertificate!);
        info.Subject.Should().Be(leaf.Subject);
    }

    [Fact]
    public async Task QueryCertificates_SkipsTheParseForAnAlreadyDetailedRow()
    {
        // The mock honours the skip the real client does, so the dev host and
        // mock backed tests see the same sync behaviour a live CA gives (issue
        // #184). Note the mock has no CA database subject columns to fall back
        // on, so a skipped row's subject is empty rather than merely missing its
        // last fallback; that is a shape the sync's blank guard already handles.
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateWindowsCsr("CN=skipped.example.com"));

        var full = await _client.QueryCertificatesAsync(new CertificateQuery());
        full.Single(c => c.RequestId == submit.RequestId).RawCertificate.Should().NotBeNull();

        var skipped = await _client.QueryCertificatesAsync(
            new CertificateQuery(AlreadyDetailed: new HashSet<int> { submit.RequestId }));

        var row = skipped.Single(c => c.RequestId == submit.RequestId);
        row.RawCertificate.Should().BeNull();
        row.CryptoDetail.Should().BeNull();
        row.SubjectAlternativeNames.Should().BeNull();
        row.Subject.Should().BeEmpty();
        // Everything the mock knows without opening the certificate survives.
        row.TemplateName.Should().Be("WebServer");
        row.Status.Should().Be(CertificateStatus.Issued);
    }

    [Fact]
    public async Task QueryCertificates_SubjectSearch_IgnoresTheSkipSet()
    {
        // A subject search runs on the mapped subject, and the parse is the only
        // thing that produces one here. Honouring both would make a search miss
        // exactly the rows it had already seen once.
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateWindowsCsr("CN=searchable.example.com"));

        var results = await _client.QueryCertificatesAsync(new CertificateQuery(
            SubjectContains: "searchable",
            AlreadyDetailed: new HashSet<int> { submit.RequestId }));

        results.Should().ContainSingle()
            .Which.RequestId.Should().Be(submit.RequestId);
    }

    [Fact]
    public async Task QueryCertificates_CommaBearingCommonName_CarriesTheWindowsQuotedForm()
    {
        // The shape the invariant above exists for, written out so the spelling
        // is a fact in the repository and not only an equality. A comma is legal
        // inside a common name and neither encoder drops it, but they disagree
        // about how: CertNameToStr wraps the whole value in quotes, the RFC 4514
        // form BouncyCastle renders puts a backslash in front instead. Issue #238
        // is a common name reader spoofed with exactly this, and while the mock
        // spoke the other dialect no mock backed test could reach the shape a
        // real certificate authority emits.
        const string commonName = "evil, O=Trusted Corp";

        await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateWindowsCsr($"CN=\"{commonName}\", O=Real Org"));

        var results = await _client.QueryCertificatesAsync(new CertificateQuery());

        results.Should().ContainSingle();
        var subject = results[0].Subject;
        subject.Should().Be("CN=\"evil, O=Trusted Corp\", O=Real Org");
        subject.Should().NotContain("\\,",
            "the Windows renderer quotes the value rather than escaping the comma");
        DistinguishedNameParser.CommonName(subject).Should().Be(commonName);
    }

    [Fact]
    public async Task QueryCertificates_SubjectContains_MatchesTheProjectedSubject()
    {
        // The filter has to read the same string the caller is handed back, the
        // way AdcsClient filters its mapped CertificateInfo rather than a raw CA
        // column. The search text is spelled the way X509Certificate2 renders a
        // name, with a comma and a space between components; BouncyCastle joins
        // with a bare comma, so matching its rendering finds nothing here. The
        // paging test above never noticed the split because a single component
        // name renders identically either way.
        await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateWindowsCsr("CN=paged.example.com, OU=IT, O=Example Corp"));
        await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateWindowsCsr("CN=other.example.com, OU=Sales, O=Example Corp"));

        var results = await _client.QueryCertificatesAsync(
            new CertificateQuery(SubjectContains: "OU=IT, O=Example Corp"));

        results.Should().ContainSingle();
        results[0].Subject.Should().Contain("paged.example.com");
    }

    [Fact]
    public async Task QueryCertificates_PendingRequest_HasNoSubjectRatherThanAPlaceholder()
    {
        // Nothing has been signed, so there is no name to read. An empty subject
        // is what the real client stores for a row it cannot name, and it is what
        // the sync's ACME backfill keys on to name the row from its order
        // identifier instead. A placeholder word is a name to every reader
        // downstream, and being non blank it switched that backfill off.
        _client.AutoApprove = false;
        await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateWindowsCsr("CN=pending.example.com"));

        var results = await _client.QueryCertificatesAsync(
            new CertificateQuery(Status: CertificateStatus.Pending));

        results.Should().ContainSingle();
        results[0].Subject.Should().BeEmpty();
        results[0].RawCertificate.Should().BeNull();
    }

    [Fact]
    public async Task QueryCertificates_HasSerialNumber()
    {
        await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=test.example.com"));

        var results = await _client.QueryCertificatesAsync(new CertificateQuery());

        results.Should().HaveCount(1);
        results[0].SerialNumber.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task SubmitCsr_IncrementingRequestIds()
    {
        var r1 = await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=a.example.com"));
        var r2 = await _client.SubmitCertificateRequestAsync("WebServer", GenerateTestCsr("CN=b.example.com"));

        r2.RequestId.Should().Be(r1.RequestId + 1);
    }

    [Fact]
    public async Task Revoke_FlipsStoredCertificateToRevoked()
    {
        var submit = await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateTestCsr("CN=revoke-me.example.com"));
        var cert = await _client.GetCertificateAsync(submit.RequestId);
        // Revoke with the X509Certificate2 serial form: uppercase and a
        // leading 00 pad, the way the ACME revoke endpoint supplies it.
        using var x509 = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(cert.CertificateDer!);

        await _client.RevokeCertificateAsync(x509.SerialNumber, reason: 4);

        var revoked = await _client.QueryCertificatesAsync(
            new CertificateQuery(Status: CertificateStatus.Revoked));
        revoked.Should().ContainSingle();
        revoked[0].RequestId.Should().Be(submit.RequestId);
        revoked[0].RevokedWhen.Should().NotBeNull();
        revoked[0].RevokedReason.Should().Be(4);
        revoked[0].Subject.Should().Contain("revoke-me.example.com");

        var issued = await _client.QueryCertificatesAsync(
            new CertificateQuery(Status: CertificateStatus.Issued));
        issued.Should().BeEmpty();
    }

    [Fact]
    public async Task Revoke_UnknownSerial_RecordsSerialWithoutFlipping()
    {
        await _client.SubmitCertificateRequestAsync(
            "WebServer", GenerateTestCsr("CN=stay.example.com"));

        await _client.RevokeCertificateAsync("DEADBEEF", reason: 0);

        _client.RevokedSerials.Should().Contain("DEADBEEF");
        var issued = await _client.QueryCertificatesAsync(
            new CertificateQuery(Status: CertificateStatus.Issued));
        issued.Should().ContainSingle();
    }

    #region Test Helpers

    /// <summary>
    /// A platform built request that also asks for subject alternative names,
    /// which is what every real client sends and what GenerateWindowsCsr above
    /// deliberately does not carry. An empty subject is a first class case here:
    /// it is the shape modern ACME clients emit.
    /// </summary>
    [Fact]
    public async Task IssuedLeaf_CarriesTheRootsKeyIdentifier_AndIsAddressableByAri()
    {
        // The ARI certificate identifier (RFC 9773 §4.1) is built from the
        // leaf's Authority Key Identifier, so the mock issues one the way real
        // ADCS always does; without it no mock issued certificate could be
        // addressed by ARI at all, on the dev host or in a test.
        var csr = GenerateCsrWithSans(
            "CN=aki.example.com", new[] { "aki.example.com" }, Array.Empty<string>());

        var submit = await _client.SubmitCertificateRequestAsync("WebServer", csr);
        var issued = await _client.GetCertificateAsync(submit.RequestId);

        using var leaf = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(issued.CertificateDer!);
        AriCertificateId.TryFromCertificate(leaf, out var keyId, out var serial)
            .Should().BeTrue("the leaf carries an AKI with a keyIdentifier");

        var chain = await _client.GetCaCertificateChainAsync();
        using var root = System.Security.Cryptography.X509Certificates.X509CertificateLoader
            .LoadCertificate(chain[0]);
        var rootSki = root.Extensions.OfType<X509SubjectKeyIdentifierExtension>()
            .Should().ContainSingle("the root carries the SKI the leaves point back at")
            .Subject;
        keyId.Should().Equal(Convert.FromHexString(rootSki.SubjectKeyIdentifier!),
            "a leaf's AKI keyid names its issuer's SKI, as on a real chain");

        // The serial half's uppercase hex is exactly the stored
        // AcmeCertificate.SerialNumber form, which is the database lookup key.
        // The mock's 120 bit prime serials always set the top bit, so the DER
        // sign pad byte is always present and this pins its round trip.
        serial.Should().HaveCount(16);
        serial[0].Should().Be(0);
        AriCertificateId.SerialHex(serial).Should().Be(leaf.SerialNumber);

        AriCertificateId.TryParse(
                AriCertificateId.FromCertificate(leaf), out var parsedKeyId, out var parsedSerial)
            .Should().BeTrue();
        parsedKeyId.Should().Equal(keyId);
        parsedSerial.Should().Equal(serial);
    }

    private static byte[] GenerateCsrWithSans(
        string subjectDn, string[] dnsNames, string[] ipAddresses)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subjectDn),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var sans = new SubjectAlternativeNameBuilder();
        foreach (var dns in dnsNames)
            sans.AddDnsName(dns);
        foreach (var ip in ipAddresses)
            sans.AddIpAddress(System.Net.IPAddress.Parse(ip));
        request.CertificateExtensions.Add(sans.Build());

        return request.CreateSigningRequest();
    }

    /// <summary>
    /// Generates a DER-encoded PKCS#10 CSR for testing.
    /// </summary>
    private static byte[] GenerateTestCsr(string subjectDn)
    {
        var keyPairGen = new RsaKeyPairGenerator();
        keyPairGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = keyPairGen.GenerateKeyPair();

        var subject = new X509Name(subjectDn);
        var csr = new Pkcs10CertificationRequest(
            "SHA256WithRSA",
            subject,
            keyPair.Public,
            null,
            keyPair.Private);

        return csr.GetDerEncoded();
    }

    /// <summary>
    /// A DER encoded PKCS#10 request whose subject the platform encoder built,
    /// rather than BouncyCastle's.
    ///
    /// Every request this product actually issues is built this way: real ACME
    /// clients, TlsCertificateEnroller.BuildCsr, and the CSR helpers in
    /// Certus.Web.Tests. The two encoders need not agree about which direction
    /// the written order and the encoded order run in, so a multi component name
    /// built by GenerateTestCsr above can read back in a different order than the
    /// same name built here. Subject tests use this one, so what they measure is
    /// the shape a live host carries.
    /// </summary>
    private static byte[] GenerateWindowsCsr(string subjectDn)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subjectDn),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return request.CreateSigningRequest();
    }

    #endregion

    public void Dispose()
    {
        // MockAdcsClient doesn't implement IDisposable but we keep the pattern for consistency
    }
}
