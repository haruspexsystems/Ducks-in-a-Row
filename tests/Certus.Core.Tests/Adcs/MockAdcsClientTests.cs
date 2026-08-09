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

    #endregion

    public void Dispose()
    {
        // MockAdcsClient doesn't implement IDisposable but we keep the pattern for consistency
    }
}
