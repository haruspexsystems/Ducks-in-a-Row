using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Services;

namespace Certus.Core.Tests.Acme;

public class CsrHelperTests
{
    [Fact]
    public void ExtractSansFromCsr_WithSanExtension_ReturnsDnsNames()
    {
        // Create a CSR with a SAN extension using .NET crypto
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=test.example.com",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add SAN extension
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("test.example.com");
        sanBuilder.AddDnsName("www.example.com");
        request.CertificateExtensions.Add(sanBuilder.Build());

        var csrDer = request.CreateSigningRequest();

        var sans = CsrHelper.ExtractSansFromCsr(csrDer);

        sans.Should().HaveCount(2);
        sans.Should().Contain("test.example.com");
        sans.Should().Contain("www.example.com");
    }

    [Fact]
    public void ExtractSansFromCsr_WithoutSan_FallsBackToCn()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=fallback.example.com",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var csrDer = request.CreateSigningRequest();

        var sans = CsrHelper.ExtractSansFromCsr(csrDer);

        sans.Should().HaveCount(1);
        sans[0].Should().Be("fallback.example.com");
    }

    [Fact]
    public void ExtractSansFromCsr_InvalidCsr_Throws()
    {
        var badCsr = new byte[] { 0x30, 0x03, 0x01, 0x01, 0xFF };

        var act = () => CsrHelper.ExtractSansFromCsr(badCsr);

        act.Should().Throw<Exception>();
    }

    [Fact]
    public void ExtractSansFromCsr_MultipleDnsNames_ReturnsAll()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=main.example.com",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("a.example.com");
        sanBuilder.AddDnsName("b.example.com");
        sanBuilder.AddDnsName("c.example.com");
        request.CertificateExtensions.Add(sanBuilder.Build());

        var csrDer = request.CreateSigningRequest();
        var sans = CsrHelper.ExtractSansFromCsr(csrDer);

        sans.Should().HaveCount(3);
        sans.Should().Contain("a.example.com");
        sans.Should().Contain("b.example.com");
        sans.Should().Contain("c.example.com");
    }
}
