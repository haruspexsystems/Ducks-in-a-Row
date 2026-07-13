using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Unit tests for AdcsClient.OrderChainLeafFirst, the ordering behind the CA
/// certificate downloads: a PKCS#7 from CR_PROP_CASIGCERTCHAIN carries the
/// certificates in no guaranteed order, and the settings page presents them
/// issuing CA first, root last.
/// </summary>
public class OrderChainLeafFirstTests
{
    [Fact]
    public void TwoTierChainInAnyOrder_ComesBackIssuingFirstRootLast()
    {
        using var root = MintSelfSignedCa("CN=Test Root CA");
        using var issuing = MintSubordinateCa("CN=Test Issuing CA", root);

        // Deliberately root first: the input order must not matter.
        var ordered = Certus.Adcs.AdcsClient.OrderChainLeafFirst(new[] { root, issuing });

        ordered.Should().HaveCount(2);
        ordered[0].Should().Equal(issuing.RawData);
        ordered[1].Should().Equal(root.RawData);
    }

    [Fact]
    public void ThreeTierShuffled_WalksTheFullChain()
    {
        using var root = MintSelfSignedCa("CN=Test Root CA");
        using var intermediate = MintSubordinateCa("CN=Test Intermediate CA", root);
        using var issuing = MintSubordinateCa("CN=Test Issuing CA", intermediate);

        var ordered = Certus.Adcs.AdcsClient.OrderChainLeafFirst(
            new[] { root, issuing, intermediate });

        ordered.Should().HaveCount(3);
        ordered[0].Should().Equal(issuing.RawData);
        ordered[1].Should().Equal(intermediate.RawData);
        ordered[2].Should().Equal(root.RawData);
    }

    [Fact]
    public void SingleSelfSignedCertificate_IsItsOwnLeafAndRoot()
    {
        using var root = MintSelfSignedCa("CN=Test Root CA");

        var ordered = Certus.Adcs.AdcsClient.OrderChainLeafFirst(new[] { root });

        ordered.Should().ContainSingle().Which.Should().Equal(root.RawData);
    }

    [Fact]
    public void EmptyInput_ReturnsEmpty()
    {
        Certus.Adcs.AdcsClient.OrderChainLeafFirst(Array.Empty<X509Certificate2>())
            .Should().BeEmpty();
    }

    #region Test helpers

    private static X509Certificate2 MintSelfSignedCa(string subject)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 2, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    }

    private static X509Certificate2 MintSubordinateCa(string subject, X509Certificate2 issuer)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        if (serial[0] == 0) serial[0] = 1;
        // Derive the validity window from the issuer instead of the clock:
        // two subordinates minted a tick apart with the same clock based
        // notAfter can exceed their issuer's notAfter by a second, which
        // CertificateRequest.Create rejects.
        using var unsigned = req.Create(issuer, issuer.NotBefore,
            issuer.NotAfter.AddDays(-1), serial);
        return unsigned.CopyWithPrivateKey(rsa);
    }

    #endregion
}
