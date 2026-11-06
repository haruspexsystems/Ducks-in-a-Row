using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

namespace Certus.Core.Tests.Security;

/// <summary>
/// Tests for <see cref="IssuedKeyCheck"/>, the key half of the leaf guard
/// (issue #604): a certificate is the order's only when it carries the key of
/// the CSR the order claimed. The end to end shape, an order collecting
/// another CA's certificate after the install was pointed at it, is in
/// <c>PendingIssuanceTests</c>.
/// </summary>
public class IssuedKeyCheckTests
{
    [Fact]
    public void Evaluate_LeafCarriesTheCsrsRsaKey_Ok()
    {
        using var key = RSA.Create(2048);

        var verdict = IssuedKeyCheck.Evaluate(LeafFor(key), CsrFor(key));

        verdict.Should().Be(CeilingVerdict.Ok);
    }

    [Fact]
    public void Evaluate_LeafCarriesTheCsrsEcKey_Ok()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var verdict = IssuedKeyCheck.Evaluate(LeafFor(key), CsrFor(key));

        verdict.Should().Be(CeilingVerdict.Ok);
    }

    [Fact]
    public void Evaluate_LeafCarriesAnotherKey_RefusesAsKeyMismatch()
    {
        // The #604 shape: another requester's certificate under the same CA
        // request id, issued for a key this order's client does not hold.
        using var ordered = RSA.Create(2048);
        using var other = RSA.Create(2048);

        var verdict = IssuedKeyCheck.Evaluate(LeafFor(other), CsrFor(ordered));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("key-mismatch");
    }

    [Fact]
    public void Evaluate_LeafCarriesAKeyOfAnotherAlgorithm_RefusesAsKeyMismatch()
    {
        using var ordered = RSA.Create(2048);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var verdict = IssuedKeyCheck.Evaluate(LeafFor(other), CsrFor(ordered));

        verdict.ReasonCode.Should().Be("key-mismatch");
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[0])]
    public void Evaluate_NoCsrStored_Refuses(byte[]? csr)
    {
        // Erasure drops the CSR of every order under a deactivated account
        // (#637). Nothing then says which key the certificate should carry.
        using var key = RSA.Create(2048);

        var verdict = IssuedKeyCheck.Evaluate(LeafFor(key), csr);

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("key-no-csr");
    }

    [Fact]
    public void Evaluate_UnreadableLeaf_RefusesRatherThanThrows()
    {
        using var key = RSA.Create(2048);

        var verdict = IssuedKeyCheck.Evaluate([0x30, 0x03, 0x02, 0x01], CsrFor(key));

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("key-unreadable");
    }

    [Fact]
    public void Evaluate_UnreadableCsr_RefusesRatherThanThrows()
    {
        using var key = RSA.Create(2048);

        var verdict = IssuedKeyCheck.Evaluate(LeafFor(key), [0x04, 0x02, 0x00, 0x00]);

        verdict.Allowed.Should().BeFalse();
        verdict.ReasonCode.Should().Be("key-unreadable");
    }

    [Fact]
    public void SameKey_RsaParametersAbsentOnOneSideAndNullOnTheOther_IsTheSameKey()
    {
        // RFC 3279 asks for NULL parameters with rsaEncryption and some encoders
        // omit them. A CA that normalised one to the other must not turn the
        // order's own certificate into a refusal.
        using var key = RSA.Create(2048);
        var bits = KeyBits(key);

        var withNull = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance), bits);
        var withNone = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption), bits);

        IssuedKeyCheck.SameKey(withNull, withNone).Should().BeTrue();
        IssuedKeyCheck.SameKey(withNone, withNull).Should().BeTrue();
    }

    [Fact]
    public void SameKey_TheSameBitsOnAnotherCurve_IsNotTheSameKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bits = KeyBits(key);

        var p256 = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, SecObjectIdentifiers.SecP256r1), bits);
        var p384 = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, SecObjectIdentifiers.SecP384r1), bits);
        var absent = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey), bits);

        IssuedKeyCheck.SameKey(p256, p384).Should().BeFalse();
        IssuedKeyCheck.SameKey(p256, absent).Should().BeFalse(
            "only the rsaEncryption style NULL counts as no parameters");
    }

    private static byte[] CsrFor(RSA key) =>
        new CertificateRequest("CN=key.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSigningRequest();

    private static byte[] CsrFor(ECDsa key) =>
        new CertificateRequest("CN=key.example.com", key, HashAlgorithmName.SHA256)
            .CreateSigningRequest();

    private static byte[] LeafFor(RSA key)
    {
        using var cert = new CertificateRequest(
                "CN=key.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        return cert.RawData;
    }

    private static byte[] LeafFor(ECDsa key)
    {
        using var cert = new CertificateRequest("CN=key.example.com", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        return cert.RawData;
    }

    private static byte[] KeyBits(AsymmetricAlgorithm key) =>
        SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(key.ExportSubjectPublicKeyInfo()))
            .PublicKey.GetBytes();
}
