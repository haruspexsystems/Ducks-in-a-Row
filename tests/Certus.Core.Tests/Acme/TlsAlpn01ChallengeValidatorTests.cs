using Certus.Core.Acme.Services;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

public class TlsAlpn01ChallengeValidatorTests
{
    private static AddressGuard TestAddressGuard() =>
        new(Options.Create(new ChallengeValidationOptions()));

    [Fact]
    public void ChallengeType_IsTlsAlpn01()
    {
        var sut = new TlsAlpn01ChallengeValidator(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<TlsAlpn01ChallengeValidator>.Instance,
            TestAddressGuard());

        sut.ChallengeType.Should().Be("tls-alpn-01");
    }

    [Fact]
    public void ExtractDigest_ValidDerOctetString_Returns32Bytes()
    {
        // Build a valid DER OCTET STRING: tag=0x04, length=0x20, then 32 bytes
        var hash = new byte[32];
        for (var i = 0; i < 32; i++) hash[i] = (byte)i;

        var der = new byte[34];
        der[0] = 0x04; // OCTET STRING tag
        der[1] = 0x20; // length = 32
        Array.Copy(hash, 0, der, 2, 32);

        var result = TlsAlpn01ChallengeValidator.ExtractDigestFromAcmeIdentifierExtension(der);

        result.Should().NotBeNull();
        result.Should().BeEquivalentTo(hash);
    }

    [Fact]
    public void ExtractDigest_Raw32Bytes_Returns32Bytes()
    {
        // Some implementations may pass just the raw 32 bytes without ASN.1 wrapper
        var hash = new byte[32];
        for (var i = 0; i < 32; i++) hash[i] = (byte)(255 - i);

        var result = TlsAlpn01ChallengeValidator.ExtractDigestFromAcmeIdentifierExtension(hash);

        result.Should().NotBeNull();
        result.Should().BeEquivalentTo(hash);
    }

    [Fact]
    public void ExtractDigest_TooShort_ReturnsNull()
    {
        var result = TlsAlpn01ChallengeValidator.ExtractDigestFromAcmeIdentifierExtension(
            new byte[] { 0x04, 0x10 }); // only 2 bytes, way too short

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractDigest_WrongTag_ReturnsNull()
    {
        // Wrong ASN.1 tag (0x30 = SEQUENCE instead of 0x04 = OCTET STRING)
        var der = new byte[34];
        der[0] = 0x30; // wrong tag
        der[1] = 0x20;

        var result = TlsAlpn01ChallengeValidator.ExtractDigestFromAcmeIdentifierExtension(der);

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractDigest_WrongLength_ReturnsNull()
    {
        // Correct tag but wrong length
        var der = new byte[34];
        der[0] = 0x04;
        der[1] = 0x10; // claims 16 bytes, not 32

        var result = TlsAlpn01ChallengeValidator.ExtractDigestFromAcmeIdentifierExtension(der);

        result.Should().BeNull();
    }

    [Fact]
    public async Task Validate_UnreachableHost_ReturnsConnectionError()
    {
        // Use a very short timeout and a non-routable address
        var sut = new TlsAlpn01ChallengeValidator(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<TlsAlpn01ChallengeValidator>.Instance,
            TestAddressGuard(),
            TimeSpan.FromMilliseconds(500));

        // 192.0.2.1 is TEST-NET-1 — guaranteed non-routable
        var result = await sut.ValidateAsync(new ChallengeValidationContext(
            "dns", "192.0.2.1", "test-token", "test-thumbprint", "test-template"));

        result.IsValid.Should().BeFalse();
        result.ErrorDetail.Should().NotBeNullOrEmpty();
        result.Transient.Should().BeTrue(); // a timeout is a transport failure, not a wrong answer
    }

    [Fact]
    public void AcmeIdentifierOid_IsCorrect()
    {
        // RFC 8737 §3 defines this OID
        TlsAlpn01ChallengeValidator.AcmeIdentifierOid.Should().Be("1.3.6.1.5.5.7.1.31");
    }
}
