using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Services;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// The ARI certificate identifier codec against RFC 9773's own Appendix A
/// example, which is the interop proof: a client builds this string from the
/// certificate alone, so both directions must land on the RFC's exact bytes.
/// </summary>
public class AriCertificateIdTests
{
    // RFC 9773 Appendix A: the AKI keyIdentifier octets ...
    private static readonly byte[] VectorKeyId =
    {
        0x69, 0x88, 0x5B, 0x6B, 0x87, 0x46, 0x40, 0x41, 0xE1, 0xB3,
        0x7B, 0x84, 0x7B, 0xA0, 0xAE, 0x2C, 0xDE, 0x01, 0xC8, 0xD4
    };

    // ... and the serial's DER content octets, sign pad byte included, for the
    // integer 0x87654321.
    private static readonly byte[] VectorSerial = { 0x00, 0x87, 0x65, 0x43, 0x21 };

    private const string Vector = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

    [Fact]
    public void Format_MatchesTheRfcAppendixAVector()
    {
        AriCertificateId.Format(VectorKeyId, VectorSerial).Should().Be(Vector);
    }

    [Fact]
    public void TryParse_RoundTripsTheRfcAppendixAVector()
    {
        AriCertificateId.TryParse(Vector, out var keyId, out var serial).Should().BeTrue();

        keyId.Should().Equal(VectorKeyId);
        serial.Should().Equal(VectorSerial);
    }

    [Fact]
    public void SerialHex_IsTheStoredSerialNumberForm()
    {
        // Uppercase hex of the content octets, which is exactly what
        // X509Certificate2.SerialNumber returns and AcmeCertificate.SerialNumber
        // stores, so the identifier's serial half is the database lookup key.
        AriCertificateId.SerialHex(VectorSerial).Should().Be("0087654321");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("noperiod")]
    [InlineData("two.periods.here")]
    [InlineData(".emptyleft")]
    [InlineData("emptyright.")]
    // RFC 9773 §4.1: all trailing '=' MUST be stripped, so padding is a refusal
    // even though the permissive JWS decoder would accept it.
    [InlineData("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE=")]
    // Standard base64 alphabet, not base64url.
    [InlineData("aYhba+dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")]
    [InlineData("aYhba/dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")]
    [InlineData("aYhba dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")]
    // A half whose length is impossible for base64 (4n + 1 characters).
    [InlineData("AAAAA.AA")]
    public void TryParse_RefusesAnythingButStrictSyntax(string? value)
    {
        AriCertificateId.TryParse(value, out _, out _).Should().BeFalse();
    }

    [Fact]
    public void TryParse_RefusesAnOverlongIdentifier()
    {
        var value = new string('A', 300) + ".AA";

        AriCertificateId.TryParse(value, out _, out _).Should().BeFalse();
    }

    [Fact]
    public void FromCertificate_ReadsTheVectorOutOfARealCertificate()
    {
        // The serial is handed to .NET without the pad byte: Create() encodes
        // the DER integer, adding the 0x00 the high bit demands, and
        // SerialNumberBytes hands the content octets back pad included. This is
        // the test that pins those platform semantics: if either side ever
        // trimmed the pad, the identifier would stop matching what a client
        // computes from the same certificate.
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=ari-appendix-a", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(VectorKeyId));
        using var cert = request.Create(
            new X500DistinguishedName("CN=ari-appendix-a"),
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30),
            new byte[] { 0x87, 0x65, 0x43, 0x21 });

        AriCertificateId.FromCertificate(cert).Should().Be(Vector);

        AriCertificateId.TryFromCertificate(cert, out var keyId, out var serial).Should().BeTrue();
        keyId.Should().Equal(VectorKeyId);
        serial.Should().Equal(VectorSerial);
        AriCertificateId.SerialHex(serial).Should().Be(cert.SerialNumber);
    }

    [Fact]
    public void FromCertificate_IsNullWithoutAnAuthorityKeyIdentifier()
    {
        // A certificate with no AKI cannot be addressed by ARI at all (the
        // client builds the identifier from the same extension), so the codec
        // says so rather than inventing a value.
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=no-aki", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        AriCertificateId.FromCertificate(cert).Should().BeNull();
        AriCertificateId.TryFromCertificate(cert, out _, out _).Should().BeFalse();
    }
}
