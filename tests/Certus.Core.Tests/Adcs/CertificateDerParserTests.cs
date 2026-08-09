using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for the shared DER parse behind the certificate inventory. The CA view
/// already returns every certificate's raw bytes alongside its row, so all of
/// this costs no CA round trip; what matters is that the values match the
/// certificate and that a certificate missing an extension, or a blob that is
/// not a certificate at all, degrades to null instead of losing the row.
/// </summary>
public class CertificateDerParserTests
{
    // ── Subject and SANs ────────────────────────────────────────────────

    [Fact]
    public void Parse_NoSanExtension_ReturnsNullSans()
    {
        var der = CreateRsaCertificate("CN=plain.example.com", sanSetup: null);

        var parsed = CertificateDerParser.Parse(der);

        parsed.Should().NotBeNull();
        parsed!.Subject.Should().Be("CN=plain.example.com");
        parsed.SubjectAlternativeNames.Should().BeNull();
    }

    [Fact]
    public void Parse_SanOnlyCertificate_ReturnsEmptySubjectAndSans()
    {
        // A SAN only certificate (typical ACME issuance): empty subject DN,
        // identity carried entirely in the SAN extension.
        var der = CreateRsaCertificate("", san => san.AddDnsName("linux.example.com"));

        var parsed = CertificateDerParser.Parse(der);

        parsed.Should().NotBeNull();
        parsed!.Subject.Should().BeEmpty();
        parsed.SubjectAlternativeNames.Should().Be("dns:linux.example.com");
    }

    [Fact]
    public void Parse_MixedSans_FormatsDnsThenIp()
    {
        var der = CreateRsaCertificate("CN=web01.example.com", san =>
        {
            san.AddDnsName("web01.example.com");
            san.AddDnsName("alt.example.com");
            san.AddIpAddress(IPAddress.Parse("10.0.0.5"));
        });

        var parsed = CertificateDerParser.Parse(der);

        parsed!.SubjectAlternativeNames.Should().Be(
            "dns:web01.example.com, dns:alt.example.com, ip:10.0.0.5");
    }

    // ── Key algorithm and size ──────────────────────────────────────────

    [Fact]
    public void Parse_Rsa2048_ReportsAlgorithmAndSize()
    {
        var der = CreateRsaCertificate("CN=rsa.example.com", sanSetup: null, keySize: 2048);

        var crypto = CertificateDerParser.Parse(der)!.Crypto;

        crypto.KeyAlgorithm.Should().Be("RSA");
        crypto.KeySizeBits.Should().Be(2048);
    }

    [Fact]
    public void Parse_Rsa4096_ReportsTheLargerSize()
    {
        var der = CreateRsaCertificate("CN=rsa4096.example.com", sanSetup: null, keySize: 4096);

        var crypto = CertificateDerParser.Parse(der)!.Crypto;

        crypto.KeyAlgorithm.Should().Be("RSA");
        crypto.KeySizeBits.Should().Be(4096);
    }

    [Theory]
    [InlineData(nameof(ECCurve.NamedCurves.nistP256), 256)]
    [InlineData(nameof(ECCurve.NamedCurves.nistP384), 384)]
    public void Parse_Ecdsa_ReportsAlgorithmAndCurveSize(string curveName, int expectedBits)
    {
        var curve = curveName == nameof(ECCurve.NamedCurves.nistP256)
            ? ECCurve.NamedCurves.nistP256
            : ECCurve.NamedCurves.nistP384;
        var der = CreateEcdsaCertificate("CN=ecdsa.example.com", curve);

        var crypto = CertificateDerParser.Parse(der)!.Crypto;

        crypto.KeyAlgorithm.Should().Be("ECDSA");
        crypto.KeySizeBits.Should().Be(expectedBits);
    }

    // ── Signature algorithm and thumbprint ──────────────────────────────

    [Fact]
    public void Parse_ReportsSignatureAlgorithmAsAnOid()
    {
        // sha256RSA. Stored as the OID, not Oid.FriendlyName, because the
        // friendly name resolves through the Windows OID table and is locale
        // dependent, so a non English CA host would persist localized strings.
        var der = CreateRsaCertificate("CN=sig.example.com", sanSetup: null);

        var crypto = CertificateDerParser.Parse(der)!.Crypto;

        crypto.SignatureAlgorithmOid.Should().Be("1.2.840.113549.1.1.11");
    }

    [Fact]
    public void Parse_ThumbprintIsSha256OfTheDer()
    {
        // Independently computed, so this fails if the implementation ever
        // reaches for X509Certificate2.Thumbprint, which is SHA-1.
        var der = CreateRsaCertificate("CN=thumb.example.com", sanSetup: null);
        var expected = Convert.ToHexString(SHA256.HashData(der));

        var crypto = CertificateDerParser.Parse(der)!.Crypto;

        crypto.Sha256Thumbprint.Should().Be(expected);
        crypto.Sha256Thumbprint.Should().HaveLength(64);
    }

    // ── EKU and key usage ───────────────────────────────────────────────

    [Fact]
    public void Parse_ReportsExtendedKeyUsageOidsInCertificateOrder()
    {
        const string serverAuth = "1.3.6.1.5.5.7.3.1";
        const string clientAuth = "1.3.6.1.5.5.7.3.2";
        var der = CreateRsaCertificate("CN=eku.example.com", sanSetup: null, extensions: request =>
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(serverAuth), new Oid(clientAuth) },
                critical: false)));

        var crypto = CertificateDerParser.Parse(der)!.Crypto;

        crypto.ExtendedKeyUsageOids.Should().Be($"{serverAuth}, {clientAuth}");
    }

    [Fact]
    public void Parse_ReportsKeyUsageAsTheRawFlags()
    {
        const X509KeyUsageFlags flags =
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment;
        var der = CreateRsaCertificate("CN=ku.example.com", sanSetup: null, extensions: request =>
            request.CertificateExtensions.Add(new X509KeyUsageExtension(flags, critical: false)));

        var crypto = CertificateDerParser.Parse(der)!.Crypto;

        crypto.KeyUsage.Should().Be((int)flags);
    }

    [Fact]
    public void Parse_NoEkuOrKeyUsageExtension_LeavesThoseNullAndTheRestPopulated()
    {
        // Null EKU means the certificate carries no EKU extension at all, which
        // is "no restriction" and a different thing from an empty list. The
        // absence must not cost the fields that are present.
        var der = CreateRsaCertificate("CN=bare.example.com", sanSetup: null);

        var crypto = CertificateDerParser.Parse(der)!.Crypto;

        crypto.ExtendedKeyUsageOids.Should().BeNull();
        crypto.KeyUsage.Should().BeNull();
        crypto.KeyAlgorithm.Should().Be("RSA");
        crypto.KeySizeBits.Should().Be(2048);
        crypto.Sha256Thumbprint.Should().NotBeNullOrEmpty();
        crypto.SignatureAlgorithmOid.Should().NotBeNullOrEmpty();
    }

    // ── ParseCapability ─────────────────────────────────────────────────

    [Fact]
    public void ParseCapability_ReadsEkuKeyUsageAndBasicConstraints()
    {
        const string serverAuth = "1.3.6.1.5.5.7.3.1";
        const X509KeyUsageFlags flags = X509KeyUsageFlags.DigitalSignature;
        var der = CreateRsaCertificate("CN=cap.example.com", sanSetup: null, extensions: request =>
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(serverAuth) }, critical: false));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(flags, critical: false));
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0,
                critical: true));
        });

        var capability = CertificateDerParser.ParseCapability(der);

        capability.Should().NotBeNull();
        capability!.ExtendedKeyUsageOids.Should().Equal(serverAuth);
        capability.KeyUsage.Should().Be(flags);
        capability.IsCa.Should().BeFalse();
    }

    [Fact]
    public void ParseCapability_BareLeaf_ReadsAllThreeAsAbsent()
    {
        // No EKU, no KU, no BasicConstraints: all three come back null, and
        // the ceiling decides what absence means, not the parser.
        var der = CreateRsaCertificate("CN=bare-cap.example.com", sanSetup: null);

        var capability = CertificateDerParser.ParseCapability(der);

        capability.Should().NotBeNull();
        capability!.ExtendedKeyUsageOids.Should().BeNull();
        capability.KeyUsage.Should().BeNull();
        capability.IsCa.Should().BeNull();
    }

    [Fact]
    public void ParseCapability_CaCertificate_ReadsIsCaTrue()
    {
        var der = CreateRsaCertificate("CN=ca-cap.example.com", sanSetup: null, extensions: request =>
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0,
                critical: true)));

        var capability = CertificateDerParser.ParseCapability(der);

        capability!.IsCa.Should().BeTrue();
    }

    [Fact]
    public void ParseCapability_GarbageAndEmptyInput_ReturnNullWithoutThrowing()
    {
        // Callers treat null as fail closed, so the undecodable cases must
        // land there rather than throw.
        var garbage = () => CertificateDerParser.ParseCapability(new byte[] { 0x00, 0x01, 0x02 });
        var empty = () => CertificateDerParser.ParseCapability(Array.Empty<byte>());

        garbage.Should().NotThrow();
        garbage().Should().BeNull();
        empty.Should().NotThrow();
        empty().Should().BeNull();
    }

    // ── Failure handling ────────────────────────────────────────────────

    [Fact]
    public void Parse_NotACertificate_ReturnsNullWithoutThrowing()
    {
        // A garbage blob throws CryptographicException straight out of the
        // X509Certificate2 constructor, which the parser catches.
        var act = () => CertificateDerParser.Parse(new byte[] { 0x00, 0x01, 0x02, 0x03 });

        act.Should().NotThrow();
        act().Should().BeNull();
    }

    [Fact]
    public void Parse_EmptyInput_ReturnsNullWithoutThrowing()
    {
        // The parser guards empty input up front instead of relying on the
        // catch. History: the pre net10 X509Certificate2 byte constructor
        // accepted an empty array and handed back a zero handle that only
        // threw on the first property read, well past the constructor's
        // try/catch (probed on net8.0, .NET 8.0.29). The
        // X509CertificateLoader.LoadCertificate path parses eagerly, but the
        // guard stays: it also rejects null, which the loader surfaces as
        // ArgumentNullException rather than CryptographicException. A CA row
        // with a null RawCertificate column arrives exactly like this, so
        // removing the guard drops the whole certificate from the sync.
        var act = () => CertificateDerParser.Parse(Array.Empty<byte>());

        act.Should().NotThrow();
        act().Should().BeNull();
    }

    [Fact]
    public void Parse_UnreadableField_DoesNotCostTheOtherFields()
    {
        // The contract the class doc promises: a field that cannot be read
        // comes back null on its own, and never takes the rest of the
        // certificate, or the row, down with it. Every reader is individually
        // guarded, so a well formed certificate always yields a non null result
        // with its readable fields intact.
        var der = CreateRsaCertificate("CN=partial.example.com", sanSetup: null);

        var parsed = CertificateDerParser.Parse(der);

        parsed.Should().NotBeNull();
        parsed!.Subject.Should().Be("CN=partial.example.com");
        parsed.Crypto.KeyAlgorithm.Should().NotBeNull();
        parsed.Crypto.SignatureAlgorithmOid.Should().NotBeNull();
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static byte[] CreateRsaCertificate(
        string subject,
        Action<SubjectAlternativeNameBuilder>? sanSetup,
        int keySize = 2048,
        Action<CertificateRequest>? extensions = null)
    {
        using var key = RSA.Create(keySize);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return Finish(request, sanSetup, extensions);
    }

    private static byte[] CreateEcdsaCertificate(string subject, ECCurve curve)
    {
        using var key = ECDsa.Create(curve);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject),
            key,
            HashAlgorithmName.SHA256);

        return Finish(request, sanSetup: null, extensions: null);
    }

    private static byte[] Finish(
        CertificateRequest request,
        Action<SubjectAlternativeNameBuilder>? sanSetup,
        Action<CertificateRequest>? extensions)
    {
        if (sanSetup != null)
        {
            var builder = new SubjectAlternativeNameBuilder();
            sanSetup(builder);
            request.CertificateExtensions.Add(builder.Build());
        }

        extensions?.Invoke(request);

        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return cert.Export(X509ContentType.Cert);
    }
}
