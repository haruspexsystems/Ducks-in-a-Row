using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Tests.Shared;

/// <summary>
/// A certificate authority for the suite: a self signed root, code signing leaves and a timestamp
/// authority, all with RSA keys made in memory and never touching a store. The module host's
/// signature check takes the root as a trust anchor (<c>ModuleSignaturePolicy</c>), so the tests
/// prove the check with a chain of their own and the production policy stays pinned to the
/// Haruspex publisher and the Windows root store (issue #636). Never a production key.
/// </summary>
public sealed class TestSigningAuthority : IDisposable
{
    private readonly RSA _rootKey;
    private long _serial = 1;

    public TestSigningAuthority(string name = "Certus Test Root", DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        _rootKey = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}, O=Certus Tests", _rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        Root = request.CreateSelfSigned(notBefore ?? new DateTimeOffset(2019, 1, 1, 0, 0, 0, TimeSpan.Zero), notAfter ?? new DateTimeOffset(2049, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }

    /// <summary>The root, with its private key.</summary>
    public X509Certificate2 Root { get; }

    /// <summary>The root as a trust anchor: the certificate alone, no key.</summary>
    public X509Certificate2Collection Anchors => [X509CertificateLoader.LoadCertificate(Root.RawData)];

    /// <summary>A code signing certificate for <paramref name="commonName"/> and <paramref name="organisation"/>, valid over the given period.</summary>
    public SigningIdentity IssueCodeSigning(string commonName, string organisation, DateTimeOffset notBefore, DateTimeOffset notAfter) =>
        Issue($"CN={Escape(commonName)}, O={Escape(organisation)}", notBefore, notAfter, new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.3")], false));

    /// <summary>
    /// A timestamp authority certificate. RFC 3161 wants exactly one extended key usage, the
    /// timestamping one, marked critical; .NET's token verification holds the authority to it.
    /// </summary>
    public SigningIdentity IssueTimeStamping(string commonName, DateTimeOffset notBefore, DateTimeOffset notAfter) =>
        Issue($"CN={Escape(commonName)}, O=Certus Tests", notBefore, notAfter, new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], true));

    private SigningIdentity Issue(string subject, DateTimeOffset notBefore, DateTimeOffset notAfter, X509Extension usage)
    {
        var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(usage);
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Root, true, false));

        var serial = BitConverter.GetBytes(Interlocked.Increment(ref _serial));
        Array.Reverse(serial);
        var certificate = request.Create(Root, notBefore, notAfter, serial);
        return new SigningIdentity(certificate, key);
    }

    /// <summary>A distinguished name attribute value, quoted when it holds a comma or an equals sign.</summary>
    private static string Escape(string value)
    {
        var inner = value.Replace("\"", "\"\"");
        return inner.Contains(',') || inner.Contains('=') ? $"\"{inner}\"" : inner;
    }

    public void Dispose()
    {
        Root.Dispose();
        _rootKey.Dispose();
    }
}

/// <summary>A certificate and the private key that goes with it, kept apart so the key never has to enter a store.</summary>
public sealed record SigningIdentity(X509Certificate2 Certificate, RSA Key) : IDisposable
{
    public void Dispose()
    {
        Certificate.Dispose();
        Key.Dispose();
    }
}

/// <summary>
/// Signs test fixtures the way signtool does: an Authenticode signature in a PE file's
/// certificate table, or a detached CMS signature over any file, each with an RFC 3161 timestamp
/// from a test authority when asked. The PE hash here is computed independently of the
/// production verifier, by skipping the checksum and the certificate table directory entry of an
/// image that has no certificate table yet, so the two implementations check each other.
/// </summary>
public static class AuthenticodeTestSigner
{
    private const string SpcIndirectDataOid = "1.3.6.1.4.1.311.2.1.4";
    private const string SpcPeImageDataOid = "1.3.6.1.4.1.311.2.1.15";
    private const string Rfc3161CounterSignatureOid = "1.3.6.1.4.1.311.3.3.1";
    private const string TstInfoOid = "1.2.840.113549.1.9.16.1.4";
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    /// <summary>
    /// <paramref name="image"/>, an unsigned PE file, with an Authenticode signature by
    /// <paramref name="signer"/> appended. With <paramref name="timestamper"/> the signature carries
    /// an RFC 3161 timestamp certifying <paramref name="timestampedAt"/>.
    /// </summary>
    public static byte[] SignPortableExecutable(
        byte[] image, SigningIdentity signer, SigningIdentity? timestamper = null, DateTimeOffset? timestampedAt = null, HashAlgorithmName? fileDigest = null)
    {
        // The file digest algorithm (signtool's /fd); SHA-256 unless a test asks for the SHA-1 the
        // verifier refuses. The signature's own digest stays SHA-256 either way.
        var digestAlgorithm = fileDigest ?? HashAlgorithmName.SHA256;
        var digestOid = digestAlgorithm == HashAlgorithmName.SHA1 ? "1.3.14.3.2.26" : Sha256Oid;
        // The certificate table starts on an 8 byte boundary, and the padding counts as file
        // data the signature covers, so pad first and hash second.
        var padded = new byte[(image.Length + 7) & ~7];
        image.CopyTo(padded, 0);

        var (checksumOffset, directoryOffset) = Offsets(padded);
        if (BitConverter.ToInt32(padded, directoryOffset + 4) != 0)
            throw new InvalidOperationException("the image already carries a certificate table");

        using var hash = IncrementalHash.CreateHash(digestAlgorithm);
        hash.AppendData(padded, 0, checksumOffset);
        hash.AppendData(padded, checksumOffset + 4, directoryOffset - (checksumOffset + 4));
        hash.AppendData(padded, directoryOffset + 8, padded.Length - (directoryOffset + 8));
        var digest = hash.GetHashAndReset();

        var cms = new SignedCms(new ContentInfo(new Oid(SpcIndirectDataOid), IndirectData(digest, digestOid)), detached: false);
        Sign(cms, signer, timestamper, timestampedAt);
        var pkcs7 = cms.Encode();

        var entryLength = 8 + pkcs7.Length;
        var tableLength = (entryLength + 7) & ~7;
        var signed = new byte[padded.Length + tableLength];
        padded.CopyTo(signed, 0);
        BitConverter.GetBytes(padded.Length).CopyTo(signed, directoryOffset);
        BitConverter.GetBytes(tableLength).CopyTo(signed, directoryOffset + 4);
        BitConverter.GetBytes(entryLength).CopyTo(signed, padded.Length);
        BitConverter.GetBytes((ushort)0x0200).CopyTo(signed, padded.Length + 4);
        BitConverter.GetBytes((ushort)0x0002).CopyTo(signed, padded.Length + 6);
        pkcs7.CopyTo(signed, padded.Length + 8);
        return signed;
    }

    /// <summary>A detached CMS signature over <paramref name="content"/>, as module.json.p7 carries.</summary>
    public static byte[] SignDetached(byte[] content, SigningIdentity signer, SigningIdentity? timestamper = null, DateTimeOffset? timestampedAt = null)
    {
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        Sign(cms, signer, timestamper, timestampedAt);
        return cms.Encode();
    }

    private static void Sign(SignedCms cms, SigningIdentity signer, SigningIdentity? timestamper, DateTimeOffset? timestampedAt)
    {
        var cmsSigner = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signer.Certificate, signer.Key)
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        cms.ComputeSignature(cmsSigner);

        if (timestamper is null)
            return;

        var signerInfo = cms.SignerInfos[0];
        var token = TimestampToken(signerInfo.GetSignature(), timestamper, timestampedAt ?? DateTimeOffset.UtcNow);
        signerInfo.AddUnsignedAttribute(new AsnEncodedData(new Oid(Rfc3161CounterSignatureOid), token));
    }

    /// <summary>
    /// An RFC 3161 time stamp token over <paramref name="signature"/>: a TSTInfo signed by the
    /// authority, with the ESSCertIDv2 attribute the RFC asks of a timestamp authority's signature.
    /// </summary>
    private static byte[] TimestampToken(byte[] signature, SigningIdentity authority, DateTimeOffset at)
    {
        // The serial is a DER INTEGER, so it must be big-endian, positive and minimal: a first byte of
        // 0x01 to 0x7F keeps it so. A random little-endian long failed that about once in a hundred
        // tokens (a leading 0x00 followed by a byte under 0x80), which was a flake in the full suite.
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        serial[0] = (byte)((serial[0] & 0x7F) | 0x01);

        var info = new Rfc3161TimestampTokenInfo(
            new Oid("1.3.6.1.4.1.311.3.2.1"),
            new Oid(Sha256Oid),
            SHA256.HashData(signature),
            serial,
            at);

        var cms = new SignedCms(new ContentInfo(new Oid(TstInfoOid), info.Encode()), detached: false);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, authority.Certificate, authority.Key)
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signer.SignedAttributes.Add(new AsnEncodedData(new Oid(SigningCertificateV2Oid), SigningCertificateV2(authority.Certificate)));
        cms.ComputeSignature(signer);
        return cms.Encode();
    }

    /// <summary>SigningCertificateV2 with one ESSCertIDv2: the SHA-256 of the certificate, the default algorithm left implicit.</summary>
    private static byte[] SigningCertificateV2(X509Certificate2 certificate)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteOctetString(SHA256.HashData(certificate.RawData));
        writer.PopSequence();
        writer.PopSequence();
        writer.PopSequence();
        return writer.Encode();
    }

    /// <summary>SpcIndirectDataContent for a PE image with the given digest, shaped as signtool writes it.</summary>
    private static byte[] IndirectData(byte[] digest, string digestOid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        writer.PushSequence(); // SpcAttributeTypeAndOptionalValue
        writer.WriteObjectIdentifier(SpcPeImageDataOid);
        writer.PushSequence(); // SpcPeImageData
        writer.WriteBitString([], 0); // flags: none
        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)); // file: SpcLink
        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)); // file
        writer.WriteCharacterString(UniversalTagNumber.BMPString, "<<<Obsolete>>>", new Asn1Tag(TagClass.ContextSpecific, 0));
        writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
        writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        writer.PopSequence();
        writer.PopSequence();

        writer.PushSequence(); // DigestInfo
        writer.PushSequence();
        writer.WriteObjectIdentifier(digestOid);
        writer.WriteNull();
        writer.PopSequence();
        writer.WriteOctetString(digest);
        writer.PopSequence();

        writer.PopSequence();
        return writer.Encode();
    }

    /// <summary>The file offsets of the checksum field and the certificate table directory entry.</summary>
    private static (int Checksum, int CertificateDirectory) Offsets(byte[] image)
    {
        var peOffset = BitConverter.ToInt32(image, 0x3C);
        var optional = peOffset + 4 + 20;
        var magic = BitConverter.ToUInt16(image, optional);
        var directory = optional + (magic == 0x20B ? 144 : 128);
        return (optional + 64, directory);
    }
}
