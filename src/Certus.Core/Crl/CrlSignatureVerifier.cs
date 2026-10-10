using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Crl;

/// <summary>What a signature check concluded about a CRL.</summary>
public enum CrlSignatureResult
{
    /// <summary>The signature is the issuing CA key's.</summary>
    Verified,

    /// <summary>The signature is not the issuing CA key's.</summary>
    Failed,

    /// <summary>
    /// The CRL is signed with an algorithm this verifier does not implement, so
    /// nothing was concluded either way.
    /// </summary>
    AlgorithmNotSupported,

    /// <summary>The issuing certificate carried no public key of a usable kind.</summary>
    NoPublicKey,
}

/// <summary>
/// Checks that a CRL was signed by the CA whose certificate the chain says
/// issued it.
///
/// A CRL arrives over plain HTTP or from the directory, so the signature is the
/// only thing tying it to the CA. Without this check, anything able to answer
/// for a distribution point could hold off an expiry warning by serving a CRL
/// with a comfortable nextUpdate.
///
/// The verdict is reported rather than enforced, and that is deliberate. An
/// algorithm this does not implement (RSASSA-PSS, whose parameters live in the
/// algorithm identifier, or something newer) must not remove a CA from
/// monitoring: losing sight of a real CRL is a worse failure than the one this
/// check exists to prevent, so an unsupported algorithm reads the dates and says
/// on the card that the signature was not verified. A signature that is present,
/// supported and wrong is another matter and the caller refuses it.
///
/// Dependency free so tools/AdcsQiProbe can link it; keep it that way.
/// </summary>
public static class CrlSignatureVerifier
{
    private const string Sha1Rsa = "1.2.840.113549.1.1.5";
    private const string Sha256Rsa = "1.2.840.113549.1.1.11";
    private const string Sha384Rsa = "1.2.840.113549.1.1.12";
    private const string Sha512Rsa = "1.2.840.113549.1.1.13";
    private const string Sha1Ecdsa = "1.2.840.10045.4.1";
    private const string Sha256Ecdsa = "1.2.840.10045.4.3.2";
    private const string Sha384Ecdsa = "1.2.840.10045.4.3.3";
    private const string Sha512Ecdsa = "1.2.840.10045.4.3.4";

    /// <summary>
    /// Verifies <paramref name="header"/> against the public key of
    /// <paramref name="issuer"/>.
    /// </summary>
    public static CrlSignatureResult Verify(CrlHeader header, X509Certificate2 issuer)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(issuer);

        var (hash, isRsa) = MapAlgorithm(header.SignatureAlgorithmOid);
        if (hash is null)
            return CrlSignatureResult.AlgorithmNotSupported;

        try
        {
            if (isRsa)
            {
                using var rsa = issuer.GetRSAPublicKey();
                if (rsa is null)
                    return CrlSignatureResult.NoPublicKey;

                return rsa.VerifyData(
                    header.TbsBytes.Span,
                    header.SignatureValue.Span,
                    hash.Value,
                    RSASignaturePadding.Pkcs1)
                    ? CrlSignatureResult.Verified
                    : CrlSignatureResult.Failed;
            }

            using var ecdsa = issuer.GetECDsaPublicKey();
            if (ecdsa is null)
                return CrlSignatureResult.NoPublicKey;

            return ecdsa.VerifyData(
                header.TbsBytes.Span,
                header.SignatureValue.Span,
                hash.Value,
                DSASignatureFormat.Rfc3279DerSequence)
                ? CrlSignatureResult.Verified
                : CrlSignatureResult.Failed;
        }
        catch (CryptographicException)
        {
            // A malformed signature value, or a key the platform will not load.
            return CrlSignatureResult.Failed;
        }
    }

    /// <summary>
    /// Whether the CRL says it was issued by the subject of
    /// <paramref name="issuer"/>. Compared as encoded bytes, never as rendered
    /// strings: a distinguished name renders in the reverse of the order it
    /// encodes in, and two different names can render alike.
    /// </summary>
    public static bool MatchesIssuer(CrlHeader header, X509Certificate2 issuer)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(issuer);

        return header.IssuerNameDer.Span.SequenceEqual(issuer.SubjectName.RawData);
    }

    private static (HashAlgorithmName? Hash, bool IsRsa) MapAlgorithm(string oid) => oid switch
    {
        Sha1Rsa => (HashAlgorithmName.SHA1, true),
        Sha256Rsa => (HashAlgorithmName.SHA256, true),
        Sha384Rsa => (HashAlgorithmName.SHA384, true),
        Sha512Rsa => (HashAlgorithmName.SHA512, true),
        Sha1Ecdsa => (HashAlgorithmName.SHA1, false),
        Sha256Ecdsa => (HashAlgorithmName.SHA256, false),
        Sha384Ecdsa => (HashAlgorithmName.SHA384, false),
        Sha512Ecdsa => (HashAlgorithmName.SHA512, false),
        _ => (null, false),
    };
}
