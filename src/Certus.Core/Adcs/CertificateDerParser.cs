using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Security;

namespace Certus.Core.Adcs;

/// <summary>
/// Everything the certificate sync reads out of an issued certificate's DER
/// encoding, produced by a single parse. A non null instance means the DER
/// decoded; the individual members may still be null or empty because a
/// certificate need not carry a subject DN, a SAN extension, or any of the
/// cryptographic extensions.
/// </summary>
public sealed record CertificateDerInfo(
    string Subject,
    string? SubjectAlternativeNames,
    CertificateCryptoDetail Crypto);

/// <summary>
/// Reads display and cryptographic detail out of the DER encoded certificate
/// the CA view already hands back in its RawCertificate column.
///
/// This lives in Certus.Core rather than inside AdcsClient so both the real
/// client and <see cref="MockAdcsClient"/> parse certificates the same way, and
/// so the parse is testable without the COM path. It must stay public:
/// Certus.Core grants InternalsVisibleTo to Certus.Core.Tests only, not to
/// Certus.Adcs.
///
/// Everything here is best effort. The sync must never lose a certificate row
/// because one extension on it failed to decode, so each field is read in
/// isolation and an unreadable one comes back null while the rest survive.
/// </summary>
public static class CertificateDerParser
{
    /// <summary>
    /// Cap for the joined SAN list, matching the 2000 character
    /// SyncedCertificate.SubjectAlternativeNames column.
    /// </summary>
    internal const int MaxSanLength = 2000;

    /// <summary>
    /// Cap for the joined EKU OID list, matching the 1000 character
    /// SyncedCertificate.ExtendedKeyUsageOids column.
    /// </summary>
    internal const int MaxEkuLength = 1000;

    // Subject public key algorithm OIDs we give a short stable token to. The
    // mapping is ours rather than the operating system's on purpose: Oid.FriendlyName
    // resolves through the Windows OID table and is locale dependent, so a CA host
    // running a non English Windows would otherwise write localized strings into
    // the database. Anything not listed here falls through to its raw OID, which
    // is never wrong, just unfriendly. ML-DSA (FIPS 204) lands on that path today;
    // give it a token here once there is a real ADCS issued one to check against.
    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string RsaPssOid = "1.2.840.113549.1.1.10";
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string DsaOid = "1.2.840.10040.4.1";
    private const string Ed25519Oid = "1.3.101.112";
    private const string Ed448Oid = "1.3.101.113";

    /// <summary>
    /// Parses a DER encoded certificate. Returns null when the bytes are not a
    /// decodable certificate, which the callers treat as "no detail available"
    /// rather than as a failure.
    /// </summary>
    public static CertificateDerInfo? Parse(byte[] der)
    {
        // Guarded as well as caught. History: the pre net10 X509Certificate2
        // byte constructor accepted an empty array and produced a zero handle
        // object whose every later property read threw, so an up front guard
        // was the only safe shape (probed on net8.0, .NET 8.0.29). The loader
        // parses eagerly and throws CryptographicException on empty or garbage
        // input, which the catch below covers, but the guard stays: it also
        // rejects null (which the loader surfaces as ArgumentNullException,
        // not CryptographicException). A CA row with a null RawCertificate
        // column reaches us as exactly this.
        if (der is not { Length: > 0 })
            return null;

        X509Certificate2 cert;
        try
        {
            cert = X509CertificateLoader.LoadCertificate(der);
        }
        catch (CryptographicException)
        {
            return null;
        }

        using (cert)
        {
            return new CertificateDerInfo(
                Subject: ReadSubject(cert),
                SubjectAlternativeNames: ReadSans(cert),
                Crypto: new CertificateCryptoDetail(
                    KeyAlgorithm: ReadKeyAlgorithm(cert),
                    KeySizeBits: ReadKeySizeBits(cert),
                    SignatureAlgorithmOid: ReadSignatureAlgorithmOid(cert),
                    Sha256Thumbprint: ReadSha256Thumbprint(cert),
                    ExtendedKeyUsageOids: ReadExtendedKeyUsageOids(cert),
                    KeyUsage: ReadKeyUsage(cert)));
        }
    }

    /// <summary>
    /// The TLS capability ceiling's view of a DER encoded certificate. Null
    /// when the bytes do not decode as a certificate, and every caller treats
    /// that as fail closed (refused), which is the opposite stance from
    /// <see cref="Parse"/>, whose callers treat null as detail unavailable.
    /// Inside a decodable certificate the per field best effort rule still
    /// holds, and it composes with the ceiling in the fail closed direction:
    /// a malformed or empty EKU extension reads as no EKU here, and no EKU is
    /// exactly what the ceiling refuses.
    /// </summary>
    public static CertificateCapability? ParseCapability(byte[] der)
    {
        if (der is not { Length: > 0 })
            return null;

        X509Certificate2 cert;
        try
        {
            cert = X509CertificateLoader.LoadCertificate(der);
        }
        catch (CryptographicException)
        {
            return null;
        }

        using (cert)
        {
            return new CertificateCapability(
                ExtendedKeyUsageOids: ReadEkuOidList(cert),
                KeyUsage: ReadKeyUsage(cert) is { } keyUsage ? (X509KeyUsageFlags)keyUsage : null,
                IsCa: ReadIsCa(cert));
        }
    }

    /// <summary>
    /// The subject DN, or an empty string when it cannot be read. Empty is
    /// already a first class case here: an ACME issued certificate routinely
    /// carries no subject DN at all, and the caller falls through to the CA
    /// database columns and then to the first SAN.
    /// </summary>
    private static string ReadSubject(X509Certificate2 cert)
    {
        try
        {
            return cert.Subject;
        }
        catch (CryptographicException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// SAN entries formatted as "dns:name" and "ip:address" joined with ", " to
    /// match the SyncedCertificate storage format, capped to the column width.
    /// Null when there is no SAN extension, and also when the extension carries
    /// no DNS or IP entry, which is the case for a certificate whose only SANs
    /// are of another kind (email or URI).
    /// </summary>
    private static string? ReadSans(X509Certificate2 cert)
    {
        try
        {
            var sanExtension = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            if (sanExtension == null)
                return null;

            var entries = sanExtension.EnumerateDnsNames().Select(d => $"dns:{d}")
                .Concat(sanExtension.EnumerateIPAddresses().Select(ip => $"ip:{ip}"))
                .ToList();
            if (entries.Count == 0)
                return null;

            var joined = string.Join(", ", entries);
            return joined.Length <= MaxSanLength ? joined : joined[..MaxSanLength];
        }
        catch (CryptographicException)
        {
            return null; // Malformed SAN extension; the row keeps everything else.
        }
    }

    /// <summary>
    /// A short stable token for the subject public key algorithm ("RSA",
    /// "ECDSA", ...), or the raw algorithm OID when it is not one we name.
    /// </summary>
    /// <remarks>
    /// Internal rather than private because the HTTPS self enrollment path
    /// compares an issued leaf against the key it generated and wants the same
    /// vocabulary in its message; see
    /// <c>TlsCertificateEnroller.DescribeLeafKey</c>.
    /// </remarks>
    internal static string? ReadKeyAlgorithm(X509Certificate2 cert)
    {
        try
        {
            var oid = cert.PublicKey.Oid.Value;
            if (string.IsNullOrEmpty(oid))
                return null;

            return oid switch
            {
                RsaOid => "RSA",
                RsaPssOid => "RSA-PSS",
                EcPublicKeyOid => "ECDSA",
                DsaOid => "DSA",
                Ed25519Oid => "Ed25519",
                Ed448Oid => "Ed448",
                _ => oid
            };
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// Key size in bits, from whichever public key type the certificate carries.
    /// Null when none of the supported key types resolves, which is the correct
    /// answer for an algorithm whose strength is not expressed as a modulus or
    /// curve size (ML-DSA names its parameter set instead).
    /// </summary>
    internal static int? ReadKeySizeBits(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null)
                return rsa.KeySize;

            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa != null)
                return ecdsa.KeySize;

            using var dsa = cert.GetDSAPublicKey();
            if (dsa != null)
                return dsa.KeySize;

            return null;
        }
        catch (CryptographicException)
        {
            // An unsupported curve or a malformed key blob: the algorithm above
            // is still reportable, the size is not.
            return null;
        }
    }

    /// <summary>
    /// The signature algorithm OID as the certificate carries it. Stored as the
    /// OID rather than Oid.FriendlyName for the locale reason above; the set is
    /// hash by algorithm and too large to be worth a hand written token table,
    /// so the dashboard labels it the same way it labels revocation reason codes.
    /// </summary>
    private static string? ReadSignatureAlgorithmOid(X509Certificate2 cert)
    {
        try
        {
            var oid = cert.SignatureAlgorithm.Value;
            return string.IsNullOrEmpty(oid) ? null : oid;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// Uppercase hex SHA-256 thumbprint. Note this is deliberately not
    /// X509Certificate2.Thumbprint, which is SHA-1.
    /// </summary>
    private static string? ReadSha256Thumbprint(X509Certificate2 cert)
    {
        try
        {
            var hash = cert.GetCertHashString(HashAlgorithmName.SHA256);
            return string.IsNullOrEmpty(hash) ? null : hash;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// Extended key usage OIDs in certificate order, joined with ", " like the
    /// SAN list and capped to the column width. Null when the certificate
    /// carries no EKU extension, which means "no EKU restriction" and is a
    /// different thing from an empty list.
    /// </summary>
    private static string? ReadExtendedKeyUsageOids(X509Certificate2 cert)
    {
        var oids = ReadEkuOidList(cert);
        if (oids == null)
            return null;

        var joined = string.Join(", ", oids);
        return joined.Length <= MaxEkuLength ? joined : joined[..MaxEkuLength];
    }

    /// <summary>
    /// The EKU OIDs as a list, the single decode path under both the joined
    /// string column and <see cref="ParseCapability"/>. Null for no extension,
    /// an extension carrying no OIDs, or a malformed one.
    /// </summary>
    private static IReadOnlyList<string>? ReadEkuOidList(X509Certificate2 cert)
    {
        try
        {
            var extension = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (extension == null)
                return null;

            // EnhancedKeyUsages decodes lazily, so this getter is what throws on
            // a malformed extension, not the OfType above.
            var oids = extension.EnhancedKeyUsages
                .Cast<Oid>()
                .Select(o => o.Value)
                .Where(v => !string.IsNullOrEmpty(v))
                .Select(v => v!)
                .ToList();
            return oids.Count == 0 ? null : oids;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// BasicConstraints cA, or null when the certificate carries no
    /// BasicConstraints extension or it cannot be read. Leaves routinely omit
    /// the extension, so null is ordinary and the ceiling treats it as not a
    /// CA; the EKU rule remains the primary gate.
    /// </summary>
    private static bool? ReadIsCa(X509Certificate2 cert)
    {
        try
        {
            var extension = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            // CertificateAuthority decodes lazily, same as the readers above.
            return extension?.CertificateAuthority;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// The RFC 5280 key usage bit field as the raw X509KeyUsageFlags value.
    /// Stored lossless as an int, the same shape as the revocation reason code,
    /// and labelled in the dashboard. Null when the certificate carries no key
    /// usage extension.
    /// </summary>
    private static int? ReadKeyUsage(X509Certificate2 cert)
    {
        try
        {
            var extension = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            // KeyUsages decodes lazily, same as EnhancedKeyUsages above.
            return extension == null ? null : (int)extension.KeyUsages;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
