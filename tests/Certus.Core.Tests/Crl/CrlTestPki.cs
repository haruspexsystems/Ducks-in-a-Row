using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// Builds the two tier hierarchy the CRL monitor exists for: an offline root
/// that signs an issuing CA certificate carrying distribution points, and CRLs
/// of any age, number and shape published under either key.
///
/// Certificates are minted with .NET, the way the rest of this test suite mints
/// them, and CRLs with BouncyCastle, because .NET's
/// <c>CertificateRevocationListBuilder</c> can write a CRL but cannot put
/// Microsoft's Next CRL Publish extension or a delta CRL indicator on it, and
/// those two are exactly what the alert rules turn on.
///
/// The issuer name is carried across as encoded bytes
/// (<see cref="X509Name.GetInstance(object)"/> over the subject's raw DER)
/// rather than through a rendered string. A distinguished name renders in the
/// reverse of the order it encodes in, and BouncyCastle's string constructor
/// encodes in the order it is given, so round tripping through a string would
/// quietly produce a CRL whose issuer does not match the certificate that
/// signed it.
/// </summary>
internal static class CrlTestPki
{
    /// <summary>szOID_CRL_NEXT_PUBLISH.</summary>
    internal const string NextPublishOid = "1.3.6.1.4.1.311.21.4";

    /// <summary>X.509 reads a two digit UTCTime year as 1950 to 2049.</summary>
    private const int TwoDigitYearMax = 2049;

    /// <summary>
    /// A self signed CA certificate with its private key.
    /// </summary>
    /// <param name="subject">The subject, and the issuer of any CRL it signs.</param>
    /// <param name="withSubjectKeyIdentifier">
    /// False mints a CA certificate carrying no subject key identifier, which is
    /// legal and which older CAs really do. It matters because the monitor then
    /// has no key identifier to expect, and has to reconcile the row when a CRL
    /// carrying a real one turns up.
    /// </param>
    internal static X509Certificate2 MintRootCa(
        string subject = "CN=Contoso Root CA",
        bool withSubjectKeyIdentifier = true)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 2, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        if (withSubjectKeyIdentifier)
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddYears(-1), DateTimeOffset.UtcNow.AddYears(10));
    }

    /// <summary>
    /// A self signed CA certificate on an elliptic curve key, so the verifier's
    /// ECDSA arm is exercised against a real signature rather than assumed.
    /// </summary>
    internal static X509Certificate2 MintEcdsaRootCa(string subject = "CN=Contoso EC Root CA")
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 2, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddYears(-1), DateTimeOffset.UtcNow.AddYears(10));
    }

    /// <summary>
    /// A subordinate CA certificate signed by <paramref name="issuer"/>, carrying
    /// the distribution points where the issuer's CRL is published. This is the
    /// certificate the monitor starts from: the URLs on it are the only route to
    /// an offline root's CRL.
    /// </summary>
    internal static X509Certificate2 MintIssuingCa(
        X509Certificate2 issuer,
        string subject = "CN=Contoso Issuing CA",
        params string[] distributionPoints)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (distributionPoints.Length > 0)
        {
            request.CertificateExtensions.Add(
                CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(
                    distributionPoints));
        }

        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        if (serial[0] == 0)
            serial[0] = 1;

        using var unsigned = request.Create(
            issuer, issuer.NotBefore, issuer.NotAfter.AddDays(-1), serial);
        return unsigned.CopyWithPrivateKey(rsa);
    }

    /// <summary>
    /// Publishes a CRL under <paramref name="issuer"/>'s key.
    /// </summary>
    /// <param name="issuer">The CA certificate, private key included.</param>
    /// <param name="crlNumber">The CRL number extension value.</param>
    /// <param name="thisUpdate">When the CA says it issued it.</param>
    /// <param name="nextUpdate">When it stops being usable, or null to omit the field.</param>
    /// <param name="nextPublish">Microsoft's Next CRL Publish, or null to omit it.</param>
    /// <param name="baseCrlNumber">Set to make it a delta CRL over that base.</param>
    /// <param name="revokedEntries">How many revocation entries to pad it with.</param>
    /// <param name="includeCrlNumber">Set false to mint a CRL with no CRL number at all.</param>
    /// <param name="includeAuthorityKeyIdentifier">Set false to omit the authority key identifier.</param>
    /// <param name="signatureAlgorithm">
    /// A BouncyCastle signature algorithm name, for minting a CRL signed with
    /// something the verifier does not implement. Defaults to SHA-256 with
    /// whatever key the issuer holds.
    /// </param>
    internal static byte[] BuildCrl(
        X509Certificate2 issuer,
        int crlNumber,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        DateTimeOffset? nextPublish = null,
        int? baseCrlNumber = null,
        int revokedEntries = 0,
        bool includeCrlNumber = true,
        bool includeAuthorityKeyIdentifier = true,
        string? signatureAlgorithm = null)
    {
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(IssuerNameOf(issuer));
        generator.SetThisUpdate(thisUpdate.UtcDateTime);
        if (nextUpdate is not null)
            generator.SetNextUpdate(nextUpdate.Value.UtcDateTime);

        if (includeCrlNumber)
        {
            generator.AddExtension(
                X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.ValueOf(crlNumber)));
        }

        if (includeAuthorityKeyIdentifier)
        {
            generator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier,
                false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(PublicKeyOf(issuer)));
        }

        if (nextPublish is not null)
        {
            generator.AddExtension(
                new DerObjectIdentifier(NextPublishOid),
                false,
                new DerUtcTime(nextPublish.Value.UtcDateTime, TwoDigitYearMax));
        }

        if (baseCrlNumber is not null)
        {
            generator.AddExtension(
                X509Extensions.DeltaCrlIndicator,
                true,
                new CrlNumber(BigInteger.ValueOf(baseCrlNumber.Value)));
        }

        for (var i = 1; i <= revokedEntries; i++)
        {
            generator.AddCrlEntry(
                BigInteger.ValueOf(i), thisUpdate.UtcDateTime.AddMinutes(-i), CrlReason.KeyCompromise);
        }

        var privateKey = PrivateKeyOf(issuer);
        var algorithm = signatureAlgorithm
            ?? (privateKey is ECPrivateKeyParameters ? "SHA256WithECDSA" : "SHA256WithRSA");
        var signatureFactory = new Asn1SignatureFactory(algorithm, privateKey);
        return generator.Generate(signatureFactory).GetEncoded();
    }

    /// <summary>The certificate's subject, carried over as encoded bytes.</summary>
    internal static X509Name IssuerNameOf(X509Certificate2 certificate) =>
        X509Name.GetInstance(Asn1Object.FromByteArray(certificate.SubjectName.RawData));

    private static AsymmetricKeyParameter PublicKeyOf(X509Certificate2 certificate) =>
        PublicKeyFactory.CreateKey(certificate.PublicKey.ExportSubjectPublicKeyInfo());

    private static AsymmetricKeyParameter PrivateKeyOf(X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
            return PrivateKeyFactory.CreateKey(rsa.ExportPkcs8PrivateKey());

        using var ecdsa = certificate.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("The test CA has no usable private key.");
        return PrivateKeyFactory.CreateKey(ecdsa.ExportPkcs8PrivateKey());
    }
}
