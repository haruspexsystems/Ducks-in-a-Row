using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Builds a finalize CSR the way Posh-ACME does, for the issue #687 tests. It
/// mirrors <c>Posh-ACME/Private/New-Csr.ps1</c> on its main branch, which uses
/// BouncyCastle too: a CN of the main domain, and one extensionRequest holding,
/// in this order, basic constraints with cA=false (not critical), key usage
/// (critical; digitalSignature, plus keyEncipherment for RSA), the DNS SANs
/// (not critical) and a subject key identifier built from the public key (not
/// critical), with the TLS feature (OCSP must staple) appended when asked for.
/// Since #548 the first of those was refused, so every Posh-ACME order failed.
/// </summary>
internal static class PoshAcmeCsrBuilder
{
    private const string TlsFeatureOid = "1.3.6.1.5.5.7.1.24";

    public static byte[] Build(bool ecKey, bool ocspMustStaple, params string[] dnsNames)
    {
        var random = new SecureRandom();
        AsymmetricCipherKeyPair keyPair;
        string sigAlgo;
        if (ecKey)
        {
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(NistNamedCurves.GetOid("P-256"), random));
            keyPair = generator.GenerateKeyPair();
            sigAlgo = "SHA256WITHECDSA";
        }
        else
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(random, 2048));
            keyPair = generator.GenerateKeyPair();
            sigAlgo = "SHA256WITHRSA";
        }

        var subject = new X509Name($"CN={dnsNames[0]}");

        var keyUsageBits = ecKey
            ? KeyUsage.DigitalSignature
            : KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment;

        var extensions = new Dictionary<DerObjectIdentifier, X509Extension>
        {
            [X509Extensions.BasicConstraints] =
                new X509Extension(false, new DerOctetString(new BasicConstraints(false))),
            [X509Extensions.KeyUsage] =
                new X509Extension(true, new DerOctetString(new KeyUsage(keyUsageBits))),
            [X509Extensions.SubjectAlternativeName] = new X509Extension(false, new DerOctetString(
                new GeneralNames(dnsNames.Select(n => new GeneralName(GeneralName.DnsName, n)).ToArray()))),
            [X509Extensions.SubjectKeyIdentifier] = new X509Extension(false, new DerOctetString(
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(keyPair.Public))),
        };
        if (ocspMustStaple)
        {
            extensions[new DerObjectIdentifier(TlsFeatureOid)] = new X509Extension(
                false, new DerOctetString(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x05 }));
        }

        var attributes = new DerSet(new AttributePkcs(
            PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
            new DerSet(new X509Extensions(extensions))));

        return new Pkcs10CertificationRequest(sigAlgo, subject, keyPair.Public, attributes, keyPair.Private)
            .GetEncoded();
    }
}
