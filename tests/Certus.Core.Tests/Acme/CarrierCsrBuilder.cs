using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Builds signed PKCS#10 requests that carry subject alternative names, and
/// requested extensions, through the attribute carriers the product's finalize
/// parser does not read, for the issue #548 hardening tests. The standard
/// <see cref="CertificateRequest"/> always puts extensions under the PKCS#9
/// extensionRequest OID, so these are assembled by hand, the same shape the
/// CsrCarrierProbe submits to a live CA.
/// </summary>
internal static class CarrierCsrBuilder
{
    public const string SzOidCertExtensions = "1.3.6.1.4.1.311.2.1.14";
    public const string EnrolmentNameValuePair = "1.3.6.1.4.1.311.13.2.1";
    public const string ApplicationPoliciesOid = "1.3.6.1.4.1.311.21.10";
    public const string UpnOtherNameOid = "1.3.6.1.4.1.311.20.2.3";

    private const string Pkcs9ExtensionRequest = "1.2.840.113549.1.9.14";
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string KeyUsageOid = "2.5.29.15";
    private const string ExtendedKeyUsageOid = "2.5.29.37";
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string SubjectKeyIdentifierOid = "2.5.29.14";
    private const string Sha256WithRsa = "1.2.840.113549.1.1.11";

    /// <summary>A SAN with a dNSName carried under szOID_CERT_EXTENSIONS.</summary>
    public static byte[] SanUnderCertExtensions(string cn, string dnsName) =>
        Build(cn, (SzOidCertExtensions, new[] { Extensions(SanExtension(Dns(dnsName))) }));

    /// <summary>A SAN requested through the enrolment name and value pair attribute.</summary>
    public static byte[] SanViaNameValuePair(string cn, string name, string value) =>
        Build(cn, (EnrolmentNameValuePair, new[] { NameValuePair(name, value) }));

    /// <summary>Two values in the PKCS#9 extensionRequest SET, each a SAN.</summary>
    public static byte[] SecondExtensionRequestValue(string cn, string firstDns, string secondDns) =>
        Build(cn, (Pkcs9ExtensionRequest, new[]
        {
            Extensions(SanExtension(Dns(firstDns))),
            Extensions(SanExtension(Dns(secondDns))),
        }));

    /// <summary>Two separate PKCS#9 extensionRequest attributes.</summary>
    public static byte[] TwoExtensionRequestAttributes(string cn, string firstDns, string secondDns) =>
        Build(cn,
            (Pkcs9ExtensionRequest, new[] { Extensions(SanExtension(Dns(firstDns))) }),
            (Pkcs9ExtensionRequest, new[] { Extensions(SanExtension(Dns(secondDns))) }));

    /// <summary>A standard extensionRequest carrying a SAN plus the given extensions.</summary>
    public static byte[] SanPlusRequestedExtension(string cn, string dnsName, params byte[][] extraExtensions) =>
        Build(cn, (Pkcs9ExtensionRequest, new[]
        {
            Extensions([SanExtension(Dns(dnsName)), .. extraExtensions]),
        }));

    /// <summary>The Application Policies extension DER (requesting the given policy OIDs).</summary>
    public static byte[] ApplicationPoliciesExtension(params string[] policyOids)
    {
        var inner = new AsnWriter(AsnEncodingRules.DER);
        using (inner.PushSequence())
            foreach (var oid in policyOids)
                using (inner.PushSequence())
                    inner.WriteObjectIdentifier(oid);
        return Extension(ApplicationPoliciesOid, inner.Encode());
    }

    /// <summary>
    /// A Basic Constraints extension DER: cA as given, an optional path length,
    /// and optionally an element the grammar does not have, after them.
    /// </summary>
    public static byte[] BasicConstraintsExtension(
        bool isCa, int? pathLen = null, bool trailingElement = false, bool critical = false)
    {
        var inner = new AsnWriter(AsnEncodingRules.DER);
        using (inner.PushSequence())
        {
            if (isCa) inner.WriteBoolean(true);
            if (pathLen is { } length) inner.WriteInteger(length);
            if (trailingElement) inner.WriteObjectIdentifier("1.3.6.1.4.1.311.21.10");
        }
        return Extension(BasicConstraintsOid, inner.Encode(), critical);
    }

    /// <summary>A Subject Key Identifier extension DER carrying the given identifier.</summary>
    public static byte[] SubjectKeyIdentifierExtension(byte[] keyIdentifier, bool critical = false)
    {
        var inner = new AsnWriter(AsnEncodingRules.DER);
        inner.WriteOctetString(keyIdentifier);
        return Extension(SubjectKeyIdentifierOid, inner.Encode(), critical);
    }

    /// <summary>
    /// A standard extensionRequest carrying a SAN plus one more extension built
    /// from the request's own subjectPublicKey bits, for the subject key
    /// identifier tests, which must know the key the CSR is signed with.
    /// </summary>
    public static byte[] SanPlusKeyDerivedExtension(
        string cn, string dnsName, Func<byte[], byte[]> extensionFromSubjectPublicKey)
    {
        using var key = RSA.Create(2048);
        var spkiReader = new AsnReader(key.ExportSubjectPublicKeyInfo(), AsnEncodingRules.DER).ReadSequence();
        spkiReader.ReadSequence(); // AlgorithmIdentifier
        var subjectPublicKey = spkiReader.ReadBitString(out _);
        return Build(key, cn, (Pkcs9ExtensionRequest, new[]
        {
            Extensions(SanExtension(Dns(dnsName)), extensionFromSubjectPublicKey(subjectPublicKey)),
        }));
    }

    /// <summary>A Key Usage extension DER (digitalSignature).</summary>
    public static byte[] KeyUsageExtension()
    {
        var inner = new AsnWriter(AsnEncodingRules.DER);
        inner.WriteBitString(new byte[] { 0x80 }, 7); // digitalSignature
        return Extension(KeyUsageOid, inner.Encode());
    }

    /// <summary>An Extended Key Usage extension DER (serverAuth).</summary>
    public static byte[] ExtendedKeyUsageExtension()
    {
        var inner = new AsnWriter(AsnEncodingRules.DER);
        using (inner.PushSequence())
            inner.WriteObjectIdentifier("1.3.6.1.5.5.7.3.1");
        return Extension(ExtendedKeyUsageOid, inner.Encode());
    }

    private static byte[] Dns(string dns)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            writer.WriteCharacterString(UniversalTagNumber.IA5String, dns, new Asn1Tag(TagClass.ContextSpecific, 2));
        return writer.Encode();
    }

    private static byte[] SanExtension(byte[] generalNamesDer) => Extension(SubjectAltNameOid, generalNamesDer);

    private static byte[] Extension(string oid, byte[] extnValue, bool critical = false)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            if (critical) writer.WriteBoolean(true);
            writer.WriteOctetString(extnValue);
        }
        return writer.Encode();
    }

    private static byte[] Extensions(params byte[][] extensions)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            foreach (var ext in extensions)
                writer.WriteEncodedValue(ext);
        return writer.Encode();
    }

    private static byte[] NameValuePair(string name, string value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.BMPString, name);
            writer.WriteCharacterString(UniversalTagNumber.BMPString, value);
        }
        return writer.Encode();
    }

    private static byte[] Build(string cn, params (string Oid, byte[][] Values)[] attributes)
    {
        using var key = RSA.Create(2048);
        return Build(key, cn, attributes);
    }

    private static byte[] Build(RSA key, string cn, params (string Oid, byte[][] Values)[] attributes)
    {
        byte[] subject = new X500DistinguishedName($"CN={cn}").RawData;
        byte[] spki = key.ExportSubjectPublicKeyInfo();

        var infoWriter = new AsnWriter(AsnEncodingRules.DER);
        using (infoWriter.PushSequence())
        {
            infoWriter.WriteInteger(0);
            infoWriter.WriteEncodedValue(subject);
            infoWriter.WriteEncodedValue(spki);
            using (infoWriter.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                foreach (var (oid, values) in attributes)
                {
                    using (infoWriter.PushSequence())
                    {
                        infoWriter.WriteObjectIdentifier(oid);
                        using (infoWriter.PushSetOf())
                            foreach (var value in values)
                                infoWriter.WriteEncodedValue(value);
                    }
                }
            }
        }

        byte[] info = infoWriter.Encode();
        byte[] signature = key.SignData(info, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(info);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Sha256WithRsa);
                writer.WriteNull();
            }
            writer.WriteBitString(signature);
        }
        return writer.Encode();
    }
}
