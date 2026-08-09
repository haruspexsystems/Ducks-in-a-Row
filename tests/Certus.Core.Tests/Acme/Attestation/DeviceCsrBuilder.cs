using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Tests.Acme.Attestation;

/// <summary>
/// Builds signed PKCS#10 requests for device order tests. The subject is
/// used verbatim ("CN=SN-1", or "O=..." for a CSR that names no CN); the
/// permanent identifier, when given, is written as the canonical RFC 4043
/// otherName SAN (OID, then [0] EXPLICIT SEQUENCE of a UTF8String value
/// and an optional assigner OID), the encoding the DeviceAttestProbe
/// proved ADCS preserves. Shared by the OrderService unit tests and the
/// device attestation integration tests.
/// </summary>
internal static class DeviceCsrBuilder
{
    public const string IdOnPermanentIdentifier = "1.3.6.1.5.5.7.8.3";
    private const string SubjectAltNameOid = "2.5.29.17";

    public static byte[] Build(
        ECDsa key,
        string subject,
        string? permanentIdentifierValue = null,
        string? assignerOid = null,
        params string[] dnsNames)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);

        if (permanentIdentifierValue != null || dnsNames.Length > 0)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                if (permanentIdentifierValue != null)
                    WritePermanentIdentifier(writer, permanentIdentifierValue, assignerOid);
                foreach (var dns in dnsNames)
                    writer.WriteCharacterString(
                        UniversalTagNumber.IA5String, dns,
                        new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            request.CertificateExtensions.Add(
                new X509Extension(SubjectAltNameOid, writer.Encode(), critical: false));
        }

        return request.CreateSigningRequest();
    }

    /// <summary>
    /// Writes one otherName GeneralName carrying an RFC 4043
    /// PermanentIdentifier, for callers composing their own SAN sequence.
    /// </summary>
    public static void WritePermanentIdentifier(
        AsnWriter writer, string value, string? assignerOid = null)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            writer.WriteObjectIdentifier(IdOnPermanentIdentifier);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            using (writer.PushSequence())
            {
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
                if (assignerOid != null)
                    writer.WriteObjectIdentifier(assignerOid);
            }
        }
    }
}
