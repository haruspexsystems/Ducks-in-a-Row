using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;

namespace Certus.Core.Acme.Services;

/// <summary>
/// The identity content of a finalize CSR: the public key, every subject CN
/// attribute value, every RFC 4043 PermanentIdentifier SAN reassembled into
/// the ACME value grammar (value["/"assigner-OID]), the DNS SANs, and whether
/// the SAN extension carried anything else. A SAN entry that is not a dNSName
/// or a well formed PermanentIdentifier sets <see cref="HasOtherSanEntries"/>
/// rather than being dropped, because ADCS forwards the raw CSR: whatever the
/// parser skipped would still land in the issued certificate, so the caller
/// must be able to refuse it. Both finalize paths judge this same parse: the
/// dns path refuses any non DNS SAN and any subject CN outside the order's
/// identifiers, and the device path
/// (draft-ietf-acme-device-attest-08 section 7) additionally uses
/// <see cref="SpkiDer"/> for the attested key comparison.
/// </summary>
public sealed record CsrIdentity(
    byte[] SpkiDer,
    IReadOnlyList<string> SubjectCns,
    IReadOnlyList<string> PermanentIdentifiers,
    IReadOnlyList<string> DnsNames,
    bool HasOtherSanEntries);

/// <summary>
/// Utility for parsing and validating PKCS#10 Certificate Signing Requests.
/// </summary>
public static class CsrHelper
{
    /// <summary>RFC 4043 id-on-permanentIdentifier.</summary>
    private const string IdOnPermanentIdentifier = "1.3.6.1.5.5.7.8.3";

    /// <summary>
    /// Extracts the identity content a finalize must judge, for both the dns
    /// and the device path (draft-ietf-acme-device-attest-08 section 7).
    /// Verifies the CSR signature, exports the SubjectPublicKeyInfo for the
    /// device path's attested key comparison, and walks the requested SAN
    /// extension with a closed vocabulary: dNSName and the RFC 4043
    /// PermanentIdentifier otherName in its canonical form (OID, then [0]
    /// EXPLICIT SEQUENCE of a UTF8String value and an optional assigner OID,
    /// the encoding the DeviceAttestProbe proved ADCS preserves). Anything
    /// else in the SAN, including a PermanentIdentifier the parser cannot
    /// read, is reported through <see cref="CsrIdentity.HasOtherSanEntries"/>
    /// so the caller can refuse instead of issuing unvetted names. Throws on
    /// a CSR that does not parse or whose signature does not verify.
    /// </summary>
    public static CsrIdentity ExtractCsrIdentity(byte[] csrDer)
    {
        var csr = new Pkcs10CertificationRequest(csrDer);

        if (!csr.Verify())
            throw new InvalidOperationException("CSR signature verification failed.");

        var info = csr.GetCertificationRequestInfo();
        var spkiDer = info.SubjectPublicKeyInfo.GetDerEncoded();

        var subjectCns = info.Subject.GetValueList(X509Name.CN)
            .Select(v => v!.ToString()!)
            .ToList();

        var permanentIdentifiers = new List<string>();
        var dnsNames = new List<string>();
        var hasOtherSanEntries = false;

        if (info.Attributes != null)
        {
            foreach (var attr in info.Attributes)
            {
                if (attr is not DerSequence seq || seq.Count < 2)
                    continue;

                var oid = (seq[0] as DerObjectIdentifier)?.Id;
                if (oid != PkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Id)
                    continue;

                var extSet = seq[1] as DerSet;
                if (extSet == null || extSet.Count == 0) continue;

                var extensions = X509Extensions.GetInstance(extSet[0]);
                var sanExtension = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
                if (sanExtension == null) continue;

                var sanSequence = GeneralNames.GetInstance(sanExtension.GetParsedValue());
                foreach (var name in sanSequence.GetNames())
                {
                    if (name.TagNo == GeneralName.DnsName)
                    {
                        dnsNames.Add(name.Name.ToString()!);
                    }
                    else if (name.TagNo == GeneralName.OtherName
                        && TryReadPermanentIdentifier(name, out var raw))
                    {
                        permanentIdentifiers.Add(raw);
                    }
                    else
                    {
                        hasOtherSanEntries = true;
                    }
                }
            }
        }

        return new CsrIdentity(
            spkiDer, subjectCns, permanentIdentifiers, dnsNames, hasOtherSanEntries);
    }

    /// <summary>
    /// Reads one otherName GeneralName as an RFC 4043 PermanentIdentifier
    /// and reassembles the ACME grammar string. False for any other
    /// otherName type, for a PermanentIdentifier with no identifierValue
    /// (nothing to compare an order identifier against), and for any
    /// encoding this method does not positively recognize.
    /// </summary>
    private static bool TryReadPermanentIdentifier(GeneralName name, out string raw)
    {
        raw = string.Empty;
        try
        {
            var otherName = OtherName.GetInstance(name.Name);
            if (otherName.TypeID.Id != IdOnPermanentIdentifier)
                return false;

            // PermanentIdentifier ::= SEQUENCE {
            //     identifierValue    UTF8String        OPTIONAL,
            //     assigner           OBJECT IDENTIFIER OPTIONAL }
            var sequence = Asn1Sequence.GetInstance(otherName.Value);
            string? value = null;
            string? assigner = null;
            foreach (var element in sequence)
            {
                switch (element)
                {
                    case DerUtf8String utf8 when value == null && assigner == null:
                        value = utf8.GetString();
                        break;
                    case DerObjectIdentifier assignerOid when assigner == null:
                        assigner = assignerOid.Id;
                        break;
                    default:
                        return false;
                }
            }

            if (string.IsNullOrEmpty(value))
                return false;

            raw = assigner == null ? value : $"{value}/{assigner}";
            return true;
        }
        catch (Exception ex) when (
            ex is ArgumentException or InvalidOperationException or InvalidCastException or IOException)
        {
            return false;
        }
    }
}
