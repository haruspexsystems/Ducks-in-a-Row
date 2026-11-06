using System.Formats.Asn1;
using System.Security.Cryptography;
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
///
/// The same forwarding of the raw CSR is why the identity carries two facts
/// about the shape of the request, not only its SAN content. ADCS honours a
/// SAN carried under the Microsoft certificate extensions attribute
/// (szOID_CERT_EXTENSIONS, 1.3.6.1.4.1.311.2.1.14), measured on lab 2019 on
/// 2026-10-13 (issue #548): a name smuggled under a carrier the SAN walk never
/// reads still reaches the issued certificate. So
/// <see cref="HasUnexpectedCsrAttributes"/> flags any attribute other than a
/// single PKCS#9 extensionRequest carrying a single value, and
/// <see cref="DisallowedRequestedExtensionOid"/> names the first requested
/// extension outside the allow list below, with
/// <see cref="DisallowedRequestedExtensionDetail"/> saying why in words a
/// client can act on. Both finalize paths refuse on either, so a name or a
/// capability the identifier check cannot see never reaches the CA.
/// </summary>
public sealed record CsrIdentity(
    byte[] SpkiDer,
    IReadOnlyList<string> SubjectCns,
    IReadOnlyList<string> PermanentIdentifiers,
    IReadOnlyList<string> DnsNames,
    bool HasOtherSanEntries,
    bool HasUnexpectedCsrAttributes,
    string? DisallowedRequestedExtensionOid,
    string? DisallowedRequestedExtensionDetail);

/// <summary>
/// Utility for parsing and validating PKCS#10 Certificate Signing Requests.
/// </summary>
public static class CsrHelper
{
    /// <summary>RFC 4043 id-on-permanentIdentifier.</summary>
    private const string IdOnPermanentIdentifier = "1.3.6.1.5.5.7.8.3";

    /// <summary>
    /// The extensions a finalize CSR may request whatever their value. The
    /// subject alternative name is validated against the order; key usage and
    /// extended key usage are tolerated because cert-manager encodes them into
    /// the CSR by default (its <c>encodeUsagesInRequest</c> option, default
    /// true), while certbot, Caddy (acmez) and lego send the SAN only and
    /// acme.sh adds an EKU. The issued certificate's key usage and extended key
    /// usage are governed by the TLS capability ceiling at the leaf guard
    /// regardless, so tolerating the request costs nothing. Basic constraints
    /// and the subject key identifier are admitted only by value, through
    /// <see cref="JudgeBasicConstraints"/> and
    /// <see cref="JudgeSubjectKeyIdentifier"/>. Anything else (Application
    /// Policies, Certificate Policies, the TLS feature, ...) is refused: ADCS
    /// may copy it into the certificate and the ceiling would not see it
    /// (issue #548, R03/ESC15).
    /// </summary>
    private static readonly HashSet<string> AllowedRequestedExtensions = new(StringComparer.Ordinal)
    {
        X509Extensions.SubjectAlternativeName.Id,
        X509Extensions.KeyUsage.Id,
        X509Extensions.ExtendedKeyUsage.Id,
    };

    /// <summary>
    /// The problem detail for a requested extension outside every admission
    /// rule. Both finalize paths return it as the badCSR detail.
    /// </summary>
    private const string AllowListSentence =
        "Only subject alternative names, key usage, extended key usage, basic constraints " +
        "with cA=false, and a subject key identifier derived from the CSR's own key may be requested.";

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
    /// so the caller can refuse instead of issuing unvetted names.
    ///
    /// It also judges the shape of the request, not only its SAN content,
    /// because ADCS reads carriers this walk does not (issue #548). A CSR is
    /// expected to carry exactly one attribute, a PKCS#9 extensionRequest with
    /// exactly one value; anything else sets
    /// <see cref="CsrIdentity.HasUnexpectedCsrAttributes"/>. That single value
    /// may request only the allow listed extensions; the first one outside the
    /// list is reported through
    /// <see cref="CsrIdentity.DisallowedRequestedExtensionOid"/>. Throws on a
    /// CSR that does not parse or whose signature does not verify.
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
        var hasUnexpectedCsrAttributes = false;
        string? disallowedRequestedExtensionOid = null;
        string? disallowedRequestedExtensionDetail = null;

        if (info.Attributes != null)
        {
            var extensionRequestCount = 0;
            foreach (var attr in info.Attributes)
            {
                // Asn1Sequence.GetInstance, not an "is DerSequence" pattern: a
                // BER or DL encoded attribute is a sibling type, not a subtype,
                // in BouncyCastle 2.x, so the pattern would skip it silently.
                // An attribute that is not a well formed SEQUENCE is itself
                // unexpected and refused.
                Asn1Sequence seq;
                try { seq = Asn1Sequence.GetInstance(attr); }
                catch (Exception ex) when (ex is ArgumentException or InvalidCastException)
                {
                    hasUnexpectedCsrAttributes = true;
                    continue;
                }
                if (seq.Count < 2)
                {
                    hasUnexpectedCsrAttributes = true;
                    continue;
                }

                var oid = (seq[0] as DerObjectIdentifier)?.Id;
                if (oid != PkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Id)
                {
                    // Any attribute other than extensionRequest is a carrier the
                    // SAN walk never reads. ADCS honours a SAN under
                    // szOID_CERT_EXTENSIONS (measured, issue #548), so an
                    // unrecognised attribute is refused rather than ignored.
                    hasUnexpectedCsrAttributes = true;
                    continue;
                }
                extensionRequestCount++;

                Asn1Set extSet;
                try { extSet = Asn1Set.GetInstance(seq[1]); }
                catch (Exception ex) when (ex is ArgumentException or InvalidCastException)
                {
                    hasUnexpectedCsrAttributes = true;
                    continue;
                }
                // extensionRequest carries exactly one Extensions value. A second
                // value is a carrier the SAN walk reads past (it reads value[0]
                // only), and a real CA refuses it as malformed, so refuse it here
                // with a clean badCSR rather than after a CA round trip.
                if (extSet.Count != 1)
                {
                    hasUnexpectedCsrAttributes = true;
                    if (extSet.Count == 0) continue;
                }

                var extensions = X509Extensions.GetInstance(extSet[0]);

                // Every requested extension outside the allow list is refused,
                // and basic constraints and the subject key identifier are
                // judged by their value. The first refusal found names it.
                foreach (DerObjectIdentifier extOid in extensions.ExtensionOids)
                {
                    if (disallowedRequestedExtensionOid != null) break;
                    if (AllowedRequestedExtensions.Contains(extOid.Id)) continue;

                    var extension = extensions.GetExtension(extOid);
                    string? refusal;
                    if (extOid.Equals(X509Extensions.BasicConstraints))
                        refusal = JudgeBasicConstraints(extension);
                    else if (extOid.Equals(X509Extensions.SubjectKeyIdentifier))
                        refusal = JudgeSubjectKeyIdentifier(extension, info.SubjectPublicKeyInfo);
                    else
                        refusal = $"The CSR requests an extension this server does not allow ({extOid.Id}). " +
                            AllowListSentence;

                    if (refusal != null)
                    {
                        disallowedRequestedExtensionOid = extOid.Id;
                        disallowedRequestedExtensionDetail = refusal;
                    }
                }

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

            // More than one extensionRequest attribute is itself a carrier
            // oddity: the SAN walk would merge their SANs, but a second
            // extensionRequest is not something a conforming client emits.
            if (extensionRequestCount > 1)
                hasUnexpectedCsrAttributes = true;
        }

        return new CsrIdentity(
            spkiDer, subjectCns, permanentIdentifiers, dnsNames, hasOtherSanEntries,
            hasUnexpectedCsrAttributes, disallowedRequestedExtensionOid,
            disallowedRequestedExtensionDetail);
    }

    /// <summary>
    /// Admits a requested basic constraints extension only when it asks for an
    /// end entity certificate: cA absent or false, and no path length
    /// constraint (RFC 5280 section 4.2.1.9 allows one only with cA true).
    /// Posh-ACME sends exactly that, non critical, on every order, and acme.sh
    /// sends CA:FALSE with OCSP must staple (issue #687). A CSR cannot be
    /// rewritten without breaking its signature and ADCS forwards it raw, so
    /// admitting the extension means the template decides whether it reaches
    /// the certificate; cA=false there states what the TLS capability ceiling
    /// already requires. A request for a CA certificate, a path length, or a
    /// value that does not decode is refused here, before the CA, rather than
    /// left to the leaf guard. The value is read as strict DER, so an element
    /// after cA and pathLenConstraint, or trailing bytes, is refused too.
    /// Returns the refusal detail, or null to admit.
    /// </summary>
    private static string? JudgeBasicConstraints(X509Extension extension)
    {
        bool isCa = false;
        bool hasPathLen = false;
        try
        {
            // BasicConstraints ::= SEQUENCE {
            //     cA                 BOOLEAN DEFAULT FALSE,
            //     pathLenConstraint  INTEGER (0..MAX) OPTIONAL }
            var reader = new AsnReader(extension.Value.GetOctets(), AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                isCa = sequence.ReadBoolean();
            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                sequence.ReadIntegerBytes();
                hasPathLen = true;
            }
            sequence.ThrowIfNotEmpty();
        }
        catch (AsnContentException)
        {
            return "The CSR requests a basic constraints extension (2.5.29.19) that does not decode. " +
                AllowListSentence;
        }

        if (isCa)
            return "The CSR requests a CA certificate (basic constraints 2.5.29.19 with cA=true). " +
                "Only an end entity certificate may be requested.";
        if (hasPathLen)
            return "The CSR requests a path length constraint (basic constraints 2.5.29.19), " +
                "which applies only to a CA certificate. Only an end entity certificate may be requested.";
        return null;
    }

    /// <summary>
    /// Admits a requested subject key identifier only when it is non critical
    /// (RFC 5280 section 4.2.1.2 requires that) and its value is the SHA-1 of
    /// the CSR's own subjectPublicKey, the section 4.2.1.2 method (1)
    /// identifier. Posh-ACME requests one, built that way by BouncyCastle, on
    /// every order (issue #687). Tying the value to the key means a requester
    /// can only name its own key: it cannot borrow another certificate's
    /// identifier, such as the issuing CA's, which a chain builder matching an
    /// authority key identifier would then consider. Returns the refusal
    /// detail, or null to admit.
    /// </summary>
    private static string? JudgeSubjectKeyIdentifier(X509Extension extension, SubjectPublicKeyInfo spki)
    {
        if (extension.IsCritical)
            return "The CSR requests a subject key identifier (2.5.29.14) marked critical, " +
                "which RFC 5280 does not allow.";

        // SubjectKeyIdentifier ::= KeyIdentifier ::= OCTET STRING, as strict DER.
        byte[] requested;
        try
        {
            var reader = new AsnReader(extension.Value.GetOctets(), AsnEncodingRules.DER);
            requested = reader.ReadOctetString();
            reader.ThrowIfNotEmpty();
        }
        catch (AsnContentException)
        {
            return "The CSR requests a subject key identifier (2.5.29.14) that does not decode. " +
                AllowListSentence;
        }

        var expected = SHA1.HashData(spki.PublicKey.GetBytes());
        if (!requested.AsSpan().SequenceEqual(expected))
            return "The CSR requests a subject key identifier (2.5.29.14) that is not the SHA-1 " +
                "of the CSR's own public key (RFC 5280 section 4.2.1.2, method 1).";
        return null;
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
