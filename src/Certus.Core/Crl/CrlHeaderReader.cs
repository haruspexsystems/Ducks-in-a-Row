using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Crl;

/// <summary>
/// The header fields of a certificate revocation list: everything the monitor
/// needs to decide whether it is current, plus the bytes a signature check
/// needs. The revocation entries themselves are deliberately absent.
/// </summary>
/// <param name="IssuerNameDer">
/// The encoded issuer Name, so a CRL can be matched to the certificate of the
/// CA that signed it by bytes rather than by a rendered string. The two orders
/// a distinguished name has make string comparison the weaker test (see the
/// distinguished name ordering section of CLAUDE.md).
/// </param>
/// <param name="IssuerName">The issuer rendered for display and for logs.</param>
/// <param name="ThisUpdate">When the CA says it issued this CRL.</param>
/// <param name="NextUpdate">
/// When the CRL stops being usable. Optional in X.509 and absent only on CRLs
/// no Windows CA produces; a CRL without it can never expire, so the monitor
/// has nothing to watch and says so rather than inventing a date.
/// </param>
/// <param name="CrlNumberHex">
/// The CRL number extension (2.5.29.20), uppercase hex with leading zero bytes
/// trimmed. This is half of the identity the alert history dedupes on, so a
/// renewed CRL re-arms every threshold and a stale copy of an older one is a
/// subject of its own. Null when the CA omitted the extension, which RFC 5280
/// forbids for a conforming CA but which the reader tolerates.
/// </param>
/// <param name="BaseCrlNumberHex">
/// The delta CRL indicator (2.5.29.27). Non null means this is a delta CRL and
/// names the base it builds on. It is the empty string, not null, when the
/// extension is present but its number could not be read: the CRL is still a
/// delta, which is what decides how it is treated, and the base number it names
/// is of no use to a monitor. A caller must not parse it without checking.
/// </param>
/// <param name="AuthorityKeyIdentifierHex">
/// The key identifier from 2.5.29.35, uppercase hex. It names the CA key that
/// signed this CRL, which is what distinguishes the CRLs of a CA that has been
/// renewed with a new key and still publishes one per key.
/// </param>
/// <param name="NextPublish">
/// Microsoft's Next CRL Publish extension (1.3.6.1.4.1.311.21.4): when the CA
/// intends to replace this CRL, which is always before <paramref name="NextUpdate"/>
/// by the configured overlap. For a CA that publishes on a timer this is the
/// only date that says whether a publish was missed.
/// </param>
/// <param name="TbsBytes">The encoded TBSCertList, the bytes the signature covers.</param>
/// <param name="SignatureAlgorithmOid">The outer signature algorithm OID.</param>
/// <param name="SignatureValue">The signature bits.</param>
public sealed record CrlHeader(
    ReadOnlyMemory<byte> IssuerNameDer,
    string IssuerName,
    DateTimeOffset ThisUpdate,
    DateTimeOffset? NextUpdate,
    string? CrlNumberHex,
    string? BaseCrlNumberHex,
    string? AuthorityKeyIdentifierHex,
    DateTimeOffset? NextPublish,
    ReadOnlyMemory<byte> TbsBytes,
    string SignatureAlgorithmOid,
    ReadOnlyMemory<byte> SignatureValue)
{
    /// <summary>A delta CRL carries the delta CRL indicator; a base CRL does not.</summary>
    public bool IsDelta => BaseCrlNumberHex is not null;
}

/// <summary>
/// Reads the header of a DER encoded CRL with <see cref="AsnReader"/>.
///
/// It exists rather than a call into a library because .NET has no CRL reader:
/// <c>CertificateRevocationListBuilder.Load</c> hands back the CRL number and
/// nothing else, and the API proposal that would add thisUpdate and nextUpdate
/// (dotnet/runtime #122337) has not shipped as of .NET 10. BouncyCastle's
/// parser would answer the question, but it materialises every revoked entry,
/// and an issuing CA's CRL on a real estate can be megabytes of them. This
/// reader walks past <c>revokedCertificates</c> without decoding it.
///
/// It is also deliberately free of any dependency beyond the base class library,
/// because tools/AdcsQiProbe links this file (see its csproj) so that a lab run
/// exercises the product's own parser against real ADCS output rather than a
/// copy of it. Anything added here has to keep compiling for net8.0-windows.
/// </summary>
public static class CrlHeaderReader
{
    private const string CrlNumberOid = "2.5.29.20";
    private const string DeltaCrlIndicatorOid = "2.5.29.27";
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";

    /// <summary>
    /// Microsoft's szOID_CRL_NEXT_PUBLISH. Not in RFC 5280: a Windows CA stamps
    /// it so clients can pre fetch before the CRL actually expires.
    /// </summary>
    public const string NextPublishOid = "1.3.6.1.4.1.311.21.4";

    /// <summary>
    /// X.509 reads a two digit UTCTime year as 1950 to 2049. Passed explicitly
    /// rather than left to the calendar default, so the answer cannot depend on
    /// the host's culture settings.
    /// </summary>
    private const int TwoDigitYearMax = 2049;

    /// <summary>
    /// Parses the header of <paramref name="der"/>. Returns false with a reason
    /// rather than throwing: every caller is reading something a CA or a web
    /// server handed over, and an unreadable CRL is a monitoring result, not an
    /// exceptional condition.
    /// </summary>
    public static bool TryRead(
        ReadOnlyMemory<byte> der,
        out CrlHeader? header,
        out string? error)
    {
        header = null;
        error = null;

        if (der.Length == 0)
        {
            error = "The CRL was empty.";
            return false;
        }

        try
        {
            var outer = new AsnReader(der, AsnEncodingRules.DER);
            var certificateList = outer.ReadSequence();

            // The TBS bytes have to be captured whole, before anything inside is
            // consumed, because that is what the signature covers.
            var tbsBytes = certificateList.PeekEncodedValue();
            var tbs = certificateList.ReadSequence();

            // version, optional, and v2 (1) on every CRL that carries extensions.
            if (tbs.PeekTag().TagClass == TagClass.Universal
                && tbs.PeekTag().TagValue == (int)UniversalTagNumber.Integer)
            {
                tbs.ReadEncodedValue();
            }

            // signature AlgorithmIdentifier: repeated in the outer structure,
            // which is the copy that is actually used, so this one is skipped.
            tbs.ReadEncodedValue();

            var issuerNameDer = tbs.ReadEncodedValue();
            var issuerName = new X500DistinguishedName(issuerNameDer.ToArray()).Name;

            var thisUpdate = ReadTime(ref tbs);
            if (thisUpdate is null)
            {
                error = "The CRL had no thisUpdate.";
                return false;
            }

            DateTimeOffset? nextUpdate = null;
            if (tbs.HasData && IsTime(tbs.PeekTag()))
                nextUpdate = ReadTime(ref tbs);

            // revokedCertificates, optional. Stepped over as one encoded value:
            // no entry is decoded and nothing is copied.
            if (tbs.HasData && tbs.PeekTag() == Asn1Tag.Sequence)
                tbs.ReadEncodedValue();

            string? crlNumberHex = null;
            string? baseCrlNumberHex = null;
            string? authorityKeyIdentifierHex = null;
            DateTimeOffset? nextPublish = null;

            var extensionsTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            if (tbs.HasData && tbs.PeekTag() == extensionsTag)
            {
                var explicitWrapper = tbs.ReadSequence(extensionsTag);
                var extensions = explicitWrapper.ReadSequence();

                while (extensions.HasData)
                {
                    var extension = extensions.ReadSequence();
                    var oid = extension.ReadObjectIdentifier();

                    if (extension.PeekTag().TagClass == TagClass.Universal
                        && extension.PeekTag().TagValue == (int)UniversalTagNumber.Boolean)
                    {
                        extension.ReadBoolean();
                    }

                    var value = extension.ReadOctetString();

                    // Each extension is read in isolation. One a CA encoded
                    // oddly must not cost the dates, which are the point.
                    switch (oid)
                    {
                        case CrlNumberOid:
                            crlNumberHex = TryReadIntegerHex(value);
                            break;
                        case DeltaCrlIndicatorOid:
                            baseCrlNumberHex = TryReadIntegerHex(value) ?? string.Empty;
                            break;
                        case AuthorityKeyIdentifierOid:
                            authorityKeyIdentifierHex = TryReadKeyIdentifierHex(value);
                            break;
                        case NextPublishOid:
                            nextPublish = TryReadTimeValue(value);
                            break;
                    }
                }
            }

            var algorithm = certificateList.ReadSequence();
            var signatureAlgorithmOid = algorithm.ReadObjectIdentifier();

            var signatureValue = certificateList.ReadBitString(out _);

            header = new CrlHeader(
                issuerNameDer,
                issuerName,
                thisUpdate.Value,
                nextUpdate,
                crlNumberHex,
                baseCrlNumberHex,
                authorityKeyIdentifierHex,
                nextPublish,
                tbsBytes,
                signatureAlgorithmOid,
                signatureValue);
            return true;
        }
        catch (AsnContentException ex)
        {
            error = $"The CRL could not be decoded: {ex.Message}";
            return false;
        }
        catch (CryptographicException ex)
        {
            error = $"The CRL could not be decoded: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Renders an integer's content octets as uppercase hex with leading zero
    /// bytes trimmed, so the sign pad byte a large CRL number carries cannot
    /// make two renderings of one number compare unequal.
    /// </summary>
    internal static string NormalizeNumberHex(ReadOnlySpan<byte> contentOctets)
    {
        var start = 0;
        while (start < contentOctets.Length - 1 && contentOctets[start] == 0)
            start++;

        return Convert.ToHexString(contentOctets[start..]);
    }

    private static bool IsTime(Asn1Tag tag) =>
        tag.TagClass == TagClass.Universal
        && (tag.TagValue == (int)UniversalTagNumber.UtcTime
            || tag.TagValue == (int)UniversalTagNumber.GeneralizedTime);

    private static DateTimeOffset? ReadTime(ref AsnReader reader)
    {
        if (!reader.HasData)
            return null;

        var tag = reader.PeekTag();
        if (!IsTime(tag))
            return null;

        return tag.TagValue == (int)UniversalTagNumber.UtcTime
            ? reader.ReadUtcTime(TwoDigitYearMax)
            : reader.ReadGeneralizedTime();
    }

    private static string? TryReadIntegerHex(ReadOnlyMemory<byte> value)
    {
        try
        {
            var reader = new AsnReader(value, AsnEncodingRules.DER);
            var contents = reader.ReadIntegerBytes();
            return NormalizeNumberHex(contents.Span);
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    private static string? TryReadKeyIdentifierHex(ReadOnlyMemory<byte> value)
    {
        try
        {
            var reader = new AsnReader(value, AsnEncodingRules.DER);
            var aki = reader.ReadSequence();

            // keyIdentifier is [0] IMPLICIT OCTET STRING and optional; the other
            // two members name the issuer and serial instead and are of no use
            // for telling one CA key from another.
            var keyIdentifierTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: false);
            if (!aki.HasData || aki.PeekTag() != keyIdentifierTag)
                return null;

            var keyIdentifier = aki.ReadOctetString(keyIdentifierTag);
            return Convert.ToHexString(keyIdentifier);
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    private static DateTimeOffset? TryReadTimeValue(ReadOnlyMemory<byte> value)
    {
        try
        {
            var reader = new AsnReader(value, AsnEncodingRules.DER);
            return ReadTime(ref reader);
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}
