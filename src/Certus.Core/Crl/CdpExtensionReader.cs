using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Crl;

/// <summary>
/// What a certificate's CRL distribution points extension names.
/// </summary>
/// <param name="Urls">
/// The distribution point URLs in the order the extension encodes them, with
/// duplicates removed. The order matters: it is the order a Windows client
/// tries, and the order MS-WCCE section 3.2.1.4.1.3 has a CA try when it
/// fetches a parent CRL on a client's behalf.
/// </param>
/// <param name="SkippedIndirect">
/// Distribution points carrying a cRLIssuer, which name a CRL signed by some
/// other authority (an indirect CRL). They are skipped rather than guessed at:
/// the monitor verifies a CRL against the certificate's own issuer, and that
/// check would be wrong for an indirect CRL.
/// </param>
/// <param name="SkippedRelativeName">
/// Distribution points naming a relative distinguished name rather than a full
/// name. Resolving one needs the CRL issuer's own name as context, which no CA
/// in this product's world emits.
/// </param>
public sealed record CdpReadResult(
    IReadOnlyList<string> Urls,
    int SkippedIndirect,
    int SkippedRelativeName)
{
    /// <summary>A certificate with no CDP extension at all.</summary>
    public static readonly CdpReadResult Empty = new([], 0, 0);
}

/// <summary>
/// Reads the CRL distribution points extension (2.5.29.31) of a certificate.
///
/// The product had no reader for this extension, or for any other extension of
/// a CA certificate, before issue #447: the offline root's CRL is reachable
/// only through the distribution points of the certificate the root signed, so
/// this is the first step of the whole path.
///
/// Best effort in the same sense as <see cref="Certus.Core.Adcs.CertificateDerParser"/>:
/// a distribution point that cannot be decoded costs that distribution point
/// and nothing else, because the alternative is losing sight of a CRL over an
/// unusual encoding somewhere else in the extension.
///
/// Dependency free so tools/AdcsQiProbe can link it; keep it that way.
/// </summary>
public static class CdpExtensionReader
{
    /// <summary>id-ce-cRLDistributionPoints.</summary>
    public const string CrlDistributionPointsOid = "2.5.29.31";

    private static readonly Asn1Tag DistributionPointNameTag =
        new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag FullNameTag =
        new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag CrlIssuerTag =
        new(TagClass.ContextSpecific, 2, isConstructed: true);
    private static readonly Asn1Tag UniformResourceIdentifierTag =
        new(TagClass.ContextSpecific, 6, isConstructed: false);

    /// <summary>
    /// Reads the extension off a parsed certificate. A certificate with no CDP
    /// extension answers <see cref="CdpReadResult.Empty"/>, which is the normal
    /// answer for a self signed root: nothing publishes a CRL that covers it.
    /// </summary>
    public static CdpReadResult ReadFrom(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != CrlDistributionPointsOid)
                continue;

            return Read(extension.RawData);
        }

        return CdpReadResult.Empty;
    }

    /// <summary>
    /// Reads the DER encoded extension value. Never throws.
    /// </summary>
    public static CdpReadResult Read(ReadOnlyMemory<byte> extensionValue)
    {
        var urls = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skippedIndirect = 0;
        var skippedRelativeName = 0;

        try
        {
            var reader = new AsnReader(extensionValue, AsnEncodingRules.DER);
            var distributionPoints = reader.ReadSequence();

            while (distributionPoints.HasData)
            {
                var distributionPoint = distributionPoints.ReadSequence();
                var pointUrls = new List<string>();
                var indirect = false;

                while (distributionPoint.HasData)
                {
                    var tag = distributionPoint.PeekTag();

                    if (tag == DistributionPointNameTag)
                    {
                        // [0] is EXPLICIT here, because DistributionPointName is
                        // a CHOICE and a CHOICE cannot carry an implicit tag.
                        var name = distributionPoint.ReadSequence(DistributionPointNameTag);
                        if (name.HasData && name.PeekTag() == FullNameTag)
                            ReadGeneralNames(name.ReadSequence(FullNameTag), pointUrls);
                        else
                            skippedRelativeName++;
                    }
                    else if (tag == CrlIssuerTag)
                    {
                        indirect = true;
                        distributionPoint.ReadEncodedValue();
                    }
                    else
                    {
                        // reasons [1], or anything a later profile adds.
                        distributionPoint.ReadEncodedValue();
                    }
                }

                if (indirect)
                {
                    skippedIndirect++;
                    continue;
                }

                foreach (var url in pointUrls)
                {
                    if (seen.Add(url))
                        urls.Add(url);
                }
            }
        }
        catch (AsnContentException)
        {
            // Whatever was read before the malformed part is kept.
        }
        catch (CryptographicException)
        {
        }

        return new CdpReadResult(urls, skippedIndirect, skippedRelativeName);
    }

    private static void ReadGeneralNames(AsnReader generalNames, List<string> urls)
    {
        while (generalNames.HasData)
        {
            if (generalNames.PeekTag() == UniformResourceIdentifierTag)
            {
                var url = generalNames.ReadCharacterString(
                    UniversalTagNumber.IA5String,
                    UniformResourceIdentifierTag);

                if (!string.IsNullOrWhiteSpace(url))
                    urls.Add(url.Trim());
            }
            else
            {
                // A directory name or an IP address is a legal GeneralName and
                // is no use as a distribution point for us.
                generalNames.ReadEncodedValue();
            }
        }
    }
}
