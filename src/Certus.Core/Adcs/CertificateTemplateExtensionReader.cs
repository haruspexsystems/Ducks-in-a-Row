using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Adcs;

/// <summary>
/// Which certificate template a certificate was issued from, as the certificate
/// itself records it.
/// </summary>
/// <param name="Oid">
/// The template's object identifier, from the Certificate Template Information
/// extension that version 2 and later templates carry. Null for a version 1
/// template.
/// </param>
/// <param name="MajorVersion">The template's major version, when recorded.</param>
/// <param name="MinorVersion">The template's minor version, when recorded.</param>
/// <param name="Name">
/// The template's name, from the Certificate Template Name extension that
/// version 1 templates carry (the stock Web Server and Machine templates are
/// both version 1). Null for a version 2 or later template.
/// </param>
public sealed record CertificateTemplateIdentity(
    string? Oid,
    long? MajorVersion,
    long? MinorVersion,
    string? Name)
{
    /// <summary>
    /// Whether two certificates came from the same template. The object
    /// identifier decides when both carry one; otherwise the version 1 name
    /// does, compared without regard to case, which is how ADCS compares
    /// template names. Anything else is not a match.
    ///
    /// The versions are ignored on purpose. "Reenroll all certificate holders"
    /// raises a template's major version, and the certificate that reenrolment
    /// produces is exactly the successor a renewal follower has to find.
    /// </summary>
    public bool SameTemplateAs(CertificateTemplateIdentity other)
    {
        ArgumentNullException.ThrowIfNull(other);

        if (Oid is not null && other.Oid is not null)
            return string.Equals(Oid, other.Oid, StringComparison.Ordinal);

        if (Oid is null && other.Oid is null && Name is not null && other.Name is not null)
            return string.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase);

        return false;
    }

    /// <summary>
    /// A short label for a log line or a picker row: the version 1 name, or the
    /// object identifier.
    /// </summary>
    public string Describe() => Name ?? Oid ?? string.Empty;
}

/// <summary>
/// Reads the two extensions through which a certificate names the template it
/// was issued from (issue #471): Certificate Template Information
/// (1.3.6.1.4.1.311.21.7), a SEQUENCE of the template OID and its major and
/// optional minor version, written for version 2 and later templates; and
/// Certificate Template Name (1.3.6.1.4.1.311.20.2), a BMPString, written for
/// version 1 templates.
///
/// The product had no reader for either before monitor mode needed one: the
/// service follows an autoenrolled HTTPS certificate across a renewal by
/// matching the successor's subject and template against the certificate it
/// was pinned to, and a template the CA database records is no help there,
/// because the certificate may come from any CA.
///
/// Never throws, in the same sense as <see cref="Crl.CdpExtensionReader"/>: an
/// extension that cannot be decoded reads as absent, which costs the follower
/// a match and nothing else. Dependency free; keep it that way.
/// </summary>
public static class CertificateTemplateExtensionReader
{
    /// <summary>szOID_CERTIFICATE_TEMPLATE, Certificate Template Information.</summary>
    public const string TemplateInformationOid = "1.3.6.1.4.1.311.21.7";

    /// <summary>szOID_ENROLL_CERTTYPE_EXTENSION, Certificate Template Name.</summary>
    public const string TemplateNameOid = "1.3.6.1.4.1.311.20.2";

    /// <summary>
    /// The template a certificate names, or null when it names none. When both
    /// extensions are present the object identifier wins, because it is the
    /// one that survives a template being renamed.
    /// </summary>
    public static CertificateTemplateIdentity? ReadFrom(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        CertificateTemplateIdentity? information = null;
        string? name = null;

        foreach (var extension in certificate.Extensions)
        {
            switch (extension.Oid?.Value)
            {
                case TemplateInformationOid:
                    information = ReadTemplateInformation(extension.RawData);
                    break;
                case TemplateNameOid:
                    name = ReadTemplateName(extension.RawData);
                    break;
            }
        }

        if (information is not null)
            return information;

        return name is null ? null : new CertificateTemplateIdentity(null, null, null, name);
    }

    /// <summary>
    /// Decodes a Certificate Template Information value:
    /// SEQUENCE { templateID OBJECT IDENTIFIER, templateMajorVersion INTEGER,
    /// templateMinorVersion INTEGER OPTIONAL }. Null when it does not decode.
    /// </summary>
    public static CertificateTemplateIdentity? ReadTemplateInformation(ReadOnlyMemory<byte> extensionValue)
    {
        try
        {
            var reader = new AsnReader(extensionValue, AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            var oid = sequence.ReadObjectIdentifier();

            long? major = null;
            long? minor = null;
            if (sequence.HasData && sequence.TryReadInt64(out var majorValue))
                major = majorValue;
            if (sequence.HasData && sequence.TryReadInt64(out var minorValue))
                minor = minorValue;

            return new CertificateTemplateIdentity(oid, major, minor, null);
        }
        catch (AsnContentException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Decodes a Certificate Template Name value, a BMPString. Null when it does
    /// not decode or is blank.
    /// </summary>
    public static string? ReadTemplateName(ReadOnlyMemory<byte> extensionValue)
    {
        try
        {
            var reader = new AsnReader(extensionValue, AsnEncodingRules.DER);
            var name = reader.ReadCharacterString(UniversalTagNumber.BMPString);
            return string.IsNullOrWhiteSpace(name) ? null : name;
        }
        catch (AsnContentException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
