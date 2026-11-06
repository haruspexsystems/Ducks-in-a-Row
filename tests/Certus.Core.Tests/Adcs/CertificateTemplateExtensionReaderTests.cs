using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// The two extensions through which a certificate names its template (issue #471).
/// The renewal follower matches on them, so a misread here either follows the
/// wrong certificate or none at all.
/// </summary>
public class CertificateTemplateExtensionReaderTests
{
    private const string WebServerV2Oid = "1.3.6.1.4.1.311.21.8.1.2.3.4.5.6.7.8.100";

    internal static byte[] EncodeTemplateInformation(string oid, long? major, long? minor)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            if (major is { } majorValue)
                writer.WriteInteger(majorValue);
            if (minor is { } minorValue)
                writer.WriteInteger(minorValue);
        }

        return writer.Encode();
    }

    internal static byte[] EncodeTemplateName(string name)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.BMPString, name);
        return writer.Encode();
    }

    private static X509Certificate2 Mint(params X509Extension[] extensions)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=web01.corp.example.com", key, HashAlgorithmName.SHA256);
        foreach (var extension in extensions)
            request.CertificateExtensions.Add(extension);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    [Fact]
    public void A_version_2_extension_reads_its_oid_and_both_versions()
    {
        var identity = CertificateTemplateExtensionReader.ReadTemplateInformation(
            EncodeTemplateInformation(WebServerV2Oid, 100, 4));

        identity.Should().Be(new CertificateTemplateIdentity(WebServerV2Oid, 100, 4, null));
    }

    [Fact]
    public void A_version_2_extension_without_a_minor_version_still_reads()
    {
        var identity = CertificateTemplateExtensionReader.ReadTemplateInformation(
            EncodeTemplateInformation(WebServerV2Oid, 100, null));

        identity.Should().Be(new CertificateTemplateIdentity(WebServerV2Oid, 100, null, null));
    }

    [Fact]
    public void A_version_1_extension_reads_its_name()
    {
        CertificateTemplateExtensionReader.ReadTemplateName(EncodeTemplateName("WebServer"))
            .Should().Be("WebServer");
    }

    [Fact]
    public void Reads_the_template_off_a_certificate()
    {
        using var certificate = Mint(new X509Extension(
            CertificateTemplateExtensionReader.TemplateNameOid, EncodeTemplateName("Machine"), critical: false));

        CertificateTemplateExtensionReader.ReadFrom(certificate)
            .Should().Be(new CertificateTemplateIdentity(null, null, null, "Machine"));
    }

    [Fact]
    public void Prefers_the_oid_when_a_certificate_carries_both()
    {
        using var certificate = Mint(
            new X509Extension(
                CertificateTemplateExtensionReader.TemplateNameOid, EncodeTemplateName("WebServer"), false),
            new X509Extension(
                CertificateTemplateExtensionReader.TemplateInformationOid,
                EncodeTemplateInformation(WebServerV2Oid, 100, 2), false));

        // The OID is what survives the template being renamed.
        CertificateTemplateExtensionReader.ReadFrom(certificate)!.Oid.Should().Be(WebServerV2Oid);
    }

    [Fact]
    public void A_certificate_without_either_extension_names_no_template()
    {
        using var certificate = Mint();

        CertificateTemplateExtensionReader.ReadFrom(certificate).Should().BeNull();
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 0x30, 0x03, 0x02, 0x01 })]
    [InlineData(new byte[] { 0x04, 0x02, 0x41, 0x42 })]
    public void Garbage_reads_as_absent_and_never_throws(byte[] value)
    {
        CertificateTemplateExtensionReader.ReadTemplateInformation(value).Should().BeNull();
        CertificateTemplateExtensionReader.ReadTemplateName(value).Should().BeNull();
    }

    [Fact]
    public void The_same_oid_is_the_same_template_whatever_the_versions()
    {
        var before = new CertificateTemplateIdentity(WebServerV2Oid, 100, 2, null);
        var reenrolled = new CertificateTemplateIdentity(WebServerV2Oid, 101, 0, null);

        // "Reenroll all certificate holders" raises the major version, and the
        // certificate it produces is exactly the successor to follow.
        before.SameTemplateAs(reenrolled).Should().BeTrue();
    }

    [Fact]
    public void A_different_oid_is_a_different_template()
    {
        var a = new CertificateTemplateIdentity(WebServerV2Oid, 100, 2, null);
        var b = new CertificateTemplateIdentity(WebServerV2Oid + "1", 100, 2, null);

        a.SameTemplateAs(b).Should().BeFalse();
    }

    [Fact]
    public void Version_1_names_compare_without_regard_to_case()
    {
        new CertificateTemplateIdentity(null, null, null, "WebServer")
            .SameTemplateAs(new CertificateTemplateIdentity(null, null, null, "webserver"))
            .Should().BeTrue();
    }

    [Fact]
    public void An_oid_never_matches_a_name_alone()
    {
        // Nothing relates a version 2 OID to a version 1 name without asking the
        // directory, so the two are never treated as the same template.
        new CertificateTemplateIdentity(WebServerV2Oid, 100, 2, null)
            .SameTemplateAs(new CertificateTemplateIdentity(null, null, null, "WebServer"))
            .Should().BeFalse();
    }
}
