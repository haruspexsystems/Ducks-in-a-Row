using System.Formats.Asn1;
using System.Text;
using Certus.Core.Crl;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// The distribution points on an issuing CA certificate are the only route to
/// the CRL its parent publishes, which on most estates is an offline root's.
/// </summary>
public class CdpExtensionReaderTests
{
    private const string LdapUrl =
        "ldap:///CN=Contoso Root CA,CN=ROOT01,CN=CDP,CN=Public Key Services,CN=Services,"
        + "CN=Configuration,DC=contoso,DC=com?certificateRevocationList?base?"
        + "objectClass=cRLDistributionPoint";

    private const string HttpUrl = "http://pki.contoso.com/Contoso%20Root%20CA.crl";

    [Fact]
    public void Reads_both_urls_in_the_order_the_extension_encodes_them()
    {
        using var root = CrlTestPki.MintRootCa();
        using var issuing = CrlTestPki.MintIssuingCa(
            root, "CN=Contoso Issuing CA", LdapUrl, HttpUrl);

        var result = CdpExtensionReader.ReadFrom(issuing);

        // Order is not cosmetic: it is the order a Windows client tries, and the
        // order MS-WCCE has a CA try when it fetches a parent CRL itself.
        result.Urls.Should().Equal(LdapUrl, HttpUrl);
        result.SkippedIndirect.Should().Be(0);
        result.SkippedRelativeName.Should().Be(0);
    }

    [Fact]
    public void A_certificate_with_no_extension_reads_empty()
    {
        using var root = CrlTestPki.MintRootCa();

        // The ordinary shape of a self signed root: nothing publishes a CRL that
        // covers it, so it names no distribution point.
        CdpExtensionReader.ReadFrom(root).Urls.Should().BeEmpty();
    }

    [Fact]
    public void Removes_a_repeated_url()
    {
        using var root = CrlTestPki.MintRootCa();
        using var issuing = CrlTestPki.MintIssuingCa(
            root, "CN=Contoso Issuing CA", HttpUrl, HttpUrl, LdapUrl);

        CdpExtensionReader.ReadFrom(issuing).Urls.Should().Equal(HttpUrl, LdapUrl);
    }

    [Fact]
    public void Skips_a_distribution_point_that_names_another_crl_issuer()
    {
        var extension = BuildDistributionPoints(
            (HttpUrl, CrlIssuer: "http://other.example/indirect.crl"),
            (LdapUrl, CrlIssuer: null));

        var result = CdpExtensionReader.Read(extension);

        // An indirect CRL is signed by someone other than the certificate's own
        // issuer, so verifying it against that issuer would fail and trusting it
        // without verifying would be worse.
        result.Urls.Should().Equal(LdapUrl);
        result.SkippedIndirect.Should().Be(1);
    }

    [Fact]
    public void Counts_a_relative_name_as_unsupported_and_keeps_the_rest()
    {
        var extension = BuildWithRelativeName(HttpUrl);

        var result = CdpExtensionReader.Read(extension);

        result.Urls.Should().Equal(HttpUrl);
        result.SkippedRelativeName.Should().Be(1);
    }

    [Fact]
    public void Ignores_a_general_name_that_is_not_a_url()
    {
        var extension = BuildWithDirectoryName(HttpUrl);

        CdpExtensionReader.Read(extension).Urls.Should().Equal(HttpUrl);
    }

    [Fact]
    public void Malformed_bytes_read_as_empty_rather_than_throwing()
    {
        var garbage = Encoding.ASCII.GetBytes("not an extension");

        var result = CdpExtensionReader.Read(garbage);

        result.Urls.Should().BeEmpty();
    }

    [Fact]
    public void A_truncated_extension_reads_as_empty_rather_than_throwing()
    {
        var whole = BuildDistributionPoints((HttpUrl, null), (LdapUrl, null));
        var truncated = whole[..(whole.Length - 5)];

        // Nothing survives a truncation, because DER puts the length of the
        // whole extension in front of it and the outer read fails before any
        // distribution point is reached. Recorded as behaviour rather than
        // claimed as partial tolerance.
        CdpExtensionReader.Read(truncated).Urls.Should().BeEmpty();
    }

    [Fact]
    public void Keeps_the_distribution_points_read_before_a_broken_one()
    {
        const string shortUrl = "http://pki/c.crl";
        var good = BuildOneDistributionPoint(shortUrl);
        // A distribution point whose inner element is not decodable, with lengths
        // that stay consistent with the extension around it: the shape where
        // being best effort actually buys something.
        var broken = new byte[] { 0x30, 0x03, 0xA0, 0x01, 0x30 };

        var extension = new byte[2 + good.Length + broken.Length];
        extension[0] = 0x30;
        extension[1] = (byte)(good.Length + broken.Length);
        good.CopyTo(extension, 2);
        broken.CopyTo(extension, 2 + good.Length);

        CdpExtensionReader.Read(extension).Urls.Should().Equal(shortUrl);
    }

    #region Encoders for the shapes no certificate builder will produce

    private static byte[] BuildDistributionPoints(
        params (string Url, string? CrlIssuer)[] points)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (var (url, crlIssuer) in points)
            {
                using (writer.PushSequence())
                {
                    WriteFullName(writer, url);

                    if (crlIssuer is not null)
                    {
                        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)))
                        {
                            WriteUri(writer, crlIssuer);
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }

    private static byte[] BuildWithRelativeName(string url)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("2.5.4.3");
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, "Contoso Root CA");
                }
            }

            using (writer.PushSequence())
            {
                WriteFullName(writer, url);
            }
        }

        return writer.Encode();
    }

    private static byte[] BuildWithDirectoryName(string url)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSequence())
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            // directoryName [4], legal and useless as a distribution point.
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4)))
            using (writer.PushSequence())
            using (writer.PushSetOf())
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("2.5.4.3");
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, "Contoso Root CA");
            }

            WriteUri(writer, url);
        }

        return writer.Encode();
    }

    private static byte[] BuildOneDistributionPoint(string url)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            WriteFullName(writer, url);
        }

        return writer.Encode();
    }

    private static void WriteFullName(AsnWriter writer, string url)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            WriteUri(writer, url);
        }
    }

    private static void WriteUri(AsnWriter writer, string url) =>
        writer.WriteCharacterString(
            UniversalTagNumber.IA5String, url, new Asn1Tag(TagClass.ContextSpecific, 6));

    #endregion
}
