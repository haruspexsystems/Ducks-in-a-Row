using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for the shared common name reader (issue #231). The three C# call sites
/// and the frontend mirror all defer to this grammar, so a change here moves the
/// activity feed, the inventory, and the supersession lineage key together.
/// </summary>
public class DistinguishedNameParserTests
{
    private const char Ellipsis = (char)0x2026;

    // The OID of the common name attribute, for reading the RDN back out of the
    // encoded name rather than out of its string rendering.
    private const string CommonNameOid = "2.5.4.3";

    // ── The round trip through a real certificate ───────────────────────

    [Fact]
    public void CommonName_MatchesWhatTheEncodedNameActuallyHolds()
    {
        // A measurement rather than an assumption, and the one test that would
        // have caught this defect. Whether the platform renders a comma bearing
        // common name with quotes (Windows CertNameToStr) or with a backslash
        // (RFC 4514) is deliberately not asserted. What is asserted is that the
        // string parser agrees with the DER parser, which holds either way.
        //
        // X500DistinguishedName.EnumerateRelativeDistinguishedNames is the
        // oracle here rather than the implementation. It is the correct reader
        // for an encoded name and it is what issue #231 first proposed, but the
        // callers hold a display string and not DER, so it can serve as the
        // reference and not as the fix.
        const string commonName = "evil, O=Trusted Corp";

        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=\"" + commonName + "\", O=Real Org"),
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var encoded = cert.SubjectName.EnumerateRelativeDistinguishedNames()
            .Single(rdn => rdn.GetSingleElementType().Value == CommonNameOid)
            .GetSingleElementValue();

        encoded.Should().Be(commonName, "the request encoded the comma inside the value");
        DistinguishedNameParser.CommonName(cert.Subject).Should().Be(
            encoded,
            "the string parser must agree with the encoded name, and the rendering was: {0}",
            cert.Subject);
    }

    // Values chosen because Windows treats them differently from one another:
    // some it quotes, some it leaves bare, two carry a common name inside another
    // value, and two carry a backslash. The last pair is what the hex escape
    // defect hid in, and no single hand written case had covered them.
    private static readonly string[] AwkwardValues =
    {
        "plain.example.com",
        "evil, O=Trusted Corp",
        "Acme, CN=trusted.example.com, Ltd",
        "has+plus",
        "has\"quote",
        "has\\backslash",
        "CORP\\ab-server",
        "\\74\\72\\75\\73\\74\\65\\64.example.com",
        "  leading and trailing  ",
        "semi;colon",
        "equals=sign",
        "unicode umlaut " + (char)0x00fc,
        "CN=looks like a type",
    };

    public static IEnumerable<object[]> AwkwardNamesInEveryPosition()
    {
        foreach (var value in AwkwardValues)
        {
            // The awkward value as the common name itself.
            var asCommonName = new X500DistinguishedNameBuilder();
            asCommonName.AddCommonName(value);
            asCommonName.AddOrganizationName("Real Org");
            yield return new object[] { asCommonName.Build(), value };

            // And as a value rendered before the common name, which is where a
            // planted "CN=" would sit. ADCS encodes general to specific, so every
            // requester authored part comes ahead of the common name in practice.
            var beforeCommonName = new X500DistinguishedNameBuilder();
            beforeCommonName.AddOrganizationName(value);
            beforeCommonName.AddCommonName("leaf.example.com");
            yield return new object[] { beforeCommonName.Build(), "leaf.example.com" };
        }
    }

    [Theory]
    [MemberData(nameof(AwkwardNamesInEveryPosition))]
    public void CommonName_AgreesWithTheEncodedNameAcrossEveryAwkwardValue(
        X500DistinguishedName name, string expected)
    {
        // The generalised form of the round trip above. That one measures a single
        // name; this one measures the whole grammar against the DER reader, which
        // is the only way a defect in a branch nobody thought to hand write gets
        // caught. The hex escape decoding this parser used to do passed every
        // hand written case and failed here on the two backslash values.
        //
        // The names are built by relative distinguished name rather than parsed
        // from a string, so no string parser sits in the loop and the encoded
        // value is exactly what was asked for.
        var encoded = name.EnumerateRelativeDistinguishedNames()
            .Single(rdn => rdn.GetSingleElementType().Value == CommonNameOid)
            .GetSingleElementValue();

        encoded.Should().Be(expected, "the builder encoded the value verbatim");
        DistinguishedNameParser.CommonName(name.Name).Should().Be(
            encoded,
            "the string parser must agree with the encoded name, and the rendering was: {0}",
            name.Name);
    }

    [Fact]
    public void SubjectRenderingQuotesACommaBearingCommonName()
    {
        // The measurement the fix rests on, recorded so it is a fact in the
        // repository rather than a claim in an issue. Windows CertNameToStr
        // quotes a value containing a separator instead of escaping it, so the
        // comma survives inside the rendering and a reader that stops at the
        // first one returns the fragment "\"evil".
        //
        // Certus.Core.Tests targets net10.0-windows, so this is the encoder the
        // product actually runs against. The parser handles the RFC 4514
        // backslash spelling too, which is covered separately and is not
        // reachable from here.
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=\"evil, O=Trusted Corp\", O=Real Org"),
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        cert.Subject.Should().Be("CN=\"evil, O=Trusted Corp\", O=Real Org");
    }

    [Fact]
    public void CommonName_RealCertificateWithAnOrdinaryNameIsUnaffected()
    {
        // The overwhelmingly common shape, kept alongside the adversarial one so
        // a parser that only handles escaping cannot pass.
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=leaf.example.com, OU=IT, O=Example"),
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        DistinguishedNameParser.CommonName(cert.Subject).Should().Be("leaf.example.com");
    }

    // ── CommonName ──────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("OU=IT, O=Example")]                 // no common name at all
    [InlineData("host.example.com")]                 // bare name, the SAN only shape
    [InlineData("CN=")]                              // present but empty
    [InlineData("CN=   , OU=IT")]                    // present but whitespace
    public void CommonName_NothingToRead_ReturnsNull(string? subject)
    {
        DistinguishedNameParser.CommonName(subject).Should().BeNull();
    }

    [Theory]
    [InlineData("CN=leaf.example.com", "leaf.example.com")]
    [InlineData("CN=leaf.example.com, OU=IT, O=Example", "leaf.example.com")]
    [InlineData("C=US, O=Example, CN=leaf.example.com", "leaf.example.com")]
    [InlineData("cn=leaf.example.com", "leaf.example.com")]
    [InlineData("Cn = leaf.example.com , OU=IT", "leaf.example.com")]
    [InlineData("C=US; O=Example; CN=leaf.example.com", "leaf.example.com")]
    public void CommonName_OrdinaryShapes(string subject, string expected)
    {
        DistinguishedNameParser.CommonName(subject).Should().Be(expected);
    }

    [Fact]
    public void CommonName_QuotedCommaIsPartOfTheNameNotASeparator()
    {
        // The defect itself. Reading to the first comma returned the fragment
        // "\"evil", which is neither the name in the certificate nor a name any
        // admin could act on.
        var subject = "CN=\"evil, O=Trusted Corp\", O=Real Org";

        DistinguishedNameParser.CommonName(subject).Should().Be("evil, O=Trusted Corp");
    }

    [Fact]
    public void CommonName_BackslashEscapedCommaIsPartOfTheName()
    {
        // The RFC 4514 spelling of the same name. Handled alongside the quoted
        // form rather than instead of it, so the parser does not depend on which
        // encoder produced the string it was handed.
        var subject = "CN=evil\\, O=Trusted Corp, O=Real Org";

        DistinguishedNameParser.CommonName(subject).Should().Be("evil, O=Trusted Corp");
    }

    [Fact]
    public void CommonName_DoubledQuoteInsideAQuotedValueIsOneLiteralQuote()
    {
        // How CertNameToStr writes a quote that was already in the name. The
        // inner pair must not be read as closing and reopening the value.
        var subject = "CN=\"say \"\"hi\"\", friend\", O=Example";

        DistinguishedNameParser.CommonName(subject).Should().Be("say \"hi\", friend");
    }

    [Fact]
    public void CommonName_HexEscapesAreNotDecoded()
    {
        // This reader used to decode the RFC 4514 "\hh" byte form, and doing so
        // forged names. Neither encoder that reaches this parser emits it:
        // CertNameToStr has no escaping form at all, and the RFC 4514 renderer in
        // BouncyCastle escapes special characters with a plain backslash. So the
        // only way "\74" arrives here is because a requester put those four
        // characters in the name, and Windows stored them verbatim.
        var subject = "CN=caf\\C3\\A9.example.com, O=Example";

        DistinguishedNameParser.CommonName(subject).Should().Be("caf\\C3\\A9.example.com");
    }

    [Fact]
    public void CommonName_HexEscapesCannotForgeADifferentHostName()
    {
        // The sharp form of the same defect, taken off a real certificate so the
        // rendering is not assumed. Seven hex escapes spell "trusted" to a reader
        // that decodes them, and Windows renders them untouched because a
        // backslash is not a character it quotes for.
        var planted = "\\74\\72\\75\\73\\74\\65\\64.example.com";

        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(planted);
        builder.AddOrganizationName("Real Org");

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(builder.Build(), key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        certificate.Subject.Should().Be($"CN={planted}, O=Real Org");

        DistinguishedNameParser.CommonName(certificate.Subject).Should().Be(planted);
        DistinguishedNameParser.CommonName(certificate.Subject)
            .Should().NotBe("trusted.example.com");
    }

    [Theory]
    [InlineData("CN=CORP\\admin, O=Example", "CORP\\admin")]
    [InlineData("CN=CORP\\ab-server, O=Example", "CORP\\ab-server")]
    [InlineData("CN=has\\backslash, O=Example", "has\\backslash")]
    public void CommonName_LiteralBackslashSurvives(string subject, string expected)
    {
        // A backslash is not on the list of characters CertNameToStr quotes for,
        // so a name holding one is rendered with it intact and no quotes around
        // it. Treating it as an escape unconditionally dropped the backslash
        // ("CORP\svc" read back as "CORPsvc"), and when the next two characters
        // happened to be hex digits it decoded them to one byte instead. That
        // byte is not valid UTF-8 alone, so "CORP\ab-server" came back as "CORP",
        // the replacement character, then "-server".
        DistinguishedNameParser.CommonName(subject).Should().Be(expected);
    }

    [Fact]
    public void CommonName_EqualsSignInsideAQuotedValueIsPartOfTheName()
    {
        var subject = "CN=\"a=b\", O=Example";

        DistinguishedNameParser.CommonName(subject).Should().Be("a=b");
    }

    [Fact]
    public void CommonName_MultiValuedRelativeDistinguishedName()
    {
        // Plus separates the parts of one relative distinguished name. A common
        // name sitting after one is still a common name.
        DistinguishedNameParser.CommonName("OU=IT+CN=leaf.example.com, O=Example")
            .Should().Be("leaf.example.com");
    }

    [Fact]
    public void CommonName_EmptyCommonNameIsSkippedRatherThanReturned()
    {
        // Both readers this replaced behaved this way, one through a regular
        // expression that required a character and the other through a length
        // test, so a subject carrying a stray "CN=" still finds the real name.
        DistinguishedNameParser.CommonName("CN=, OU=IT, CN=leaf.example.com")
            .Should().Be("leaf.example.com");
    }

    [Fact]
    public void CommonName_QuotedValueKeepsItsOwnSpacing()
    {
        // Quoting is how CertNameToStr preserves a leading or trailing space in a
        // name, so trimming after decoding would undo the reason for the quotes.
        DistinguishedNameParser.CommonName("CN=\"  spaced  \", O=Example")
            .Should().Be("  spaced  ");
    }

    [Fact]
    public void CommonName_TruncatedSubjectFromTheSanitizerStillReads()
    {
        // The sanitizer's lead with the common name form. The marker is a
        // component with no equals sign, so it is skipped rather than misread.
        var subject = "CN=leaf.example.com, " + Ellipsis;

        DistinguishedNameParser.CommonName(subject).Should().Be("leaf.example.com");
    }

    [Fact]
    public void CommonName_TruncatedCommonNameKeepsTheMarkerInTheName()
    {
        // The pathological sanitizer shape: the name itself did not fit, so the
        // marker is genuinely inside it. Reporting the cut name is correct here,
        // because the cut name is all that was stored.
        var subject = "CN=aaa" + Ellipsis;

        DistinguishedNameParser.CommonName(subject).Should().Be("aaa" + Ellipsis);
    }

    // ── CommonNameRdn ───────────────────────────────────────────────────

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("OU=IT, O=Example", null)]
    [InlineData("host.example.com", null)]
    [InlineData("CN=leaf.example.com", "CN=leaf.example.com")]
    [InlineData("C=US, O=Example, CN=leaf.example.com", "CN=leaf.example.com")]
    [InlineData("C=US, CN=leaf.example.com, OU=IT", "CN=leaf.example.com")]
    public void CommonNameRdn_ReturnsTheComponentWithItsPrefix(string? subject, string? expected)
    {
        DistinguishedNameParser.CommonNameRdn(subject).Should().Be(expected);
    }

    [Fact]
    public void CommonNameRdn_KeepsTheOriginalSpelling()
    {
        // Load bearing rather than incidental. CertificateTextSanitizer re-emits
        // this slice into a truncated subject that has to parse back to the same
        // name, and an unescaped value would turn the quoted comma into a real
        // separator on the second pass.
        var subject = "CN=\"evil, O=Trusted Corp\", O=Real Org";

        DistinguishedNameParser.CommonNameRdn(subject)
            .Should().Be("CN=\"evil, O=Trusted Corp\"");
    }

    [Fact]
    public void CommonNameRdn_RoundTripsBackToTheSameName()
    {
        // The property the sanitizer actually depends on, asserted directly.
        var subject = "CN=\"evil, O=Trusted Corp\", O=Real Org";

        var rdn = DistinguishedNameParser.CommonNameRdn(subject)!;

        DistinguishedNameParser.CommonName(rdn + ", " + Ellipsis)
            .Should().Be(DistinguishedNameParser.CommonName(subject));
    }

    [Fact]
    public void CommonNameRdn_MultiValuedNameReturnsTheCommonNamePartAlone()
    {
        // Shorter than the whole relative distinguished name, which is all the
        // caller needs: it has to parse back to the same common name, not to
        // reproduce the name it came from.
        DistinguishedNameParser.CommonNameRdn("OU=IT+CN=leaf.example.com, O=Example")
            .Should().Be("CN=leaf.example.com");
    }
}
