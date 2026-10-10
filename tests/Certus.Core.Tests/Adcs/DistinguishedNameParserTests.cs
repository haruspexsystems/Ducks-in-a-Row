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
    // value, and several carry a backslash. The backslash group is what the hex
    // escape defect hid in, and no single hand written case had covered them.
    //
    // The six that end in a backslash were added for issue #296 and cover a
    // position the earlier group did not. A backslash in the middle of a value is
    // followed by a character of the name; a backslash at the end of one is
    // followed by the separator that starts the next component, which is where a
    // reader that treats it as an escape steps over the boundary and swallows the
    // rest of the subject.
    //
    // Three of them also carry a character Windows quotes for, which puts the
    // backslash immediately in front of the closing quote rather than in front of
    // the separator: "a,b\" renders as CN="a,b\". That is the one place the
    // quoting mechanism and a literal backslash meet, and a reader that treated
    // the pair as an escaped quote would run past the end of the value and into
    // the rest of the subject. "a\\" is the other shape the earlier group missed:
    // it used to read back as "a\", one backslash short, because the first was
    // taken as escaping the second.
    private static readonly string[] AwkwardValues =
    {
        "plain.example.com",
        "evil, O=Trusted Corp",
        "Acme, CN=trusted.example.com, Ltd",
        "has+plus",
        "has\"quote",
        "has\\backslash",
        "CORP\\ab-server",
        "CORP\\",
        "\\",
        "CORP\\svc\\",
        "a,b\\",
        "a\"b\\",
        "a\\\\",
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
            // planted "CN=" would sit. Not the ordinary rendering, whatever this
            // said before issue #297: a name encoded general to specific renders
            // common name first (X500NameOrderingTests). The position is covered
            // because it is where the grammar is hardest, not because it is
            // common.
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
    public void SubjectRenderingLeavesAValueEndingInABackslashBare()
    {
        // The measurement issue #296 rests on, recorded so it is a fact in the
        // repository rather than a claim in an issue.
        //
        // Issue #238 established that a backslash is not on the list of
        // characters CertNameToStr quotes for, but it measured one in the middle
        // of a value. The end of a value is exactly where a renderer is most
        // likely to have a special case, because that is where the character sits
        // against the separator, so it is measured separately rather than
        // inferred. It does not: the value is rendered bare and the backslash
        // lands immediately in front of the ", " that starts the next component.
        //
        // The name is built by relative distinguished name rather than parsed
        // from a string, so no string parser sits in the loop and the encoded
        // value is exactly what was asked for.
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName("CORP\\");
        builder.AddOrganizationName("Example");

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(builder.Build(), key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        certificate.Subject.Should().Be("CN=CORP\\, O=Example");
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
    public void CommonName_BackslashIsAlwaysLiteralAndNeverAnEscape()
    {
        // The deliberate behaviour change of issue #296, and the inverse of what
        // this test asserted before it.
        //
        // This is the RFC 4514 spelling, which the parser used to read alongside
        // the Windows one so it did not depend on which encoder produced the
        // string. PR #293 moved MockAdcsClient onto X509Certificate2, which
        // retired the only producer of that spelling, and reading it was not free:
        // the same rule that decodes an escaped comma here swallows a component
        // boundary whenever a Windows rendered value ends in a backslash. One
        // dialect can be read correctly, two cannot.
        //
        // So this string now reads as a common name of "evil\" followed by two
        // more components, which is what a certificate carrying that name would
        // actually render as.
        var subject = "CN=evil\\, O=Trusted Corp, O=Real Org";

        DistinguishedNameParser.CommonName(subject).Should().Be("evil\\");
    }

    [Fact]
    public void CommonName_TrailingBackslashDoesNotSwallowTheNextComponent()
    {
        // Issue #296 off a real certificate, so the rendering is measured rather
        // than assumed. A backslash read as an escape steps over the separator
        // behind it, the scan never finds a component boundary, and the whole
        // subject decodes into the common name.
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName("CORP\\");
        builder.AddOrganizationName("Example");

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(builder.Build(), key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        DistinguishedNameParser.CommonName(certificate.Subject).Should().Be("CORP\\");
        DistinguishedNameParser.CommonName(certificate.Subject)
            .Should().NotBe("CORP, O=Example");
    }

    [Fact]
    public void CommonName_TrailingBackslashAheadOfTheCommonNameDoesNotHideIt()
    {
        // The same defect with a component ahead of the common name, which is
        // where it stops being a misread and becomes a disappearance. Called the
        // ordinary certificate authority ordering here until issue #297 corrected
        // that: general to specific encoding renders common name first, so this
        // is the adverse shape. Reachable all the same, and a trailing backslash
        // in the organisation name swallowed the common name outright rather than
        // forging one: the reader returned null and every caller fell back to
        // showing the whole subject.
        //
        // This half needs no requester chosen component order, only a requester
        // chosen value, which is what enrollee supplies subject hands over.
        var builder = new X500DistinguishedNameBuilder();
        builder.AddOrganizationName("CORP\\");
        builder.AddCommonName("leaf.example.com");

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(builder.Build(), key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        certificate.Subject.Should().Be("O=CORP\\, CN=leaf.example.com");
        DistinguishedNameParser.CommonName(certificate.Subject)
            .Should().Be("leaf.example.com");
    }

    [Fact]
    public void CommonNameRdn_TrailingBackslashRoundTripsThroughTheSanitizerShape()
    {
        // The amplifier, asserted directly. CertificateTextSanitizer re-emits the
        // slice this returns as "<rdn>, …" when a subject is over the column
        // width, which moves the common name to the front and puts a separator
        // right behind it. So a trailing backslash that was harmless at the end
        // of a rendering became the forged shape once the sanitizer had run, and
        // the rewrite is persisted by SanitizeStoredSubjects on every start.
        var subject = "O=Example, CN=CORP\\";

        var rdn = DistinguishedNameParser.CommonNameRdn(subject)!;

        rdn.Should().Be("CN=CORP\\");
        DistinguishedNameParser.CommonName(rdn + ", " + Ellipsis).Should().Be("CORP\\");
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
