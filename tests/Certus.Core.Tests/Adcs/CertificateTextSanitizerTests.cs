using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Tests for the shared CA text sanitizer. These moved out of
/// AdcsColumnMappingTests when the sanitizer moved out of AdcsClient in issue
/// #224, so the mapping tests cover mapping and these cover the function itself.
/// </summary>
public class CertificateTextSanitizerTests
{
    // Control characters composed with casts rather than escape sequences, so
    // every string literal in this file stays plain readable text.
    private const char Esc = (char)0x1b;
    private const char Nul = (char)0x00;
    private const char Bell = (char)0x07;
    private const char Del = (char)0x7f;
    private const char Tab = (char)0x09;
    private const char Cr = (char)0x0d;
    private const char Lf = (char)0x0a;
    private const char LineSep = (char)0x2028;
    private const char ParaSep = (char)0x2029;
    private const char Ellipsis = (char)0x2026;

    // ── SanitizeDispositionMessage ──────────────────────────────────────

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("\t\r\n", null)]
    [InlineData("Denied by HOME\\admin", "Denied by HOME\\admin")]
    [InlineData("  padded  ", "padded")]
    public void SanitizeDispositionMessage_NormalizesDegenerateValues(string? input, string? expected)
    {
        CertificateTextSanitizer.SanitizeDispositionMessage(input).Should().Be(expected);
    }

    [Fact]
    public void SanitizeDispositionMessage_KeepsTabAndLineBreaks()
    {
        // The CA composes multi line messages and the detail page preserves the
        // breaks with whitespace-pre-line, so these three survive verbatim.
        var raw = "Error Constructing or Publishing Certificate"
            + Cr + Lf + "Invalid Request" + Tab + "code";

        CertificateTextSanitizer.SanitizeDispositionMessage(raw).Should().Be(raw);
    }

    [Fact]
    public void SanitizeDispositionMessage_StripsLineSeparatorsEvenThoughItKeepsRealLineBreaks()
    {
        // The keepLineBreaks escape hatch above covers tab, CR and LF and stops
        // there. U+2028 and U+2029 are categories Zl and Zp, so they passed this
        // strip entirely until issue #234, and they are exactly the characters a
        // reader cannot agree with the writer about: this file's own reader does
        // not break on them and a SIEM's splitter does. A CA that means a line
        // break writes one, so nothing legitimate is lost by dropping these.
        CertificateTextSanitizer.SanitizeDispositionMessage(
                "Denied" + LineSep + "FATAL Certificate issued")
            .Should().Be("DeniedFATAL Certificate issued");

        CertificateTextSanitizer.SanitizeDispositionMessage("Denied" + ParaSep + " by admin")
            .Should().Be("Denied by admin");

        // And the real breaks still survive alongside them in one value.
        CertificateTextSanitizer.SanitizeDispositionMessage(
                "Invalid Request" + Cr + Lf + "code" + LineSep + "forged")
            .Should().Be("Invalid Request" + Cr + Lf + "codeforged");
    }

    [Fact]
    public void SanitizeSubject_StripsLineSeparators()
    {
        // The subject is requester authored on an enrollee supplies subject
        // template, and this runs on the sync write path.
        CertificateTextSanitizer.SanitizeSubject("CN=host" + LineSep + "evil.example")
            .Should().Be("CN=hostevil.example");
    }

    [Fact]
    public void SanitizeFileNameComponent_StripsLineSeparators()
    {
        // The download name reaches Content-Disposition filename* and the file
        // saved on disk (issue #232).
        CertificateTextSanitizer.SanitizeFileNameComponent("host" + LineSep + "name")
            .Should().Be("hostname");
    }

    [Fact]
    public void SanitizeDispositionMessage_StripsControlCharacters()
    {
        // This value is partly attacker influenced: a denial message frequently
        // quotes the subject name the requester put in the CSR, so an ACME client
        // controls a substring that reaches a log sink and an admin screen. React
        // escapes the render; the control characters are stripped here so no
        // terminal can be driven by the stored value. Note which three this does
        // not strip. Tab, CR and LF stay, so this function alone does not stop a
        // forged log line; SanitizeDispositionMessageForLog is what closes that
        // half, and the tests for it below are where that claim lives (issue #362).
        CertificateTextSanitizer.SanitizeDispositionMessage(Esc + "[31mDenied" + Esc + "[0m")
            .Should().Be("[31mDenied[0m");
        CertificateTextSanitizer.SanitizeDispositionMessage("Denied" + Nul + " by" + Bell + " admin")
            .Should().Be("Denied by admin");
        CertificateTextSanitizer.SanitizeDispositionMessage("Denied" + Del + " by admin")
            .Should().Be("Denied by admin");
    }

    [Fact]
    public void SanitizeDispositionMessage_TruncatesToTheColumnWidth()
    {
        // The CA schema allows 8192 characters; the column stores 2000. The
        // ellipsis counts toward the width, so the result fits the column exactly
        // and the sanitizer can never hand EF a value the column would reject.
        var raw = new string('x', CertificateTextSanitizer.MaxDispositionMessageLength + 500);

        var cleaned = CertificateTextSanitizer.SanitizeDispositionMessage(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Should().HaveLength(CertificateTextSanitizer.MaxDispositionMessageLength);
        cleaned.Should().EndWith(Ellipsis.ToString());
    }

    [Fact]
    public void SanitizeDispositionMessage_StripsBidirectionalOverrides()
    {
        // The class of character HTML escaping does not defend against. A right
        // to left override embedded in a CSR subject name makes the CA's denial
        // quote a hostname that reads as a different hostname on the admin's
        // screen, which is exactly the spoof this feature would otherwise carry.
        var rlo = (char)0x202e;      // RIGHT-TO-LEFT OVERRIDE
        var pdf = (char)0x202c;      // POP DIRECTIONAL FORMATTING
        var isolate = (char)0x2066;  // LEFT-TO-RIGHT ISOLATE
        var zwsp = (char)0x200b;     // ZERO WIDTH SPACE

        CertificateTextSanitizer.SanitizeDispositionMessage("Denied for " + rlo + "moc.live" + pdf)
            .Should().Be("Denied for moc.live");
        CertificateTextSanitizer.SanitizeDispositionMessage(isolate + "host" + zwsp + "name")
            .Should().Be("hostname");
    }

    [Theory]
    [InlineData(0xE0001)] // language tag
    [InlineData(0xE0020)] // tag space, the start of the invisible ASCII block
    [InlineData(0xE007F)] // cancel tag
    [InlineData(0x110BD)] // Kaithi number sign
    public void SanitizeDispositionMessage_StripsFormatCharactersAboveTheBmp(int codePoint)
    {
        // Same class as the bidirectional overrides above, but encoded as a
        // surrogate pair. The category of a lone surrogate is Surrogate and
        // never Format, so the per char scan used to walk straight past these
        // (issue #228). The tag block hides arbitrary ASCII outright.
        CertificateTextSanitizer.SanitizeDispositionMessage(
            "Denied for host" + char.ConvertFromUtf32(codePoint) + "name")
            .Should().Be("Denied for hostname");
    }

    [Fact]
    public void SanitizeDispositionMessage_KeepsCharactersAboveTheBmpThatAreNotFormat()
    {
        // Stripping is decided by the resolved category, never by being a
        // surrogate pair. Both halves have to survive together, or what is
        // stored is invalid UTF-16.
        var emoji = char.ConvertFromUtf32(0x1F600);

        CertificateTextSanitizer.SanitizeDispositionMessage("Denied " + emoji + " by admin")
            .Should().Be("Denied " + emoji + " by admin");
    }

    [Fact]
    public void SanitizeDispositionMessage_TruncationKeepsSurrogatePairsWhole()
    {
        // A cut on a UTF-16 index can land between a surrogate pair and store
        // half a character. Pad with an odd length so the boundary falls inside
        // the pair rather than between two of them.
        var pair = char.ConvertFromUtf32(0x1F600); // two UTF-16 units
        var raw = new string('x', CertificateTextSanitizer.MaxDispositionMessageLength - 2)
            + string.Concat(Enumerable.Repeat(pair, 10));

        var cleaned = CertificateTextSanitizer.SanitizeDispositionMessage(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().BeLessThanOrEqualTo(
            CertificateTextSanitizer.MaxDispositionMessageLength);
        char.IsHighSurrogate(cleaned[^2]).Should().BeFalse(
            "the character before the ellipsis must not be an orphaned high surrogate");
    }

    // ── SanitizeSubject ─────────────────────────────────────────────────

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("CN=host.example.com", "CN=host.example.com")]
    public void SanitizeSubject_NormalizesDegenerateValues(string? input, string? expected)
    {
        CertificateTextSanitizer.SanitizeSubject(input).Should().Be(expected);
    }

    [Fact]
    public void SanitizeSubject_StripsLineBreaksUnlikeTheDispositionMessage()
    {
        // The one deliberate divergence from SanitizeDispositionMessage. The CA
        // composes multi line explanations and the detail page preserves them,
        // but nothing legitimate puts a newline in a distinguished name, and one
        // there forges log lines. It forges alert email lines too: the expiry
        // notifier writes the subject into a fixed label plain text block.
        CertificateTextSanitizer.SanitizeSubject("CN=host" + Cr + Lf + "INF Bogus log line")
            .Should().Be("CN=hostINF Bogus log line");
        CertificateTextSanitizer.SanitizeSubject("CN=host" + Tab + "name")
            .Should().Be("CN=hostname");
    }

    [Theory]
    [InlineData(0xE0001)] // language tag
    [InlineData(0xE0020)] // tag space, the start of the invisible ASCII block
    [InlineData(0xE007F)] // cancel tag
    [InlineData(0x110BD)] // Kaithi number sign
    public void SanitizeSubject_StripsFormatCharactersAboveTheBmp(int codePoint)
    {
        // The other half of the issue #228 class, reached through the subject
        // rather than the disposition message. Both sanitizers share
        // StripAndBound, so this pins that the shared fix serves both callers
        // rather than only the one the original defect was reported against.
        CertificateTextSanitizer.SanitizeSubject(
            "CN=host" + char.ConvertFromUtf32(codePoint) + "name.example.com")
            .Should().Be("CN=hostname.example.com");
    }

    [Fact]
    public void SanitizeSubject_KeepsCharactersAboveTheBmpThatAreNotFormat()
    {
        var emoji = char.ConvertFromUtf32(0x1F600);

        CertificateTextSanitizer.SanitizeSubject("CN=" + emoji + ".example.com")
            .Should().Be("CN=" + emoji + ".example.com");
    }

    [Fact]
    public void SanitizeSubject_TruncationKeepsSurrogatePairsWhole()
    {
        var pair = char.ConvertFromUtf32(0x1F600);
        var raw = new string('x', CertificateTextSanitizer.MaxSubjectLength - 2)
            + string.Concat(Enumerable.Repeat(pair, 10));

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().BeLessThanOrEqualTo(CertificateTextSanitizer.MaxSubjectLength);
        char.IsHighSurrogate(cleaned[^2]).Should().BeFalse(
            "the character before the ellipsis must not be an orphaned high surrogate");
    }

    [Fact]
    public void SanitizeSubject_TruncationKeepsTheCommonNameWhenItComesLast()
    {
        // The case a plain tail cut gets wrong, and a deliberately adverse shape
        // rather than the ordinary one. A name encoded general to specific
        // renders with the common name first, because the rendering reverses the
        // encoding (issue #297, pinned in X500NameOrderingTests), so this fixture
        // is not what X509Certificate2.Subject hands back for an ordinary issued
        // certificate. It is kept exactly as it is because it is the only shape
        // that reaches the CN leading repair branch: with the common name first
        // the head cut already carries it and the early return fires, which
        // SanitizeSubject_TruncationLeavesACommonNameFirstSubjectAlone covers.
        // The shape is reachable in production all the same, from the certificate
        // authority's own columns, from a certificate another tool enrolled, and
        // from a multi valued relative distinguished name. A tail cut would keep
        // the country and lose the hostname, which is the only part the
        // dashboard, the activity feed, and the supersession linker read.
        var raw = "C=US, S=Washington, L=Seattle, O=" + new string('o', 600)
            + ", CN=leaf.example.com";

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().BeLessThanOrEqualTo(CertificateTextSanitizer.MaxSubjectLength);
        cleaned.Should().Be("CN=leaf.example.com, " + Ellipsis);
    }

    [Fact]
    public void SanitizeSubject_TruncatedCommonNameStillExtractsCleanly()
    {
        // The reason the marker sits after a comma rather than inside the name.
        // Every consumer reads the CN up to the next comma, so the ellipsis must
        // not end up looking like part of the hostname.
        var raw = "C=US, O=" + new string('o', 600) + ", CN=leaf.example.com";

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw)!;
        var extracted = System.Text.RegularExpressions.Regex.Match(cleaned, "CN=([^,]+)");

        extracted.Success.Should().BeTrue();
        extracted.Groups[1].Value.Should().Be("leaf.example.com");
    }

    [Fact]
    public void SanitizeSubject_TruncationLeavesACommonNameFirstSubjectAlone()
    {
        // The ordinary shape, and the one an issued certificate actually renders
        // as: encoded general to specific, reversed by the rendering, so the
        // common name comes first (issue #297). The head cut already keeps it, so
        // the early return fires and the value stays the plain prefix it always
        // was. The CN last fixtures around this one are the adverse case, chosen
        // because they are the only way to reach the repair branch.
        var raw = "CN=leaf.example.com, OU=IT, O=" + new string('o', 600);

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().Be(CertificateTextSanitizer.MaxSubjectLength);
        cleaned.Should().StartWith("CN=leaf.example.com, OU=IT, O=ooo");
        cleaned.Should().EndWith(Ellipsis.ToString());
    }

    [Fact]
    public void SanitizeSubject_OverLongCommonNameIsCutRatherThanDropped()
    {
        // The pathological shape, adverse for the reason set out on
        // SanitizeSubject_TruncationKeepsTheCommonNameWhenItComesLast: the CN
        // comes last, so the tail cut misses it entirely, and the CN alone still
        // does not fit. Leading with it whole is
        // impossible, so it is cut like any other value and the name is at least
        // partly readable instead of absent.
        var raw = "C=US, O=" + new string('o', 600) + ", CN=" + new string('x', 900);

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().Be(CertificateTextSanitizer.MaxSubjectLength);
        cleaned.Should().StartWith("CN=xxx");
        cleaned.Should().EndWith(Ellipsis.ToString());
    }

    [Fact]
    public void SanitizeSubject_TailCutThatAlreadyKeepsTheCommonNameIsLeftAlone()
    {
        // The CN preserving branch is a repair, not a rewrite. When the plain tail
        // cut already carries the CN marker there is nothing to fix, so the value
        // keeps its real RDN order rather than being reordered for no reason.
        var raw = "C=US, O=Example, CN=leaf.example.com, OU=" + new string('u', 600);

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Should().StartWith("C=US, O=Example, CN=leaf.example.com, OU=uuu");
        cleaned!.Length.Should().Be(CertificateTextSanitizer.MaxSubjectLength);
    }

    [Fact]
    public void SanitizeSubject_NoCommonNameFallsBackToTheTailCut()
    {
        // A bare SAN name, which the sync stores with no "CN=" prefix at all.
        var raw = new string('a', 600) + ".example.com";

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().Be(CertificateTextSanitizer.MaxSubjectLength);
        cleaned.Should().StartWith("aaa");
        cleaned.Should().EndWith(Ellipsis.ToString());
    }

    [Fact]
    public void SanitizeDispositionMessage_TruncationDoesNotReorderAroundACommonName()
    {
        // The CN preserving cut is a subject rule only. A denial message often
        // quotes a subject, but it is prose, and leading with the quoted CN would
        // rewrite what the CA actually said.
        var raw = "Denied: the request named CN=leaf.example.com and "
            + new string('x', CertificateTextSanitizer.MaxDispositionMessageLength);

        var cleaned = CertificateTextSanitizer.SanitizeDispositionMessage(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Should().StartWith("Denied: the request named CN=leaf.example.com and ");
        cleaned.Should().HaveLength(CertificateTextSanitizer.MaxDispositionMessageLength);
    }

    [Fact]
    public void SanitizeSubject_TruncationLeadsWithAWholeQuotedCommonName()
    {
        // The cut has to end the name where the name actually ends. Reading to
        // the first comma led with the fragment "CN=\"evil" and then appended
        // the marker, which stored a name that was never in the certificate
        // (issue #231).
        var raw = "C=US, O=" + new string('o', 600) + ", CN=\"evil, O=Trusted Corp\"";

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().BeLessThanOrEqualTo(CertificateTextSanitizer.MaxSubjectLength);
        cleaned.Should().Be("CN=\"evil, O=Trusted Corp\", " + Ellipsis);
    }

    [Fact]
    public void SanitizeSubject_TruncatedQuotedCommonNameStillExtractsCleanly()
    {
        // The property the lead exists for, checked through the reader every
        // consumer now uses rather than through a regular expression the way
        // SanitizeSubject_TruncatedCommonNameStillExtractsCleanly does.
        var raw = "C=US, O=" + new string('o', 600) + ", CN=\"evil, O=Trusted Corp\"";

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw)!;

        DistinguishedNameParser.CommonName(cleaned).Should().Be("evil, O=Trusted Corp");
    }

    [Fact]
    public void SanitizeSubject_TruncatedCommonNameEndingInABackslashStillExtractsCleanly()
    {
        // Issue #296. This truncation is what turned a harmless rendering into a
        // forged name, and it did so without a requester choosing the component
        // order.
        //
        // On the certificate the backslash sits at the very end of the subject,
        // where there is nothing behind it to swallow. The lead moves the common
        // name to the front and puts a separator immediately behind the
        // backslash, which is the exact shape a reader that treats a backslash as
        // an escape misreads. The result was then written back to the database by
        // SanitizeStoredSubjects on the next start, so the misread outlived the
        // sync that produced it.
        var raw = "C=US, O=" + new string('o', 600) + ", CN=CORP\\";

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw)!;

        cleaned.Should().Be("CN=CORP\\, " + Ellipsis);
        DistinguishedNameParser.CommonName(cleaned).Should().Be("CORP\\");
        CertificateTextSanitizer.SanitizeSubject(cleaned).Should().Be(cleaned);
    }

    [Fact]
    public void SanitizeSubject_IsIdempotentWithAQuotedCommonName()
    {
        // The round trip the original spelling of the RDN protects. A second
        // pass reads the lead the first pass wrote, so a lead that had unescaped
        // the value would find a different, shorter name the second time.
        var raw = "C=US, O=" + new string('o', 600) + ", CN=\"evil, O=Trusted Corp\"";

        var once = CertificateTextSanitizer.SanitizeSubject(raw);
        var twice = CertificateTextSanitizer.SanitizeSubject(once);

        twice.Should().Be(once);
    }

    [Fact]
    public void SanitizeSubject_IsIdempotent()
    {
        // Load bearing, because the value is sanitized more than once on its way
        // to the database: once in the client that read it, again at the entity
        // writer that covers every IAdcsClient, and again by the startup sweep.
        // A second pass that shortened or changed the value would make those
        // three disagree about what is stored.
        var rlo = (char)0x202e;
        var raw = "CN=" + rlo + new string('x', CertificateTextSanitizer.MaxSubjectLength + 100);

        var once = CertificateTextSanitizer.SanitizeSubject(raw);
        var twice = CertificateTextSanitizer.SanitizeSubject(once);

        once.Should().NotBeNull();
        once!.Should().HaveLength(CertificateTextSanitizer.MaxSubjectLength);
        twice.Should().Be(once);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(1)]
    [InlineData(0)]
    public void SanitizeSubject_SurvivesACommonNameThatJustFillsTheWidth(int under)
    {
        // The CN leading branch spends three characters of the width on the ", …"
        // separator, so it is entered once the common name is within two
        // characters of the cap, and it then asks for a cut one character wider
        // than the name it was handed. Reading that index before checking the
        // length threw IndexOutOfRangeException on a subject the requester
        // authored, on the sync write path. Found by code review on issue #232.
        //
        // The padding puts the CN last and pushes the whole subject past the cap,
        // so the tail carries no "CN=" and the early return is skipped.
        var commonNameValue = new string('b', CertificateTextSanitizer.MaxSubjectLength - 3 - under);
        var raw = "O=" + new string('a', CertificateTextSanitizer.MaxSubjectLength + 20)
            + ", CN=" + commonNameValue;

        var cleaned = CertificateTextSanitizer.SanitizeSubject(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().BeLessThanOrEqualTo(CertificateTextSanitizer.MaxSubjectLength);
        cleaned.Should().StartWith("CN=", "the cut leads with the common name whatever its length");
    }

    // ── SanitizeFileNameComponent ───────────────────────────────────────

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("www.contoso.com", "www.contoso.com")]
    [InlineData("  padded  ", "padded")]
    public void SanitizeFileNameComponent_NormalizesDegenerateValues(string? input, string? expected)
    {
        CertificateTextSanitizer.SanitizeFileNameComponent(input).Should().Be(expected);
    }

    [Fact]
    public void SanitizeFileNameComponent_StripsBidirectionalOverrides()
    {
        // The finding in issue #232. ASP.NET Core writes the download name into
        // Content-Disposition twice: filename= with everything outside printable
        // ASCII replaced by an underscore, and filename*=UTF-8'' carrying the
        // original percent encoded and intact. Browsers prefer the second, so an
        // override here reaches the download bar and names the saved file after a
        // host the operator never asked for.
        var rlo = (char)0x202e;      // RIGHT-TO-LEFT OVERRIDE
        var pdf = (char)0x202c;      // POP DIRECTIONAL FORMATTING
        var isolate = (char)0x2066;  // LEFT-TO-RIGHT ISOLATE
        var zwsp = (char)0x200b;     // ZERO WIDTH SPACE
        var shy = (char)0x00ad;      // SOFT HYPHEN

        CertificateTextSanitizer.SanitizeFileNameComponent(rlo + "moc.live" + pdf)
            .Should().Be("moc.live");
        CertificateTextSanitizer.SanitizeFileNameComponent(isolate + "host" + zwsp + "name" + shy)
            .Should().Be("hostname");
    }

    [Fact]
    public void SanitizeFileNameComponent_StripsControlCharactersWithoutAskingTheOperatingSystem()
    {
        // Path.GetInvalidFileNameChars answers for the running OS, not for the
        // file system the download lands on: on Unix it returns only the null
        // character and the forward slash. The control range is covered by the
        // shared strip rather than by that call, so this holds on every OS the
        // test suite might run on.
        CertificateTextSanitizer.SanitizeFileNameComponent("host" + Nul + Bell + Esc + "name")
            .Should().Be("hostname");
        CertificateTextSanitizer.SanitizeFileNameComponent("host" + Tab + Cr + Lf + "name")
            .Should().Be("hostname");
        CertificateTextSanitizer.SanitizeFileNameComponent("host" + Del + "name")
            .Should().Be("hostname");
    }

    [Theory]
    [InlineData('"')]
    [InlineData('<')]
    [InlineData('>')]
    [InlineData('|')]
    [InlineData(':')]
    [InlineData('*')]
    [InlineData('?')]
    [InlineData('\\')]
    [InlineData('/')]
    public void SanitizeFileNameComponent_StripsEveryCharacterWindowsRejects(char rejected)
    {
        // The star is in this set rather than in a clause of its own. It is
        // legal in a certificate name and not in a Windows file name, and a
        // wildcard certificate is the ordinary case that reaches it.
        CertificateTextSanitizer.SanitizeFileNameComponent("host" + rejected + "name")
            .Should().Be("hostname");
    }

    [Fact]
    public void SanitizeFileNameComponent_NamesAWildcardCertificateWithoutTheStar()
    {
        CertificateTextSanitizer.SanitizeFileNameComponent("*.contoso.com")
            .Should().Be(".contoso.com");
    }

    [Theory]
    [InlineData(0xE0001)] // language tag
    [InlineData(0xE0020)] // tag space, the start of the invisible ASCII block
    [InlineData(0xE007F)] // cancel tag
    public void SanitizeFileNameComponent_StripsFormatCharactersAboveTheBmp(int codePoint)
    {
        // Both halves of the surrogate pair go together, or the name carries a
        // lone surrogate, which has no UTF-8 encoding and so cannot survive the
        // percent encoding in the filename* parameter.
        CertificateTextSanitizer.SanitizeFileNameComponent(
            "host" + char.ConvertFromUtf32(codePoint) + "name")
            .Should().Be("hostname");
    }

    [Fact]
    public void SanitizeFileNameComponent_ReturnsNull_WhenTheNameIsOnlyFormatCharacters()
    {
        // The caller reads this as "try the next candidate", so a certificate
        // whose common name renders as nothing is named from its SAN or its
        // serial instead of from a string that looks empty in the download bar.
        var rlo = (char)0x202e;
        var zwsp = (char)0x200b;

        CertificateTextSanitizer.SanitizeFileNameComponent(rlo.ToString() + zwsp).Should().BeNull();
        CertificateTextSanitizer.SanitizeFileNameComponent("***").Should().BeNull();
    }

    [Fact]
    public void SanitizeFileNameComponent_CutsToTheCapWithNoEllipsis()
    {
        // Nothing capped this before issue #232. A Windows path component stops
        // at 255 characters and the percent encoding in filename* triples every
        // non ASCII character, so an uncapped common name produced a download the
        // browser could not save. The ellipsis StripAndBound appends is itself
        // non ASCII and would only add percent encoded noise here.
        var raw = new string('x', CertificateTextSanitizer.MaxFileNameLength + 200);

        var cleaned = CertificateTextSanitizer.SanitizeFileNameComponent(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Should().HaveLength(CertificateTextSanitizer.MaxFileNameLength);
        cleaned.Should().NotContain(Ellipsis.ToString());
    }

    [Fact]
    public void SanitizeFileNameComponent_CutKeepsSurrogatePairsWhole()
    {
        // Pad with an odd length so the cut falls inside a pair rather than
        // between two of them.
        var pair = char.ConvertFromUtf32(0x1F600); // two UTF-16 units
        var raw = new string('x', CertificateTextSanitizer.MaxFileNameLength - 1)
            + string.Concat(Enumerable.Repeat(pair, 10));

        var cleaned = CertificateTextSanitizer.SanitizeFileNameComponent(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Length.Should().BeLessThanOrEqualTo(CertificateTextSanitizer.MaxFileNameLength);
        char.IsHighSurrogate(cleaned[^1]).Should().BeFalse(
            "a trailing lone surrogate has no UTF-8 encoding and cannot survive filename* encoding");
    }

    [Theory]
    [InlineData("CON", "_CON")]
    [InlineData("con", "_con")]
    [InlineData("NUL", "_NUL")]
    [InlineData("aux", "_aux")]
    [InlineData("PRN", "_PRN")]
    [InlineData("COM1", "_COM1")]
    [InlineData("lpt9", "_lpt9")]
    public void SanitizeFileNameComponent_GuardsReservedDeviceNames(string input, string expected)
    {
        // A download named for a device does not fail loudly, it disappears into
        // the device.
        CertificateTextSanitizer.SanitizeFileNameComponent(input).Should().Be(expected);
    }

    [Fact]
    public void SanitizeFileNameComponent_GuardsAReservedNameCarryingADomainSuffix()
    {
        // Windows reads the device name from the segment before the first dot,
        // so con.contoso.com.cer is the console exactly as CON.cer is. This is a
        // plausible host name rather than a contrived one, which is what makes
        // the whole segment comparison worth having.
        CertificateTextSanitizer.SanitizeFileNameComponent("con.contoso.com")
            .Should().Be("_con.contoso.com");
    }

    [Theory]
    [InlineData("CONSOLE")]
    [InlineData("NULL")]
    [InlineData("COM10")]
    [InlineData("contoso.com")]
    [InlineData("LPT")]
    public void SanitizeFileNameComponent_LeavesNamesThatMerelyResembleADevice(string input)
    {
        // The reserved set is exact, not a prefix match. A name that starts with
        // a device name is an ordinary file name.
        CertificateTextSanitizer.SanitizeFileNameComponent(input).Should().Be(input);
    }

    [Fact]
    public void SanitizeFileNameComponent_KeepsAccentedAndNonLatinNamesReadable()
    {
        // The policy is a denylist of the classes that deceive, matching
        // SanitizeSubject, not an ASCII allowlist. An accented or non Latin
        // common name is a real name that an admin should still recognise on
        // disk, so it survives whole.
        CertificateTextSanitizer.SanitizeFileNameComponent("José Müller")
            .Should().Be("José Müller");
        CertificateTextSanitizer.SanitizeFileNameComponent("münchen.contoso.de")
            .Should().Be("münchen.contoso.de");
    }

    [Fact]
    public void SanitizeFileNameComponent_IsIdempotent()
    {
        // The class documents every function here as idempotent. The reserved
        // name guard is the one that could break it: the guarded form must no
        // longer match the reserved set, or a second pass would prefix it again.
        var rlo = (char)0x202e;
        string[] inputs =
        [
            "CON",
            "con.contoso.com",
            rlo + "moc.live",
            new string('x', CertificateTextSanitizer.MaxFileNameLength + 100),
            // Reserved stem and over the cap at once, so the guard has to make
            // room for its underscore rather than push the name past the cap.
            "COM1." + new string('y', CertificateTextSanitizer.MaxFileNameLength),
        ];

        foreach (var input in inputs)
        {
            var once = CertificateTextSanitizer.SanitizeFileNameComponent(input);
            var twice = CertificateTextSanitizer.SanitizeFileNameComponent(once);

            once.Should().NotBeNull();
            once!.Length.Should().BeLessThanOrEqualTo(CertificateTextSanitizer.MaxFileNameLength);
            twice.Should().Be(once, "sanitizing {0} twice must not differ from once", input);
        }
    }

    // ── SanitizeDispositionMessageForLog ────────────────────────────────

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    public void SanitizeDispositionMessageForLog_NormalizesDegenerateValues(
        string? input, string? expected)
    {
        CertificateTextSanitizer.SanitizeDispositionMessageForLog(input).Should().Be(expected);
    }

    [Fact]
    public void SanitizeDispositionMessageForLog_NormalizesAValueThatIsOnlyBreaks()
    {
        // Composed rather than inlined, because a theory attribute cannot carry
        // the cast constants this file uses in place of escape sequences.
        CertificateTextSanitizer
            .SanitizeDispositionMessageForLog(Tab.ToString() + Cr + Lf)
            .Should().BeNull();
    }

    [Fact]
    public void SanitizeDispositionMessageForLog_ReplacesEveryBreakWithASpace()
    {
        // The whole point of the function. Serilog's file sink writes the rendered
        // message straight through, so each of these would otherwise open a new
        // line in ducks-<date>.log that nothing wrote (issue #362).
        CertificateTextSanitizer
            .SanitizeDispositionMessageForLog("Denied" + Cr + Lf + "Invalid Request")
            .Should().Be("Denied Invalid Request");

        CertificateTextSanitizer
            .SanitizeDispositionMessageForLog("Denied" + Lf + "Invalid Request")
            .Should().Be("Denied Invalid Request");

        CertificateTextSanitizer
            .SanitizeDispositionMessageForLog("Denied" + Cr + "Invalid Request")
            .Should().Be("Denied Invalid Request");

        CertificateTextSanitizer
            .SanitizeDispositionMessageForLog("Denied" + Tab + "Invalid Request")
            .Should().Be("Denied Invalid Request");
    }

    [Fact]
    public void SanitizeDispositionMessageForLog_CollapsesARunToOneSpace()
    {
        // A blank line between two paragraphs is four break characters in a row,
        // and the log wants one separator, not four.
        var raw = "Error Constructing or Publishing Certificate"
            + Cr + Lf + Cr + Lf + Tab + "Invalid Request";

        CertificateTextSanitizer.SanitizeDispositionMessageForLog(raw)
            .Should().Be("Error Constructing or Publishing Certificate Invalid Request");
    }

    [Fact]
    public void SanitizeDispositionMessageForLog_DoesNotFuseTheWordsEitherSide()
    {
        // This is why the function substitutes rather than stripping. Passing
        // keepLineBreaks: false to the shared strip would delete the break and
        // leave the two words joined, which is a different message from the one
        // the CA sent.
        var joined = CertificateTextSanitizer.SanitizeDispositionMessage(
            "Denied by Policy Module" + Cr + Lf + "Invalid Request");
        joined.Should().Contain(Cr.ToString());

        CertificateTextSanitizer
            .SanitizeDispositionMessageForLog("Denied by Policy Module" + Cr + Lf + "Invalid Request")
            .Should().Be("Denied by Policy Module Invalid Request")
            .And.NotContain("ModuleInvalid");
    }

    [Fact]
    public void SanitizeDispositionMessageForLog_NeverLeadsOrTrailsWithASpace()
    {
        // It leans on the sibling's trim for this rather than trimming again, so
        // the dependency is worth pinning.
        //
        // ToString on the first constant, not decoration. Two char constants added
        // together are an int, so Cr + Lf here would be 23 and the value under test
        // would open with the characters two and three. Every other case in this
        // file happens to start with a string literal and so never meets it.
        CertificateTextSanitizer
            .SanitizeDispositionMessageForLog(Cr.ToString() + Lf + "Denied" + Lf + Tab)
            .Should().Be("Denied");
    }

    [Fact]
    public void SanitizeDispositionMessageForLog_StillStripsEverythingItsSiblingDoes()
    {
        // It delegates, so this is a guard against someone reimplementing the
        // strip here and missing a class. Escape sequences, C0 and DEL, the two
        // line separators, and a bidirectional override.
        var rlo = (char)0x202e;
        var raw = Esc + "[31mDenied" + Nul + Bell + Del + LineSep + ParaSep + rlo + " by admin";

        CertificateTextSanitizer.SanitizeDispositionMessageForLog(raw)
            .Should().Be("[31mDenied by admin");
    }

    [Fact]
    public void SanitizeDispositionMessageForLog_StillBoundsToTheColumnWidth()
    {
        // Collapsing runs can only shorten a value, so the sibling's bound is the
        // whole bound and no second cut is needed. The CA schema allows 8192.
        var raw = string.Join(Cr.ToString() + Lf, Enumerable.Repeat(new string('x', 100), 90));

        var flattened = CertificateTextSanitizer.SanitizeDispositionMessageForLog(raw);

        flattened.Should().NotBeNull();
        flattened!.Length.Should()
            .BeLessThanOrEqualTo(CertificateTextSanitizer.MaxDispositionMessageLength);
        flattened.Should().NotContain(Cr.ToString()).And.NotContain(Lf.ToString());
    }

    [Fact]
    public void SanitizeDispositionMessageForLog_IsIdempotent()
    {
        string[] inputs =
        [
            "Denied by Policy Module",
            "Denied" + Cr + Lf + Cr + Lf + "Invalid Request",
            Esc + "[31mDenied" + Tab + Del + LineSep + " by admin",
            new string('x', CertificateTextSanitizer.MaxDispositionMessageLength + 500),
        ];

        foreach (var input in inputs)
        {
            var once = CertificateTextSanitizer.SanitizeDispositionMessageForLog(input);
            var twice = CertificateTextSanitizer.SanitizeDispositionMessageForLog(once);

            twice.Should().Be(once, "flattening {0} twice must not differ from once", input);
        }
    }

    // ---- SanitizeTemplateName (issue #378) --------------------------------

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("  WebServer  ", "WebServer")]
    [InlineData("WebServer", "WebServer")]
    public void SanitizeTemplateName_NormalizesDegenerateValues(string? input, string? expected)
    {
        CertificateTextSanitizer.SanitizeTemplateName(input).Should().Be(expected);
    }

    [Fact]
    public void SanitizeTemplateName_StripsEveryClassItsSiblingsDo()
    {
        // The same scanner, so this is really asserting that the template name
        // was wired to it at all: before issue #378 the CA's value reached the
        // database with no scan of any kind.
        var rlo = (char)0x202e;
        var zwsp = (char)0x200b;
        var raw = Esc + "[31mWeb" + rlo + "Ser" + zwsp + "ver" + Tab + Del + LineSep + Cr + Lf;

        CertificateTextSanitizer.SanitizeTemplateName(raw).Should().Be("[31mWebServer");
    }

    [Fact]
    public void SanitizeTemplateName_BoundsToTheColumnWidth()
    {
        var raw = new string('x', CertificateTextSanitizer.MaxTemplateNameLength + 500);

        var cleaned = CertificateTextSanitizer.SanitizeTemplateName(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Should().HaveLength(CertificateTextSanitizer.MaxTemplateNameLength);
    }

    [Fact]
    public void SanitizeTemplateName_DoesNotLeadTheCutWithACommonName()
    {
        // The one place it deliberately differs from SanitizeSubject. A template
        // name is not a distinguished name, so there is no part to rescue and an
        // over long value is simply cut from the front. Pinning it because the
        // two sit next to each other and the flag is easy to copy across.
        var raw = new string('a', CertificateTextSanitizer.MaxTemplateNameLength) + ", CN=rescue.me";

        var cleaned = CertificateTextSanitizer.SanitizeTemplateName(raw);

        cleaned.Should().NotBeNull();
        cleaned!.Should().StartWith("aaa");
        cleaned.Should().NotContain("CN=");
    }

    [Fact]
    public void SanitizeTemplateName_ReturnsNull_WhenNothingUsableSurvives()
    {
        // The writers coalesce this to the empty string, because the column is
        // declared required. Null rather than "" here so a caller with a
        // fallback chain could still tell "nothing" from "something blank".
        var rlo = (char)0x202e;
        var zwsp = (char)0x200b;

        CertificateTextSanitizer.SanitizeTemplateName($"{rlo}{zwsp}{LineSep}").Should().BeNull();
    }

    [Fact]
    public void SanitizeTemplateName_IsIdempotent()
    {
        // Load bearing for the same reason the subject's is: the value is
        // sanitized in the client that read it and again at both entity writers,
        // and IsUnchanged compares a stored value against a freshly sanitized
        // one. A second pass that changed the value would make the sync treat
        // every row as moved on every cycle.
        var rlo = (char)0x202e;
        string[] inputs =
        [
            "WebServer",
            "Web" + rlo + "Server",
            "1.3.6.1.4.1.311.21.8.1234567.7654321.1.2.3",
            new string('x', CertificateTextSanitizer.MaxTemplateNameLength + 100),
        ];

        foreach (var input in inputs)
        {
            var once = CertificateTextSanitizer.SanitizeTemplateName(input);
            var twice = CertificateTextSanitizer.SanitizeTemplateName(once);

            twice.Should().Be(once, "sanitizing {0} twice must not differ from once", input);
        }
    }
}
