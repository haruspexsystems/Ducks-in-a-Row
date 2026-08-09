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
    public void SanitizeDispositionMessage_StripsControlCharacters()
    {
        // This value is partly attacker influenced: a denial message frequently
        // quotes the subject name the requester put in the CSR, so an ACME client
        // controls a substring that reaches a log sink and an admin screen. React
        // escapes the render; the control characters are stripped here so a log
        // line cannot be forged, nor a terminal driven by the stored value.
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
        // The case a plain tail cut gets wrong. ADCS conventionally encodes a
        // distinguished name general to specific, which puts the CN at the end,
        // and X509Certificate2.Subject does not reorder it on the way back (see
        // SanitizeSubject_SubjectRenderingDoesNotReorderRdns). A tail cut would
        // keep the country and lose the hostname, which is the only part the
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
        // When the tail cut already keeps the CN there is nothing to reorder, so
        // the value stays the plain prefix it always was.
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
        // The pathological shape: the CN comes last, so the tail cut misses it
        // entirely, and the CN alone still does not fit. Leading with it whole is
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
}
