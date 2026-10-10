using Certus.Core.Security;

namespace Certus.Core.Tests.Security;

/// <summary>
/// The shared character scanner behind every guard in the product. The classes
/// it names are load bearing twice over: each guard words its refusal from the
/// class, and the three together are the whole answer to "can this value forge a
/// line in the service log".
/// </summary>
public class DeceptiveCharactersTests
{
    private static DeceptiveCharacterClass ClassOf(int codePoint) =>
        DeceptiveCharacters.Classify(char.ConvertFromUtf32(codePoint), 0);

    // Written as numeric code points rather than escapes so the C1 entries stay
    // readable in source instead of becoming invisible bytes.
    [Theory]
    [InlineData(0x0A)] // line feed, the ADCS attribute pair separator
    [InlineData(0x0D)] // carriage return
    [InlineData(0x09)] // tab
    [InlineData(0x00)] // NUL, the C string terminator
    [InlineData(0x0B)] // vertical tab
    [InlineData(0x0C)] // form feed
    [InlineData(0x7F)] // DEL
    [InlineData(0x85)] // NEL, a C1 control and a line terminator in its own right
    [InlineData(0x9B)] // C1 control sequence introducer
    public void Classify_ControlCharacter(int codePoint) =>
        ClassOf(codePoint).Should().Be(DeceptiveCharacterClass.Control);

    // Zl and Zp. Every guard in the product passed both until issue #234,
    // because neither is Control and neither is Format.
    [Theory]
    [InlineData(0x2028)] // LINE SEPARATOR
    [InlineData(0x2029)] // PARAGRAPH SEPARATOR
    public void Classify_LineSeparator(int codePoint) =>
        ClassOf(codePoint).Should().Be(DeceptiveCharacterClass.LineSeparator);

    [Theory]
    [InlineData(0x200B)] // zero width space
    [InlineData(0x200E)] // left to right mark
    [InlineData(0x202E)] // right to left override
    [InlineData(0x2066)] // left to right isolate
    [InlineData(0x2069)] // pop directional isolate
    [InlineData(0x00AD)] // soft hyphen
    [InlineData(0xE0001)] // language tag, above the BMP
    [InlineData(0xE0020)] // tag space, the start of the invisible ASCII block
    [InlineData(0xE007F)] // cancel tag
    [InlineData(0x110BD)] // Kaithi number sign
    [InlineData(0x1BCA0)] // shorthand format letter overlap
    public void Classify_FormatCharacter(int codePoint) =>
        ClassOf(codePoint).Should().Be(DeceptiveCharacterClass.Format);

    [Theory]
    [InlineData(0x41)]    // 'A'
    [InlineData(0x20)]    // an ordinary space
    [InlineData(0x2D)]    // a hyphen
    [InlineData(0x00E9)]  // 'é', ordinary in a template display name
    [InlineData(0x00A0)]  // no break space: category Zs, deliberately not refused
    [InlineData(0x3000)]  // ideographic space, also Zs
    [InlineData(0x3164)]  // hangul filler: renders blank but is Lo, a known residual
    [InlineData(0x1F600)] // an emoji, above the BMP
    [InlineData(0x20000)] // a CJK extension B ideograph, above the BMP
    public void Classify_OrdinaryCharacter(int codePoint) =>
        ClassOf(codePoint).Should().Be(DeceptiveCharacterClass.None);

    /// <summary>
    /// The closed class claim behind issue #234. Every code point a mainstream
    /// splitter treats as a line break is one of the three classes, so once
    /// U+2028 and U+2029 are covered there is no eleventh character to find in a
    /// later sweep. This list is Python's <c>str.splitlines</c> set, which is the
    /// widest in common use and a superset of what a .NET reader, grep, or less
    /// will break on.
    /// </summary>
    [Theory]
    [InlineData(0x0A)]
    [InlineData(0x0B)]
    [InlineData(0x0C)]
    [InlineData(0x0D)]
    [InlineData(0x1C)]
    [InlineData(0x1D)]
    [InlineData(0x1E)]
    [InlineData(0x85)]
    [InlineData(0x2028)]
    [InlineData(0x2029)]
    public void EveryLineBreakingCodePoint_IsRefused(int codePoint) =>
        ClassOf(codePoint).Should().NotBe(
            DeceptiveCharacterClass.None,
            "no code point any log reader treats as a line break may reach a log line");

    [Fact]
    public void Find_ReportsTheFirstMatchWithItsPosition()
    {
        var found = DeceptiveCharacters.Find("WebServer\u2028cdc:evil");

        found.Should().NotBeNull();
        found!.Value.Class.Should().Be(DeceptiveCharacterClass.LineSeparator);
        found.Value.Position.Should().Be(9);
        found.Value.CodePoint.Should().Be(0x2028);
    }

    [Fact]
    public void Find_ReportsTheWholeRuneNotASurrogateHalf()
    {
        // A pair reported as its leading half (U+DB40) names a character that
        // does not exist on its own and cannot be looked up (issue #228).
        var found = DeceptiveCharacters.Find("WebServer" + char.ConvertFromUtf32(0xE0041));

        found.Should().NotBeNull();
        found!.Value.Class.Should().Be(DeceptiveCharacterClass.Format);
        found.Value.CodePoint.Should().Be(0xE0041);
    }

    [Fact]
    public void Find_ControlBeatsAFormatCharacterFurtherAlong()
    {
        // First match wins, whatever its class, so the reported position is
        // always the one an operator would look at first.
        var found = DeceptiveCharacters.Find("a\nb\u202Ec");

        found!.Value.Class.Should().Be(DeceptiveCharacterClass.Control);
        found.Value.Position.Should().Be(1);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("WebServer")]
    [InlineData("ca01.contoso.local\\Contoso-CA")]
    [InlineData("Contoso Web Server v2.1_final-copy")]
    [InlineData("Serveur Web étendu")]
    public void Find_CleanValue_ReturnsNull(string? value) =>
        DeceptiveCharacters.Find(value).Should().BeNull();

    [Fact]
    public void Find_LoneHighSurrogate_IsNotRefused()
    {
        // A broken pair reads as Surrogate, never Format, and CodePointAt must
        // not try to resolve it: ConvertToUtf32 throws on a broken pair, and
        // this runs on hostile input.
        DeceptiveCharacters.Find("WebServer\uDB40").Should().BeNull();
    }
}
