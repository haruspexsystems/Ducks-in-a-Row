using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// The CA connection string boundary (issue #220). The string is its own
/// Submit parameter, so it cannot smuggle a request attribute the way a
/// template name can, but it is written verbatim into the service log on every
/// ordinary CA call. A line break there forges entries in the record an
/// operator reads to reconstruct what happened, and a bidirectional override
/// makes one CA render as another.
/// </summary>
public class AdcsCaConnectionStringTests
{
    [Fact]
    public void TryValidate_OrdinaryConnectionString_Passes()
    {
        AdcsCaConnectionString.TryValidate("ca01.contoso.local\\Contoso-CA", out var error)
            .Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void TryValidate_CaNameWithSpacesAndPunctuation_Passes()
    {
        // A CA common name is a directory CN: spaces, hyphens, dots and digits
        // are all ordinary. The guard refuses character categories only, and
        // must not narrow what a real deployment can name its CA.
        AdcsCaConnectionString.TryValidate(
            "ca01.contoso.local\\Contoso Issuing CA 01 (v2.1)", out var error)
            .Should().BeTrue();
        error.Should().BeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryValidate_MissingValue_Passes(string? caConnectionString)
    {
        // Presence is the caller's rule, not this guard's: a mock CA install has
        // no connection string and a partly filled wizard draft has none yet.
        AdcsCaConnectionString.TryValidate(caConnectionString, out var error)
            .Should().BeTrue();
        error.Should().BeNull();
    }

    // Written as numeric char constants rather than escapes so the C1 entries
    // stay readable in source instead of becoming invisible bytes.
    [Theory]
    [InlineData((char)0x0A)] // line feed, the log line separator
    [InlineData((char)0x0D)] // carriage return
    [InlineData((char)0x09)] // tab
    [InlineData((char)0x00)] // NUL, the C string terminator
    [InlineData((char)0x0B)] // vertical tab
    [InlineData((char)0x0C)] // form feed
    [InlineData((char)0x7F)] // DEL
    [InlineData((char)0x85)] // NEL, a C1 control the CLR treats as a line break
    [InlineData((char)0x9B)] // C1 control sequence introducer
    public void TryValidate_AnyControlCharacter_IsRefused(char control)
    {
        var valid = AdcsCaConnectionString.TryValidate(
            $"ca01.contoso.local\\Contoso-CA{control}FATAL Certificate issued", out var error);

        valid.Should().BeFalse();
        error.Should().Contain("control character");
    }

    [Theory]
    [InlineData((char)0x200B)] // zero width space
    [InlineData((char)0x200E)] // left to right mark
    [InlineData((char)0x202E)] // right to left override
    [InlineData((char)0x2066)] // left to right isolate
    [InlineData((char)0x2069)] // pop directional isolate
    [InlineData((char)0x00AD)] // soft hyphen
    public void TryValidate_AnyFormatCharacter_IsRefused(char format)
    {
        var valid = AdcsCaConnectionString.TryValidate(
            $"ca01.contoso.local\\Contoso{format}-CA", out var error);

        valid.Should().BeFalse();
        error.Should().Contain("formatting character");
    }

    [Theory]
    [InlineData(0xE0001)] // language tag
    [InlineData(0xE0020)] // tag space, the start of the invisible ASCII block
    [InlineData(0xE007F)] // cancel tag
    [InlineData(0x110BD)] // Kaithi number sign
    [InlineData(0x1BCA0)] // shorthand format letter overlap
    public void TryValidate_FormatCharacterAboveTheBmp_IsRefused(int codePoint)
    {
        // These arrive as a surrogate pair. The category of a lone surrogate is
        // Surrogate and never Format, so a per char lookup would let the whole
        // class through — including the tag block, which encodes arbitrary
        // ASCII invisibly.
        var valid = AdcsCaConnectionString.TryValidate(
            "ca01.contoso.local\\Contoso" + char.ConvertFromUtf32(codePoint) + "-CA", out var error);

        valid.Should().BeFalse();
        error.Should().Contain("formatting character");
        error.Should().Contain($"U+{codePoint:X4}", "the reported code point is the rune, not a surrogate half");
    }

    [Fact]
    public void TryValidate_CharacterAboveTheBmpThatIsNotAFormatCharacter_Passes()
    {
        // A surrogate pair is not refused for being one: only its resolved
        // category decides. An emoji in a CA name is odd but not a spoof.
        AdcsCaConnectionString.TryValidate(
            "ca01.contoso.local\\Contoso \U0001F600 CA", out var error).Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void TryValidate_ErrorNeverEchoesTheRejectedValue()
    {
        // The error reaches the log and HTTP response bodies, so it reports the
        // position and code point rather than the value. Echoing it would carry
        // the control character onward and forge the very line that reports it.
        AdcsCaConnectionString.TryValidate(
            "ca01\\CA\nFATAL Certificate issued to Administrator", out var error);

        error.Should().NotContain("FATAL");
        error.Should().Contain("U+000A");
        error.Should().Contain("position 7");
    }

    [Fact]
    public void TryValidate_OverTheLengthLimit_IsRefused()
    {
        var oversized = "ca01.contoso.local\\" + new string('A', AdcsCaConnectionString.MaxLength);

        AdcsCaConnectionString.TryValidate(oversized, out var error).Should().BeFalse();
        error.Should().Contain("longer than");
    }

    [Fact]
    public void TryValidate_AtTheLengthLimit_Passes()
    {
        // The limit is generous on purpose (a real config string tops out near
        // 318 characters), so the boundary itself must not refuse.
        var atLimit = new string('A', AdcsCaConnectionString.MaxLength);

        AdcsCaConnectionString.TryValidate(atLimit, out var error).Should().BeTrue();
        error.Should().BeNull();
    }
}
