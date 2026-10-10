using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// The ADCS request attribute boundary (issue #175). ADCS separates attribute
/// pairs with newlines, so a template name carrying one could append attributes
/// the caller never sent. CVE-2026-54121 ("CertiGhost") is why that matters:
/// cdc and rmd redirect the CA's identity lookup to an attacker controlled host
/// and yield a domain controller certificate.
/// </summary>
public class AdcsRequestAttributesTests
{
    [Fact]
    public void ForTemplate_NormalName_BuildsExactlyTheTemplateAttribute()
    {
        AdcsRequestAttributes.ForTemplate("WebServer")
            .Should().Be("CertificateTemplate:WebServer");
    }

    [Fact]
    public void ForTemplate_NameWithSpacesAndPunctuation_IsAccepted()
    {
        // Display names carry spaces, and real templates carry dots, hyphens
        // and underscores. The guard refuses control characters only, so none
        // of these may be rejected.
        AdcsRequestAttributes.ForTemplate("Contoso Web Server v2.1_final-copy")
            .Should().Be("CertificateTemplate:Contoso Web Server v2.1_final-copy");
    }

    [Fact]
    public void ForTemplate_CertiGhostPayload_IsRefused()
    {
        // The shape the CVE needs: a newline closes the template pair, then cdc
        // points the CA at a rogue host and rmd names the DC to impersonate.
        var payload = "WebServer\ncdc:evil.attacker.example\nrmd:DC01.contoso.com";

        var act = () => AdcsRequestAttributes.ForTemplate(payload);

        act.Should().Throw<ArgumentException>().WithMessage("*control character*");
    }

    // Written as numeric char constants rather than escapes so the C1 entries
    // stay readable in source instead of becoming invisible bytes.
    [Theory]
    [InlineData((char)0x0A)] // line feed, the documented pair separator
    [InlineData((char)0x0D)] // carriage return
    [InlineData((char)0x09)] // tab
    [InlineData((char)0x00)] // NUL, the C string terminator
    [InlineData((char)0x0B)] // vertical tab
    [InlineData((char)0x0C)] // form feed
    [InlineData((char)0x7F)] // DEL
    [InlineData((char)0x85)] // NEL, a C1 control the CLR treats as a line break
    [InlineData((char)0x9B)] // C1 control sequence introducer
    public void TryValidateTemplateName_AnyControlCharacter_IsRefused(char control)
    {
        var valid = AdcsRequestAttributes.TryValidateTemplateName(
            $"WebServer{control}cdc:evil", out var error);

        valid.Should().BeFalse();
        error.Should().Contain("control character");
    }

    // U+2028 and U+2029 are categories Zl and Zp, so they are neither Control
    // nor Format and passed every guard in the product until issue #234. ADCS
    // does not treat either as a pair separator and neither does .NET's line
    // reader, but a SIEM's own splitter does, so the name reads as two lines
    // there and as one line here.
    [Theory]
    [InlineData((char)0x2028)] // LINE SEPARATOR
    [InlineData((char)0x2029)] // PARAGRAPH SEPARATOR
    public void TryValidateTemplateName_AnyLineSeparator_IsRefused(char separator)
    {
        var valid = AdcsRequestAttributes.TryValidateTemplateName(
            $"WebServer{separator}cdc:evil", out var error);

        valid.Should().BeFalse();
        error.Should().Contain("line separator character");
        error.Should().Contain($"U+{(int)separator:X4}");
        error.Should().NotContain(
            "control character", "U+2028 is not a control character and the refusal must not say it is");
    }

    // Format characters cannot smuggle an attribute, but the name is logged and
    // shown on the wizard and settings screens, where a bidirectional override
    // makes it read as a different name. Same call CertificateTextSanitizer
    // already makes for CA authored text in SanitizeDispositionMessage.
    [Theory]
    [InlineData((char)0x200B)] // zero width space
    [InlineData((char)0x200E)] // left to right mark
    [InlineData((char)0x202E)] // right to left override
    [InlineData((char)0x2066)] // left to right isolate
    [InlineData((char)0x2069)] // pop directional isolate
    [InlineData((char)0x00AD)] // soft hyphen
    public void TryValidateTemplateName_AnyFormatCharacter_IsRefused(char format)
    {
        var valid = AdcsRequestAttributes.TryValidateTemplateName(
            $"WebServer{format}Evil", out var error);

        valid.Should().BeFalse();
        error.Should().Contain("formatting character");
    }

    // Format characters above the BMP arrive as a surrogate pair, and the
    // category of a lone surrogate is Surrogate and never Format, so a per char
    // lookup let the whole class through (issue #228). The tag block is the one
    // that matters: it encodes arbitrary ASCII invisibly, so a name could carry
    // hidden text through every screen that shows it.
    [Theory]
    [InlineData(0xE0001)] // language tag
    [InlineData(0xE0020)] // tag space, the start of the invisible ASCII block
    [InlineData(0xE007F)] // cancel tag
    [InlineData(0x110BD)] // Kaithi number sign
    [InlineData(0x1BCA0)] // shorthand format letter overlap
    public void TryValidateTemplateName_FormatCharacterAboveTheBmp_IsRefused(int codePoint)
    {
        var valid = AdcsRequestAttributes.TryValidateTemplateName(
            "WebServer" + char.ConvertFromUtf32(codePoint) + "Evil", out var error);

        valid.Should().BeFalse();
        error.Should().Contain("formatting character");
        error.Should().Contain($"U+{codePoint:X4}", "the reported code point is the rune, not a surrogate half");
    }

    [Fact]
    public void TryValidateTemplateName_CharacterAboveTheBmpThatIsNotAFormatCharacter_Passes()
    {
        // A surrogate pair is not refused for being one: only its resolved
        // category decides. The guard must not start refusing names it used to
        // accept just because they reach outside the BMP.
        AdcsRequestAttributes.TryValidateTemplateName("WebServer \U0001F600", out var error)
            .Should().BeTrue();
        error.Should().BeNull();
    }

    [Fact]
    public void TryValidateTemplateName_ErrorNeverEchoesTheRejectedName()
    {
        // The error reaches logs and HTTP response bodies, so it reports the
        // position and code point rather than the value: echoing it would carry
        // the control characters onward and let a rejected name forge a log line.
        AdcsRequestAttributes.TryValidateTemplateName("WebServer\ncdc:evil", out var error);

        error.Should().NotContain("cdc:evil");
        error.Should().Contain("U+000A");
        error.Should().Contain("position 9");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryValidateTemplateName_MissingName_IsRefused(string? templateName)
    {
        AdcsRequestAttributes.TryValidateTemplateName(templateName, out var error)
            .Should().BeFalse();
        error.Should().Contain("required");
    }

    [Fact]
    public void TryValidateTemplateName_NormalName_Passes()
    {
        AdcsRequestAttributes.TryValidateTemplateName("WebServer", out var error)
            .Should().BeTrue();
        error.Should().BeNull();
    }
}
