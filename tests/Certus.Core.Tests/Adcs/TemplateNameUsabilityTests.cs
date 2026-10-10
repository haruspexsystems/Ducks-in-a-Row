using Certus.Core.Adcs;
using Certus.Core.Security;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// A published template has three values and they fail differently. The
/// programmatic name is what ADCS matches a request against, so a refused
/// character there means the template cannot be enrolled at all; the display
/// name only ever reaches a URL, so a refused character there costs one
/// addressing form (issue #235); the OID reaches neither, so a refused
/// character there costs nothing at all and is reported only because the wizard
/// prints it (issue #292). Everything downstream, the wizard's hiding rule and
/// the startup report's wording alike, is built on getting those distinctions
/// right.
/// </summary>
public class TemplateNameUsabilityTests
{
    // Built from numeric code points rather than written literally, for the
    // reason the whole feature exists: a soft hyphen pasted into source is
    // invisible to the next reader of this file too. Word inserts one at a
    // hyphenation point and a display name is routinely populated by paste,
    // which is the shape issue #235 was filed about.
    private const int SoftHyphen = 0x00AD;
    private const int LineSeparator = 0x2028;
    private const int TagLatinA = 0xE0041;

    private static string With(int codePoint, string before, string after) =>
        before + char.ConvertFromUtf32(codePoint) + after;

    [Fact]
    public void Inspect_BothNamesClean_IsClean()
    {
        var verdict = TemplateNameUsability.Inspect("WebServer", "Web Server");

        verdict.IsClean.Should().BeTrue();
        verdict.CanEnroll.Should().BeTrue();
        verdict.DisplayNameUnusable.Should().BeFalse();
        verdict.First.Should().BeNull();
    }

    [Fact]
    public void Inspect_DisplayNameCarriesASoftHyphen_IsAddressingOnly()
    {
        var verdict = TemplateNameUsability.Inspect(
            "WebServer", With(SoftHyphen, "Web", " Server"));

        // Enrollment is untouched: the programmatic name is what reaches ADCS.
        verdict.CanEnroll.Should().BeTrue();
        verdict.ProgrammaticFault.Should().BeNull();

        verdict.DisplayNameUnusable.Should().BeTrue();
        verdict.DisplayFault!.Value.Part.Should().Be(TemplateNamePart.Display);
        verdict.DisplayFault!.Value.Character.CodePoint.Should().Be(SoftHyphen);
        verdict.DisplayFault!.Value.Character.Position.Should().Be(3);
        verdict.DisplayFault!.Value.ClassNoun.Should().Be("formatting");
    }

    [Fact]
    public void Inspect_ProgrammaticNameCarriesAControlCharacter_CannotEnroll()
    {
        var verdict = TemplateNameUsability.Inspect(
            With(0x0A, "Web", "Server"), "Web Server");

        verdict.CanEnroll.Should().BeFalse();
        verdict.ProgrammaticFault!.Value.Part.Should().Be(TemplateNamePart.Programmatic);
        verdict.ProgrammaticFault!.Value.Character.CodePoint.Should().Be(0x0A);
        verdict.ProgrammaticFault!.Value.ClassNoun.Should().Be("control");
        verdict.DisplayNameUnusable.Should().BeFalse();
    }

    [Fact]
    public void Inspect_BothNamesDirty_ReportsBothAndLeadsWithTheProgrammaticOne()
    {
        var verdict = TemplateNameUsability.Inspect(
            With(SoftHyphen, "Web", "Server"), With(SoftHyphen, "Web", " Server"));

        verdict.ProgrammaticFault.Should().NotBeNull();
        verdict.DisplayFault.Should().NotBeNull();

        // Nothing is lost, and the fatal one leads: its fix subsumes the other.
        verdict.First!.Value.Part.Should().Be(TemplateNamePart.Programmatic);
    }

    [Fact]
    public void Inspect_DisplayNameEqualsProgrammaticName_ReportsOneFaultNotTwo()
    {
        // The shape AdcsClient leaves behind when the AD lookup could not run:
        // it falls the display name back to the programmatic name. Scanning it
        // twice would make every dirty name on a host that is not domain joined
        // read as two separate problems.
        var name = With(SoftHyphen, "Web", "Server");

        var verdict = TemplateNameUsability.Inspect(name, name);

        verdict.ProgrammaticFault.Should().NotBeNull();
        verdict.DisplayFault.Should().BeNull();
    }

    [Fact]
    public void Inspect_LineSeparatorInTheDisplayName_IsNamedAsOne()
    {
        // Calling U+2028 a control character in the one message an operator
        // reads to understand a refusal would be untrue (issue #234).
        var verdict = TemplateNameUsability.Inspect(
            "WebServer", With(LineSeparator, "Web", " Server"));

        verdict.DisplayFault!.Value.ClassNoun.Should().Be("line separator");
    }

    [Fact]
    public void Inspect_FormatCharacterAboveTheBmp_NamesTheWholeRune()
    {
        // The issue #228 shape. A tag block character arrives as a surrogate
        // pair, and naming a surrogate half would name a code point that does
        // not exist on its own.
        var verdict = TemplateNameUsability.Inspect(
            "WebServer", With(TagLatinA, "Web", "Server"));

        verdict.DisplayFault!.Value.Character.CodePoint.Should().Be(TagLatinA);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("WebServer", null)]
    [InlineData("WebServer", "")]
    public void Inspect_MissingNames_AreClean(string? name, string? displayName)
    {
        // Absence is not this type's question. A template with no name at all
        // is refused by AdcsRequestAttributes on its own presence rule, and
        // answering "unusable" here would make the wizard hide it for the wrong
        // stated reason.
        TemplateNameUsability.Inspect(name, displayName).IsClean.Should().BeTrue();
    }

    [Fact]
    public void Inspect_TemplateInfo_ReadsBothNamesOffIt()
    {
        var template = new TemplateInfo(
            "WebServer", With(SoftHyphen, "Web", "Server"), "1.2.3");

        TemplateNameUsability.Inspect(template).DisplayNameUnusable.Should().BeTrue();
    }

    [Fact]
    public void Inspect_OidCarriesAFormatCharacter_CostsNothingButIsReported()
    {
        var verdict = TemplateNameUsability.Inspect(
            "WebServer", "Web Server", With(SoftHyphen, "1.3.6", ".1.4.1"));

        // Neither consequence applies. Nothing routes on the OID and nothing is
        // built from it, so a template carrying a dirty one enrolls and is
        // addressed exactly as any other.
        verdict.CanEnroll.Should().BeTrue();
        verdict.DisplayNameUnusable.Should().BeFalse();

        // Reported all the same, because the wizard prints it.
        verdict.IsClean.Should().BeFalse(
            "a value the wizard renders is worth reporting even when it refuses nothing");
        verdict.OidFault!.Value.Part.Should().Be(TemplateNamePart.Oid);
        verdict.OidFault!.Value.Character.CodePoint.Should().Be(SoftHyphen);
        verdict.OidFault!.Value.Character.Position.Should().Be(5);
        verdict.OidFault!.Value.ClassNoun.Should().Be("formatting");
    }

    [Fact]
    public void Inspect_AllThreeCarrySomething_NoneIsLost()
    {
        var verdict = TemplateNameUsability.Inspect(
            With(LineSeparator, "Web", "Server"),
            With(SoftHyphen, "Web", " Server"),
            With(TagLatinA, "1.3.6", ".1"));

        verdict.ProgrammaticFault!.Value.Character.CodePoint.Should().Be(LineSeparator);
        verdict.DisplayFault!.Value.Character.CodePoint.Should().Be(SoftHyphen);
        verdict.OidFault!.Value.Character.CodePoint.Should().Be(TagLatinA);
    }

    [Fact]
    public void First_OrdersByWhatTheFaultCosts()
    {
        var prog = With(LineSeparator, "Web", "Server");
        var display = With(SoftHyphen, "Web", " Server");
        var oid = With(SoftHyphen, "1.3.6", ".1");

        // Fatal first: a template renamed to fix the programmatic name gets a
        // clean display name on the way, so it is the one remediation to name.
        TemplateNameUsability.Inspect(prog, display, oid)
            .First!.Value.Part.Should().Be(TemplateNamePart.Programmatic);

        // Then the lost addressing form, which is something a client feels.
        TemplateNameUsability.Inspect("WebServer", display, oid)
            .First!.Value.Part.Should().Be(TemplateNamePart.Display);

        // The OID last, because it costs nobody anything.
        TemplateNameUsability.Inspect("WebServer", "Web Server", oid)
            .First!.Value.Part.Should().Be(TemplateNamePart.Oid);
    }

    [Fact]
    public void Inspect_OidEqualToTheDisplayName_IsReportedTwiceNotOnce()
    {
        // The dedup above it exists because AdcsClient copies the programmatic
        // name into DisplayName when the directory lookup fails, so the same
        // value arrives twice. Nothing copies anything into Oid, so an equal
        // value there is a second occurrence and both are real.
        var dirty = With(SoftHyphen, "Web", " Server");

        var verdict = TemplateNameUsability.Inspect("WebServer", dirty, dirty);

        verdict.DisplayFault.Should().NotBeNull();
        verdict.OidFault.Should().NotBeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Inspect_MissingOid_IsClean(string? oid)
    {
        // A template with no OID published is not this type's problem either,
        // and the default on the overload has to answer the same way or a
        // caller holding only the two names would report a fault it never saw.
        TemplateNameUsability.Inspect("WebServer", "Web Server", oid)
            .IsClean.Should().BeTrue();
    }

    [Fact]
    public void Inspect_TemplateInfo_ReadsTheOidOffItToo()
    {
        var template = new TemplateInfo(
            "WebServer", "Web Server", With(SoftHyphen, "1.3.6", ".1"));

        var verdict = TemplateNameUsability.Inspect(template);

        verdict.OidFault.Should().NotBeNull();
        verdict.CanEnroll.Should().BeTrue();
    }

    // The three nouns are the ones the existing guards already spell. A fourth
    // spelling for the same three classes would be a fourth vocabulary in one
    // product, so they are pinned rather than left to drift.
    [Theory]
    [InlineData(DeceptiveCharacterClass.Control, "control")]
    [InlineData(DeceptiveCharacterClass.LineSeparator, "line separator")]
    [InlineData(DeceptiveCharacterClass.Format, "formatting")]
    public void ClassNoun_MatchesTheWordingTheOtherGuardsUse(
        DeceptiveCharacterClass characterClass, string expected)
    {
        var fault = new TemplateNameFault(
            TemplateNamePart.Display, new DeceptiveCharacter(characterClass, 0, SoftHyphen));

        fault.ClassNoun.Should().Be(expected);
    }
}
