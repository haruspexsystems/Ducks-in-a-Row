using Certus.Core.Acme.Models;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for the permanent-identifier value grammar
/// (draft-ietf-acme-device-attest-08 section 3):
/// device-identifier-value ["/" assigner-OID], compared octet for octet.
/// </summary>
public class PermanentIdentifierValueTests
{
    [Fact]
    public void TryParse_BareValue_Parses()
    {
        var ok = PermanentIdentifierValue.TryParse("PROBE-SN-0001", out var parsed, out var error);

        ok.Should().BeTrue();
        error.Should().BeNull();
        parsed!.Value.Should().Be("PROBE-SN-0001");
        parsed.AssignerOid.Should().BeNull();
        parsed.Raw.Should().Be("PROBE-SN-0001");
    }

    [Fact]
    public void TryParse_WithAssigner_SplitsOnFirstSlash()
    {
        var ok = PermanentIdentifierValue.TryParse(
            "PROBE-SN-0001/1.3.6.1.4.1.99999.1", out var parsed, out _);

        ok.Should().BeTrue();
        parsed!.Value.Should().Be("PROBE-SN-0001");
        parsed.AssignerOid.Should().Be("1.3.6.1.4.1.99999.1");
        parsed.Raw.Should().Be("PROBE-SN-0001/1.3.6.1.4.1.99999.1");
    }

    [Fact]
    public void TryParse_InnerSpace_IsAllowed()
    {
        // The draft does not restrict the value alphabet; asset style
        // identifiers may contain spaces.
        var ok = PermanentIdentifierValue.TryParse("ASSET TAG 7", out var parsed, out _);

        ok.Should().BeTrue();
        parsed!.Value.Should().Be("ASSET TAG 7");
    }

    [Fact]
    public void TryParse_Root2AllowsLargeSecondArc()
    {
        // Under root arc 2 the second arc is unrestricted (X.660); 2.999 is
        // the ITU-T documentation arc.
        var ok = PermanentIdentifierValue.TryParse("SN-1/2.999.1", out var parsed, out _);

        ok.Should().BeTrue();
        parsed!.AssignerOid.Should().Be("2.999.1");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TryParse_Empty_Rejects(string? raw)
    {
        var ok = PermanentIdentifierValue.TryParse(raw, out var parsed, out var error);

        ok.Should().BeFalse();
        parsed.Should().BeNull();
        error.Should().NotBeNullOrEmpty();
    }

    [Theory]
    [InlineData("/1.2.3")]     // empty device identifier part
    [InlineData("ABC/")]       // empty assigner after the slash
    [InlineData("ABC/1")]      // an OID needs at least two arcs
    [InlineData("ABC/1..2")]   // empty arc
    [InlineData("ABC/1.x")]    // non digit arc
    [InlineData("ABC/3.1")]    // root arc out of range (0 to 2)
    [InlineData("ABC/0.40")]   // second arc over 39 under root arc 0
    [InlineData("ABC/1.05")]   // leading zero in an arc
    [InlineData("A/B/C")]      // everything after the first slash must be one OID
    [InlineData(" ABC")]       // leading whitespace
    [InlineData("ABC ")]       // trailing whitespace
    [InlineData("AB\u0007C")]   // control character
    public void TryParse_Invalid_Rejects(string raw)
    {
        var ok = PermanentIdentifierValue.TryParse(raw, out var parsed, out var error);

        ok.Should().BeFalse();
        parsed.Should().BeNull();
        error.Should().NotBeNullOrEmpty();
    }

    // Until issue #234 this guard checked control characters and nothing else,
    // so a device serial could carry a bidirectional override into the domain
    // policy audit rows and the dashboard that renders them. The value arrives
    // client supplied over ACME newOrder.
    [Theory]
    [InlineData("AB\u2028C", "line separator", 0x2028)] // Zl, the issue #234 gap
    [InlineData("AB\u2029C", "line separator", 0x2029)] // Zp
    [InlineData("AB\u202EC", "formatting", 0x202E)]     // right to left override
    [InlineData("AB\u200BC", "formatting", 0x200B)]     // zero width space
    [InlineData("AB\u0007C", "control", 0x0007)]        // unchanged behaviour
    public void TryParse_DeceptiveCharacter_RejectsWithItsOwnLabel(
        string raw, string kind, int codePoint)
    {
        var ok = PermanentIdentifierValue.TryParse(raw, out var parsed, out var error);

        ok.Should().BeFalse();
        parsed.Should().BeNull();
        error.Should().Contain($"{kind} character");
        error.Should().Contain($"U+{codePoint:X4}");
        error.Should().NotContain(raw, "a client supplied value is never echoed back");
    }

    [Theory]
    [InlineData(0xE0001)] // language tag
    [InlineData(0xE0041)] // tag latin capital A, which hides text outright
    [InlineData(0xE007F)] // cancel tag
    public void TryParse_FormatCharacterAboveTheBmp_Rejects(int codePoint)
    {
        // The old per char loop could not see these at all: they arrive as a
        // surrogate pair and the category of a lone surrogate is Surrogate,
        // never Format. This guard never got the issue #228 fix the others did.
        var raw = "SN-1" + char.ConvertFromUtf32(codePoint) + "234";

        PermanentIdentifierValue.TryParse(raw, out var parsed, out var error).Should().BeFalse();
        parsed.Should().BeNull();
        error.Should().Contain(
            $"U+{codePoint:X4}", "the reported code point is the rune, not a surrogate half");
    }

    [Fact]
    public void TryParse_TrailingLineSeparator_ReportsTheSeparatorNotWhitespace()
    {
        // char.IsWhiteSpace is true for Zl and Zp, so the leading and trailing
        // whitespace check would answer first and name the wrong reason. The
        // character scan deliberately runs ahead of it.
        PermanentIdentifierValue.TryParse("SN-1\u2028", out _, out var error).Should().BeFalse();

        error.Should().Contain("line separator character");
        error.Should().NotContain("whitespace");
    }

    [Fact]
    public void TryParse_OrdinaryCharacterAboveTheBmp_Parses()
    {
        // The guard refuses named classes, not everything wide. An asset tag
        // reaching outside the BMP is not this guard's business.
        PermanentIdentifierValue.TryParse("SN-1 \U0001F600", out var parsed, out var error)
            .Should().BeTrue();
        parsed.Should().NotBeNull();
        error.Should().BeNull();
    }

    [Fact]
    public void TryParse_MaxLength_IsExactly253()
    {
        var atLimit = new string('A', PermanentIdentifierValue.MaxLength);
        var overLimit = new string('A', PermanentIdentifierValue.MaxLength + 1);

        PermanentIdentifierValue.TryParse(atLimit, out var parsed, out _).Should().BeTrue();
        parsed!.Raw.Should().HaveLength(253);

        PermanentIdentifierValue.TryParse(overLimit, out var rejected, out var error).Should().BeFalse();
        rejected.Should().BeNull();
        error.Should().Contain("253");
    }

    [Fact]
    public void OctetMatches_IsOctetExact()
    {
        PermanentIdentifierValue.TryParse("abc-123", out var parsed, out _).Should().BeTrue();

        parsed!.OctetMatches("abc-123").Should().BeTrue();
        parsed.OctetMatches("ABC-123").Should().BeFalse("the draft compares octet for octet, no case folding");
        parsed.OctetMatches("abc-123 ").Should().BeFalse();
        parsed.OctetMatches(null).Should().BeFalse();
    }
}
