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
