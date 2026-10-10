using Certus.Core.Acme.Models;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// The dns identifier grammar (issue #345). Before it, new-order took any
/// non-empty value that was not <c>localhost</c> or a blocked IP literal, so
/// the whole corpus in the security report became authorizations and
/// challenges. Every value the report named is pinned here, alongside the
/// bypasses of the old blocked literal screen that the same report's evidence
/// implied without naming.
///
/// These live in Certus.Core.Tests deliberately. The wire behaviour is proved
/// in Certus.Web.Tests, but those tests boot a host and carry the Integration
/// trait, which CI filters out; the grammar itself has to be provable on the
/// pull request runner.
/// </summary>
public class DnsIdentifierValueTests
{
    // ---- accepted ----

    [Theory]
    [InlineData("example.com")]
    [InlineData("test.example.com")]
    [InlineData("a.b.c.home.local")]
    // A single label with no dot at all. Ordinary on an internal network, and
    // an internal certificate authority is the product this is.
    [InlineData("myserver")]
    // Case is not folded here. The identifier is stored as sent and finalize
    // does its own case insensitive compare against the CSR.
    [InlineData("EXAMPLE.com")]
    // Underscore. Strict RFC 1123 would refuse it, but Windows DNS accepts it
    // and ADCS issues for it, and AllowedDomainsPolicy.ValidateEntry already
    // lets an administrator allow such a name.
    [InlineData("my_server.corp.local")]
    // An internationalized name in the form a client is expected to send.
    [InlineData("xn--mnchen-3ya.corp.local")]
    [InlineData("web-1.home.local")]
    // Not an IP address in any form, so not the IP rule's business, and a
    // perfectly legal host name. The boundary is deliberate: the grammar
    // refuses addresses, not every name that merely looks numeric.
    [InlineData("1.2.3.4.5")]
    [InlineData("10.20.30.40.corp.local")]
    public void TryParse_ValidHostName_Parses(string value)
    {
        var ok = DnsIdentifierValue.TryParse(value, out var parsed, out var refusal);

        ok.Should().BeTrue();
        refusal.Should().BeNull();
        parsed!.Raw.Should().Be(value);
        parsed.Name.Should().Be(value);
        parsed.IsWildcard.Should().BeFalse();
    }

    [Fact]
    public void TryParse_Wildcard_KeepsTheRawAndStripsTheName()
    {
        var ok = DnsIdentifierValue.TryParse("*.example.com", out var parsed, out _);

        ok.Should().BeTrue();
        // Raw is what gets stored and compared; Name is what gets screened,
        // resolved, and matched against a policy entry.
        parsed!.Raw.Should().Be("*.example.com");
        parsed.Name.Should().Be("example.com");
        parsed.IsWildcard.Should().BeTrue();
    }

    [Fact]
    public void TryParse_MaximumLabelAndName_Parse()
    {
        var label = new string('a', 63);
        DnsIdentifierValue.TryParse($"{label}.example.com", out _, out _).Should().BeTrue();

        // 253 exactly: four 63 character labels and three dots is 255, so trim
        // the first label to land on the limit.
        var name = string.Join('.', new string('a', 61), label, label, label);
        name.Length.Should().Be(253);
        DnsIdentifierValue.TryParse(name, out _, out _).Should().BeTrue();
    }

    [Fact]
    public void TryParse_WildcardMarkerCountsAgainstTheLimit()
    {
        // The stored value keeps the marker, and AcmeAuthorization.IdentifierValue
        // is declared HasMaxLength(253), so an accepted wildcard has to fit
        // inside the 253 with its marker. Measuring the stripped name instead
        // would accept 255 characters and break that promise on any provider
        // that enforces a declared length.
        var name = string.Join('.',
            new string('a', 61), new string('b', 63), new string('c', 63), new string('d', 63));
        name.Length.Should().Be(253);

        DnsIdentifierValue.TryParse($"*.{name}", out _, out var refusal).Should().BeFalse();
        refusal!.Value.Detail.Should().Contain("exceeds 253 characters");

        // Two characters shorter and the whole value lands on the limit.
        var trimmed = name[2..];
        DnsIdentifierValue.TryParse($"*.{trimmed}", out var parsed, out _).Should().BeTrue();
        parsed!.Raw.Length.Should().Be(253);
        parsed.Name.Length.Should().Be(251);
    }

    [Theory]
    // IPAddress.TryParse reads every shorthand IPv4 form, so these never reach
    // the label rules and are never left for the resolver to expand at
    // validation time, where the private range fence is off by default.
    [InlineData("10.1")]
    [InlineData("10.0.1")]
    [InlineData("167772161")]
    [InlineData("0x0a000001")]
    [InlineData("127.1")]
    // The same breadth catches a single label all-digit name. Intended: RFC
    // 1123 section 2.1 discourages an all-numeric top label for exactly this
    // ambiguity, and the Windows resolver does expand "2026" to an address, so
    // a certificate for it would name something no resolver answers for. This
    // pins the boundary so it reads as a decision rather than an oversight.
    [InlineData("2026")]
    [InlineData("1234")]
    [InlineData("07")]
    public void TryParse_ShorthandOrPackedAddress_IsRejectedIdentifier(string value)
    {
        DnsIdentifierValue.TryParse(value, out _, out var refusal).Should().BeFalse();

        refusal!.Value.Kind.Should().Be(DnsIdentifierRefusalKind.IpLiteral);
    }

    // ---- refused as malformed ----

    [Theory]
    // The security report's own corpus, minus the IP literal, which is a
    // policy refusal and is pinned separately below.
    [InlineData("localhost#", "not allowed in a host name")]
    [InlineData("a b", "not allowed in a host name")]
    [InlineData("foo|bar", "not allowed in a host name")]
    [InlineData("http://x/", "not allowed in a host name")]
    [InlineData("../../etc", "empty label")]
    // Bypasses of the old blocked literal screen, which matched only the exact
    // string "localhost" or a bare parseable address.
    [InlineData("LOCALHOST.", "ends in a dot")]
    [InlineData("10.0.0.5:22", "not allowed in a host name")]
    [InlineData("user@internal.host", "not allowed in a host name")]
    // A trailing dot is a legal DNS presentation form, so it earns its own
    // sentence. Accepting it would create an order that can only ever fail at
    // finalize, where the CSR will carry the name without it.
    [InlineData("example.com.", "ends in a dot")]
    // An internationalized name in U label form. Refused rather than mapped,
    // because mapping would store a name the client did not send.
    [InlineData("münchen.corp.local", "non ASCII character")]
    [InlineData(".example.com", "empty label")]
    [InlineData("a..b.example.com", "empty label")]
    [InlineData("-foo.example.com", "starts or ends with a hyphen")]
    [InlineData("foo-.example.com", "starts or ends with a hyphen")]
    public void TryParse_NotAHostName_IsMalformed(string value, string expectedReason)
    {
        var ok = DnsIdentifierValue.TryParse(value, out var parsed, out var refusal);

        ok.Should().BeFalse();
        parsed.Should().BeNull();
        refusal!.Value.Kind.Should().Be(DnsIdentifierRefusalKind.Malformed);
        refusal.Value.Detail.Should().Contain(expectedReason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryParse_Empty_KeepsTheWordingNewOrderAlwaysUsed(string? value)
    {
        var ok = DnsIdentifierValue.TryParse(value, out _, out var refusal);

        ok.Should().BeFalse();
        refusal!.Value.Kind.Should().Be(DnsIdentifierRefusalKind.Malformed);
        refusal.Value.Detail.Should().Be("Identifier value must not be empty.");
    }

    [Theory]
    // The marker is for one whole leading label and nothing else. Each of
    // these is told what the marker is for rather than that an asterisk is a
    // bad character.
    [InlineData("*")]
    [InlineData("*.")]
    [InlineData("*.*.example.com")]
    [InlineData("**.example.com")]
    [InlineData("web*.example.com")]
    public void TryParse_MisplacedWildcard_IsMalformed(string value)
    {
        var ok = DnsIdentifierValue.TryParse(value, out _, out var refusal);

        ok.Should().BeFalse();
        refusal!.Value.Kind.Should().Be(DnsIdentifierRefusalKind.Malformed);
        refusal.Value.Detail.Should().Contain("single leading '*.'");
    }

    [Fact]
    public void TryParse_OversizeLabel_IsMalformed()
    {
        var ok = DnsIdentifierValue.TryParse(
            $"{new string('a', 64)}.example.com", out _, out var refusal);

        ok.Should().BeFalse();
        refusal!.Value.Kind.Should().Be(DnsIdentifierRefusalKind.Malformed);
        refusal.Value.Detail.Should().Contain("longer than 63 characters");
    }

    [Fact]
    public void TryParse_OversizeName_IsMalformed()
    {
        var name = string.Join('.',
            new string('a', 62), new string('b', 63), new string('c', 63), new string('d', 63));
        name.Length.Should().Be(254);

        var ok = DnsIdentifierValue.TryParse(name, out _, out var refusal);

        ok.Should().BeFalse();
        refusal!.Value.Kind.Should().Be(DnsIdentifierRefusalKind.Malformed);
        refusal.Value.Detail.Should().Contain("exceeds 253 characters");
    }

    [Fact]
    public void TryParse_BidiOverride_NamesTheCodePointNotTheCharacter()
    {
        // The same DeceptiveCharacters scan the device path runs (issues #228
        // and #234), ahead of the ASCII rule so the reason is the real one.
        var ok = DnsIdentifierValue.TryParse("exa‮mple.com", out _, out var refusal);

        ok.Should().BeFalse();
        refusal!.Value.Kind.Should().Be(DnsIdentifierRefusalKind.Malformed);
        refusal.Value.Detail.Should().Contain("formatting character");
        refusal.Value.Detail.Should().Contain("U+202E");
        refusal.Value.Detail.Should().Contain("position 3");
    }

    [Fact]
    public void TryParse_ControlCharacter_IsNamedAsControl()
    {
        var ok = DnsIdentifierValue.TryParse("foo\nbar.example.com", out _, out var refusal);

        ok.Should().BeFalse();
        refusal!.Value.Detail.Should().Contain("control character");
        refusal.Value.Detail.Should().Contain("U+000A");
    }

    // ---- refused as an IP literal ----

    [Theory]
    // The value the report reproduced against the live deployment. RFC1918 is
    // not fenced by default at validation time, so this is the only place it
    // is refused on a default install.
    [InlineData("192.168.2.1")]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.4.9")]
    [InlineData("8.8.8.8")]
    [InlineData("::1")]
    [InlineData("2001:db8::1")]
    // The URL authority form. Unwrapped before the probe so it is answered as
    // the address it is, not for its brackets.
    [InlineData("[::1]")]
    // A trailing dot is seen through for the same reason: this is plainly an
    // address, and telling the client about its dot would be a wasted round
    // trip.
    [InlineData("127.0.0.1.")]
    // A wildcard over an address is still an address.
    [InlineData("*.192.168.2.1")]
    public void TryParse_IpLiteral_IsRejectedIdentifier(string value)
    {
        var ok = DnsIdentifierValue.TryParse(value, out var parsed, out var refusal);

        ok.Should().BeFalse();
        parsed.Should().BeNull();
        refusal!.Value.Kind.Should().Be(DnsIdentifierRefusalKind.IpLiteral);
        refusal.Value.Detail.Should().Contain("IP address");
    }

    // ---- the refusal never carries the payload ----

    [Theory]
    [InlineData("localhost#")]
    [InlineData("foo|bar")]
    [InlineData("http://x/")]
    [InlineData("../../etc")]
    [InlineData("10.0.0.5:22")]
    [InlineData("user@internal.host")]
    [InlineData("192.168.2.1")]
    [InlineData("münchen.corp.local")]
    [InlineData("exa‮mple.com")]
    public void TryParse_Refusal_NeverEchoesTheValue(string value)
    {
        // Matching PermanentIdentifierValue and the other guards. A refusal
        // reaches a problem document, the service log, and any operator screen
        // that renders one, so it must not be a way to walk client controlled
        // text into all three.
        DnsIdentifierValue.TryParse(value, out _, out var refusal).Should().BeFalse();

        refusal!.Value.Detail.Should().NotContain(value);
    }
}
