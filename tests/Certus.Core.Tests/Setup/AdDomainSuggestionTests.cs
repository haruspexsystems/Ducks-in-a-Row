using Certus.Core.Setup;

namespace Certus.Core.Tests.Setup;

/// <summary>
/// Tests for the pure core of AdDomainSuggestion. The live Get() reads the
/// machine's IP configuration and cannot be asserted on in a test that must
/// pass on both domain joined and workgroup machines.
/// </summary>
public class AdDomainSuggestionTests
{
    [Theory]
    [InlineData("home.local", "home.local")]
    [InlineData("HOME.LOCAL", "home.local")]
    [InlineData(" home.local. ", "home.local")]
    [InlineData("BÜCHER.example", "xn--bcher-kva.example")]
    public void Normalize_DomainJoined_ReturnsTheCanonicalForm(string raw, string expected)
    {
        // The same canonical form as stored allowed domain entries, so the
        // suggestion matches the saved list and the add button dedupes.
        AdDomainSuggestion.Normalize(raw).Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(".")]
    [InlineData("bad..name")]
    public void Normalize_NoUsableDomain_ReturnsNull(string raw)
    {
        AdDomainSuggestion.Normalize(raw).Should().BeNull();
    }
}
