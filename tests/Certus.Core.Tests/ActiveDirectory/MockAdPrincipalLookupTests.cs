using Certus.Core.ActiveDirectory;

namespace Certus.Core.Tests.ActiveDirectory;

/// <summary>
/// Tests for the canned mock directory: the search contract (name prefix,
/// case insensitive, empty for a blank query) and the resolve contract
/// (exact SID or null) that the owner picker and the principal endpoints
/// build on. The real DirectorySearcher implementation in Certus.Adcs is
/// verified manually against the lab domain, the CA discovery precedent.
/// </summary>
public class MockAdPrincipalLookupTests
{
    private readonly MockAdPrincipalLookup _sut = new();

    [Fact]
    public async Task SearchAsync_MatchesByNamePrefix_CaseInsensitively()
    {
        var matches = await _sut.SearchAsync("web");

        matches.Select(p => p.Name).Should().BeEquivalentTo(
            ["websvc$", "WEB01$", "Web Admins"],
            "the prefix crosses service accounts, computers, and groups");
        matches.Select(p => p.Type).Should().BeEquivalentTo(
            ["service account", "computer", "group"]);
        matches.Should().OnlyContain(
            p => p.Sid.StartsWith("S-1-5-21-") && p.DistinguishedName != null);
    }

    [Fact]
    public async Task SearchAsync_MatchesTheCommonNameToo()
    {
        // "Jane" matches nothing by account name (jsmith), only the CN, the
        // same double prefix the real DirectorySearcher filter carries.
        var matches = await _sut.SearchAsync("jane");

        matches.Single().Name.Should().Be("jsmith");
    }

    [Fact]
    public async Task SearchAsync_BlankOrUnmatchedQuery_ReturnsNothing()
    {
        (await _sut.SearchAsync("   ")).Should().BeEmpty();
        (await _sut.SearchAsync("no-such-principal")).Should().BeEmpty();
    }

    [Fact]
    public async Task ResolveSidAsync_RoundTripsASearchResult()
    {
        var jsmith = (await _sut.SearchAsync("jsmith")).Single();

        var resolved = await _sut.ResolveSidAsync(jsmith.Sid);

        resolved.Should().Be(jsmith);
    }

    [Fact]
    public async Task ResolveSidAsync_UnknownSid_ReturnsNull()
    {
        (await _sut.ResolveSidAsync("S-1-5-21-1-2-3-9999")).Should().BeNull();
        (await _sut.ResolveSidAsync("not a sid")).Should().BeNull();
    }
}
