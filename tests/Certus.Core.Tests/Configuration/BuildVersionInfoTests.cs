using Certus.Core.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// Splitting AssemblyInformationalVersion into the release version and the
/// commit stamp (issue #112). These are pure and always run: they must not
/// depend on the assembly under test actually carrying a stamp, because
/// `dotnet test` also has to pass on a source-only tree where build.ps1 had no
/// .git to resolve a commit from. The assertion that a real build carries the
/// stamp lives in build.ps1, which is the only place the expected sha is known.
/// </summary>
public class BuildVersionInfoTests
{
    [Fact]
    public void Split_StampedPrereleaseVersion_SeparatesVersionFromCommit()
    {
        var (version, commit) = BuildVersionInfo.Split(
            "0.9.0-beta.1+84282a812a818b931aa382fdbf29787209ba033c");

        version.Should().Be("0.9.0-beta.1");
        commit.Should().Be("84282a812a818b931aa382fdbf29787209ba033c");
    }

    [Fact]
    public void Split_StampedStableVersion_SeparatesVersionFromCommit()
    {
        var (version, commit) = BuildVersionInfo.Split(
            "1.0.0+84282a812a818b931aa382fdbf29787209ba033c");

        version.Should().Be("1.0.0");
        commit.Should().Be("84282a812a818b931aa382fdbf29787209ba033c");
    }

    [Theory]
    [InlineData("0.9.0-beta.1")]
    [InlineData("1.0.0")]
    [InlineData("0.9.0.0")]
    public void Split_UnstampedVersion_ReturnsTheWholeStringAndNoCommit(string value)
    {
        var (version, commit) = BuildVersionInfo.Split(value);

        version.Should().Be(value);
        commit.Should().BeNull();
    }

    [Fact]
    public void Split_DirtyTreeStamp_KeepsTheMarkerOnTheCommit()
    {
        // build.ps1 stamps "<sha>.dirty" so a developer build never claims to
        // be a clean commit. It travels through as part of the stamp.
        var (version, commit) = BuildVersionInfo.Split(
            "0.9.0-beta.1+84282a812a818b931aa382fdbf29787209ba033c.dirty");

        version.Should().Be("0.9.0-beta.1");
        commit.Should().Be("84282a812a818b931aa382fdbf29787209ba033c.dirty");
    }

    [Fact]
    public void Split_MultipleSeparators_SplitsOnTheFirstOnly()
    {
        // The SDK appends with a "." when the version already carries a "+", so
        // a second "+" is not expected. If one ever appears, everything past
        // the first separator is one opaque stamp rather than a parse failure.
        var (version, commit) = BuildVersionInfo.Split("1.0.0+abc+def");

        version.Should().Be("1.0.0");
        commit.Should().Be("abc+def");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Split_BlankInput_ReturnsEmptyVersionAndNoCommit(string? value)
    {
        var (version, commit) = BuildVersionInfo.Split(value);

        version.Should().BeEmpty();
        commit.Should().BeNull();
    }

    [Fact]
    public void Split_TrailingSeparatorWithNoStamp_ReturnsNoCommit()
    {
        var (version, commit) = BuildVersionInfo.Split("1.0.0+");

        version.Should().Be("1.0.0");
        commit.Should().BeNull();
    }
}
