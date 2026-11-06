using System.Reflection;

namespace Certus.Core.Tests.Security;

/// <summary>
/// When a scan that asks git is skipped (issue #518). Each case builds the shape of tree it
/// names in a temporary folder and starts the walk where a test assembly would sit, three
/// folders below the root, so the walk up is exercised too.
/// </summary>
public sealed class GitCheckoutFactAttributeTests : IDisposable
{
    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "certus-518-" + Guid.NewGuid().ToString("N"));

    public GitCheckoutFactAttributeTests()
    {
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: a stray temp folder is harmless.
        }
    }

    [Fact]
    public void ACheckoutWithAGitFolderRunsTheScan()
    {
        var start = Tree(solution: true);
        Directory.CreateDirectory(Path.Combine(_root, ".git"));

        GitCheckoutFactAttribute.SkipReason(start).Should().BeNull();
    }

    [Fact]
    public void ALinkedWorktreeRunsTheScan()
    {
        // A linked worktree's .git is a file naming where its repository lives.
        var start = Tree(solution: true);
        File.WriteAllText(Path.Combine(_root, ".git"), "gitdir: C:/elsewhere/.git/worktrees/x\n");

        GitCheckoutFactAttribute.SkipReason(start).Should().BeNull();
    }

    [Fact]
    public void ASourceSnapshotSkipsTheScanAndSaysWhy()
    {
        var start = Tree(solution: true);

        // Folders a reader could make for their own use in an extracted snapshot. They are
        // not what marks the private tree, so they must not turn the skip back into a failure.
        Directory.CreateDirectory(Path.Combine(_root, ".claude"));
        Directory.CreateDirectory(Path.Combine(_root, "scripts"));

        var reason = GitCheckoutFactAttribute.SkipReason(start);

        reason.Should().Be(GitCheckoutFactAttribute.SnapshotReason);
        reason.Should().Contain("no .git").And.Contain("source snapshot").And.Contain("never skipped");
    }

    [Fact]
    public void APrivateTreeWithNoRepositoryRunsTheScanSoItFailsLoudly()
    {
        // The release script ships only in the private repository. A tree that holds it with
        // no .git has lost its repository, and a skip there would hide the scan from the build.
        var start = Tree(solution: true);
        var script = Path.Combine(_root, NoLabArtefactsTests.ReleaseScript);
        Directory.CreateDirectory(Path.GetDirectoryName(script)!);
        File.WriteAllText(script, "# release script\n");

        GitCheckoutFactAttribute.SkipReason(start).Should().BeNull();
    }

    [Fact]
    public void NoSolutionAboveRunsTheScanSoItsOwnWalkThrows()
    {
        var start = Tree(solution: false);

        GitCheckoutFactAttribute.SkipReason(start).Should().BeNull();
    }

    [Theory]
    [InlineData(typeof(NoLabArtefactsTests), nameof(NoLabArtefactsTests.ShippedFiles_NameNoRealHost))]
    [InlineData(typeof(LicenceBoundaryScanTests), nameof(LicenceBoundaryScanTests.PublishedTreeCarriesNoLicenceVerificationOrKeyMaterial))]
    public void EveryScanThatAsksGitCarriesTheAttribute(Type type, string method)
    {
        // Nothing else in this repository's own runs would notice the attribute going back
        // to a plain fact, because a checkout always has .git. Only a snapshot would.
        var facts = type.GetMethod(method)!.GetCustomAttributes<FactAttribute>(inherit: false);

        facts.Should().ContainSingle().Which.Should().BeOfType<GitCheckoutFactAttribute>();
    }

    /// <summary>
    /// Creates the folder a test assembly would run from, three below the root, and the
    /// solution file at the root when asked. Returns the folder to start the walk from.
    /// </summary>
    private string Tree(bool solution)
    {
        var start = Path.Combine(_root, "tests", "bin", "Release");
        Directory.CreateDirectory(start);
        if (solution) File.WriteAllText(Path.Combine(_root, "Certus.sln"), string.Empty);
        return start;
    }
}
