namespace Certus.Core.Tests.Security;

/// <summary>
/// A fact that asks git which files the repository holds, skipped with its reason stated
/// in a published source snapshot, where there is no repository to ask (issue #518).
///
/// <para><see cref="NoLabArtefactsTests"/> and <see cref="LicenceBoundaryScanTests"/> both
/// find their files with <c>git ls-files</c>. The public source snapshot is built by
/// <c>git archive</c>, which carries no <c>.git</c>, and the source code archive GitHub
/// attaches to a release tag carries none either. There git exits with 128 and both scans
/// failed with an error that says nothing about the product, for anyone who built from the
/// public source and ran <c>dotnet test</c>.</para>
///
/// <para><b>The skip is narrow on purpose.</b> A scan that quietly reads nothing is the
/// exact failure these tests exist to prevent, so a test carrying this attribute is skipped
/// only when all three of these hold, and runs otherwise, failing loudly if git cannot
/// answer:</para>
/// <list type="bullet">
/// <item><c>Certus.sln</c> is found walking up from the test assembly. When it is not, the
/// test runs and throws, as it always has.</item>
/// <item>That directory has no <c>.git</c>, either as a directory or as a file. A linked
/// worktree has a file there, naming where its repository lives.</item>
/// <item>That directory does not hold the release script. The script is stripped from the
/// snapshot along with everything else only the private repository carries, so a tree that
/// still holds it is a private checkout that lost its repository, for example a CI checkout
/// that fell back to downloading an archive. There the scan must fail, not skip, because a
/// skipped test does not fail a build. A file is the marker rather than a folder name such as
/// <c>.claude</c> or <c>scripts</c>, which someone working in a snapshot could create for
/// their own use.</item>
/// </list>
///
/// <para>xunit 2 has no way to skip a test from inside it, so the decision is taken here, at
/// discovery. The constructor only reads the file system and never throws.</para>
/// </summary>
public sealed class GitCheckoutFactAttribute : FactAttribute
{
    /// <summary>The reason a skipped scan reports.</summary>
    internal const string SnapshotReason =
        "This tree has no .git, so git cannot list the files it tracks. It is a source snapshot, " +
        "such as the public one release/Publish-Release.ps1 builds with git archive, or the source " +
        "code archive of a release. The scan runs, and is never skipped, in a git checkout of the " +
        "repository (issue #518).";

    public GitCheckoutFactAttribute()
    {
        var reason = SkipReason(AppContext.BaseDirectory);
        if (reason is not null) Skip = reason;
    }

    /// <summary>
    /// Why a scan started from <paramref name="startDirectory"/> should be skipped, or null
    /// when it should run.
    /// </summary>
    internal static string? SkipReason(string startDirectory)
    {
        var directory = new DirectoryInfo(startDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
        {
            directory = directory.Parent;
        }

        // No repository root at all. The test's own walk up throws for this, with a message
        // that says what it looked for, and that is better than a skip.
        if (directory is null) return null;

        var gitLink = Path.Combine(directory.FullName, ".git");
        if (Directory.Exists(gitLink) || File.Exists(gitLink)) return null;

        if (File.Exists(Path.Combine(directory.FullName, NoLabArtefactsTests.ReleaseScript))) return null;

        return SnapshotReason;
    }
}
