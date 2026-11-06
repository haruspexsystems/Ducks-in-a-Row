using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Certus.Core.Tests.Security;

/// <summary>
/// Nothing that ships or is published may name a real host of the maintainer's.
///
/// This exists because the rule was broken twice by the same mechanism. An
/// example string is written against whatever lab is live at the time, the lab
/// is later retired, and the name stays behind: the setup wizard shipped a
/// <c>home.local</c> domain placeholder for months after that lab was gone, and
/// four documentation screenshots captured against the lab reached the public
/// repository carrying its AD domain, its CA connection string and a list of
/// its clients. Neither was caught by review, because a plausible looking host
/// name reads as an example either way.
///
/// <para><b>What it scans is what ships.</b> Every tracked file goes into the
/// public source snapshot except the paths <c>$ExcludePaths</c> in
/// <c>release/Publish-Release.ps1</c> strips, so the scan reads that list out of
/// the script instead of keeping a list of roots of its own, and the two cannot
/// drift. Until issue #431 it read <c>src/</c>, <c>installer/</c> and
/// <c>docs/</c> only, on the reasoning that <c>tests/</c> and <c>tools/</c> are
/// fixtures and probes. They are, but they ship: the product test projects, both
/// probes and every file at the repository root reach the public repository, and
/// three test files there named the live lab. In the public tree the release
/// script is itself stripped, and there every tracked file ships, so the whole
/// tree is read. A tree with no release script that still carries
/// <c>scripts/</c> is a damaged private checkout, and the scan refuses it rather
/// than read the wrong set.</para>
///
/// <para><b>Two tiers of terms.</b> The live estate (the hand run lab, the three
/// matrix labs, a Windows profile path) is refused in everything that ships,
/// fixtures included. A fixture has no reason to name a machine that still
/// exists, and those are the names a real lab run leaves behind when its output
/// is pasted into a test. Retired and borrowed names (the old home lab, another
/// vendor's example brand, a domain that was never ours) are refused only on the
/// product surface, which is everything outside <c>tests/</c> and <c>tools/</c>.
/// The test projects carry them by the hundred as fixture data, no customer ever
/// sees them there, and a gate that fires on legitimate fixture data is one that
/// gets deleted, which would cost more than the defect it catches.</para>
///
/// <para><b>The terms are assembled from halves</b>, the pattern
/// <see cref="LicenceBoundaryScanTests"/> uses, so this file contains none of
/// them and is scanned like any other. That also stops it being the one shipped
/// file that spells out the live lab's names.</para>
///
/// <para>It reads <b>tracked files only</b>, via <c>git ls-files</c>, because
/// "can this reach the public" is a question about what is committed. Scanning
/// the working tree instead would fail on files that can never be published: a
/// <c>docs/reviews/</c> report from <c>certus-code-review</c> quotes the lab CA
/// connection string by design, and a developer's gitignored
/// <c>appsettings.Development.json</c> holds a real CA connection string
/// precisely so the dev host can reach one. A source snapshot built by
/// <c>git archive</c> has no repository to ask, so there the scan is skipped
/// with its reason stated (<see cref="GitCheckoutFactAttribute"/>, issue #518),
/// and only there.</para>
///
/// <para>The terms are a curated list rather than a general pattern. A regular
/// expression over RFC 1918 addresses was the obvious first design and is
/// wrong: it fires on <c>AddressGuard</c>, where those ranges are the product's
/// actual subject matter, and on <c>docs/hardening.md</c>, which documents them.
/// For the same reason no lab address is a term: listing them would put the
/// whole layout of the maintainer's network in one shipped file.</para>
/// </summary>
public class NoLabArtefactsTests
{
    private const string ThisFile = "tests/Certus.Core.Tests/Security/NoLabArtefactsTests.cs";

    internal const string ReleaseScript = "release/Publish-Release.ps1";

    /// <summary>
    /// Names of the live estate, refused in every file that ships. Matched case
    /// insensitively. Use RFC 2606 names (example.com and its subdomains) and
    /// RFC 5737 addresses instead.
    /// </summary>
    internal static readonly string[] LiveEstateTerms =
    [
        // The hand run lab, its two hosts and its operator profile, and the
        // misspelt year it once shipped under.
        "manual" + "2025",
        "manual" + "2026",
        "manual" + "-adcs",
        "manual" + "-dc",
        "administrator" + ".manual",
        // Any Windows profile path. A dev box path in a shipped file names the
        // maintainer's machine whichever box it is, and a path written before a
        // move can still be pasted out of an old transcript, so the term is the
        // prefix rather than a list of profiles to keep current.
        @"c:\" + @"users\",
        .. MatrixLabTerms(),
    ];

    /// <summary>
    /// Names refused on the product surface only, everywhere outside the fixture
    /// trees. Matched case insensitively.
    /// </summary>
    internal static readonly string[] ProductSurfaceTerms =
    [
        // The retired home lab.
        "home" + ".local",
        "home" + ".lab",
        // Not a leak but a Microsoft trademark: a commercial product should not
        // use another vendor's fictional brand in its own interface.
        "con" + "toso",
        // Not a leak either: a domain that was never ours. The dashboard used it
        // as the base of every problem type it emits from the 2026-06-09 rebrand
        // on, and an unrelated business registered it on 2026-09-07, so the 0.9.0
        // and 0.10.0 betas send their errors to a stranger's site.
        // DashboardProblemType carries the .dev domain since issue #402.
        "ducksinarow" + ".app",
    ];

    /// <summary>Every term, which is what applies on the product surface.</summary>
    private static readonly string[] AllTerms = [.. LiveEstateTerms, .. ProductSurfaceTerms];

    /// <summary>
    /// Shipped trees whose files are fixtures and probes rather than the product.
    /// Only the live estate terms apply inside them.
    /// </summary>
    private static readonly string[] FixtureRoots = ["tests/", "tools/"];

    /// <summary>
    /// Paths only the private repository holds. A tree without the release script
    /// must carry none of them, or it is not the public tree.
    /// </summary>
    private static readonly string[] PrivateOnlyRoots = ["scripts/", ".claude/"];

    /// <summary>
    /// A term a shipped file may carry on one line, named by a fragment of that
    /// line, each with the reason it may. The fragment keeps the allowance to the
    /// line the decision was about, so a new mention elsewhere in the same file is
    /// still refused. An entry that matches nothing fails the scan, so a decision
    /// cannot outlive its subject.
    /// </summary>
    private static readonly (string Path, string Term, string Line, string Reason)[] Allowed = [];

    /// <summary>
    /// Extensions worth reading, as an allow list. An allow list rather than a
    /// list of binary extensions to skip, so a new binary format added to a
    /// shipped tree cannot be read as text and produce noise.
    /// </summary>
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".ts", ".tsx", ".js", ".jsx", ".json", ".css", ".html", ".md",
        ".wxs", ".wxl", ".wxi", ".config", ".props", ".targets", ".ps1", ".py",
        ".csproj", ".sln", ".txt", ".yml", ".yaml", ".svg", ".sha256",
        ".editorconfig", ".gitattributes", ".gitignore",
    };

    /// <summary>Text files with no extension, by repository relative path.</summary>
    private static readonly HashSet<string> TextFileNames = new(StringComparer.Ordinal)
    {
        "LICENSE", "NOTICE",
    };

    [GitCheckoutFact]
    public void ShippedFiles_NameNoRealHost()
    {
        var root = FindRepositoryRoot();
        var tracked = TrackedFiles(root);
        var releaseScript = tracked.Contains(ReleaseScript)
            ? File.ReadAllText(Path.Combine(root, ReleaseScript))
            : null;
        var scanned = ShippedPaths(tracked, releaseScript).Where(IsText).ToList();

        // A scan that read the wrong set passes for the wrong reason, so each kind
        // of shipped tree it exists to cover is named here, and so is the absence
        // of the one it must never read.
        scanned.Should().Contain(new[] { "README.md", "tools/AdcsQiProbe/Program.cs", ThisFile },
            "the scan must read the root files, the probes and the test projects, which all ship");
        scanned.Should().NotContain(path => path.StartsWith("scripts/", StringComparison.Ordinal),
            "scripts/ is stripped before anything is published and documents real lab runs on purpose");

        var used = new bool[Allowed.Length];
        var violations = new List<string>();
        foreach (var relative in scanned)
        {
            // Deleted in the working tree but still in the index: it cannot ship
            // once the deletion is committed, and there is nothing to read.
            var path = Path.Combine(root, relative);
            if (!File.Exists(path)) continue;

            var lines = File.ReadAllLines(path);
            for (var i = 0; i < lines.Length; i++)
            {
                foreach (var term in FindTerms(relative, lines[i]))
                {
                    var line = lines[i];
                    var allowance = Array.FindIndex(Allowed, a => a.Path == relative && a.Term == term
                        && line.Contains(a.Line, StringComparison.Ordinal));
                    if (allowance >= 0)
                    {
                        used[allowance] = true;
                        continue;
                    }

                    violations.Add($"{relative}:{i + 1}  [{term}]  {lines[i].Trim()}");
                }
            }
        }

        for (var i = 0; i < Allowed.Length; i++)
        {
            if (!used[i])
            {
                violations.Add($"{Allowed[i].Path}  [{Allowed[i].Term}]  the allow entry matched " +
                    $"nothing, so remove it (it was there because {Allowed[i].Reason})");
            }
        }

        violations.Should().BeEmpty(
            "no shipped file may name a real host, domain, or account. " +
            "Replace it with an RFC 2606 reserved name such as corp.example.com, or " +
            "an RFC 5737 documentation address such as 203.0.113.10. A problem type " +
            "belongs in DashboardProblemType, under ducksinarow.dev.");
    }

    [Fact]
    public void TheMatcherFindsEveryTermAndNoLegalSpelling()
    {
        // The positive control: each term, planted in a line in either case, is found.
        foreach (var term in LiveEstateTerms.Concat(ProductSurfaceTerms))
        {
            FindTerms("src/Certus.Core/X.cs", $"var host = \"{term}x\";").Should().Contain(term);
            FindTerms("src/Certus.Core/X.cs", $"var host = \"{term.ToUpperInvariant()}x\";").Should().Contain(term);
        }

        // And the spellings that must stay legal are not. The year alone is not a
        // matrix term because an identifier carries it, and a member access on
        // that identifier puts a period straight after it.
        foreach (var legal in new[]
        {
            "ServiceRightsFindings.MeasuredOnLab2019.CaRolesTrusted",
            "Measured on lab 2019 (Server 2019) on 2026-09-26",
            "https://certus.corp.example.com:5001",
            "https://192.168.2.1:5001",
            "the manual fallback, not the lab Certus drives",
        })
        {
            FindTerms("src/Certus.Core/X.cs", legal).Should().BeEmpty(legal);
        }
    }

    [Fact]
    public void TheFixtureTreesMayCarryRetiredNamesButNeverTheLiveEstate()
    {
        foreach (var term in ProductSurfaceTerms)
        {
            var line = $"san.AddDnsName(\"web01.{term}\");";
            FindTerms("tests/Certus.Core.Tests/X.cs", line).Should().BeEmpty(term);
            FindTerms("tools/AdcsQiProbe/Program.cs", line).Should().BeEmpty(term);
            FindTerms("src/Certus.Core/X.cs", line).Should().Contain(term);
            FindTerms("README.md", line).Should().Contain(term);
        }

        foreach (var term in LiveEstateTerms)
        {
            var line = $"san.AddDnsName(\"web01.{term}\");";
            FindTerms("tests/Certus.Web.Tests/X.cs", line).Should().Contain(term);
            FindTerms("tools/AdcsQiProbe/Program.cs", line).Should().Contain(term);
        }
    }

    [Fact]
    public void TheExclusionListIsAppliedTheWayTheReleaseScriptAppliesIt()
    {
        const string script =
            "$ExcludePaths = @(\n" +
            "    \"scripts\",\n" +
            "    # A comment inside the list is not an entry.\n" +
            "    \"tests/lab\",\n" +
            "    \"docs/images/README.md\"\n" +
            ")\n" +
            "# \"not-an-entry\" sits after the list and is not part of it.\n";
        string[] tracked =
        [
            "scripts/x.ps1", "tests/lab/x.ps1", "docs/images/README.md",
            "tests/Certus.Core.Tests/x.cs", "docs/images/a.png", "tools/AdcsQiProbe/Program.cs",
            // An entry strips a path equal to it or under it, never one that only
            // starts with the same characters.
            "scriptsfoo/y.cs", "tests/labs/z.cs",
        ];

        // Line endings must not matter, since a checkout's are not this test's choice.
        foreach (var text in new[] { script, script.Replace("\n", "\r\n") })
        {
            ParseExcludePaths(text).Should().Equal("scripts", "tests/lab", "docs/images/README.md");
            ShippedPaths(tracked, text).Should().Equal(
                "tests/Certus.Core.Tests/x.cs", "docs/images/a.png", "tools/AdcsQiProbe/Program.cs",
                "scriptsfoo/y.cs", "tests/labs/z.cs");
        }
    }

    [Fact]
    public void AnExclusionListThatCannotBeReadIsRefused()
    {
        // Renamed, and reshaped so that scripts is no longer in it: both would
        // otherwise scan a tree the release script does not strip.
        var renamed = () => ParseExcludePaths("$Excluded = @(\n    \"scripts\"\n)\n");
        renamed.Should().Throw<InvalidOperationException>();

        var reshaped = () => ParseExcludePaths("$ExcludePaths = @(\n    \"release\"\n)\n");
        reshaped.Should().Throw<InvalidOperationException>();

        // The closing parenthesis indented: the block runs on into the code below
        // it, and the quoted "src" there must not quietly become an exclusion.
        var overrun = () => ParseExcludePaths(
            "$ExcludePaths = @(\n    \"scripts\"\n    )\n$target = Join-Path $root \"src\"\n)\n");
        overrun.Should().Throw<InvalidOperationException>().WithMessage("*not a quoted path*");
    }

    [Fact]
    public void WithoutTheReleaseScriptEveryTrackedFileShipsUnlessThePrivateTreesArePresent()
    {
        string[] publicTree = ["README.md", "src/Certus.Core/X.cs", "tests/Certus.Core.Tests/X.cs"];
        ShippedPaths(publicTree, null).Should().Equal(publicTree);

        string[] damaged = ["README.md", "scripts/lab/LabFacts.ps1"];
        var act = () => ShippedPaths(damaged, null);
        act.Should().Throw<InvalidOperationException>().WithMessage("*scripts/lab/LabFacts.ps1*");
    }

    /// <summary>
    /// The terms that apply to a shipped file: the live estate everywhere, and the
    /// product surface terms outside the fixture trees.
    /// </summary>
    internal static IEnumerable<string> FindTerms(string path, string line)
    {
        var isFixture = FixtureRoots.Any(r => path.StartsWith(r, StringComparison.Ordinal));
        var terms = isFixture ? LiveEstateTerms : AllTerms;
        return terms.Where(term => line.Contains(term, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The tracked paths that reach the public source snapshot. With the release
    /// script present, that is every path its <c>$ExcludePaths</c> does not strip.
    /// Without it, this should be the public tree, where the stripping has already
    /// happened and every tracked path ships, and that is checked rather than assumed.
    /// </summary>
    internal static IReadOnlyList<string> ShippedPaths(IReadOnlyList<string> tracked, string? releaseScriptText)
    {
        if (releaseScriptText is null)
        {
            var privateOnly = tracked.FirstOrDefault(
                path => PrivateOnlyRoots.Any(r => path.StartsWith(r, StringComparison.Ordinal)));
            if (privateOnly is not null)
            {
                throw new InvalidOperationException(
                    $"{ReleaseScript} is not tracked, so this should be the public tree, where every " +
                    $"tracked file ships. But {privateOnly} is tracked, and only the private repository " +
                    "holds that. The scan cannot tell what ships, and reading the wrong set would pass " +
                    "for the wrong reason.");
            }

            return tracked;
        }

        var excluded = ParseExcludePaths(releaseScriptText);
        return tracked
            .Where(path => !excluded.Any(e => path == e || path.StartsWith(e + "/", StringComparison.Ordinal)))
            .ToList();
    }

    /// <summary>
    /// Reads <c>$ExcludePaths</c> out of the release script, finding the block with
    /// the regex tests/release/Test-ReleaseScripts.ps1 uses, so the two read one
    /// list. Throws when the list is missing or no longer carries <c>scripts</c>,
    /// the one entry that list has always held, and when any line inside the block
    /// is not a quoted path or a comment. The second check is what catches a list
    /// that grew rather than shrank: with its closing parenthesis indented, the
    /// match would run on to the next one at the start of a line, and every quoted
    /// string in the code between would silently become an exclusion. A list that
    /// cannot be read exactly must not become a scan of the wrong tree.
    /// </summary>
    internal static IReadOnlyList<string> ParseExcludePaths(string scriptText)
    {
        var block = Regex.Match(scriptText, @"\$ExcludePaths = @\((.*?)\r?\n\)", RegexOptions.Singleline);
        var paths = new List<string>();
        if (block.Success)
        {
            foreach (var raw in block.Groups[1].Value.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;

                var entry = Regex.Match(line, "^\"([^\"]+)\",?\\s*(#.*)?$");
                if (!entry.Success)
                {
                    throw new InvalidOperationException(
                        $"$ExcludePaths in {ReleaseScript} holds a line that is not a quoted path: {line}. " +
                        "The lab artefact scan reads one quoted path per line, closed by a parenthesis " +
                        "at the start of a line, and will not guess at anything else.");
                }

                paths.Add(entry.Groups[1].Value);
            }
        }

        if (!paths.Contains("scripts"))
        {
            throw new InvalidOperationException(
                $"Could not read $ExcludePaths out of {ReleaseScript}, or it no longer strips scripts. " +
                "The lab artefact scan derives what ships from that list, and cannot run without it.");
        }

        return paths;
    }

    /// <summary>
    /// The three matrix labs Certus-QA provisions, each named by its year. A term
    /// is the year with what follows it in a real name: the domain, the dash of a
    /// host or a CA name, and the backslash of an account. The year alone is not
    /// one, for the reason the matcher test gives.
    /// </summary>
    private static IEnumerable<string> MatrixLabTerms() =>
        from year in new[] { "2019", "2022", "2025" }
        from follower in new[] { ".local", "-", @"\" }
        select "lab" + year + follower;

    private static bool IsText(string path) =>
        TextExtensions.Contains(Path.GetExtension(path)) || TextFileNames.Contains(path);

    /// <summary>Tracked files as repository relative paths with forward slashes.</summary>
    private static IReadOnlyList<string> TrackedFiles(string root) =>
        RunGit(root, "ls-files -z")
            .Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .ToList();

    /// <summary>
    /// Throws rather than returning empty when git cannot answer. A scan that
    /// quietly passes because it read nothing is the exact failure this test
    /// exists to prevent, and it is why the docs guide gate in pr-build.yml
    /// errors instead of skipping when Python is missing. The one tree where git
    /// is expected not to answer, a source snapshot with no .git, never reaches
    /// this: <see cref="GitCheckoutFactAttribute"/> skips the scan first.
    /// </summary>
    private static string RunGit(string root, string arguments)
    {
        var startInfo = new ProcessStartInfo("git", arguments)
        {
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Could not start git. The lab artefact scan needs it to tell "
                + "tracked files from a developer's gitignored ones.");

        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"git {arguments} failed with exit code {process.ExitCode}: {stderr}");
        }

        return stdout;
    }

    /// <summary>
    /// Walks up from the test assembly to the directory holding Certus.sln.
    /// Throws when there is none, for the same reason <see cref="RunGit"/> does.
    /// Shared with <see cref="SupportedPlatformGuardTests"/>, which reads shipped
    /// files from the same root.
    /// </summary>
    internal static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new InvalidOperationException(
                $"Could not find Certus.sln walking up from {AppContext.BaseDirectory}. "
                + "The scans that read the repository cannot run, and passing without "
                + "scanning would defeat the point of it.");
        }

        return directory.FullName;
    }
}
