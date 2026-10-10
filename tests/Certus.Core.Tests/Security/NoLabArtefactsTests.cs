using System.Diagnostics;

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
/// The scan covers the three trees a customer or the public can see:
/// <c>src/</c> (what ships), <c>installer/</c> (what the MSI carries), and
/// <c>docs/</c> (published, and compiled into the installation guide PDF).
/// <c>tests/</c>, <c>tools/</c> and <c>scripts/</c> are deliberately out of
/// scope: the first two are fixtures and probes, and <c>scripts/</c> documents
/// real lab runs on purpose and is stripped by
/// <c>release/Publish-Release.ps1</c> before anything is published.
///
/// Two design choices, both about not producing a false positive. A gate that
/// cries wolf gets deleted, which would cost more than the defect it catches.
///
/// It reads **tracked files only**, via <c>git ls-files</c>, because "can this
/// reach the public" is a question about what is committed. Scanning the
/// working tree instead would fail on files that can never be published: a
/// <c>docs/reviews/</c> report from <c>certus-code-review</c> quotes the lab CA
/// connection string by design, and a developer's gitignored
/// <c>appsettings.Development.json</c> holds a real CA connection string
/// precisely so the dev host can reach one. Both sit under a scanned root and
/// carry a scanned extension.
///
/// The terms are a curated list rather than a general pattern. A regular
/// expression over RFC 1918 addresses was the obvious first design and is
/// wrong: it fires on <c>AddressGuard</c>, where those ranges are the product's
/// actual subject matter, and on <c>docs/hardening.md</c>, which documents them.
/// </summary>
public class NoLabArtefactsTests
{
    /// <summary>
    /// Identifiers that name a real machine, domain, or account rather than a
    /// reserved example. Matched case insensitively. Use RFC 2606 names
    /// (example.com and its subdomains) and RFC 5737 addresses instead.
    ///
    /// "contoso" is here for a different reason than the rest: it is not a leak
    /// but a Microsoft trademark, and a commercial product should not use
    /// another vendor's fictional brand in its own interface.
    /// </summary>
    private static readonly string[] ForbiddenTerms =
    [
        "manual2025",
        "manual2026",
        "manual-adcs",
        "manual-dc",
        "administrator.manual",
        "home.local",
        "home.lab",
        "contoso",
        // Any Windows profile path. A dev box path in a shipped file names the
        // maintainer's machine whichever box it is (the one retired in 2026-09 was
        // c:\users\admin, the current one is c:\users\sean), and a path written
        // before a move can still be pasted out of an old transcript, so the term
        // is the prefix rather than a list of profiles to keep current. The lab
        // operator profile is caught by administrator.manual above.
        @"c:\users\",
        // Like contoso, not a leak: a domain that was never ours. The dashboard
        // used it as the base of every problem type it emits from the 2026-06-09
        // rebrand on, and an unrelated business registered it on 2026-09-07, so
        // the 0.9.0 and 0.10.0 betas send their errors to a stranger's site.
        // DashboardProblemType carries ducksinarow.dev since issue #402.
        "ducksinarow.app",
    ];

    /// <summary>Trees that ship or are published, as git path prefixes.</summary>
    private static readonly string[] ScannedRoots = ["src/", "installer/", "docs/"];

    /// <summary>
    /// Extensions worth reading, as an allow list. An allow list rather than a
    /// list of binary extensions to skip, so a new binary format added to
    /// docs/ cannot be read as text and produce noise.
    /// </summary>
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".ts", ".tsx", ".js", ".jsx", ".json", ".css", ".html", ".md",
        ".wxs", ".wxl", ".wxi", ".config", ".props", ".targets", ".ps1", ".py",
        ".csproj", ".txt", ".yml", ".yaml",
    };

    [Fact]
    public void ShippedAndPublishedTrees_NameNoRealHost()
    {
        var root = FindRepositoryRoot();

        var scanned = TrackedTextFiles(root);
        scanned.Should().NotBeEmpty(
            "the scan proves nothing if it read no files at all");

        var violations = new List<string>();
        foreach (var relative in scanned)
        {
            var lines = File.ReadAllLines(Path.Combine(root, relative));
            for (var i = 0; i < lines.Length; i++)
            {
                foreach (var term in ForbiddenTerms)
                {
                    if (lines[i].Contains(term, StringComparison.OrdinalIgnoreCase))
                    {
                        violations.Add($"{relative}:{i + 1}  [{term}]  {lines[i].Trim()}");
                    }
                }
            }
        }

        violations.Should().BeEmpty(
            "no shipped or published file may name a real host, domain, or account. " +
            "Replace it with an RFC 2606 reserved name such as corp.example.com, or " +
            "an RFC 5737 documentation address such as 203.0.113.10. A problem type " +
            "on ducksinarow.app belongs in DashboardProblemType, under ducksinarow.dev.");
    }

    /// <summary>
    /// Tracked files under the scanned roots that are worth reading as text,
    /// as repository relative paths with forward slashes.
    /// </summary>
    private static IReadOnlyList<string> TrackedTextFiles(string root)
    {
        return RunGit(root, "ls-files -z -- src installer docs")
            .Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Where(path => ScannedRoots.Any(
                r => path.StartsWith(r, StringComparison.Ordinal)))
            .Where(path => TextExtensions.Contains(Path.GetExtension(path)))
            .ToList();
    }

    /// <summary>
    /// Throws rather than returning empty when git cannot answer. A scan that
    /// quietly passes because it read nothing is the exact failure this test
    /// exists to prevent, and it is why the docs guide gate in pr-build.yml
    /// errors instead of skipping when Python is missing.
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
    /// </summary>
    private static string FindRepositoryRoot()
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
                + "The lab artefact scan cannot run, and passing without scanning "
                + "would defeat the point of it.");
        }

        return directory.FullName;
    }
}
