using System.Diagnostics;
using System.Text;

namespace Certus.Core.Tests.Security;

/// <summary>
/// The public core holds the load hook and nothing more: no licence verification and no key
/// material (acceptance criterion 3 of lethe377/Certus#413; licence design section 4). That
/// code lives in the private lethe377/Certus-Commercial, because every file tracked here ships
/// in the public snapshot unless release/Publish-Release.ps1 excludes it.
///
/// <para><b>What it scans.</b> Every text file git knows about: tracked, plus new files not yet
/// ignored, so a file is caught before its commit rather than after (deviation Dv8). The design
/// named only src/, installer/ and docs/, but tests/Certus.*, tools/ and src/frontend ship too.
/// Ignored files are skipped for the reason NoLabArtefactsTests gives. A source snapshot built by
/// git archive has no repository to ask, so there the scan is skipped with its reason stated
/// (<see cref="GitCheckoutFactAttribute"/>, issue #518), and only there.</para>
///
/// <para><b>The markers stay specific on purpose.</b> The tree already names Ed25519 as a display
/// label for an algorithm OID (CertificateDerParser.cs and the frontend's types), and a bare
/// "rfc8032" would match a link to the RFC. Each marker is assembled from two halves here, so
/// this file does not contain them and the scan needs no exclusion, not even for itself.</para>
/// </summary>
public class LicenceBoundaryScanTests
{
    /// <summary>The design's section 4 list, matched case sensitively.</summary>
    internal static readonly string[] Markers =
    [
        "ducks-licence" + "+jws",          // the licence header type
        "Ed25519" + "Signer",              // BouncyCastle's Ed25519 signing and verification
        "Ed25519" + "PublicKeyParameters", // an Ed25519 public key
        "Rfc" + "8032",                    // an EdDSA implementation by name
        "BEGIN " + "PRIVATE KEY",          // PEM private key material
        "AGE-SECRET" + "-KEY-",            // an age identity
        "age-encryption" + ".org",         // an age encrypted file's header
    ];

    [GitCheckoutFact]
    public void PublishedTreeCarriesNoLicenceVerificationOrKeyMaterial()
    {
        var root = RepositoryRoot();
        var files = CandidateFiles(root);

        // Anti vacuity: the scan read the tree, including this very file.
        files.Should().HaveCountGreaterThan(400, "a scan that read almost nothing proves nothing");
        files.Should().Contain("tests/Certus.Core.Tests/Security/LicenceBoundaryScanTests.cs");

        var hits = new List<string>();
        var read = 0;
        foreach (var relative in files)
        {
            var path = Path.Combine(root, relative);
            if (!File.Exists(path)) continue;   // deleted in the working tree, still in the index
            var bytes = File.ReadAllBytes(path);
            if (LooksBinary(bytes)) continue;
            read++;
            var text = Encoding.UTF8.GetString(bytes);
            foreach (var marker in Markers)
            {
                if (text.Contains(marker, StringComparison.Ordinal)) hits.Add($"{relative}  [{marker}]");
            }
        }

        read.Should().BeGreaterThan(400);
        hits.Should().BeEmpty(
            "licence verification and key material belong in lethe377/Certus-Commercial, never in the public core " +
            "(licence design section 4). The module host stores licence bytes and displays what the module returns.");
    }

    [Fact]
    public void TheMatcherFindsEveryMarker()
    {
        // The positive control: each marker, planted in text, is found.
        foreach (var marker in Markers)
        {
            var planted = $"var x = \"{marker}\";";
            Markers.Count(m => planted.Contains(m, StringComparison.Ordinal)).Should().BeGreaterThan(0, marker);
        }

        // And the specific spellings that must stay legal are not found.
        foreach (var legal in new[] { "Ed25519", "rfc8032", "RFC 8032", "ducks-licence", "PRIVATE KEY ID" })
            Markers.Any(m => legal.Contains(m, StringComparison.Ordinal)).Should().BeFalse(legal);
    }

    private static bool LooksBinary(byte[] bytes) =>
        bytes.AsSpan(0, Math.Min(bytes.Length, 8000)).IndexOf((byte)0) >= 0;

    private static IReadOnlyList<string> CandidateFiles(string root) =>
        RunGit(root, "ls-files -z --cached --others --exclude-standard")
            .Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.Ordinal)
            .ToList();

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
            ?? throw new InvalidOperationException("Could not start git; the boundary scan needs it to tell shipped files from ignored ones.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"git {arguments} failed with exit code {process.ExitCode}: {stderr}");
        return stdout;
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
            directory = directory.Parent;
        return directory?.FullName
            ?? throw new InvalidOperationException($"Could not find Certus.sln walking up from {AppContext.BaseDirectory}.");
    }
}
