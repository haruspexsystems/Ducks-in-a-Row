using System.Text.RegularExpressions;

namespace Certus.Core.Tests.Security;

/// <summary>
/// Pins the three facts that change when a release is about to drop a Windows
/// Server version that 1.0.0 supports, so that the drop cannot happen by accident
/// (issue #625, the operating system guard adopted on #539 on 2026-10-21).
///
/// <para><b>Why a test.</b> The support period promise, security fixes until
/// 31 December 2031 through upgrades to the latest release with no backports,
/// rests on Article 13(10) of the Cyber Resilience Act. That article lets a
/// manufacturer fix only the latest version provided that users of earlier
/// versions can reach it free of charge and without extra cost to adjust their
/// hardware and software environment, and the Commission guidance (C(2026) 5252,
/// paragraph 130) counts a forced purchase of new hardware or software as such a
/// cost. A release that no longer runs on a Windows Server version 1.0.0 supports
/// therefore costs us the no backports route for those users, unless a decision
/// is recorded first on how they keep receiving fixes. Nothing mechanical carried
/// the rule: the installer conditions only on 64 bit Windows, and the facts that
/// would move live in four files that a release decision could miss.</para>
///
/// <para><b>What is pinned, and what is not.</b> The target framework major in the
/// shared build properties, the Hosting Bundle major in <c>build.ps1</c> and in
/// <c>installer/Bundle.wxs</c>, and the supported operating system row of
/// <c>docs/system-requirements.md</c>. The first trigger is the move off .NET 10,
/// whose Microsoft support ends in November 2028, before Server 2019's extended
/// support ends in January 2029. Not pinned, on purpose: the installer's accept
/// list, which the decision on #625 leaves as it is, and the patch version of the
/// Hosting Bundle, which moves with every servicing release.</para>
///
/// <para>In <c>Bundle.wxs</c> the major is not authored but supplied as a define
/// by <c>build.ps1</c>, derived from the same pin as the payload, so what this
/// test reads there is the documented build invocation in the file's header,
/// the one place in the file that states the major, plus the two uses of the
/// define (the runtime search and the detect floor), which must stay references
/// to it rather than become literals.</para>
///
/// <para>Every file read here ships in the public source snapshot, so the test
/// runs there too and needs no git.</para>
/// </summary>
public class SupportedPlatformGuardTests
{
    /// <summary>The .NET major the product targets. Moving it is the first trigger of the rule.</summary>
    private const int FrameworkMajor = 10;

    /// <summary>The ASP.NET Core Hosting Bundle major the setup bundle embeds and detects.</summary>
    private const int HostingBundleMajor = 10;

    /// <summary>The Windows Server versions 1.0.0 supports. Dropping one is what the rule guards.</summary>
    private static readonly string[] SupportedServers = ["2019", "2022", "2025"];

    private const string BuildProps = "Directory.Build.props";
    private const string BuildScript = "build.ps1";
    private const string BundleSource = "installer/Bundle.wxs";
    private const string SystemRequirements = "docs/system-requirements.md";

    /// <summary>
    /// The rule, the decision record and what to do, given as the reason of every
    /// assertion so that a failure explains itself to whoever runs into it.
    /// </summary>
    private const string Rule =
        "no release drops a Windows Server version that 1.0.0 supports (2019, 2022 with " +
        "current updates, 2025) during the support period, which runs to 31 December 2031, " +
        "unless a decision is recorded first on how those users keep receiving security " +
        "fixes. The support period promise rests on Article 13(10) of the Cyber Resilience " +
        "Act, which allows fixing only the latest version while users of earlier versions " +
        "can reach it at no extra cost, and the Commission guidance (C(2026) 5252, " +
        "paragraph 130) counts a forced operating system or software purchase as such a " +
        "cost. Moving the target framework major, the Hosting Bundle major or the supported " +
        "operating system sentence is that kind of change. Record the decision first in " +
        "Legal/support-period-statement.md (outside the repository; the rule was adopted on " +
        "issue #539, and issue #625 pinned it), then update the pinned values in " +
        "SupportedPlatformGuardTests in the same pull request";

    [Fact]
    public void TheTargetFrameworkMajorIsPinned()
    {
        var text = ReadShippedFile(BuildProps);
        var match = Regex.Match(text, @"<TargetFramework>net(\d+)\.\d+</TargetFramework>");

        match.Success.Should().BeTrue(
            $"{BuildProps} must declare the shared <TargetFramework> as netN.M, which is where the " +
            $"target framework major is read from, because {Rule}");
        int.Parse(match.Groups[1].Value).Should().Be(FrameworkMajor,
            $"the target framework major in {BuildProps} is pinned, because {Rule}");
    }

    [Fact]
    public void TheHostingBundleMajorIsPinnedInTheBuildScript()
    {
        var text = ReadShippedFile(BuildScript);
        var match = Regex.Match(text, @"(?m)^\$HostingBundleVersion = ""(\d+)\.\d+\.\d+""");

        match.Success.Should().BeTrue(
            $"{BuildScript} must pin $HostingBundleVersion as a three part version at the start of a " +
            $"line, which is where the Hosting Bundle major is read from, because {Rule}");
        int.Parse(match.Groups[1].Value).Should().Be(HostingBundleMajor,
            $"the Hosting Bundle major in {BuildScript} is pinned, because {Rule}");
    }

    [Fact]
    public void TheHostingBundleMajorIsPinnedInTheBundleSource()
    {
        var text = ReadShippedFile(BundleSource);
        var match = Regex.Match(text, @"-d HostingBundleMajor=(\d+)\b");

        match.Success.Should().BeTrue(
            $"the header of {BundleSource} must document the build invocation with its " +
            $"-d HostingBundleMajor=N define, which is where the Hosting Bundle major is read from, " +
            $"because {Rule}");
        int.Parse(match.Groups[1].Value).Should().Be(HostingBundleMajor,
            $"the Hosting Bundle major documented in {BundleSource} is pinned, because {Rule}");

        // What holds the bundle to the build script's pin is that the runtime
        // search and the detect floor take the major from the define rather than
        // authoring one. A literal there would let the embedded payload and the
        // floor drift apart with no pin reading it, so both uses are checked.
        text.Should().Contain("MajorVersion=\"$(var.HostingBundleMajor)\"",
            $"the runtime search in {BundleSource} must take its major from the HostingBundleMajor " +
            $"define build.ps1 passes, never a literal, because {Rule}");
        text.Should().Contain("v$(var.HostingBundleMajor).0.0",
            $"the detect floor in {BundleSource} must take its major from the HostingBundleMajor " +
            $"define build.ps1 passes, never a literal, because {Rule}");
    }

    [Fact]
    public void TheHostingBundleMajorMatchesTheTargetFramework()
    {
        // build.ps1 refuses a bundle build where the two disagree, but only on a
        // build box. Here the two pins are held together where CI runs.
        HostingBundleMajor.Should().Be(FrameworkMajor,
            "the setup bundle installs the runtime the product targets, so the two majors move " +
            $"together, and {Rule}");
    }

    [Fact]
    public void TheSupportedOperatingSystemSentenceIsPinned()
    {
        const string marker = "| Operating system |";
        var lines = File.ReadAllLines(Path.Combine(NoLabArtefactsTests.FindRepositoryRoot(), SystemRequirements));
        var rows = lines.Where(line => line.StartsWith(marker, StringComparison.Ordinal)).ToList();

        rows.Should().ContainSingle(
            $"{SystemRequirements} must carry exactly one table row starting with \"{marker}\", " +
            $"whose first sentence is the supported operating system sentence, because {Rule}");

        // The first sentence of the row is the supported set. The rest of the row
        // may mention a version for another reason (the note on servicing Server
        // 2022 is one), which is why the whole row is not the thing checked: a row
        // that dropped a version from the set and still pointed at its note would
        // otherwise pass. A sentence ends at a period followed by a space, so a
        // build number or a version inside the sentence does not end it early, and
        // a row with no sentence break is read whole.
        var details = rows[0][marker.Length..];
        var sentenceEnd = details.IndexOf(". ", StringComparison.Ordinal);
        var supportedSentence = sentenceEnd < 0 ? details : details[..sentenceEnd];
        foreach (var year in SupportedServers)
        {
            supportedSentence.Should().Contain($"Server {year}",
                $"the first sentence of the operating system row in {SystemRequirements} names every " +
                $"Windows Server version 1.0.0 supports, because {Rule}");
        }
    }

    /// <summary>
    /// Reads one of the pinned files from the repository root. Throws when the
    /// file is missing, because a pin that reads nothing proves nothing.
    /// </summary>
    private static string ReadShippedFile(string relative)
    {
        var path = Path.Combine(NoLabArtefactsTests.FindRepositoryRoot(), relative);
        File.Exists(path).Should().BeTrue(
            $"{relative} is one of the files the supported platform guard pins, and it must ship " +
            $"with the source, because {Rule}");
        return File.ReadAllText(path);
    }
}
