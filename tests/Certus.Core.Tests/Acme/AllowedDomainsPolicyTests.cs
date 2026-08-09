using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for AllowedDomainsPolicy. A missing wizard status file, the enabled
/// flag off, or an enabled flag with no usable entries all mean no
/// restriction; an enabled non empty list restricts orders to the listed
/// domains and their subdomains, matched on label boundaries after
/// normalization to lowercase punycode A labels.
/// </summary>
public class AllowedDomainsPolicyTests : IDisposable
{
    private readonly string _tempDir;
    private readonly CertusOptions _options;

    public AllowedDomainsPolicyTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _options = new CertusOptions { DatabasePath = Path.Combine(_tempDir, "certus.db") };
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: a stray temp folder is harmless.
        }
    }

    private AllowedDomainsPolicy BuildPolicy()
    {
        return new AllowedDomainsPolicy(
            Options.Create(_options), NullLogger<AllowedDomainsPolicy>.Instance);
    }

    private void WriteStatus(bool enabled, params string[] allowedDomains)
    {
        var status = new SetupStatus
        {
            SetupCompleted = true,
            EnabledTemplates = ["WebServer"],
            AllowedDomainsEnabled = enabled,
            AllowedDomains = allowedDomains.ToList(),
        };
        status.Save(SetupStatus.GetStatusPath(_options));
    }

    private static AcmeIdentifier[] Identifiers(params string[] values)
    {
        return values.Select(v => new AcmeIdentifier { Type = "dns", Value = v }).ToArray();
    }

    // ---- Inactive states: everything is allowed ----

    [Fact]
    public void FindDisallowed_NoStatusFile_AllowsEverything()
    {
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("anything.example.com")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_RestrictionOff_AllowsEverything()
    {
        WriteStatus(enabled: false, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("anything.example.com")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_EnabledWithEmptyList_FailsOpen()
    {
        // Only reachable by hand editing the file; the API refuses to save
        // this state. Fail open rather than refusing every order.
        WriteStatus(enabled: true);
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("anything.example.com")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_EnabledWithOnlyUnusableEntries_FailsOpen()
    {
        WriteStatus(enabled: true, "*.home.local", "https://home.local", "1.2.3.4");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("anything.example.com")).Should().BeEmpty();
    }

    // ---- Matching ----

    [Fact]
    public void FindDisallowed_ExactMatch_Allowed()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("home.local")).Should().BeEmpty();
    }

    [Theory]
    [InlineData("web.home.local")]
    [InlineData("a.b.home.local")]
    public void FindDisallowed_Subdomains_AllowedAtAnyDepth(string name)
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers(name)).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_LabelBoundary_SuffixLookalikeRefused()
    {
        // The classic trap: myhome.local ends with home.local as a string
        // but is a different domain. The match is on label boundaries.
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("myhome.local"))
            .Should().ContainSingle().Which.Should().Be("myhome.local");
    }

    [Fact]
    public void FindDisallowed_CaseInsensitive()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("WEB.HOME.LOCAL")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_TrailingDotOnIdentifier_Allowed()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("web.home.local.")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_EntryIsNormalizedBeforeMatching()
    {
        // A hand edited entry with stray casing and a trailing dot still
        // matches, because entries and names normalize the same way.
        WriteStatus(enabled: true, " HOME.Local. ");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("web.home.local")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_PunycodeAndUnicodeAreTheSameName()
    {
        WriteStatus(enabled: true, "bücher.example");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("xn--bcher-kva.example")).Should().BeEmpty();
        sut.FindDisallowed(Identifiers("shop.xn--bcher-kva.example")).Should().BeEmpty();
        sut.FindDisallowed(Identifiers("shop.bücher.example")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_UnparseableIdentifier_RefusedWhileActive()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("bad..name"))
            .Should().ContainSingle().Which.Should().Be("bad..name");
    }

    [Fact]
    public void FindDisallowed_MixedIdentifiers_ReturnsOnlyRefusedInRequestOrder()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        var result = sut.FindDisallowed(Identifiers(
            "ok.home.local", "bad.other.local", "home.local", "worse.example"));

        result.Should().Equal("bad.other.local", "worse.example");
    }

    // ---- Wildcards: *.D is allowed exactly when D would be ----

    [Fact]
    public void FindDisallowed_WildcardWithAllowedBase_Allowed()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("*.home.local")).Should().BeEmpty();
        sut.FindDisallowed(Identifiers("*.a.home.local")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_WildcardWithRefusedBase_Refused()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("*.other.local"))
            .Should().ContainSingle().Which.Should().Be("*.other.local");
    }

    [Fact]
    public void FindDisallowed_WildcardAboveTheEntry_Refused()
    {
        // Entry sub.home.local does not allow *.home.local: that wildcard
        // also covers siblings of sub, which are outside the entry's scope.
        WriteStatus(enabled: true, "sub.home.local");
        var sut = BuildPolicy();

        sut.FindDisallowed(Identifiers("*.home.local"))
            .Should().ContainSingle().Which.Should().Be("*.home.local");
    }

    // ---- Hot reload ----

    [Fact]
    public void FindDisallowed_ReloadsWhenFileChanges()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();
        sut.FindDisallowed(Identifiers("web.other.local")).Should().NotBeEmpty();

        // A settings page edit rewrites the file; the policy must pick up the
        // new list without a restart. Bump the write time explicitly so the
        // test does not depend on file system timestamp resolution.
        WriteStatus(enabled: true, "home.local", "other.local");
        var path = SetupStatus.GetStatusPath(_options);
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddSeconds(1));

        sut.FindDisallowed(Identifiers("web.other.local")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_TransientReadFailure_KeepsLastKnownPolicy()
    {
        WriteStatus(enabled: true, "home.local");
        var sut = BuildPolicy();
        sut.FindDisallowed(Identifiers("web.other.local")).Should().NotBeEmpty();

        // Bump the write time so the cache would reload, then hold the file
        // open exclusively (an antivirus scanner or backup does the same).
        // The reload fails; the policy must keep refusing from the last
        // known list instead of caching a fail open decision.
        var path = SetupStatus.GetStatusPath(_options);
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddSeconds(1));
        using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            sut.FindDisallowed(Identifiers("web.other.local")).Should().NotBeEmpty();
        }

        // Lock released: the next order reloads and enforcement continues.
        sut.FindDisallowed(Identifiers("web.other.local")).Should().NotBeEmpty();
        sut.FindDisallowed(Identifiers("web.home.local")).Should().BeEmpty();
    }

    [Fact]
    public void FindDisallowed_FileAppearsAfterFirstCheck_Restricts()
    {
        var sut = BuildPolicy();
        sut.FindDisallowed(Identifiers("anything.example.com"))
            .Should().BeEmpty("no file means no restriction");

        WriteStatus(enabled: true, "home.local");

        sut.FindDisallowed(Identifiers("anything.example.com")).Should().NotBeEmpty();
        sut.FindDisallowed(Identifiers("web.home.local")).Should().BeEmpty();
    }

    // ---- Entry validation ----

    [Theory]
    [InlineData("home.local", "home.local")]
    [InlineData(" HOME.Local. ", "home.local")]
    [InlineData("corp", "corp")]
    [InlineData("bücher.example", "xn--bcher-kva.example")]
    public void ValidateEntry_UsableEntries_ReturnNullAndNormalize(string raw, string expected)
    {
        var reason = AllowedDomainsPolicy.ValidateEntry(raw, out var normalized);

        reason.Should().BeNull();
        normalized.Should().Be(expected);
    }

    [Theory]
    [InlineData("", "Enter a domain name.")]
    [InlineData("   ", "Enter a domain name.")]
    [InlineData("*.home.local", "included automatically")]
    [InlineData("https://home.local", "without a scheme")]
    [InlineData("home.local/path", "without a path")]
    [InlineData("home local", "cannot contain spaces")]
    [InlineData("192.168.1.10", "IP addresses are not allowed")]
    [InlineData("::1", "IP addresses are not allowed")]
    [InlineData("[fe80::1]", "IP addresses are not allowed")]
    [InlineData("home.local:443", "without a port")]
    [InlineData("a..b", "not a valid domain name")]
    public void ValidateEntry_UnusableEntries_ReturnAReason(string raw, string reasonFragment)
    {
        var reason = AllowedDomainsPolicy.ValidateEntry(raw, out _);

        reason.Should().NotBeNull();
        reason.Should().Contain(reasonFragment);
    }

    // ---- The static matcher shared with the EAB credential namespaces ----

    [Fact]
    public void FindDisallowedAgainst_AppliesTheSameRulesAsThePolicy()
    {
        var entries = new List<string> { "home.local" };

        AllowedDomainsPolicy.FindDisallowedAgainst(
                Identifiers("home.local", "web.home.local", "*.home.local"), entries)
            .Should().BeEmpty();

        AllowedDomainsPolicy.FindDisallowedAgainst(
                Identifiers("ok.home.local", "myhome.local", "*.other.local", "bad..name"),
                entries)
            .Should().Equal("myhome.local", "*.other.local", "bad..name");
    }

    [Fact]
    public void FindDisallowedAgainst_EmptyEntryList_RefusesEverything()
    {
        // The contract callers must respect: an empty list refuses every
        // identifier, so a caller meaning "no restriction" must not call at
        // all. FindDisallowed maps its inactive states to a null entry list
        // before reaching the matcher, and the EAB namespace check skips
        // credentials whose namespace is empty.
        AllowedDomainsPolicy.FindDisallowedAgainst(
                Identifiers("anything.example"), new List<string>())
            .Should().ContainSingle().Which.Should().Be("anything.example");
    }
}
