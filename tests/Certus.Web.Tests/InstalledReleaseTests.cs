using System.Reflection;
using Certus.Web.Configuration;
using Certus.Web.Controllers.Settings;
using Microsoft.Extensions.Configuration;

namespace Certus.Web.Tests;

/// <summary>
/// Issue #623. The Settings About block's release age rests on three pure
/// pieces: the commit date read off the assembly, the age rule, and the
/// threshold setting. Each is pinned here without a host, because the only
/// value that varies at runtime is the clock, and the clock is a parameter.
/// </summary>
public class InstalledReleaseTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 22, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Evaluate_NoStamp_HasNoAgeAndNoWarning()
    {
        var age = InstalledRelease.Evaluate(null, Now, warningDays: 180);

        age.AgeDays.Should().BeNull();
        age.Outdated.Should().BeFalse("without a date there is nothing to be older than");
    }

    [Theory]
    [InlineData(179, false)]
    [InlineData(180, false)]
    [InlineData(181, true)]
    [InlineData(400, true)]
    public void Evaluate_WarnsOnlyPastTheThreshold(int daysOld, bool expectOutdated)
    {
        var commitDate = Now.AddDays(-daysOld);

        var age = InstalledRelease.Evaluate(commitDate, Now, warningDays: 180);

        age.AgeDays.Should().Be(daysOld);
        age.Outdated.Should().Be(expectOutdated, "'older than 180 days' means more than 180, not 180");
    }

    [Fact]
    public void Evaluate_CountsWholeDaysOnly()
    {
        // 181 days less one hour is still 180 whole days: not yet past.
        var commitDate = Now.AddDays(-181).AddHours(1);

        var age = InstalledRelease.Evaluate(commitDate, Now, warningDays: 180);

        age.AgeDays.Should().Be(180);
        age.Outdated.Should().BeFalse();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Evaluate_ZeroOrLessDisablesTheWarningButKeepsTheAge(int warningDays)
    {
        var age = InstalledRelease.Evaluate(Now.AddYears(-3), Now, warningDays);

        age.AgeDays.Should().BeGreaterThan(1000, "the date line stays whatever the threshold is");
        age.Outdated.Should().BeFalse("0 disables the warning per the decision on #623");
    }

    [Fact]
    public void Evaluate_ClockBehindTheCommit_ReadsAsZeroDays()
    {
        // A server with its date set wrong must not show a negative age.
        var age = InstalledRelease.Evaluate(Now.AddDays(3), Now, warningDays: 180);

        age.AgeDays.Should().Be(0);
        age.Outdated.Should().BeFalse();
    }

    [Theory]
    [InlineData("2026-10-22T09:00:00Z")]
    [InlineData("2026-10-22T11:00:00+02:00")]
    [InlineData(" 2026-10-22T09:00:00Z ")]
    public void ParseCommitDate_ReadsIso8601AsTheSameInstant(string raw)
    {
        var parsed = InstalledRelease.ParseCommitDate(raw);

        parsed.Should().Be(new DateTimeOffset(2026, 10, 22, 9, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void ParseCommitDate_NoOffset_IsReadAsUtcNotLocalTime()
    {
        // Whatever the server's time zone, the age must not move with it.
        var parsed = InstalledRelease.ParseCommitDate("2026-10-22T09:00:00");

        parsed.Should().Be(new DateTimeOffset(2026, 10, 22, 9, 0, 0, TimeSpan.Zero));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a date")]
    [InlineData("1760000000")]
    public void ParseCommitDate_RefusesWhatItCannotRead(string? raw)
    {
        InstalledRelease.ParseCommitDate(raw).Should().BeNull(
            "a stamp that does not parse drops the age rather than throwing on every Settings visit");
    }

    [Fact]
    public void ReadCommitDate_AssemblyWithoutTheStamp_IsNull()
    {
        // The test assembly is built by a plain dotnet build, which carries no
        // CertusCommitDate, exactly like a build from the source snapshot.
        var assembly = typeof(InstalledReleaseTests).Assembly;
        assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Should().NotContain(a => a.Key == InstalledRelease.CommitDateMetadataKey,
                "this test needs an unstamped assembly to prove the null path");

        InstalledRelease.ReadCommitDate(assembly).Should().BeNull();
    }

    [Fact]
    public void RuntimeVersions_NameBothSharedFrameworks()
    {
        // Runtime patches arrive through Windows Update, not the installer, so
        // the page names what the process actually runs on.
        InstalledRelease.RuntimeVersion().Should().StartWith(".NET ");
        InstalledRelease.AspNetCoreVersion().Should().MatchRegex(@"^\d+\.\d+",
            "the ASP.NET Core version is shown as a plain version, the build metadata split off");
        InstalledRelease.AspNetCoreVersion().Should().NotContain("+");
    }

    [Fact]
    public void ReleaseAgeOptions_DefaultsTo180Days()
    {
        var options = Bind(new Dictionary<string, string?>());

        options.ReleaseAgeWarningDays.Should().Be(180);
        options.EffectiveWarningDays.Should().Be(180);
    }

    [Theory]
    [InlineData("30", 30)]
    [InlineData("0", 0)]
    [InlineData("-5", 0)]
    public void ReleaseAgeOptions_BindsCertusReleaseAgeWarningDays(string configured, int effective)
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["Certus:ReleaseAgeWarningDays"] = configured,
        });

        options.EffectiveWarningDays.Should().Be(effective,
            "0 disables and a negative value can only mean the same");
    }

    /// <summary>
    /// Binds the way both hosts do: from the "Certus" section, beside
    /// CertusOptions, so the key is Certus:ReleaseAgeWarningDays.
    /// </summary>
    private static ReleaseAgeOptions Bind(Dictionary<string, string?> values)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var options = new ReleaseAgeOptions();
        configuration.GetSection("Certus").Bind(options);
        return options;
    }
}
