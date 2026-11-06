using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using Certus.Core.Configuration;

namespace Certus.Web.Controllers.Settings;

/// <summary>
/// What the Settings About block can say about the installed release without
/// contacting anyone (issue #623). Ducks in a Row never contacts the internet,
/// so it cannot learn whether a newer release exists; what it can do is read
/// the date of the commit it was built from, say how old that is, and warn
/// when the age passes a threshold. Every function here is pure and reads only
/// the process' own assemblies and the clock it is handed.
///
/// The date comes from an <see cref="AssemblyMetadataAttribute"/> with the key
/// <see cref="CommitDateMetadataKey"/>. build.ps1 resolves the committer date
/// of the commit it stamps as the sha (issue #112) and passes it to the
/// compiler as /p:CertusCommitDate; Directory.Build.props turns that into the
/// attribute on every assembly. It is the commit's date, never the build
/// machine's clock, so two builds of one commit carry the same value and the
/// binaries stay identical for the SBOM (issue #396).
///
/// The stamp is optional for the same reason the sha is: a plain dotnet build
/// and a build from the release source snapshot carry none. Without a date
/// there is no age, and without an age there is no warning; the page shows
/// the rows it can and hides the rest.
/// </summary>
public static class InstalledRelease
{
    /// <summary>The AssemblyMetadata key Directory.Build.props writes the commit date under.</summary>
    public const string CommitDateMetadataKey = "CommitDate";

    /// <summary>
    /// The outcome of <see cref="Evaluate"/>: how old the release is in whole
    /// days (null without a stamp), and whether that age passed the threshold.
    /// </summary>
    public readonly record struct ReleaseAge(int? AgeDays, bool Outdated);

    /// <summary>
    /// Reads the commit date stamped on <paramref name="assembly"/>, or null
    /// when the build carried none or the value does not parse. Never throws:
    /// the stamp is best effort and the page copes with its absence.
    /// </summary>
    public static DateTimeOffset? ReadCommitDate(Assembly assembly)
    {
        var raw = assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => string.Equals(a.Key, CommitDateMetadataKey, StringComparison.Ordinal))?
            .Value;

        return ParseCommitDate(raw);
    }

    /// <summary>
    /// Parses the stamped value. build.ps1 writes an ISO 8601 instant in UTC
    /// ("2026-10-22T09:30:00Z"), but any round trippable ISO 8601 value with an
    /// offset is accepted, and one with no offset is read as UTC rather than
    /// as the server's local time, so the age never moves with the time zone.
    /// </summary>
    public static DateTimeOffset? ParseCommitDate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return DateTimeOffset.TryParse(
            raw.Trim(),
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AllowWhiteSpaces,
            out var parsed)
            ? parsed
            : null;
    }

    /// <summary>
    /// How old the release is at <paramref name="now"/>, and whether that is
    /// past <paramref name="warningDays"/>. The age is whole days, never
    /// negative: a clock behind the commit (a server with a wrong date, or a
    /// build stamped from a commit made minutes ago in another time zone)
    /// reads as 0 days rather than as a negative number. The warning fires
    /// when the age exceeds the threshold, so 180 days old with a threshold of
    /// 180 is not yet "older than"; a threshold of 0 or less disables it.
    /// </summary>
    public static ReleaseAge Evaluate(DateTimeOffset? commitDate, DateTimeOffset now, int warningDays)
    {
        if (commitDate is null)
        {
            return new ReleaseAge(null, false);
        }

        var days = (int)Math.Floor((now - commitDate.Value).TotalDays);
        if (days < 0)
        {
            days = 0;
        }

        var outdated = warningDays > 0 && days > warningDays;
        return new ReleaseAge(days, outdated);
    }

    /// <summary>
    /// The .NET runtime the process runs on, as the runtime describes itself
    /// (".NET 10.0.1"). Patches to it arrive through Windows Update, not through
    /// the installer, which is why the page shows it beside the release.
    /// </summary>
    public static string RuntimeVersion() => RuntimeInformation.FrameworkDescription;

    /// <summary>
    /// The ASP.NET Core shared framework version, read off the assembly that
    /// defines WebApplication. Its informational version carries the same
    /// "+sha" build metadata our own does, and the same split takes it off.
    /// Falls back to the assembly version when the attribute is missing.
    /// </summary>
    public static string AspNetCoreVersion()
    {
        var assembly = typeof(WebApplication).Assembly;
        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        var (version, _) = BuildVersionInfo.Split(informational);
        if (!string.IsNullOrEmpty(version))
        {
            return version;
        }

        return assembly.GetName().Version?.ToString() ?? "unknown";
    }
}
