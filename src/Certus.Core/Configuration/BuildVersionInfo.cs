namespace Certus.Core.Configuration;

/// <summary>
/// Splits an AssemblyInformationalVersion into its release version and its
/// commit stamp (issue #112).
///
/// build.ps1 passes the commit to the compiler as SourceRevisionId, and the
/// SDK appends it to AssemblyInformationalVersion as SemVer 2.0 build
/// metadata, giving "0.10.0-beta.1+&lt;sha&gt;". The dashboard wants those two
/// halves apart: the Settings page shows a clean release version, with the
/// commit as its own field for support triage.
///
/// Do not assume the stamp is a bare 40 character sha. build.ps1 appends
/// ".dirty" when it builds from a dirty working tree, which is the normal
/// state of a developer build, so the stamp is treated as opaque here.
///
/// The stamp is optional on purpose. A build from the release source snapshot
/// has no .git to resolve a commit from, so the value arrives with no "+" at
/// all and Commit is null. That is a supported build, not a defect, which is
/// why this is a pure function that never throws and never demands a stamp.
/// </summary>
public static class BuildVersionInfo
{
    /// <summary>
    /// Splits <paramref name="informationalVersion"/> at the first "+".
    /// Returns the whole string as Version and a null Commit when there is no
    /// build metadata. Empty or whitespace input yields an empty Version and a
    /// null Commit, leaving the caller's own fallback in charge.
    /// </summary>
    public static (string Version, string? Commit) Split(string? informationalVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalVersion))
        {
            return (string.Empty, null);
        }

        var trimmed = informationalVersion.Trim();

        // First "+" only. SemVer allows dots inside build metadata, and the SDK
        // itself appends with a "." when the version already carries a "+", so
        // everything past the first separator is one opaque stamp.
        var separator = trimmed.IndexOf('+');
        if (separator < 0)
        {
            return (trimmed, null);
        }

        var version = trimmed[..separator];
        var commit = trimmed[(separator + 1)..];

        return (version, string.IsNullOrWhiteSpace(commit) ? null : commit);
    }
}
