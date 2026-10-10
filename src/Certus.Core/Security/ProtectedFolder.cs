using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Certus.Core.Security;

/// <summary>
/// Creates the folders the service keeps its configuration and data in, so that only the
/// service and administrators can write them (issue #489).
///
/// <para>The default parent, %ProgramData%, lets every local user create files and folders
/// in it, and gives each creator full control of what they create (CREATOR OWNER). A folder
/// that simply inherits that lets a standard user plant a file the service later reads or
/// writes as LocalSystem. So a folder created here gets a protected DACL: it inherits
/// nothing from its parent, and grants full control to SYSTEM, to the Administrators group
/// and to the identity this process runs as, and to no one else. The installer applies the
/// same DACL to the data folder (installer/Certus.wxs), so the result does not depend on
/// which of the two creates it first. In production the process identity is SYSTEM, so
/// the two are identical; it is there so a development host or a test, which runs as a
/// developer, keeps access to the folder it created.</para>
///
/// <para><see cref="EnsureExists"/> leaves an existing folder as it is, for a folder whose
/// permissions are not ours to decide. <see cref="EnsureProtected"/> is for the data folder
/// itself: it repairs an existing one, because an upgrade of a server first installed by a
/// version before this fix inherits that version's permissive folder, and the children it
/// already holds keep their stale entries until something re-propagates.</para>
/// </summary>
public static class ProtectedFolder
{
    /// <summary>Creates <paramref name="path"/> with the protected DACL, unless it already exists.</summary>
    public static void EnsureExists(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        if (Directory.Exists(fullPath))
            return;

        // The parents are created plainly: the protection that matters is on the folder
        // that holds the files.
        var parent = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(parent))
            Directory.CreateDirectory(parent);

        if (OperatingSystem.IsWindows())
            CreateProtected(fullPath);
        else
            Directory.CreateDirectory(fullPath);
    }

    /// <summary>
    /// Creates <paramref name="path"/> with the protected DACL, or, when it already exists,
    /// applies that DACL to it. The data folder calls this, and nothing else should: on an
    /// upgrade from a version before issue #489, the folder was created under
    /// %ProgramData%'s permissive default, and the installer's own DACL reaches only the
    /// folder, not the files and subfolders it already holds (their inherited entries were
    /// baked in when the folder was open). Re-applying the DACL with inheritance reset
    /// re-propagates it to every child that is not itself protected, which replaces those
    /// stale entries. On a fresh install this is a no-op: the folder already carries exactly
    /// this DACL.
    ///
    /// <para>This deliberately overrides any wider grant an administrator may have added to
    /// the data folder. The folder holds the dashboard's admin group and the ACME policy, so
    /// it is the one folder whose permissions the service does decide. A child with its own
    /// protected DACL is left alone, because inheritance does not cross a protected boundary.</para>
    /// </summary>
    public static void EnsureProtected(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);

        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(fullPath);
            return;
        }

        if (!Directory.Exists(fullPath))
        {
            EnsureExists(fullPath);
            return;
        }

        // SetAccessControl with the protected flag resets inheritance on the folder and
        // propagates its inheritable entries down, so an existing child's inherited entries
        // are recomputed from this DACL rather than kept from the folder's former state.
        new DirectoryInfo(fullPath).SetAccessControl(ProtectedSecurity());
    }

    [SupportedOSPlatform("windows")]
    private static void CreateProtected(string path) =>
        ProtectedSecurity().CreateDirectory(path);

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity ProtectedSecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in TrustedIdentities.Sids)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        return security;
    }
}

/// <summary>
/// The identities the service trusts with its configuration files: SYSTEM, the
/// Administrators group, and the identity this process runs as. In production that last
/// one is SYSTEM again; under a development host or a test it is the developer, who owns
/// the folders and files the run creates.
/// </summary>
[SupportedOSPlatform("windows")]
public static class TrustedIdentities
{
    private static readonly Lazy<IReadOnlyList<SecurityIdentifier>> All = new(Build);

    /// <summary>The trusted SIDs, without duplicates.</summary>
    public static IReadOnlyList<SecurityIdentifier> Sids => All.Value;

    private static IReadOnlyList<SecurityIdentifier> Build()
    {
        var sids = new List<SecurityIdentifier>
        {
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
        };
        using var current = WindowsIdentity.GetCurrent();
        if (current.User is { } user && !sids.Contains(user))
            sids.Add(user);
        return sids;
    }
}
