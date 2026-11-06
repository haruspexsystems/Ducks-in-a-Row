using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Certus.Core.Security;

namespace Certus.Core.Modules;

/// <summary>
/// Decides whether the service may load a module from a folder, by licence design section 6.3
/// (issue #413). A module's code runs in process, so the folder it loads from, every folder above
/// it up to the install folder, and every file in its tree, at any depth, must be writable only by
/// SYSTEM, the Administrators group or TrustedInstaller. Anyone else who can write any link could
/// replace the module assembly, a satellite or resource assembly the runtime loads from a culture
/// subfolder, or a native dependency under runtimes\, with their own.
///
/// <para>The rule over one descriptor is <see cref="TrustedFile.Evaluate"/> (issue #489), given a
/// set of trusted owners: for a module tree that set adds TrustedInstaller, which owns a default
/// install under Program Files and which the data folder's files never are. That reuse is the
/// collapse the plan's FolderTrustEvaluator folded into, one rule over a descriptor rather than
/// two. <see cref="EvaluateLink"/> is shared with <see cref="CheckDataPath"/>, which passes the
/// narrower <see cref="TrustedIdentities"/> for what the service keeps under its data directory.</para>
///
/// <para>The module gate is Windows only, and off Windows it fails closed, no modules, because the
/// service runs only on Windows and the platform analyser CA1416 is an error here. A folder or
/// file that cannot be read, by any failure, is treated as untrusted rather than thrown out of, so
/// an unreadable link cannot abort the loading of other modules.</para>
/// </summary>
public static class FolderTrust
{
    /// <summary>
    /// The verdict for a module at <paramref name="moduleFolder"/>: that folder, every folder above
    /// it up to and including <paramref name="installFolder"/>, and every file and subfolder in its
    /// tree at any depth. The first link that is not trusted decides, so its reason is the one
    /// returned. A reparse point anywhere is refused and never followed, so the walk cannot cycle.
    /// </summary>
    public static FileTrust CheckModule(string installFolder, string moduleFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(moduleFolder);

        if (!OperatingSystem.IsWindows())
            return FileTrust.Untrusted("modules load only on Windows");

        var install = Path.GetFullPath(installFolder);
        var module = Path.GetFullPath(moduleFolder);
        if (!IsAtOrUnder(install, module))
            throw new ArgumentException($"'{moduleFolder}' is not inside '{installFolder}'.", nameof(moduleFolder));

        return CheckModuleOnWindows(install, module);
    }

    /// <summary>
    /// The verdict for one folder or file against the module owner set, with no chain above it and
    /// no descent below it. It evaluates against SYSTEM, Administrators and TrustedInstaller, the
    /// owners a module tree may have, so it is for module paths only. A path under the data
    /// directory is checked by <see cref="CheckDataPath"/> instead.
    /// </summary>
    public static FileTrust CheckModulePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!OperatingSystem.IsWindows())
            return FileTrust.Untrusted("modules load only on Windows");

        return EvaluateLink(Path.GetFullPath(path), ModuleFolderOwners.Sids);
    }

    /// <summary>
    /// The verdict for one folder or file the module host keeps under the data directory (licence
    /// design sections 12.3 and 12.7, issue #523): the licence folder, the modules folder, a
    /// module's state folder, and the load journal. Each is checked as one link, against
    /// <see cref="TrustedIdentities"/>, the owners the data folder's own files may have, which
    /// include the process identity. A reparse point is refused, and so is a path that does not
    /// exist, so a caller for which absence means "nothing to believe" asks about that first. Off
    /// Windows there are no ACLs to read, and the service runs only on Windows, so every path is
    /// trusted there, the stance of <see cref="TrustedFile.Check"/>.
    /// </summary>
    public static FileTrust CheckDataPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!OperatingSystem.IsWindows())
            return FileTrust.Trusted;

        return EvaluateLink(Path.GetFullPath(path), TrustedIdentities.Sids);
    }

    [SupportedOSPlatform("windows")]
    private static FileTrust CheckModuleOnWindows(string install, string module)
    {
        try
        {
            foreach (var link in ChainTopDown(install, module))
            {
                var verdict = EvaluateLink(link, ModuleFolderOwners.Sids);
                if (!verdict.IsTrusted)
                    return verdict;
            }

            return Directory.Exists(module) ? CheckContents(module) : FileTrust.Trusted;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Fail closed: an enumeration or descriptor read that fails is treated as untrusted, so
            // it cannot throw out of a loop that was loading other modules.
            return FileTrust.Untrusted($"a module folder could not be read ({ex.Message})");
        }
    }

    [SupportedOSPlatform("windows")]
    private static FileTrust CheckContents(string folder)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(folder))
        {
            var verdict = EvaluateLink(entry, ModuleFolderOwners.Sids);
            if (!verdict.IsTrusted)
                return verdict;

            // A trusted directory that is not a reparse point: descend. EvaluateLink has already
            // refused a reparse point, so a junction is never followed and the walk cannot cycle.
            if (Directory.Exists(entry))
            {
                var sub = CheckContents(entry);
                if (!sub.IsTrusted)
                    return sub;
            }
        }

        return FileTrust.Trusted;
    }

    /// <summary>
    /// The rule for one link: refuse a reparse point, refuse a descriptor that cannot be read, and
    /// otherwise defer to <see cref="TrustedFile.Evaluate"/> against <paramref name="trusted"/>.
    /// Shared so the module gate and the licence store apply the same reparse and descriptor
    /// handling, differing only in the owner set.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static FileTrust EvaluateLink(string path, IReadOnlyCollection<SecurityIdentifier> trusted)
    {
        FileSystemInfo info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
        if (!info.Exists)
            return FileTrust.Untrusted($"'{path}' does not exist");

        // A reparse point is refused: it can point the load, or this very descriptor read, at a
        // target the walk never saw.
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            return FileTrust.Untrusted($"'{path}' is a reparse point");

        RawSecurityDescriptor descriptor;
        try
        {
            FileSystemSecurity security = info is DirectoryInfo directory
                ? directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : ((FileInfo)info).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return FileTrust.Untrusted($"the permissions of '{path}' could not be read ({ex.Message})");
        }

        return TrustedFile.Evaluate(descriptor, trusted);
    }

    private static IEnumerable<string> ChainTopDown(string installFolder, string moduleFolder)
    {
        var chain = new List<string>();
        var installTrimmed = Path.TrimEndingDirectorySeparator(installFolder);
        var current = moduleFolder;
        while (!string.IsNullOrEmpty(current))
        {
            chain.Add(current);
            if (string.Equals(Path.TrimEndingDirectorySeparator(current), installTrimmed, StringComparison.OrdinalIgnoreCase))
                break;
            current = Path.GetDirectoryName(current);
        }

        chain.Reverse();
        return chain;
    }

    internal static bool IsAtOrUnder(string ancestor, string descendant)
    {
        var a = Path.TrimEndingDirectorySeparator(ancestor);
        var d = Path.TrimEndingDirectorySeparator(descendant);
        return string.Equals(a, d, StringComparison.OrdinalIgnoreCase)
            || d.StartsWith(a + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// The owners a module folder chain may have: SYSTEM, BUILTIN\Administrators and TrustedInstaller
/// (licence design section 6.3). Wider than <see cref="TrustedIdentities"/> by TrustedInstaller,
/// which owns a default Program Files tree, and without the process identity, which has no business
/// owning the install tree. Built once, like TrustedIdentities, so a missing domain controller
/// cannot stall it.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ModuleFolderOwners
{
    private const string TrustedInstallerSid =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private static readonly Lazy<IReadOnlyList<SecurityIdentifier>> All = new(Build);

    public static IReadOnlyList<SecurityIdentifier> Sids => All.Value;

    private static IReadOnlyList<SecurityIdentifier> Build() => new List<SecurityIdentifier>
    {
        new(WellKnownSidType.LocalSystemSid, null),
        new(WellKnownSidType.BuiltinAdministratorsSid, null),
        new(TrustedInstallerSid),
    };
}
