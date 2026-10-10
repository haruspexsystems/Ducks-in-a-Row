using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Certus.Core.Security;

/// <summary>
/// Decides whether the service may believe a configuration file it reads (issue #489). A
/// file is trusted when its owner is one of <see cref="TrustedIdentities"/> and its DACL
/// grants write access to no one else. The service treats an untrusted settings.json or
/// ducks-setup.json as absent and logs why.
///
/// <para>The owner check is the one that matters for a box attacked before the upgrade
/// that protects its data folder: a file a standard user planted stays theirs after the
/// folder's DACL changes, and an owner may always rewrite its own file's DACL. The write
/// check catches a file whose own entries let someone else in.</para>
///
/// <para>The rule is deliberately stricter than effective access. Every allow entry that
/// applies to the file counts, deny entries are never credited, and an entry the check
/// cannot read is untrusted, so a verdict never depends on evaluating ACE order or a
/// condition correctly.</para>
/// </summary>
public static class TrustedFile
{
    // Any right that changes the file's content, its attributes, its descriptor, or
    // whether it exists. GENERIC_READ is the sign bit and is not among them.
    private const int WriteRights =
        0x00000002 | // FILE_WRITE_DATA
        0x00000004 | // FILE_APPEND_DATA
        0x00000010 | // FILE_WRITE_EA
        0x00000100 | // FILE_WRITE_ATTRIBUTES
        0x00010000 | // DELETE
        0x00040000 | // WRITE_DAC
        0x00080000 | // WRITE_OWNER
        0x02000000 | // MAXIMUM_ALLOWED
        0x10000000 | // GENERIC_ALL
        0x40000000;  // GENERIC_WRITE

    /// <summary>
    /// The verdict for the file at <paramref name="path"/>. A missing file is trusted,
    /// since there is nothing in it to believe. Off Windows there are no ACLs to read, and
    /// the service runs only on Windows, so every file is trusted there.
    /// </summary>
    public static FileTrust Check(string path)
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(path))
            return FileTrust.Trusted;

        return CheckOnWindows(path);
    }

    [SupportedOSPlatform("windows")]
    private static FileTrust CheckOnWindows(string path)
    {
        RawSecurityDescriptor descriptor;
        try
        {
            var security = new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A file whose permissions cannot be read cannot be shown to be safe.
            return FileTrust.Untrusted($"its permissions could not be read ({ex.Message})");
        }

        return Evaluate(descriptor, TrustedIdentities.Sids);
    }

    /// <summary>The rule itself, over a descriptor, so it can be tested without a file.</summary>
    [SupportedOSPlatform("windows")]
    public static FileTrust Evaluate(RawSecurityDescriptor descriptor, IReadOnlyCollection<SecurityIdentifier> trusted)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(trusted);

        if (descriptor.Owner is not { } owner || !trusted.Contains(owner))
            return FileTrust.Untrusted($"it is owned by {NameOf(descriptor.Owner)}");

        if (descriptor.DiscretionaryAcl is not { } dacl)
            return FileTrust.Untrusted("it has no access control list, so anyone may write it");

        foreach (var ace in dacl)
        {
            if (ace is not QualifiedAce entry)
                return FileTrust.Untrusted("it carries an access control entry this check cannot read");

            // An inherit only entry is a template for children and does not apply here.
            if ((entry.AceFlags & AceFlags.InheritOnly) != 0 || entry.AceQualifier == AceQualifier.AccessDenied)
                continue;

            if (entry.AceQualifier != AceQualifier.AccessAllowed)
                return FileTrust.Untrusted("it carries an access control entry this check cannot read");

            // A conditional (callback) entry counts as if its condition always held.
            if ((entry.AccessMask & WriteRights) != 0 && !trusted.Contains(entry.SecurityIdentifier))
                return FileTrust.Untrusted($"it grants write access to {NameOf(entry.SecurityIdentifier)}");
        }

        return FileTrust.Trusted;
    }

    [SupportedOSPlatform("windows")]
    private static string NameOf(SecurityIdentifier? sid)
    {
        if (sid is null)
            return "no one";
        try
        {
            return $"{sid.Translate(typeof(NTAccount)).Value} ({sid.Value})";
        }
        catch (SystemException)
        {
            // Unmapped, or no domain controller to ask (the same two failures
            // StartupValidator.CanResolveGroup tolerates). The SID still names it.
            return sid.Value;
        }
    }
}

/// <summary>What <see cref="TrustedFile"/> decided, and why when the answer is no.</summary>
public sealed record FileTrust(bool IsTrusted, string? Reason)
{
    public static FileTrust Trusted { get; } = new(true, null);

    public static FileTrust Untrusted(string reason) => new(false, reason);
}
