using System.Security.AccessControl;
using System.Security.Principal;

namespace Certus.Core.Tests.Security;

/// <summary>
/// Puts a file into a state the service must not trust (issue #489). A test cannot make
/// another account own a file, which needs a privilege it does not hold, so it uses the
/// other half of the rule: an entry that lets someone else write.
/// </summary>
internal static class FileAcl
{
    /// <summary>The well known SID of Everyone, stable across display languages.</summary>
    public const string EveryoneSid = "S-1-1-0";

    public static void GrantEveryoneWrite(string path)
    {
        var file = new FileInfo(path);
        var security = file.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Write,
            AccessControlType.Allow));
        file.SetAccessControl(security);
    }

    /// <summary>Whether any entry on the file lets Everyone write it.</summary>
    public static bool EveryoneCanWrite(string path) =>
        new FileInfo(path).GetAccessControl()
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Any(r => r.IdentityReference.Value == EveryoneSid
                      && r.AccessControlType == AccessControlType.Allow
                      && (r.FileSystemRights & FileSystemRights.WriteData) != 0);
}
