using System.Security.AccessControl;
using System.Security.Principal;
using Certus.Core.Security;

namespace Certus.Core.Tests.Security;

/// <summary>
/// The folder the service creates for its data, when the installer has not already
/// (issue #489): protected, and writable by SYSTEM, Administrators and the process
/// identity only.
/// </summary>
public class ProtectedFolderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-folder-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void ANewFolder_InheritsNothing_AndAdmitsOnlyTheTrustedIdentities()
    {
        var path = Path.Combine(_root, "data");

        ProtectedFolder.EnsureExists(path);

        var security = new DirectoryInfo(path).GetAccessControl();
        security.AreAccessRulesProtected.Should().BeTrue();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToList();
        rules.Should().OnlyContain(r =>
            !r.IsInherited
            && r.AccessControlType == AccessControlType.Allow
            && r.FileSystemRights == FileSystemRights.FullControl
            && r.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit));
        rules.Select(r => r.IdentityReference.Value).Should().BeEquivalentTo(TrustedIdentities.Sids.Select(s => s.Value));
    }

    [Fact]
    public void AFileWrittenInIt_IsTrusted()
    {
        var path = Path.Combine(_root, "data");
        ProtectedFolder.EnsureExists(path);
        var file = Path.Combine(path, "settings.json");

        File.WriteAllText(file, "{}");

        TrustedFile.Check(file).IsTrusted.Should().BeTrue();
    }

    [Fact]
    public void AnExistingFolder_IsLeftAsItIs()
    {
        var path = Path.Combine(_root, "data");
        Directory.CreateDirectory(path);

        ProtectedFolder.EnsureExists(path);

        new DirectoryInfo(path).GetAccessControl().AreAccessRulesProtected.Should().BeFalse();
    }

    [Fact]
    public void MissingParents_AreCreatedPlainly_AndOnlyTheLeafIsProtected()
    {
        var path = Path.Combine(_root, "a", "b");

        ProtectedFolder.EnsureExists(path);

        new DirectoryInfo(path).GetAccessControl().AreAccessRulesProtected.Should().BeTrue();
        new DirectoryInfo(Path.Combine(_root, "a")).GetAccessControl().AreAccessRulesProtected.Should().BeFalse();
    }

    // ── EnsureProtected repairs an upgraded install (issue #489) ──

    [Fact]
    public void EnsureProtected_CreatesTheFolder_WhenAbsent()
    {
        var path = Path.Combine(_root, "data");

        ProtectedFolder.EnsureProtected(path);

        new DirectoryInfo(path).GetAccessControl().AreAccessRulesProtected.Should().BeTrue();
    }

    [Fact]
    public void EnsureProtected_RepairsAWidenedFolder_AndRePropagatesToStaleChildren()
    {
        // The upgrade case: a folder first created under a permissive parent, with files and
        // a subfolder already inside it inheriting that width. The headline settings.json
        // sits in the root; logs is the subfolder that kept Users write on the real lab.
        var data = Path.Combine(_root, "data");
        Directory.CreateDirectory(data);
        WidenToEveryone(data);

        var settings = Path.Combine(data, "settings.json");
        File.WriteAllText(settings, "{}");
        var logs = Path.Combine(data, "logs");
        Directory.CreateDirectory(logs);
        // The children inherited the wide entry when they were created.
        FileAcl.EveryoneCanWrite(settings).Should().BeTrue("the fixture must start exposed");
        EveryoneCanWrite(logs).Should().BeTrue("the fixture must start exposed");

        ProtectedFolder.EnsureProtected(data);

        new DirectoryInfo(data).GetAccessControl().AreAccessRulesProtected.Should().BeTrue();
        FileAcl.EveryoneCanWrite(settings).Should().BeFalse("re-propagation replaced the child's inherited entries");
        EveryoneCanWrite(logs).Should().BeFalse();
    }

    [Fact]
    public void EnsureProtected_RePropagatesToAGrandchild_TheRealLabArtifact()
    {
        // The files that mattered on the lab were grandchildren: a log file inside logs,
        // the keyring XML inside keys. The parent repair must reach them, not just the
        // immediate children. OS auto inheritance is recursive, so this holds; the test
        // pins it, because the other repair test only reaches one level down.
        var data = Path.Combine(_root, "data");
        Directory.CreateDirectory(data);
        WidenToEveryone(data);
        var logs = Path.Combine(data, "logs");
        Directory.CreateDirectory(logs);
        var logFile = Path.Combine(logs, "ducks-20261003.log");
        File.WriteAllText(logFile, "x");
        FileAcl.EveryoneCanWrite(logFile).Should().BeTrue("the fixture grandchild must start exposed");

        ProtectedFolder.EnsureProtected(data);

        FileAcl.EveryoneCanWrite(logFile).Should().BeFalse("the repair reaches a file two levels down");
    }

    [Fact]
    public void EnsureProtected_IsIdempotent_OnAnAlreadyProtectedFolder()
    {
        var data = Path.Combine(_root, "data");
        ProtectedFolder.EnsureProtected(data);

        ProtectedFolder.EnsureProtected(data);

        // Still protected, still exactly the trusted identities and no one else.
        var security = new DirectoryInfo(data).GetAccessControl();
        security.AreAccessRulesProtected.Should().BeTrue();
        security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().Select(r => r.IdentityReference.Value)
            .Should().BeEquivalentTo(TrustedIdentities.Sids.Select(s => s.Value));
    }

    [Fact]
    public void EnsureProtected_LeavesAChildWithItsOwnProtectedDacl_Alone()
    {
        // Inheritance does not cross a protected boundary, so a child that protects itself
        // keeps its own grant. keys, were it ever locked separately, is the case in mind.
        var data = Path.Combine(_root, "data");
        Directory.CreateDirectory(data);
        WidenToEveryone(data);
        var child = Path.Combine(data, "own");
        Directory.CreateDirectory(child);
        WidenToEveryone(child, protect: true);

        ProtectedFolder.EnsureProtected(data);

        EveryoneCanWrite(child).Should().BeTrue("a protected child does not inherit the repaired parent");
    }

    private static void WidenToEveryone(string dir, bool protect = false)
    {
        var info = new DirectoryInfo(dir);
        var security = info.GetAccessControl();
        if (protect)
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: true);
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        info.SetAccessControl(security);
    }

    private static bool EveryoneCanWrite(string dir) =>
        new DirectoryInfo(dir).GetAccessControl()
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Any(r => r.IdentityReference.Value == FileAcl.EveryoneSid
                      && r.AccessControlType == AccessControlType.Allow
                      && (r.FileSystemRights & FileSystemRights.WriteData) != 0);
}
