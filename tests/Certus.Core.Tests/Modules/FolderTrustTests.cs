using System.Security.AccessControl;
using System.Security.Principal;
using Certus.Core.Modules;
using Certus.Core.Security;
using Certus.Core.Tests.Security;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The module folder trust gate (licence design section 6.3, issue #413). The rule over one
/// descriptor is TrustedFile.Evaluate (issue #489); these tests cover what the gate adds around
/// it: the owner set, the reparse refusal, and the chain. The data path check (issue #523) is the
/// same rule against the data folder's owners, so it gets the owner case the #523 review described.
/// </summary>
public class FolderTrustTests : IDisposable
{
    // A standard user, as an SDDL owner: a test cannot make another account own a real folder.
    private const string AttackerSid = "S-1-5-21-1-2-3-1003";

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-foldertrust-{Guid.NewGuid():N}");

    public FolderTrustTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public void TheTrustedOwners_AreSystemAdministratorsAndTrustedInstaller_NotTheProcessIdentity()
    {
        var sids = ModuleFolderOwners.Sids.Select(s => s.Value).ToList();

        sids.Should().Contain(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value);
        sids.Should().Contain(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value);
        sids.Should().Contain("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

        using var me = WindowsIdentity.GetCurrent();
        sids.Should().NotContain(me.User!.Value, "the install tree is not the process identity's to own");
    }

    [Fact]
    public void AFolderThisAccountOwns_IsRefused_BecauseTheOwnerIsNotTrustedForAModuleTree()
    {
        // A temp folder is never a trusted module tree: run non-elevated it is owned by the account
        // (not a trusted owner), and run elevated it is owned by Administrators (trusted) but its
        // inherited DACL grants that account write. Either way the verdict is untrusted; the reason
        // text differs between the two, so it is not asserted (the owner arm itself is covered by
        // the SDDL fixtures in TrustedFileTests).
        var verdict = FolderTrust.CheckModulePath(_root);

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void ProgramFiles_IsTrusted_TheRealPositiveControl()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        Directory.Exists(programFiles).Should().BeTrue();

        FolderTrust.CheckModulePath(programFiles).IsTrusted.Should().BeTrue(
            "a default Program Files is owned by TrustedInstaller and grants Users only read and execute");
    }

    [Fact]
    public void AReparsePoint_IsRefused()
    {
        var target = Path.Combine(_root, "target");
        Directory.CreateDirectory(target);
        var link = Path.Combine(_root, "link");
        ReparsePoints.TryCreateJunction(link, target).Should().BeTrue("the test needs a junction to check");

        var verdict = FolderTrust.CheckModulePath(link);

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().Contain("reparse point");
    }

    [Fact]
    public void CheckModule_Throws_WhenTheModuleIsNotInsideTheInstallFolder()
    {
        var install = Path.Combine(_root, "install");
        var elsewhere = Path.Combine(_root, "elsewhere", "mod");
        Directory.CreateDirectory(install);
        Directory.CreateDirectory(elsewhere);

        var act = () => FolderTrust.CheckModule(install, elsewhere);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void CheckModule_RefusesTheChain_WhenAFolderInItIsNotTrusted()
    {
        // The whole chain is under the account owned temp root, so the install folder is the
        // first untrusted link, and its reason is the one returned.
        var install = Path.Combine(_root, "install");
        var module = Path.Combine(install, "modules", "paid");
        Directory.CreateDirectory(module);

        var verdict = FolderTrust.CheckModule(install, module);

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void AFolderPlantedBeforeTheDataFolderWasProtected_IsRefused_ThoughItsDaclIsTheProtectedOne()
    {
        // The #523 comment's case. A standard user created the modules folder while the data folder
        // was still open (before #489). EnsureProtected later reset the DACL beneath it, but a DACL
        // reset leaves ownership alone, so the user still owns the folder and may change it at will.
        // The data path rule is TrustedFile.Evaluate against TrustedIdentities, so the owner decides.
        var planted = new RawSecurityDescriptor($"O:{AttackerSid}D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");

        var verdict = TrustedFile.Evaluate(planted, TrustedIdentities.Sids);

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().Contain("owned by").And.Contain(AttackerSid);
    }

    [Fact]
    public void TheInstallersProgramFolderDescriptors_AreTrustedForAModuleTree()
    {
        // Issue #495: the MSI creates the modules folder, and the gate walks every link from the
        // install folder down to a module, so both descriptors the MSI writes must pass the
        // module owner rule. The modules folder carries the install folder's SDDL explicitly
        // rather than inheriting it, so a folder that was already there is re-locked too.
        var install = InstallerSource.FolderSddl("InstallFolderPermissions");
        var modules = InstallerSource.FolderSddl("ModulesDirectory");

        modules.Should().Be(install, "the modules folder carries exactly the install folder's DACL and owner");
        TrustedFile.Evaluate(new RawSecurityDescriptor(install), ModuleFolderOwners.Sids).IsTrusted.Should().BeTrue();
        TrustedFile.Evaluate(new RawSecurityDescriptor(modules), ModuleFolderOwners.Sids).IsTrusted.Should().BeTrue();

        // The control: the same descriptor with Users given write is refused, so a pass above
        // is the rule judging this SDDL rather than a rule that passes anything.
        var writable = modules.Replace("(A;OICI;0x1200a9;;;BU)", "(A;OICI;0x1201bf;;;BU)", StringComparison.Ordinal);
        writable.Should().NotBe(modules);
        TrustedFile.Evaluate(new RawSecurityDescriptor(writable), ModuleFolderOwners.Sids).IsTrusted.Should().BeFalse();
    }

    [Fact]
    public void CheckDataPath_TrustsAFolderTheServiceCreated_AndNotOneAnotherAccountCanWrite()
    {
        var folder = Path.Combine(_root, "data", "modules");
        ProtectedFolder.EnsureExists(folder);

        FolderTrust.CheckDataPath(folder).IsTrusted.Should().BeTrue("the service's own protected folder is the positive control");

        FileAcl.GrantEveryoneWriteToFolder(folder);

        var verdict = FolderTrust.CheckDataPath(folder);
        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().Contain("write");
    }
}
