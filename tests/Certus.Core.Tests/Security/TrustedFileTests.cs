using System.Security.AccessControl;
using System.Security.Principal;
using Certus.Core.Security;

namespace Certus.Core.Tests.Security;

/// <summary>
/// The trust rule for the service's configuration files (issue #489): owned by SYSTEM, the
/// Administrators group or the process identity, and writable by no one else. The fixtures
/// are security descriptors in SDDL, so each case says exactly what is on the file.
/// </summary>
public class TrustedFileTests : IDisposable
{
    // Stands in for the identity the process runs as, which production makes SYSTEM.
    private const string ProcessSid = "S-1-5-21-1-2-3-1001";
    private const string AttackerSid = "S-1-5-21-1-2-3-1003";

    private static readonly IReadOnlyCollection<SecurityIdentifier> Trusted =
    [
        new(WellKnownSidType.LocalSystemSid, null),
        new(WellKnownSidType.BuiltinAdministratorsSid, null),
        new(ProcessSid),
    ];

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"certus-trust-{Guid.NewGuid():N}");

    public TrustedFileTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Theory]
    // What the protected data folder gives a file the service writes.
    [InlineData("O:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)")]
    [InlineData("O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)")]
    [InlineData("O:" + ProcessSid + "D:(A;;FA;;;" + ProcessSid + ")")]
    // A file the service wrote into the old, unprotected folder: Users may read it, and
    // nothing more. Such a file keeps working after the upgrade.
    [InlineData("O:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)")]
    // A deny entry grants nothing, and is not needed to keep anyone out here.
    [InlineData("O:SYD:(D;;FW;;;BU)(A;;FA;;;SY)(A;;0x1200a9;;;BU)")]
    // An inherit only entry is a template for children and does not apply to the file.
    [InlineData("O:SYD:(A;OICIIO;FA;;;BU)(A;;FA;;;SY)")]
    // An empty DACL lets no one in but the owner.
    [InlineData("O:SYD:")]
    public void Trusted_Cases(string sddl) =>
        Evaluate(sddl).IsTrusted.Should().BeTrue();

    [Fact]
    public void TheHijackedFile_IsNotTrusted_ForItsOwner()
    {
        // The shape the lab run of #489 found: the standard user who pre-created the
        // temporary file owns the service's configuration file afterwards.
        var verdict = Evaluate(
            $"O:{AttackerSid}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{AttackerSid})(A;ID;0x1200a9;;;BU)");

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().Contain("owned by").And.Contain(AttackerSid);
    }

    [Fact]
    public void NoOwner_IsNotTrusted() =>
        Evaluate("D:(A;;FA;;;SY)").Reason.Should().Contain("owned by no one");

    [Theory]
    [InlineData("0x2")]        // FILE_WRITE_DATA
    [InlineData("0x4")]        // FILE_APPEND_DATA
    [InlineData("0x10")]       // FILE_WRITE_EA
    [InlineData("0x100")]      // FILE_WRITE_ATTRIBUTES
    [InlineData("0x10000")]    // DELETE
    [InlineData("0x40000")]    // WRITE_DAC
    [InlineData("0x80000")]    // WRITE_OWNER
    [InlineData("0x2000000")]  // MAXIMUM_ALLOWED
    [InlineData("0x10000000")] // GENERIC_ALL
    [InlineData("0x40000000")] // GENERIC_WRITE
    public void EachWriteRight_GivenToUsers_IsNotTrusted(string mask)
    {
        var verdict = Evaluate($"O:SYD:(A;;FA;;;SY)(A;;{mask};;;BU)");

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().Contain("grants write access to").And.Contain("S-1-5-32-545");
    }

    [Theory]
    [InlineData("WD", "S-1-1-0")]     // Everyone
    [InlineData("AU", "S-1-5-11")]    // Authenticated Users
    [InlineData(AttackerSid, AttackerSid)]
    public void WriteForAnyoneElse_IsNotTrusted(string who, string sid) =>
        Evaluate($"O:SYD:(A;;FA;;;SY)(A;;FW;;;{who})").Reason.Should().Contain(sid);

    [Fact]
    public void AConditionalEntry_CountsAsIfItsConditionHeld()
    {
        // A condition the check cannot evaluate must not be what keeps a writer out.
        var verdict = Evaluate("O:SYD:(A;;FA;;;SY)(XA;;FW;;;BU;(Member_of {SID(BA)}))");

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().Contain("S-1-5-32-545");
    }

    [Fact]
    public void ANullDacl_IsNotTrusted() =>
        Evaluate("O:SYD:NO_ACCESS_CONTROL").Reason.Should().Contain("no access control list");

    [Fact]
    public void OnDisk_AFileThisProcessWrote_IsTrusted()
    {
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, "{}");

        TrustedFile.Check(path).IsTrusted.Should().BeTrue();
    }

    [Fact]
    public void OnDisk_AFileEveryoneCanWrite_IsNotTrusted_AndSaysWhoCan()
    {
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, "{}");
        FileAcl.GrantEveryoneWrite(path);

        var verdict = TrustedFile.Check(path);

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().Contain(FileAcl.EveryoneSid);
    }

    [Fact]
    public void OnDisk_AMissingFile_IsTrusted_SinceThereIsNothingToBelieve() =>
        TrustedFile.Check(Path.Combine(_dir, "absent.json")).IsTrusted.Should().BeTrue();

    private static FileTrust Evaluate(string sddl) =>
        TrustedFile.Evaluate(new RawSecurityDescriptor(sddl), Trusted);
}
