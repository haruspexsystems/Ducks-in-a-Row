using System.Security.AccessControl;
using Certus.Adcs.ServiceRights;
using Certus.Core.ServiceRights;

namespace Certus.Core.Tests.ServiceRights;

/// <summary>
/// The pure half of the directory reader, issue #440: turning a template's
/// stored security descriptor into the entries the Enroll test walks. The
/// directory calls themselves need a domain and are proved on the lab, the
/// same stance as <c>AdPrincipalLookup</c>. The descriptors here are written
/// in SDDL, the form a lab read back prints, so a lab fixture drops straight in.
/// </summary>
public class DirectoryRightsReaderTests
{
    private const string Account = "S-1-5-21-1004336348-1177238915-682003330-1105";
    private const string EnrollGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
    private const string AutoenrollGuid = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";

    // Domain relative aliases such as DA and EA only translate on a domain member,
    // and these tests run anywhere, so the administrators are written as SIDs.
    private const string DomainAdmins = "S-1-5-21-1004336348-1177238915-682003330-512";
    private const string EnterpriseAdmins = "S-1-5-21-1004336348-1177238915-682003330-519";

    private static IReadOnlyList<AclEntry> Parse(string sddl, out string accessListSddl)
    {
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return DirectoryRightsReader.ToAclEntries(bytes, out accessListSddl);
    }

    private static IReadOnlyList<AclEntry> Parse(string sddl) => Parse(sddl, out _);

    private static EnrollVerdict EnrollFor(string sddl) =>
        TemplateEnrollEvaluator.Evaluate(
            Parse(sddl),
            TemplateEnrollEvaluator.SidsForNetworkLogon(Account, []),
            TemplateEnrollEvaluator.EnrollRight).Verdict;

    [Fact]
    public void ObjectEntries_KeepTheirKindRightTrusteeAndOrder()
    {
        var entries = Parse($"O:BAG:BAD:(OD;;CR;{EnrollGuid};;{Account})(OA;;CR;{EnrollGuid};;AU)");

        entries.Should().HaveCount(2);
        entries[0].Should().Be(new AclEntry(
            AclEntryKind.Deny, TemplateEnrollEvaluator.ControlAccess,
            TemplateEnrollEvaluator.EnrollRight, false, false, Account));
        entries[1].Should().Be(new AclEntry(
            AclEntryKind.Allow, TemplateEnrollEvaluator.ControlAccess,
            TemplateEnrollEvaluator.EnrollRight, false, false, TemplateEnrollEvaluator.AuthenticatedUsersSid));
    }

    [Fact]
    public void APlainEntry_HasNoObjectType()
    {
        var entries = Parse($"O:BAG:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{DomainAdmins})");

        entries.Should().ContainSingle().Which.ObjectType.Should().BeNull();
        entries[0].Kind.Should().Be(AclEntryKind.Allow);
    }

    [Fact]
    public void TheInheritedAndInheritOnlyFlags_AreRead()
    {
        var entries = Parse($"O:BAG:BAD:(OA;ID;CR;{EnrollGuid};;AU)(OA;CIIO;CR;{EnrollGuid};;AU)");

        entries[0].Inherited.Should().BeTrue();
        entries[0].InheritOnly.Should().BeFalse();
        entries[1].InheritOnly.Should().BeTrue();
    }

    [Fact]
    public void TheAccessListIsReturnedInSddl_ForTheRecord()
    {
        Parse($"O:BAG:BAD:(OA;;CR;{EnrollGuid};;AU)", out var sddl);

        sddl.Should().StartWith("D:").And.Contain(EnrollGuid);
        sddl.Should().NotContain("O:BA", "only the access list is asked for, never the owner");
    }

    [Fact]
    public void AStockTemplateSharedWithAuthenticatedUsers_GrantsEnroll()
    {
        EnrollFor($"O:BAG:BAD:(A;;LCRPLORC;;;AU)(OA;;CR;{EnrollGuid};;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{DomainAdmins})")
            .Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void AnExplicitDenyForTheAccount_BeatsTheAuthenticatedUsersGrant()
    {
        // The shape the lab's state S4 plants.
        EnrollFor($"O:BAG:BAD:(OD;;CR;{EnrollGuid};;{Account})(OA;;CR;{EnrollGuid};;AU)")
            .Should().Be(EnrollVerdict.Denied);
    }

    [Fact]
    public void ATemplateOnlyAdministratorsMayEnrollOn_GrantsNothing()
    {
        // WebServer as installed: read for Authenticated Users, Enroll for the
        // administrators only.
        EnrollFor($"O:BAG:BAD:(A;;LCRPLORC;;;AU)(OA;;CR;{EnrollGuid};;{DomainAdmins})(OA;;CR;{EnrollGuid};;{EnterpriseAdmins})")
            .Should().Be(EnrollVerdict.NotGranted);
    }

    [Fact]
    public void AutoenrollAlone_IsNotEnroll()
    {
        EnrollFor($"O:BAG:BAD:(OA;;CR;{AutoenrollGuid};;AU)")
            .Should().Be(EnrollVerdict.NotGranted);
    }

    [Fact]
    public void NoAccessListAtAll_GrantsEveryoneEverything()
    {
        var entries = Parse("O:BAG:BAD:NO_ACCESS_CONTROL");

        entries.Should().ContainSingle()
            .Which.Should().Be(new AclEntry(
                AclEntryKind.Allow, TemplateEnrollEvaluator.GenericAll, null, false, false,
                TemplateEnrollEvaluator.EveryoneSid));
        EnrollFor("O:BAG:BAD:NO_ACCESS_CONTROL").Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void AnEmptyAccessList_GrantsNothing()
    {
        Parse("O:BAG:BAD:").Should().BeEmpty();
        EnrollFor("O:BAG:BAD:").Should().Be(EnrollVerdict.NotGranted);
    }

    [Fact]
    public void AConditionalEntry_IsNotEvaluated()
    {
        // A callback entry carries a condition only Windows can evaluate, so it
        // must make the verdict Undetermined rather than count as an allow.
        var entries = Parse($"O:BAG:BAD:(XA;;CR;;;AU;(Member_of {{SID(BA)}}))(OA;;CR;{EnrollGuid};;AU)");

        entries[0].Kind.Should().Be(AclEntryKind.Unsupported);
        EnrollFor($"O:BAG:BAD:(XA;;CR;;;AU;(Member_of {{SID(BA)}}))(OA;;CR;{EnrollGuid};;AU)")
            .Should().Be(EnrollVerdict.Undetermined);
    }

    // The permission list of lab 2019's WebServerACME template as the directory
    // returned it on 2026-09-26, before and after the lab run planted a deny
    // Enroll entry for the Certus computer account (state S4 of the issue #440
    // measurement). The lab's own SIDs are replaced by this file's synthetic
    // ones; the shape, the flags and the order are the directory's.
    private const string LabTemplateBefore =
        "D:AI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" +
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + DomainAdmins + ")" +
        "(OA;;CR;" + EnrollGuid + ";;AU)" +
        "(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + EnterpriseAdmins + ")" +
        "(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;" + DomainAdmins + ")";

    private const string LabTemplateWithDeny =
        "D:AI(OD;;CR;" + EnrollGuid + ";;" + Account + ")" +
        "(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" +
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + DomainAdmins + ")" +
        "(OA;;CR;" + EnrollGuid + ";;AU)" +
        "(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + EnterpriseAdmins + ")" +
        "(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;" + DomainAdmins + ")";

    [Fact]
    public void TheLabTemplate_GrantsEnrollThroughAuthenticatedUsers()
    {
        var result = TemplateEnrollEvaluator.Evaluate(
            Parse("O:BAG:BA" + LabTemplateBefore),
            TemplateEnrollEvaluator.SidsForNetworkLogon(Account, []),
            TemplateEnrollEvaluator.EnrollRight);

        result.Verdict.Should().Be(EnrollVerdict.Granted);
        result.DecidingSid.Should().Be(TemplateEnrollEvaluator.AuthenticatedUsersSid);
    }

    [Fact]
    public void TheLabTemplate_WithThePlantedDeny_RefusesTheAccount()
    {
        var result = TemplateEnrollEvaluator.Evaluate(
            Parse("O:BAG:BA" + LabTemplateWithDeny),
            TemplateEnrollEvaluator.SidsForNetworkLogon(Account, []),
            TemplateEnrollEvaluator.EnrollRight);

        result.Verdict.Should().Be(EnrollVerdict.Denied);
        result.DecidingSid.Should().Be(Account);
    }

    [Fact]
    public void TheLabTemplate_WithThePlantedDeny_StillGrantsEveryoneElse()
    {
        const string someoneElse = "S-1-5-21-1004336348-1177238915-682003330-2001";

        TemplateEnrollEvaluator.Evaluate(
                Parse("O:BAG:BA" + LabTemplateWithDeny),
                TemplateEnrollEvaluator.SidsForNetworkLogon(someoneElse, []),
                TemplateEnrollEvaluator.EnrollRight)
            .Verdict.Should().Be(EnrollVerdict.Granted);
    }
}
