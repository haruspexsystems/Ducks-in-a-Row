using Certus.Core.ServiceRights;

namespace Certus.Core.Tests.ServiceRights;

/// <summary>
/// The template Enroll test ([MS-CRTD] section 2.5.1) as the policy module
/// applies it, issue #440. Most of these pin a way the test could be wrong and
/// still look reasonable: deciding by the last entry rather than the first,
/// looking at every deny before any allow, counting an entry meant only for
/// child objects, or letting an entry for a different extended right decide.
/// </summary>
public class TemplateEnrollEvaluatorTests
{
    private const string Account = "S-1-5-21-1004336348-1177238915-682003330-1105";
    private const string DomainComputers = "S-1-5-21-1004336348-1177238915-682003330-515";
    private const string SomeoneElse = "S-1-5-21-1004336348-1177238915-682003330-2001";

    private static readonly Guid Enroll = TemplateEnrollEvaluator.EnrollRight;
    private static readonly Guid Autoenroll = TemplateEnrollEvaluator.AutoenrollRight;

    private static readonly IReadOnlySet<string> Sids =
        TemplateEnrollEvaluator.SidsForNetworkLogon(Account, [DomainComputers]);

    private static AclEntry Allow(string sid, Guid? objectType = null, int mask = TemplateEnrollEvaluator.ControlAccess,
        bool inheritOnly = false, bool inherited = false)
        => new(AclEntryKind.Allow, mask, objectType, inheritOnly, inherited, sid);

    private static AclEntry Deny(string sid, Guid? objectType = null, int mask = TemplateEnrollEvaluator.ControlAccess,
        bool inheritOnly = false, bool inherited = false)
        => new(AclEntryKind.Deny, mask, objectType, inheritOnly, inherited, sid);

    [Fact]
    public void EnrollGrantedThroughAuthenticatedUsers_IsGranted()
    {
        var result = TemplateEnrollEvaluator.Evaluate(
            [Allow(TemplateEnrollEvaluator.AuthenticatedUsersSid, Enroll)], Sids, Enroll);

        result.Verdict.Should().Be(EnrollVerdict.Granted);
        result.DecidingSid.Should().Be(TemplateEnrollEvaluator.AuthenticatedUsersSid);
    }

    [Fact]
    public void EnrollGrantedThroughAGroupTheAccountIsIn_IsGranted()
    {
        TemplateEnrollEvaluator.Evaluate([Allow(DomainComputers, Enroll)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void AnEntryForSomeoneElse_DoesNotApply()
    {
        TemplateEnrollEvaluator.Evaluate([Allow(SomeoneElse, Enroll)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.NotGranted);
    }

    [Fact]
    public void AnEmptyList_GrantsNothing()
    {
        TemplateEnrollEvaluator.Evaluate([], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.NotGranted);
    }

    [Fact]
    public void ControlAccessWithNoObjectType_CoversEveryExtendedRight()
    {
        // "All extended rights" is a plain entry carrying control access.
        TemplateEnrollEvaluator.Evaluate([Allow(Account, objectType: null)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void GenericAll_CoversEnroll()
    {
        TemplateEnrollEvaluator.Evaluate(
                [Allow(Account, objectType: null, mask: TemplateEnrollEvaluator.GenericAll)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void FullControl_AsTheDirectoryStoresIt_CoversEnroll()
    {
        // The directory stores "Full Control" as the mapped mask, which carries
        // control access among the rest.
        TemplateEnrollEvaluator.Evaluate([Allow(Account, objectType: null, mask: 0x000F01FF)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void AMaskWithoutControlAccess_DoesNotCoverEnroll()
    {
        // Read and write property alone never grant an extended right.
        TemplateEnrollEvaluator.Evaluate([Allow(Account, objectType: null, mask: 0x30)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.NotGranted);
    }

    [Fact]
    public void AnEntryForAnotherExtendedRight_SaysNothingAboutEnroll()
    {
        var entries = new[] { Allow(Account, Autoenroll) };

        TemplateEnrollEvaluator.Evaluate(entries, Sids, Enroll).Verdict.Should().Be(EnrollVerdict.NotGranted);
        TemplateEnrollEvaluator.Evaluate(entries, Sids, Autoenroll).Verdict.Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void ADenyForAnotherExtendedRight_DoesNotDenyEnroll()
    {
        TemplateEnrollEvaluator.Evaluate(
                [Deny(Account, Autoenroll), Allow(TemplateEnrollEvaluator.AuthenticatedUsersSid, Enroll)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void ADenyBeforeAnAllow_Denies()
    {
        var result = TemplateEnrollEvaluator.Evaluate(
            [Deny(Account, Enroll), Allow(TemplateEnrollEvaluator.AuthenticatedUsersSid, Enroll)], Sids, Enroll);

        result.Verdict.Should().Be(EnrollVerdict.Denied);
        result.DecidingSid.Should().Be(Account);
    }

    [Fact]
    public void AnExplicitAllowBeforeAnInheritedDeny_Grants()
    {
        // Canonical order puts explicit entries first, and the first entry
        // decides. A check that looked at every deny first would say Denied.
        var result = TemplateEnrollEvaluator.Evaluate(
            [Allow(Account, Enroll), Deny(DomainComputers, Enroll, inherited: true)], Sids, Enroll);

        result.Verdict.Should().Be(EnrollVerdict.Granted);
        result.DecidedByInheritedEntry.Should().BeFalse();
    }

    [Fact]
    public void AnInheritedDecision_IsReportedAsInherited()
    {
        TemplateEnrollEvaluator.Evaluate([Deny(DomainComputers, Enroll, inherited: true)], Sids, Enroll)
            .DecidedByInheritedEntry.Should().BeTrue();
    }

    [Fact]
    public void AnInheritOnlyEntry_DoesNotApplyToTheTemplateItself()
    {
        TemplateEnrollEvaluator.Evaluate([Allow(Account, Enroll, inheritOnly: true)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.NotGranted);
    }

    [Fact]
    public void AnInheritOnlyDeny_DoesNotHideAnAllowAfterIt()
    {
        TemplateEnrollEvaluator.Evaluate(
                [Deny(Account, Enroll, inheritOnly: true), Allow(Account, Enroll)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void AnUnsupportedEntryThatCouldDecide_IsUndetermined()
    {
        var conditional = new AclEntry(
            AclEntryKind.Unsupported, TemplateEnrollEvaluator.ControlAccess, Enroll, false, false, Account);

        TemplateEnrollEvaluator.Evaluate(
                [conditional, Allow(TemplateEnrollEvaluator.AuthenticatedUsersSid, Enroll)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Undetermined);
    }

    [Fact]
    public void AnUnsupportedEntryThatCannotDecide_IsSkipped()
    {
        var unrelated = new AclEntry(AclEntryKind.Unsupported, 0x10, null, false, false, Account);

        TemplateEnrollEvaluator.Evaluate(
                [unrelated, Allow(TemplateEnrollEvaluator.AuthenticatedUsersSid, Enroll)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Granted);
    }

    [Fact]
    public void AnEntryWhoseTrusteeCouldNotBeRead_MatchesEveryone()
    {
        var unreadable = new AclEntry(AclEntryKind.Unsupported, -1, null, false, false, AclEntry.AnyTrustee);

        TemplateEnrollEvaluator.Evaluate(
                [unreadable, Allow(TemplateEnrollEvaluator.AuthenticatedUsersSid, Enroll)], Sids, Enroll)
            .Verdict.Should().Be(EnrollVerdict.Undetermined);
    }

    [Fact]
    public void SidsForNetworkLogon_CarriesTheAccountItsGroupsAndTheWellKnownGroups()
    {
        Sids.Should().Contain(
        [
            Account,
            DomainComputers,
            TemplateEnrollEvaluator.EveryoneSid,
            TemplateEnrollEvaluator.AuthenticatedUsersSid,
            TemplateEnrollEvaluator.NetworkSid,
            TemplateEnrollEvaluator.ThisOrganizationSid,
        ]);
    }

    [Fact]
    public void SidsForNetworkLogon_MatchesRegardlessOfCase()
    {
        Sids.Contains(Account.ToLowerInvariant()).Should().BeTrue();
    }
}
