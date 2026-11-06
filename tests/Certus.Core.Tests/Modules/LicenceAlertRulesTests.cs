using Certus.Core.Alerts;
using Certus.Core.Modules;
using Certus.Modules;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// Which licence alert is due (issue #494, licence design section 13.6). The
/// status picks the alert and the notice picks the stage (Sean's decision of
/// 2026-10-14), every mapping is an allow list, and nothing the module supplies
/// reaches the alert unless the core has typed or checked it.
/// </summary>
public class LicenceAlertRulesTests
{
    internal const string Id = "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b";

    internal static LicenceSnapshot Snapshot(
        LicenceStatus status,
        NoticeStage notice,
        string? licenceId = Id,
        string? tier = "standard",
        int? daysRemaining = 6) =>
        LicenceViewsTests.Verdict(status) with
        {
            LicenceId = licenceId,
            Tier = tier,
            Notice = notice,
            DaysRemaining = daysRemaining,
        };

    internal static LicenceStatusView Loaded(LicenceSnapshot? licence, bool stored = true) =>
        new(ModuleState.Loaded, null, "paid", "1.0.0+test", stored, licence);

    [Theory]
    [InlineData(LicenceStatus.Expiring, NoticeStage.Days30, LicenceAlertKind.Expiring, LicenceAlertStages.Days30)]
    [InlineData(LicenceStatus.Expiring, NoticeStage.Days14, LicenceAlertKind.Expiring, LicenceAlertStages.Days14)]
    [InlineData(LicenceStatus.Expiring, NoticeStage.Days7, LicenceAlertKind.Expiring, LicenceAlertStages.Days7)]
    [InlineData(LicenceStatus.Expiring, NoticeStage.Days1, LicenceAlertKind.Expiring, LicenceAlertStages.Days1)]
    [InlineData(LicenceStatus.Grace, NoticeStage.Expired, LicenceAlertKind.Grace, LicenceAlertStages.Expired)]
    [InlineData(LicenceStatus.Lapsed, NoticeStage.GraceEnded, LicenceAlertKind.Lapsed, LicenceAlertStages.GraceEnded)]
    public void EachNoticeTheModuleReports_IsTheAlertOfItsStatus(
        LicenceStatus status, NoticeStage notice, LicenceAlertKind kind, string stage)
    {
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(status, notice)));

        decision.Problems.Should().BeEmpty();
        decision.Alert.Should().Be(new LicenceAlert(
            kind, stage, Id, "standard",
            new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 31, 0, 0, 0, TimeSpan.Zero),
            6));
    }

    [Fact]
    public void ATrialEnding_IsALapse_NotAGracePeriod()
    {
        // A trial has graceDays 0, so the module reports Expired while the status
        // is already Lapsed and never reports GraceEnded at all. The notice alone
        // would announce a grace period that does not exist.
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Lapsed, NoticeStage.Expired)));

        decision.Alert!.Kind.Should().Be(LicenceAlertKind.Lapsed);
        decision.Alert.Stage.Should().Be(LicenceAlertStages.Expired);
    }

    [Theory]
    [InlineData(LicenceStatus.None)]
    [InlineData(LicenceStatus.NotYetValid)]
    [InlineData(LicenceStatus.Valid)]
    [InlineData(LicenceStatus.BindingMismatch)]
    [InlineData(LicenceStatus.Invalid)]
    public void AStatusThatDoesNotAlert_SendsNothing_WhateverTheNoticeSays(LicenceStatus status)
    {
        // BindingMismatch is the case this guards: the module sets the notice
        // before it checks the forest binding, so a licence bound to another
        // forest can carry "7 days left" while it switches nothing on here.
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(status, NoticeStage.Days7)));

        decision.Alert.Should().BeNull();
        decision.Problems.Should().BeEmpty("every one of these is a status this release knows");
    }

    [Fact]
    public void NoNotice_SendsNothing()
    {
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Expiring, NoticeStage.None)));

        decision.Alert.Should().BeNull();
        decision.Problems.Should().BeEmpty();
    }

    [Fact]
    public void AModuleThatIsNotLoaded_IsNotStandingBehindItsLastNotice()
    {
        var stale = Snapshot(LicenceStatus.Expiring, NoticeStage.Days7);

        foreach (var state in Enum.GetValues<ModuleState>().Where(s => s != ModuleState.Loaded))
        {
            var view = new LicenceStatusView(state, "gone", "paid", "1.0.0+test", true, stale);

            LicenceAlertRules.Evaluate(view).Alert.Should().BeNull($"the module is {state}");
        }
    }

    [Fact]
    public void NothingStored_OrNoVerdict_SendsNothing()
    {
        LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Expiring, NoticeStage.Days7), stored: false))
            .Alert.Should().BeNull();
        LicenceAlertRules.Evaluate(Loaded(null)).Alert.Should().BeNull();
    }

    [Fact]
    public void AStatusThisReleaseDoesNotKnow_SendsNothing_AndSaysSo()
    {
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot((LicenceStatus)99, NoticeStage.Days7)));

        decision.Alert.Should().BeNull();
        decision.Problems.Should().ContainSingle().Which.Key.Should().Be("status:99");
    }

    [Fact]
    public void ANoticeThisReleaseDoesNotKnow_SendsNothing_AndSaysSo()
    {
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Expiring, (NoticeStage)42)));

        decision.Alert.Should().BeNull();
        decision.Problems.Should().ContainSingle().Which.Key.Should().Be("notice:42");
    }

    [Fact]
    public void AnUnknownNotice_IsReportedEvenWhenTheStatusSendsNothing()
    {
        // Both mappings always run, so a gap in either shows in the log.
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Valid, (NoticeStage)42)));

        decision.Alert.Should().BeNull();
        decision.Problems.Select(p => p.Key).Should().Equal("notice:42");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("LIC-1")]
    [InlineData("0192A3B4-C5D6-7E8F-9A0B-1C2D3E4F5A6B")]
    [InlineData("{0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b}")]
    [InlineData("0192a3b4c5d67e8f9a0b1c2d3e4f5a6b")]
    [InlineData("0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6bx")]
    [InlineData(" 0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6")]
    public void ALicenceIdThatIsNotCanonical_SendsNothing_AndIsNotRepeatedInTheMessage(string? licenceId)
    {
        var decision = LicenceAlertRules.Evaluate(
            Loaded(Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, licenceId: licenceId)));

        decision.Alert.Should().BeNull();
        var problem = decision.Problems.Should().ContainSingle().Which;
        problem.Key.Should().Be("licence-id");
        if (!string.IsNullOrEmpty(licenceId))
            problem.Message.Should().NotContain(licenceId.Trim());
    }

    [Theory]
    [InlineData("standard")]
    [InlineData("compliance")]
    [InlineData("a-b-1")]
    public void ATierName_IsCarried(string tier)
    {
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, tier: tier)));

        decision.Alert!.Tier.Should().Be(tier);
        decision.Problems.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Standard")]
    [InlineData("standard edition")]
    [InlineData("standard\n")]
    [InlineData("")]
    [InlineData("abcdefghijklmnopqrstuvwxyz0123456")]
    public void AValueThatIsNotATierName_IsDropped_AndTheAlertStillGoes(string tier)
    {
        // The trailing newline is the case a regular expression's end anchor
        // would have let through.
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, tier: tier)));

        decision.Alert.Should().NotBeNull();
        decision.Alert!.Tier.Should().BeNull();
        decision.Problems.Should().ContainSingle().Which.Key.Should().Be($"tier:{Id}");
    }

    [Fact]
    public void ATierCarryingALineSeparator_IsDropped()
    {
        // U+2028 is a line separator that ModuleBoundary.Copy lets through, because
        // it strips only control characters. Built from its code point so the
        // source file holds no character a reader cannot see.
        var tier = "standard" + (char)0x2028 + "x";

        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, tier: tier)));

        decision.Alert!.Tier.Should().BeNull();
        decision.Problems.Should().ContainSingle().Which.Key.Should().Be($"tier:{Id}");
    }

    [Fact]
    public void NoTier_IsNotAProblem()
    {
        var decision = LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, tier: null)));

        decision.Alert!.Tier.Should().BeNull();
        decision.Problems.Should().BeEmpty();
    }

    [Fact]
    public void EveryNoticeTheContractDefines_HasADecision()
    {
        // A notice added to the contract later fails here, rather than being
        // ignored in production with a warning nobody reads.
        foreach (var notice in Enum.GetValues<NoticeStage>())
        {
            LicenceAlertRules.Evaluate(Loaded(Snapshot(LicenceStatus.Expiring, notice)))
                .Problems.Should().BeEmpty($"{notice} needs a decision in LicenceAlertRules");
        }
    }

    [Fact]
    public void EveryStatusTheContractDefines_HasADecision()
    {
        foreach (var status in Enum.GetValues<LicenceStatus>())
        {
            LicenceAlertRules.Evaluate(Loaded(Snapshot(status, NoticeStage.Days7)))
                .Problems.Should().BeEmpty($"{status} needs a decision in LicenceAlertRules");
        }
    }

    [Fact]
    public void TheAlert_CarriesNothingButTheFieldsTheDesignNames()
    {
        // A free text field added to the record would be a way for a module to put
        // words in front of an administrator. Adding one has to fail a test.
        typeof(LicenceAlert).GetProperties().Select(p => p.Name).Should().BeEquivalentTo(
            nameof(LicenceAlert.Kind),
            nameof(LicenceAlert.Stage),
            nameof(LicenceAlert.LicenceId),
            nameof(LicenceAlert.Tier),
            nameof(LicenceAlert.ValidUntil),
            nameof(LicenceAlert.GraceUntil),
            nameof(LicenceAlert.DaysRemaining));
    }
}
