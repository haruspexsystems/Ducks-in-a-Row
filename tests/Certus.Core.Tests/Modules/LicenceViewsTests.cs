using Certus.Core.Modules;
using Certus.Modules;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The licence API's views (licence design section 13.3, deviation Dv15): the contract's verdict
/// mapped into the core's vocabulary, plus StoredNotVerified, which only the core can know, and the
/// rule that a file which did not pass the signature contributes nothing but its status and reason.
/// </summary>
public class LicenceViewsTests
{
    internal static LicenceSnapshot Verdict(
        LicenceStatus status,
        string reason = "ok",
        bool worse = false) => new(
        status,
        reason,
        "lid-1",
        "standard",
        ["placeholder"],
        2,
        "Example BV",
        "REF-1",
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2027, 1, 31, 0, 0, 0, TimeSpan.Zero),
        42,
        ["corp.example.com"],
        "corp.example.com",
        false,
        false,
        NoticeStage.None,
        worse);

    private static LicenceStatusView Loaded(LicenceSnapshot? licence) =>
        new(ModuleState.Loaded, null, "paid", "1.0.0+test", true, licence);

    [Theory]
    [InlineData(LicenceStatus.NotYetValid, "NotYetValid")]
    [InlineData(LicenceStatus.Valid, "Valid")]
    [InlineData(LicenceStatus.Expiring, "Expiring")]
    [InlineData(LicenceStatus.Grace, "Grace")]
    [InlineData(LicenceStatus.Lapsed, "Lapsed")]
    [InlineData(LicenceStatus.BindingMismatch, "BindingMismatch")]
    public void Current_MapsEachVerifiedVerdict_AndCarriesItsDisplayFields(LicenceStatus status, string expected)
    {
        var view = LicenceViews.Current(Loaded(Verdict(status)), stored: true);

        view.Status.Should().Be(expected);
        view.IsVerified.Should().BeTrue();
        view.LicenceId.Should().Be("lid-1");
        view.Tier.Should().Be("standard");
        view.Features.Should().Equal("placeholder");
        view.DaysRemaining.Should().Be(42);
        view.BoundForests.Should().Equal("corp.example.com");
    }

    [Fact]
    public void Current_Invalid_CarriesTheReasonAndTheServersForest_AndNothingFromTheFile()
    {
        var view = LicenceViews.Current(Loaded(Verdict(LicenceStatus.Invalid, "bad-signature")), stored: true);

        view.Status.Should().Be("Invalid");
        view.IsVerified.Should().BeFalse();
        view.ReasonCode.Should().Be("bad-signature");
        view.ObservedForest.Should().Be("corp.example.com");
        view.LicenceId.Should().BeNull();
        view.Tier.Should().BeNull();
        view.LicenseeName.Should().BeNull();
        view.LicenseeRef.Should().BeNull();
        view.ValidUntil.Should().BeNull();
        view.Features.Should().BeEmpty();
        view.BoundForests.Should().BeEmpty();
    }

    [Fact]
    public void Current_AStatusOutsideTheContract_FailsClosed_AsInvalidWithNoFields()
    {
        var view = LicenceViews.Current(Loaded(Verdict((LicenceStatus)99)), stored: true);

        view.Status.Should().Be("Invalid");
        view.LicenceId.Should().BeNull();
        view.Tier.Should().BeNull();
    }

    [Fact]
    public void Current_NothingStored_ReadsNone_EvenWithAStaleVerdict()
    {
        // The view is refreshed only when the module thread next publishes, so a licence removed a
        // moment ago still has its old verdict in the view.
        var view = LicenceViews.Current(Loaded(Verdict(LicenceStatus.Valid)), stored: false);

        view.Status.Should().Be("None");
        view.LicenceId.Should().BeNull();
    }

    [Fact]
    public void Current_NothingStored_StillShowsTheServersForest_AndNothingElse()
    {
        // Issue #493, design section 10.4: a customer quotes this forest when buying a bound licence.
        // The module reads it off the server, never out of a file, so it is shown with nothing stored.
        var view = LicenceViews.Current(Loaded(Verdict(LicenceStatus.None, "None")), stored: false);

        view.Status.Should().Be("None");
        view.ObservedForest.Should().Be("corp.example.com");
        view.IsVerified.Should().BeFalse();
        view.ReasonCode.Should().BeNull();
        view.LicenceId.Should().BeNull();
        view.Tier.Should().BeNull();
        view.BoundForests.Should().BeEmpty();
        view.DaysRemaining.Should().BeNull();
    }

    [Theory]
    [InlineData(ModuleState.NotPresent)]
    [InlineData(ModuleState.Failed)]
    [InlineData(ModuleState.Unresponsive)]
    [InlineData(ModuleState.Quarantined)]
    [InlineData(ModuleState.Incompatible)]
    [InlineData(ModuleState.Refused)]
    public void Current_NothingStored_ShowsNoForest_FromAModuleNoLongerLoaded(ModuleState state)
    {
        var status = new LicenceStatusView(state, "stopped", "paid", "1.0.0+test", false, Verdict(LicenceStatus.None, "None"));

        LicenceViews.Current(status, stored: false).ObservedForest.Should().BeNull();
    }

    [Fact]
    public void Current_StoredWithNoModule_ReadsStoredNotVerified()
    {
        var status = new LicenceStatusView(ModuleState.NotPresent, "no module folder", null, null, true, null);

        LicenceViews.Current(status, stored: true).Status.Should().Be("StoredNotVerified");
    }

    [Fact]
    public void Current_StoredButTheModuleHasNotJudgedTheFileYet_ReadsStoredNotVerified()
    {
        // The module last evaluated "no licence"; the file arrived after that.
        var view = LicenceViews.Current(Loaded(Verdict(LicenceStatus.None)), stored: true);

        view.Status.Should().Be("StoredNotVerified");
    }

    [Theory]
    [InlineData(ModuleState.Failed)]
    [InlineData(ModuleState.Unresponsive)]
    [InlineData(ModuleState.Quarantined)]
    [InlineData(ModuleState.Incompatible)]
    [InlineData(ModuleState.Refused)]
    public void Current_AModuleNoLongerLoaded_DoesNotStandBehindTheVerdictItLeft(ModuleState state)
    {
        var status = new LicenceStatusView(state, "stopped", "paid", "1.0.0+test", true, Verdict(LicenceStatus.Valid));

        var view = LicenceViews.Current(status, stored: true);

        view.Status.Should().Be("StoredNotVerified");
        view.LicenceId.Should().BeNull();
    }

    [Fact]
    public void Candidate_CarriesWorseThanInstalled_AndTheVerdict()
    {
        var candidate = LicenceViews.Candidate(Verdict(LicenceStatus.Lapsed, worse: true));

        candidate.WorseThanInstalled.Should().BeTrue();
        candidate.Licence.Status.Should().Be("Lapsed");
        candidate.Licence.LicenceId.Should().Be("lid-1");
    }

    [Fact]
    public void Candidate_AVerdictOfNoneForBytesThatExist_ReadsInvalid()
    {
        var candidate = LicenceViews.Candidate(Verdict(LicenceStatus.None, "empty"));

        candidate.Licence.Status.Should().Be("Invalid");
        candidate.Licence.ReasonCode.Should().Be("empty");
        candidate.Licence.LicenceId.Should().BeNull();
    }

    [Fact]
    public void Module_ReportsTheStateByName()
    {
        var module = LicenceViews.Module(new LicenceStatusView(ModuleState.Quarantined, "set aside", "paid", "2.0.0", false, null));

        module.Should().Be(new ModuleView("Quarantined", "set aside", "paid", "2.0.0"));
    }

    [Fact]
    public void Module_CarriesTheContracts_ForAnIncompatibleModule()
    {
        var status = new LicenceStatusView(ModuleState.Incompatible, "the module needs contract major 2", "paid", "2.0.0", false, null)
        {
            Contract = new ModuleContractView("2.0", "1.0"),
        };

        LicenceViews.Module(status).Should().Be(
            new ModuleView("Incompatible", "the module needs contract major 2", "paid", "2.0.0", new ModuleContractView("2.0", "1.0")));
    }

    [Theory]
    [InlineData(ModuleState.NotPresent)]
    [InlineData(ModuleState.Loaded)]
    [InlineData(ModuleState.Failed)]
    [InlineData(ModuleState.Refused)]
    public void Module_CarriesNoContracts_ForAnyOtherState(ModuleState state)
    {
        // The contract numbers describe only the Incompatible state, so a stale pair on the view must
        // never reach the wire beside another state.
        var status = new LicenceStatusView(state, null, "paid", "2.0.0", false, null)
        {
            Contract = new ModuleContractView("2.0", "1.0"),
        };

        LicenceViews.Module(status).Contract.Should().BeNull();
    }

    [Theory]
    [InlineData(LicenceDisplayStatus.None, false)]
    [InlineData(LicenceDisplayStatus.StoredNotVerified, false)]
    [InlineData(LicenceDisplayStatus.NotYetValid, true)]
    [InlineData(LicenceDisplayStatus.Valid, true)]
    [InlineData(LicenceDisplayStatus.Expiring, true)]
    [InlineData(LicenceDisplayStatus.Grace, true)]
    [InlineData(LicenceDisplayStatus.Lapsed, true)]
    [InlineData(LicenceDisplayStatus.BindingMismatch, true)]
    [InlineData(LicenceDisplayStatus.Invalid, false)]
    public void OnlyAVerdictThatPassedTheSignature_CountsAsVerified(LicenceDisplayStatus status, bool expected) =>
        LicenceViews.IsVerifiedStatus(status).Should().Be(expected);

    [Fact]
    public void EveryDisplayStatus_IsDecidedOnePlaceOrTheOther()
    {
        // A status added to the enum must be placed deliberately; the theory above lists all nine.
        Enum.GetValues<LicenceDisplayStatus>().Should().HaveCount(9);
    }

    [Fact]
    public void TheEmptyViews_AreNotVerified()
    {
        LicenceViews.StoredNotVerified().IsVerified.Should().BeFalse();
        LicenceViews.Current(Loaded(Verdict(LicenceStatus.Invalid)), stored: true).IsVerified.Should().BeFalse();
        LicenceViews.Current(Loaded(Verdict(LicenceStatus.Valid)), stored: false).IsVerified.Should().BeFalse();
    }

    [Theory]
    [InlineData(ModuleState.NotPresent, false)]
    [InlineData(ModuleState.Loaded, false)]
    [InlineData(ModuleState.Failed, true)]
    [InlineData(ModuleState.Unresponsive, true)]
    [InlineData(ModuleState.Quarantined, true)]
    [InlineData(ModuleState.Incompatible, false)] // a restart cannot change the contract a module was built for
    [InlineData(ModuleState.Refused, false)]      // nor the permissions on its folder
    public void IsSetAside_IsTrueForEveryStateRetryApplies(ModuleState state, bool expected) =>
        state.IsSetAside().Should().Be(expected);

    [Fact]
    public void EveryModuleState_IsDecidedForRetry()
    {
        // A state added to the enum must be placed in the theory above deliberately, and in the
        // card's mirror of this rule (src/frontend/src/lib/licence.ts, isSetAside).
        Enum.GetValues<ModuleState>().Should().HaveCount(7);
    }
}
