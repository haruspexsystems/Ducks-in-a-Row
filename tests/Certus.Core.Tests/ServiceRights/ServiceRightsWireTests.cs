using Certus.Core.ServiceRights;

namespace Certus.Core.Tests.ServiceRights;

/// <summary>
/// The names the API carries for the service rights check, issue #440. Every
/// map throws for a member it does not name, so these fail when a member is
/// added without one, instead of it reaching the browser as something else.
/// </summary>
public class ServiceRightsWireTests
{
    [Fact]
    public void EveryStatus_HasAName()
    {
        foreach (var status in Enum.GetValues<RightsStatus>())
            ServiceRightsWire.Status(status).Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void EveryBasis_HasAName()
    {
        foreach (var basis in Enum.GetValues<RightsBasis>())
            ServiceRightsWire.Basis(basis).Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void EveryGroup_HasAName()
    {
        foreach (var group in Enum.GetValues<RightsGroup>())
            ServiceRightsWire.Group(group).Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void EveryNeededForFlag_HasAName()
    {
        foreach (var flag in Enum.GetValues<RightNeededFor>().Where(f => f != RightNeededFor.None))
            ServiceRightsWire.NeededFor(flag).Should().ContainSingle();
    }

    [Fact]
    public void TheStatusNames_AreTheOnesTheFrontendReads()
    {
        Enum.GetValues<RightsStatus>().Select(ServiceRightsWire.Status)
            .Should().Equal("proven", "inferred", "unproven", "failed", "skipped");
    }

    [Fact]
    public void NeededFor_ListsEveryFlagSet_InOrder()
    {
        ServiceRightsWire.NeededFor(RightNeededFor.CrlWatching | RightNeededFor.Issuance)
            .Should().Equal("issuance", "crlWatching");
    }

    [Fact]
    public void AnUnnamedValue_Throws()
    {
        var status = () => ServiceRightsWire.Status((RightsStatus)99);
        var flag = () => ServiceRightsWire.NeededFor((RightNeededFor)64);

        status.Should().Throw<ArgumentOutOfRangeException>();
        flag.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void AReport_GoesOnTheWireWithNamesNotNumbers()
    {
        var report = new ServiceRightsReport(
            @"ca\CA",
            new ServiceRightsIdentity(@"NT AUTHORITY\SYSTEM", true, @"CORP\DUCKS01$", "S-1-5-21-1-2-3-1105", "CORP", 3),
            [new ServiceRightsRow("ca-read", RightsGroup.Ca, "View", RightsStatus.Failed, RightsBasis.Exercised,
                RightNeededFor.Inventory, "refused", Remedy: "grant Read")],
            Simulated: false,
            CheckedAt: DateTimeOffset.UnixEpoch);

        var wire = report.ToWire();

        wire.Rows.Should().ContainSingle().Which.Should().BeEquivalentTo(new ServiceRightsRowWire(
            "ca-read", "ca", "View", "failed", "exercised", ["inventory"], "refused", "grant Read", false, null));
    }
}
