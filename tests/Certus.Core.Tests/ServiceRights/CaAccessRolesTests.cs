using System.Runtime.InteropServices;
using Certus.Adcs.ServiceRights;
using Certus.Core.ServiceRights;

namespace Certus.Core.Tests.ServiceRights;

/// <summary>
/// Decoding what <c>ICertAdmin2::GetMyRoles</c> returns, and mapping the ways
/// it can fail, issue #440. The call itself needs a CA and is proved on the lab.
/// </summary>
public class CaAccessRolesTests
{
    [Fact]
    public void Describe_UsesTheConsoleNamesInSecurityTabOrder()
    {
        CaAccessRoles.Describe(CaAccessRoles.Read | CaAccessRoles.Officer | CaAccessRoles.Enroll)
            .Should().Equal("Issue and Manage Certificates", "Read", "Request Certificates");
    }

    [Fact]
    public void Describe_ReportsBitsItDoesNotKnowRatherThanDroppingThem()
    {
        CaAccessRoles.Describe(CaAccessRoles.Read | 0x1000)
            .Should().Equal("Read", "unknown bits 0x1000");
    }

    [Fact]
    public void Describe_OfNothing_IsEmpty()
    {
        CaAccessRoles.Describe(0).Should().BeEmpty();
    }

    [Fact]
    public void Has_NeedsEveryBitOfTheRole()
    {
        CaAccessRoles.Has(0x102, CaAccessRoles.Officer).Should().BeTrue();
        CaAccessRoles.Has(0x100, CaAccessRoles.Officer).Should().BeFalse();
        CaAccessRoles.Has(0x102, CaAccessRoles.Officer | CaAccessRoles.Enroll).Should().BeFalse();
    }

    [Fact]
    public void AnAccessDeniedThroughDynamic_IsAccessDenied()
    {
        // The IDispatch path usually surfaces E_ACCESSDENIED as this type.
        AdcsServiceRightsProbe.ClassifyRolesFailure(new UnauthorizedAccessException())
            .Outcome.Should().Be(ReadingOutcome.AccessDenied);
    }

    [Fact]
    public void AnAccessDeniedHResult_IsAccessDenied_AndNamesTheOtherCause()
    {
        var reading = AdcsServiceRightsProbe.ClassifyRolesFailure(
            new COMException("denied", unchecked((int)0x80070005)));

        reading.Outcome.Should().Be(ReadingOutcome.AccessDenied);
        reading.HResult.Should().Be(unchecked((int)0x80070005));
        reading.Detail.Should().Contain("IF_NOREMOTEICERTADMIN",
            "a CA that refuses remote administration answers exactly like a missing right");
        reading.Detail.Should().Contain("Request Certificates alone is not enough",
            "lab 2019 refused the roles to an account holding only Request Certificates (issue #440, state S1)");
    }

    [Fact]
    public void AnUnreachableCa_IsUnavailable()
    {
        AdcsServiceRightsProbe.ClassifyRolesFailure(new COMException("rpc", unchecked((int)0x800706BA)))
            .Outcome.Should().Be(ReadingOutcome.Unavailable);
    }

    [Theory]
    [InlineData(unchecked((int)0x80040154))]
    [InlineData(unchecked((int)0x80020003))]
    public void AMissingOrIncompleteComClass_IsNotRegistered(int hresult)
    {
        var reading = AdcsServiceRightsProbe.ClassifyRolesFailure(new COMException("rsat", hresult));

        reading.Outcome.Should().Be(ReadingOutcome.NotRegistered);
        reading.Detail.Should().Contain("RSAT-ADCS-Mgmt");
    }

    [Fact]
    public void AnythingElse_IsFailed_WithItsHResult()
    {
        var reading = AdcsServiceRightsProbe.ClassifyRolesFailure(
            new COMException("odd", unchecked((int)0x80004005)));

        reading.Outcome.Should().Be(ReadingOutcome.Failed);
        reading.HResult.Should().Be(unchecked((int)0x80004005));
        reading.RolesMask.Should().BeNull();
    }
}
