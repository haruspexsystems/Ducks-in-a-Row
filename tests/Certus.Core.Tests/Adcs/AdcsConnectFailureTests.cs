using System.Runtime.InteropServices;
using Certus.Adcs;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// How a failed <c>GetCaInfoAsync</c>, which is the wizard's Test Connection,
/// leaves (issue #440). Before this it folded every COM error into "not
/// accessible", so the button could not tell a missing right from a CA that
/// was down, and the operator was sent to check the firewall either way.
/// </summary>
public class AdcsConnectFailureTests
{
    [Fact]
    public void AnAccessDeniedThroughDynamic_IsAccessDenied_NamingRequestCertificates()
    {
        var mapped = AdcsClient.ClassifyConnectFailure(new UnauthorizedAccessException());

        mapped.Should().BeOfType<CaAccessDeniedException>()
            .Which.Message.Should().Be(CaAccessDeniedException.ConnectPermissionMessage);
    }

    [Fact]
    public void AnAccessDeniedHResult_IsAccessDenied()
    {
        AdcsClient.ClassifyConnectFailure(new COMException("denied", CaAccessDeniedException.AccessDeniedHResult))
            .Should().BeOfType<CaAccessDeniedException>();
    }

    [Fact]
    public void EnrollDenied_IsAccessDenied()
    {
        // What the lab CA answered Test Connection with when the account lacked
        // Request Certificates (lab 2019, 2026-09-26): not E_ACCESSDENIED.
        AdcsClient.ClassifyConnectFailure(new COMException("enroll denied", CaStatusCode.EnrollDenied))
            .Should().BeOfType<CaAccessDeniedException>();
    }

    [Fact]
    public void RpcUnavailable_IsUnavailable()
    {
        AdcsClient.ClassifyConnectFailure(new COMException("rpc", CaUnavailableException.RpcServerUnavailableHResult))
            .Should().BeOfType<CaUnavailableException>();
    }

    [Theory]
    [InlineData(unchecked((int)0x80040154))]
    [InlineData(unchecked((int)0x80020003))]
    public void AMissingComponent_IsNotMapped_SoItReachesTheRsatArm(int hresult)
    {
        var ex = new COMException("missing", hresult);

        AdcsClient.ClassifyConnectFailure(ex).Should().BeNull();
        AdcsClient.IsMissingComponent(ex).Should().BeTrue();
    }

    [Fact]
    public void AnyOtherComFailure_StaysNotAccessible()
    {
        var ex = new COMException("odd", unchecked((int)0x80004005));

        AdcsClient.ClassifyConnectFailure(ex).Should().BeNull();
        AdcsClient.IsMissingComponent(ex).Should().BeFalse();
    }

    [Fact]
    public void TheConnectMessage_NamesRequestCertificates()
    {
        CaAccessDeniedException.ConnectPermissionMessage.Should().Contain("'Request Certificates'");
    }

    [Fact]
    public void TheCrlMessage_NamesRequestCertificates_NotRead()
    {
        // The CRL reads go through the request interface. With Read and without
        // Request Certificates the lab CA refused them, so telling an operator to
        // grant Read would fix nothing.
        CaAccessDeniedException.CrlReadPermissionMessage.Should().Contain("'Request Certificates'");
        CaAccessDeniedException.CrlReadPermissionMessage.Should().NotContain("lacks 'Read'");
    }
}
