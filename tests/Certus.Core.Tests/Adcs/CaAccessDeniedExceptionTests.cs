using System.Runtime.InteropServices;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Adcs;

/// <summary>
/// Unit tests for CaAccessDeniedException (issue #26 follow-up). The live
/// CCertView::OpenConnection access-denied path in AdcsClient.QueryCertificatesAsync
/// cannot be exercised on a dev box without a CA that denies the service account,
/// so these tests pin the mapping seam instead: the HRESULT predicate, the
/// remediation message, and the inheritance that lets existing catch sites match.
/// </summary>
public class CaAccessDeniedExceptionTests
{
    [Fact]
    public void IsAccessDenied_TrueForEAccessDeniedHResult()
    {
        var ex = new COMException("Access is denied.", unchecked((int)0x80070005));

        CaAccessDeniedException.IsAccessDenied(ex).Should().BeTrue(
            "E_ACCESSDENIED (0x80070005) is the access-denied HRESULT the CA returns");
    }

    [Fact]
    public void IsAccessDenied_FalseForOtherHResult()
    {
        // RPC server unavailable — a different failure handled by CaUnavailableException.
        var ex = new COMException("RPC server unavailable.", unchecked((int)0x800706BA));

        CaAccessDeniedException.IsAccessDenied(ex).Should().BeFalse(
            "only E_ACCESSDENIED maps to the permission remediation path");
    }

    [Fact]
    public void SyncReadPermissionMessage_NamesTheRemediation()
    {
        CaAccessDeniedException.SyncReadPermissionMessage.Should()
            .Contain("Read", "the operator must grant the 'Read' permission")
            .And.Contain("CA Properties", "the message points at the Certificate Authority console location")
            .And.Contain("sync", "the message ties the failure to dashboard certificate sync");
    }

    [Fact]
    public void IsUnauthorizedAccessException_SoExistingCatchSitesMatch()
    {
        var ex = new CaAccessDeniedException(
            CaAccessDeniedException.SyncReadPermissionMessage,
            new COMException("Access is denied.", unchecked((int)0x80070005)));

        ex.Should().BeAssignableTo<UnauthorizedAccessException>();
        ex.Message.Should().Be(CaAccessDeniedException.SyncReadPermissionMessage);
        ex.InnerException.Should().BeOfType<COMException>();
    }
}
