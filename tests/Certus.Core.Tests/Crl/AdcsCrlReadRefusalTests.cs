using System.Runtime.InteropServices;
using Certus.Adcs.Crl;
using Certus.Core.Adcs;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// Which COM failures of a CRL read mean the CA refused the service (issue
/// #440). A refusal carries <see cref="CaAccessDeniedException.CrlReadPermissionMessage"/>,
/// which names Request Certificates. Anything else is an outage or a fault,
/// and must not send the operator off to change a permission.
/// </summary>
public class AdcsCrlReadRefusalTests
{
    [Fact]
    public void EnrollDenied_IsARefusal()
    {
        // What lab 2019 answered the first CRL property read with, for an
        // account holding Read but not Request Certificates (2026-09-26).
        AdcsCrlReader.IsRefusal(new COMException("enroll denied", CaStatusCode.EnrollDenied))
            .Should().BeTrue();
    }

    [Fact]
    public void AccessDenied_IsARefusal()
    {
        AdcsCrlReader.IsRefusal(new COMException("denied", CaAccessDeniedException.AccessDeniedHResult))
            .Should().BeTrue();
    }

    [Theory]
    [InlineData(unchecked((int)0x800706BA))] // RPC server unavailable, an outage
    [InlineData(unchecked((int)0x80004005))] // E_FAIL, a fault
    public void AnythingElse_IsNotARefusal(int hresult)
    {
        AdcsCrlReader.IsRefusal(new COMException("other", hresult)).Should().BeFalse();
    }
}
