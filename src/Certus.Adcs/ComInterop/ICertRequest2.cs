using System.Runtime.InteropServices;

namespace Certus.Adcs.ComInterop;

// COM interop for the CCertRequest coclass.
//
// History:
//   - Issue #9 (114bc4d) switched ICertRequest2 from InterfaceIsDual to
//     InterfaceIsIUnknown so calls would dispatch through the vtable instead
//     of IDispatch::Invoke (which had failed for GetCAProperty).
//   - Issue #13 (49c1cfb) corrected an IID typo in ICertRequest2.
//   - Issue #14 (66973a7) found that the deployed certcli.dll on Windows
//     Server 2025 (10.0.26100.1) does not expose IID_ICertRequest2 to
//     QueryInterface. v2-only methods (GetCAProperty, GetIssuedCertificate)
//     were routed through IDispatch via C# `dynamic`; v1 methods were left as
//     typed vtable calls on a [InterfaceType(InterfaceIsIUnknown)] declaration.
//   - Issue #15: ICertRequest (v1) is a dual interface (inherits IDispatch).
//     The InterfaceIsIUnknown declaration placed the C# methods four vtable
//     slots short of the real custom-method offset. Subsequent typed calls
//     would dispatch into the IDispatch slot range and crash. The interface
//     declaration has been removed; AdcsClient now calls every CCertRequest
//     method through IDispatch via `dynamic`.

/// <summary>
/// COM coclass for CCertRequest. Instantiates the DCOM client for ADCS
/// certificate requests. Method calls are dispatched via IDispatch from
/// AdcsClient using C# `dynamic`.
/// </summary>
[ComImport]
[Guid("98aff3f0-5524-11d0-8812-00a0c903b83c")]
internal class CertRequestClass
{
}
