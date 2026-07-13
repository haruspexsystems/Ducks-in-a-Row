using System.Runtime.InteropServices;

namespace Certus.Adcs.ComInterop;

// COM interop for the CCertAdmin coclass.
//
// Issue #15: the previous typed [ComImport] interface for ICertAdmin2 was
// declared [InterfaceType(InterfaceIsIUnknown)] but ICertAdmin2 is a dual
// interface (inherits IDispatch). Any future typed call would have crashed
// with the same vtable-offset access violation seen on ICertView. The
// interface declaration is removed pre-emptively; if AdcsClient later needs
// CCertAdmin functionality, dispatch through IDispatch via C# `dynamic`,
// matching the CCertRequest and CCertView pattern.

/// <summary>
/// COM coclass for CCertAdmin. Instantiates the DCOM client for CA
/// administration. Currently unused; reserved for future use.
/// </summary>
[ComImport]
[Guid("37eabaf0-7fb6-11d0-8817-00a0c903b83c")]
internal class CertAdminClass
{
}
