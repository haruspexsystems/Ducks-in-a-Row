using System.Runtime.InteropServices;

namespace Certus.Adcs.ComInterop;

// COM interop for the CCertView coclass.
//
// Issue history:
//   - Issue #14 (66973a7): IID_ICertView2 is not exposed to QueryInterface on
//     the deployed certcli.dll for the target Windows build. The v1 IID does
//     resolve, so the cast was retargeted to ICertView (v1).
//   - Issue #15: ICertView (v1) is a dual interface (inherits IDispatch). The
//     [InterfaceType(InterfaceIsIUnknown)] declaration left over from #14 placed
//     the C# methods at the wrong vtable offset; SetResultColumnCount was
//     dispatched into the IDispatch slot range and the process crashed with
//     AccessViolationException. The interface declaration has been removed.
//     AdcsClient.QueryCertificatesAsync now invokes every method through
//     IDispatch via C# `dynamic`, which resolves names through the server's
//     ITypeInfo and does not depend on managed vtable layout.

/// <summary>
/// COM coclass for CCertView. Instantiates the CA database view. Method calls
/// are dispatched via IDispatch from AdcsClient using C# `dynamic`.
/// </summary>
[ComImport]
[Guid("a12d0f7a-1e84-11d1-9bd6-00c04fb683fa")]
internal class CertViewClass
{
}
