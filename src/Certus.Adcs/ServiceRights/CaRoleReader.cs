using System.Runtime.InteropServices;
using Certus.Adcs.ComInterop;

namespace Certus.Adcs.ServiceRights;

/// <summary>
/// Asks a CA which roles it grants the caller, through
/// <c>ICertAdmin2::GetMyRoles</c> (issue #440). Dispatched by name through
/// <c>dynamic</c> on a fresh CertAdmin coclass, like every other ADCS call in
/// this assembly (CLAUDE.md, "ADCS COM dispatch").
///
/// Read only: [MS-CSRA] gates it on Read, which Enroll, Officer and
/// Administrator all imply, and it changes nothing on the CA. One object per
/// call, because the documentation warns that GetMyRoles keeps its answer for
/// the first configuration string an object was given.
///
/// Raw exceptions come out; the caller maps them. Also compiled into
/// tools/AdcsQiProbe, so keep it to the base class library and C# 12.
/// </summary>
internal static class CaRoleReader
{
    /// <summary>The CA_ACCESS bit mask the CA reports for the calling account.</summary>
    public static int ReadMyRoles(string caConnectionString)
    {
        object? certAdmin = null;
        try
        {
            certAdmin = new CertAdminClass();
            dynamic d = certAdmin;
            return (int)d.GetMyRoles(caConnectionString);
        }
        finally
        {
            if (certAdmin != null && Marshal.IsComObject(certAdmin))
                Marshal.FinalReleaseComObject(certAdmin);
        }
    }
}
