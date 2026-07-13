using System.Runtime.InteropServices;

namespace Certus.Core.Adcs;

/// <summary>
/// Thrown when an ADCS operation is rejected with E_ACCESSDENIED (0x80070005),
/// typically because the Certus service account lacks the required permission on
/// the CA. The dashboard certificate sync reads the CA database through
/// CCertView::OpenConnection, whose ACL is separate from the request/submission
/// ACL: the service can enroll certificates yet still be denied the view, which
/// is why sync fails while ACME issuance succeeds.
///
/// Inherits from UnauthorizedAccessException so existing catch sites match, but
/// carries an actionable message naming the exact fix (grant "Read" on the CA).
/// </summary>
public sealed class CaAccessDeniedException : UnauthorizedAccessException
{
    public const int AccessDeniedHResult = unchecked((int)0x80070005);

    /// <summary>
    /// Operator-facing remediation message for the certificate-sync view path.
    /// </summary>
    public const string SyncReadPermissionMessage =
        "CA view access denied: the Certus service account lacks 'Read' permission on the CA. " +
        "Grant 'Read' to the service account via the Certificate Authority console " +
        "(CA Properties -> Security) to enable dashboard certificate sync (ICertView). " +
        "This permission is separate from certificate request/submission, which is why " +
        "enrollment works while sync fails.";

    /// <summary>
    /// Operator facing remediation message for the certificate revocation path (ICertAdmin).
    /// </summary>
    public const string RevokePermissionMessage =
        "CA revoke access denied: the Certus service account lacks 'Issue and Manage Certificates' " +
        "permission on the CA. Grant it to the service account via the Certificate Authority console " +
        "(CA Properties -> Security) to enable ACME certificate revocation (ICertAdmin::RevokeCertificate). " +
        "This permission is separate from certificate request/submission, which is why " +
        "enrollment works while revocation fails.";

    public CaAccessDeniedException(string message, Exception inner)
        : base(message, inner) { }

    /// <summary>
    /// True when a COMException carries the E_ACCESSDENIED HRESULT. The dynamic
    /// IDispatch path usually surfaces access denied as UnauthorizedAccessException,
    /// but a COMException with the same HRESULT is possible depending on the call.
    /// </summary>
    public static bool IsAccessDenied(COMException ex)
        => ex.HResult == AccessDeniedHResult;
}
