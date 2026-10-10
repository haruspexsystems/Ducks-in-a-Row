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
        "CA view access denied: the Ducks in a Row service account lacks 'Read' permission on the CA. " +
        "Grant 'Read' to the service account via the Certificate Authority console " +
        "(CA Properties -> Security) to enable dashboard certificate sync (ICertView). " +
        "This permission is separate from certificate request/submission, which is why " +
        "enrollment works while sync fails.";

    /// <summary>
    /// Operator facing remediation message for the certificate revocation path (ICertAdmin).
    /// </summary>
    public const string RevokePermissionMessage =
        "CA revoke access denied: the Ducks in a Row service account lacks 'Issue and Manage Certificates' " +
        "permission on the CA. Grant it to the service account via the Certificate Authority console " +
        "(CA Properties -> Security) to enable ACME certificate revocation (ICertAdmin::RevokeCertificate). " +
        "This permission is separate from certificate request/submission, which is why " +
        "enrollment works while revocation fails.";

    /// <summary>
    /// Operator facing remediation message for the certificate submission path
    /// (ICertRequest::Submit), issue #336.
    ///
    /// Distinct from the denial a CA policy module issues, which is the commoner
    /// shape by far and does not throw at all: a template the account cannot enroll
    /// against comes back as a Denied disposition, whose message on the lab CA is
    /// the bare string "Denied by Policy Module" with no reason after it.
    /// This message is for the rarer case where the CA refuses the call itself, so
    /// it names the CA level right rather than the template level one.
    /// </summary>
    public const string EnrollPermissionMessage =
        "CA request access denied: the Ducks in a Row service account lacks 'Request Certificates' " +
        "permission on the CA. Grant it to the service account via the Certificate Authority console " +
        "(CA Properties -> Security) to enable certificate enrollment (ICertRequest::Submit). " +
        "If enrollment is refused with this permission already granted, check Enroll on the " +
        "Security tab of the certificate template itself, which is a separate access control list.";

    /// <summary>
    /// Operator facing remediation message for collecting an issued certificate
    /// (ICertRequest::GetIssuedCertificate), issue #336.
    ///
    /// Deliberately not <see cref="SyncReadPermissionMessage"/>, even though the two
    /// name the same CA level right. That one is written for ICertView and tells the
    /// operator dashboard sync is what is broken, which would misdescribe this: here
    /// the certificate exists and ACME issuance is what cannot finish.
    /// </summary>
    public const string CollectPermissionMessage =
        "CA collection access denied: the Ducks in a Row service account lacks 'Read' permission " +
        "on the CA, so a certificate the CA has already issued cannot be retrieved. Grant 'Read' " +
        "to the service account via the Certificate Authority console (CA Properties -> Security) " +
        "to let ACME orders complete (ICertRequest::GetIssuedCertificate). The certificate itself " +
        "is safe at the CA and the order is collected automatically once this is fixed.";

    /// <summary>
    /// Operator facing remediation message for reading the CA's own CRLs
    /// (ICertRequest::GetCAProperty), issue #447.
    ///
    /// Named for what stops rather than for the right, like the two above: an
    /// operator told that sync is broken would look in the wrong place when what
    /// went quiet is the warning that a CRL is about to expire.
    ///
    /// It named 'Read' until issue #440, which was the wrong right. These reads go
    /// through the request interface, and on lab 2019 on 2026-09-26 an account
    /// holding Read with Request Certificates denied was refused them with
    /// CERTSRV_E_ENROLL_DENIED, while an account holding only Request
    /// Certificates read them. Granting Read would not have fixed anything.
    /// </summary>
    public const string CrlReadPermissionMessage =
        "CA property access denied: the Ducks in a Row service account lacks 'Request Certificates' " +
        "permission on the CA, so the CA's own certificate revocation lists cannot be read and nothing " +
        "will warn before one expires. The CA answers these reads only to an account holding that right, " +
        "which Authenticated Users hold on a default CA. Grant it to the service account via the " +
        "Certificate Authority console (CA Properties -> Security). Certificates published to a " +
        "distribution point are still read from there, so some of the picture survives this.";

    /// <summary>
    /// Operator facing remediation message for reading the CA's own properties
    /// through the request interface (ICertRequest::GetCAProperty), which is what
    /// the setup wizard's Test Connection does, issue #440.
    ///
    /// [MS-CSRA] lists that call under the CA's Enroll right, the one the console
    /// calls Request Certificates, rather than under Read. The same interface
    /// carries the template list, the CA certificate downloads and the CRL
    /// reads, so a refusal here reaches all of them.
    /// </summary>
    public const string ConnectPermissionMessage =
        "CA connection access denied: the CA refused the Ducks in a Row service account at its request " +
        "interface (ICertRequest::GetCAProperty). Grant the service account 'Request Certificates' on the CA " +
        "via the Certificate Authority console (CA Properties -> Security). The connection test, the template " +
        "list, the CA certificate downloads and CRL watching all read through this interface. If the right is " +
        "already granted, the CA may refuse remote requests altogether (the IF_NOREMOTEICERTREQUEST interface flag).";

    public CaAccessDeniedException(string message, Exception inner)
        : base(message, inner) { }

    /// <summary>
    /// True when a COMException carries the E_ACCESSDENIED HRESULT. The dynamic
    /// IDispatch path usually surfaces access denied as UnauthorizedAccessException,
    /// but a COMException with the same HRESULT is possible depending on the call.
    /// </summary>
    public static bool IsAccessDenied(COMException ex)
        => ex.HResult == AccessDeniedHResult;

    /// <summary>
    /// True when a COMException from the CA's request interface means the CA
    /// refused the service: E_ACCESSDENIED, or CERTSRV_E_ENROLL_DENIED, which that
    /// interface answers to an account without Request Certificates (measured on
    /// lab 2019 on 2026-09-26, issue #440) and to every account when the CA
    /// refuses remote requests (IF_NOREMOTEICERTREQUEST). Every catch on a path
    /// that reads through the request interface should decide with this, so a
    /// missing right is never reported as a generic failure.
    /// </summary>
    public static bool IsRefusal(COMException ex)
        => IsAccessDenied(ex) || ex.HResult == CaStatusCode.EnrollDenied;
}
