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
/// carries an actionable message naming the exact fix, which differs per path:
/// one message constant per path, below.
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
        "If enrollment is refused with this permission already granted, the CA may refuse remote " +
        "requests altogether (the IF_NOREMOTEICERTREQUEST interface flag); also check Enroll on the " +
        "Security tab of the certificate template itself, which is a separate access control list.";

    /// <summary>
    /// Operator facing remediation message for collecting an issued certificate
    /// (ICertRequest::GetIssuedCertificate), issues #336 and #477.
    ///
    /// It named 'Read' until issue #477, which was the wrong right, for the reason
    /// <see cref="CrlReadPermissionMessage"/> was. Measured on lab 2025 on
    /// 2026-10-03: the account's own request was collected with Request
    /// Certificates alone, and refused with CERTSRV_E_ENROLL_DENIED under Read
    /// with Request Certificates denied. Granting Read would not have fixed it.
    ///
    /// Two callers read it, so it is worded for both. The ACME finalize and the
    /// pending issuance sweep leave the order processing and collect it once the
    /// right is back. The server's own HTTPS enrolment has no order to come back
    /// to, so its certificate stays at the CA and the enrolment has to be run
    /// again.
    /// </summary>
    public const string CollectPermissionMessage =
        "CA collection access denied: the CA refused the Ducks in a Row service account when it asked " +
        "for a certificate the CA has already issued (ICertRequest::GetIssuedCertificate). Grant the " +
        "service account 'Request Certificates' on the CA via the Certificate Authority console " +
        "(CA Properties -> Security); Authenticated Users hold it on a default CA. The certificate itself " +
        "is safe at the CA: an ACME order waiting for it is collected automatically once this is fixed, " +
        "and an HTTPS certificate enrolment has to be run again. If the right is already granted, the CA " +
        "may refuse remote requests altogether (the IF_NOREMOTEICERTREQUEST interface flag).";

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

    /// <summary>
    /// Operator facing remediation message for reading the templates the CA
    /// publishes (ICertRequest::GetCAProperty, CR_PROP_TEMPLATES), issues #467
    /// and #476.
    ///
    /// Its own constant rather than <see cref="ConnectPermissionMessage"/>, which
    /// opens by describing the connection test, because this is read long after
    /// setup: by the ACME template gate on every request, by the dashboard and by
    /// the wizard. Named for what stops, like the others. The right is the one
    /// lab 2019 (#440) and lab 2025 (#469) measured for property 29 on the request
    /// interface. Issue #531 may move this read to the admin interface, which
    /// answers it to Read instead, and this message moves with it.
    /// </summary>
    public const string TemplateReadPermissionMessage =
        "CA template list access denied: the CA refused the Ducks in a Row service account when it asked " +
        "for the certificate templates the CA publishes (ICertRequest::GetCAProperty). Grant the service " +
        "account 'Request Certificates' on the CA via the Certificate Authority console " +
        "(CA Properties -> Security); Authenticated Users hold it on a default CA. Until then the template " +
        "lists cannot load, and a server that issues turns ACME clients away. If the right is already " +
        "granted, the CA may refuse remote requests altogether (the IF_NOREMOTEICERTREQUEST interface flag).";

    /// <summary>
    /// Operator facing remediation message for reading the CA's own signing
    /// certificate chain (ICertRequest::GetCAProperty, CR_PROP_CASIGCERTCOUNT and
    /// CR_PROP_CASIGCERTCHAIN), issues #467 and #476.
    ///
    /// The same right as <see cref="TemplateReadPermissionMessage"/>, measured for
    /// properties 11 and 13 on lab 2025 (#469), and the same note about issue
    /// #531 applies. Kept apart because what stops is different: the chain feeds
    /// the CA certificate downloads, the ACME issuer certificate link and the
    /// CRL watch's view of which CA it is watching.
    /// </summary>
    public const string ChainReadPermissionMessage =
        "CA certificate chain access denied: the CA refused the Ducks in a Row service account when it asked " +
        "for the CA's own certificate chain (ICertRequest::GetCAProperty). Grant the service account " +
        "'Request Certificates' on the CA via the Certificate Authority console (CA Properties -> Security); " +
        "Authenticated Users hold it on a default CA. Until then the CA certificate downloads and the ACME " +
        "issuer certificate link fail. If the right is already granted, the CA may refuse remote requests " +
        "altogether (the IF_NOREMOTEICERTREQUEST interface flag).";

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
