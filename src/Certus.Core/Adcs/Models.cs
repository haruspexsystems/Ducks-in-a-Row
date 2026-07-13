namespace Certus.Core.Adcs;

/// <summary>
/// Information about a connected Certificate Authority.
/// </summary>
public sealed record CaInfo(
    string Name,
    string DnsName,
    string? DisplayName,
    bool IsAccessible);

/// <summary>
/// Information about an ADCS certificate template.
/// </summary>
/// <param name="Name">Programmatic template name (the AD <c>cn</c>, no spaces).</param>
/// <param name="DisplayName">Human readable name from the AD <c>displayName</c>.</param>
/// <param name="Oid">The template OID (not an EKU OID).</param>
/// <param name="ExtendedKeyUsages">
/// The resolved Extended Key Usage OIDs from the AD <c>pKIExtendedKeyUsage</c> attribute.
/// <c>null</c> means the EKU set could not be resolved (host not domain joined, AD unreachable,
/// or the template object was not found); callers treat that as "unverified", not "no EKU".
/// An empty list means the EKU set was resolved and the template carries no EKU restriction.
/// </param>
/// <param name="Viability">
/// ACME viability signals read from the same AD object. <c>null</c> when the
/// template object could not be read at all, same contract as
/// <paramref name="ExtendedKeyUsages"/>.
/// </param>
public sealed record TemplateInfo(
    string Name,
    string DisplayName,
    string Oid,
    IReadOnlyList<string>? ExtendedKeyUsages = null,
    TemplateAcmeViability? Viability = null);

/// <summary>
/// Whether a template's AD configuration lets ACME issuance run unattended.
/// Each member is nullable: <c>null</c> means the attribute behind it could
/// not be read, and the wizard shows "could not verify" instead of a verdict.
/// The checklist these feed is advisory; nothing here blocks setup.
/// </summary>
/// <param name="RequiresManagerApproval">
/// CT_FLAG_PEND_ALL_REQUESTS in <c>msPKI-Enrollment-Flag</c>. When set, every
/// request pends for CA manager approval, so every ACME finalize hangs.
/// </param>
/// <param name="RequiresRaSignatures">
/// <c>msPKI-RA-Signature</c> &gt; 0: requests must carry enrollment agent
/// signatures, which ACME CSRs never do, so the CA denies them.
/// </param>
/// <param name="SubjectSuppliedInRequest">
/// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT in <c>msPKI-Certificate-Name-Flag</c>.
/// When false the CA builds the subject from the requester's AD object —
/// the service's computer account, since the service submits every ACME
/// order — and every client's requested names are ignored.
/// </param>
/// <param name="KeyAlgorithm">
/// From <c>msPKI-Asymmetric-Algorithm</c> (schema v3+ templates), or
/// inferred from the legacy <c>pKIDefaultCSPs</c> list on v1/v2 templates.
/// Informational: it drives the "your client must request an RSA key" note.
/// </param>
/// <param name="MinimalKeySize">From <c>msPKI-Minimal-Key-Size</c>.</param>
public sealed record TemplateAcmeViability(
    bool? RequiresManagerApproval,
    bool? RequiresRaSignatures,
    bool? SubjectSuppliedInRequest,
    string? KeyAlgorithm,
    int? MinimalKeySize)
{
    /// <summary>CT_FLAG_PEND_ALL_REQUESTS in msPKI-Enrollment-Flag.</summary>
    private const int PendAllRequestsFlag = 0x2;

    /// <summary>CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT in msPKI-Certificate-Name-Flag.</summary>
    private const int EnrolleeSuppliesSubjectFlag = 0x1;

    /// <summary>
    /// Interpret the raw AD attribute values. Any attribute that was absent
    /// or unreadable arrives as null and stays "could not verify" in the
    /// corresponding member.
    /// </summary>
    public static TemplateAcmeViability FromAdAttributes(
        int? enrollmentFlags,
        int? raSignatureCount,
        int? certificateNameFlags,
        string? asymmetricAlgorithm,
        IReadOnlyList<string> defaultCsps,
        int? minimalKeySize)
    {
        return new TemplateAcmeViability(
            RequiresManagerApproval: enrollmentFlags is { } ef ? (ef & PendAllRequestsFlag) != 0 : null,
            RequiresRaSignatures: raSignatureCount is { } ra ? ra > 0 : null,
            SubjectSuppliedInRequest: certificateNameFlags is { } nf ? (nf & EnrolleeSuppliesSubjectFlag) != 0 : null,
            KeyAlgorithm: ResolveKeyAlgorithm(asymmetricAlgorithm, defaultCsps),
            MinimalKeySize: minimalKeySize);
    }

    /// <summary>
    /// v3+ templates name the algorithm directly. v1/v2 templates carry only
    /// legacy CSP names, all of which are RSA providers except the DSS ones,
    /// so the presence of any non DSS provider reads as RSA.
    /// </summary>
    internal static string? ResolveKeyAlgorithm(string? asymmetricAlgorithm, IReadOnlyList<string> defaultCsps)
    {
        if (!string.IsNullOrWhiteSpace(asymmetricAlgorithm))
            return asymmetricAlgorithm.Trim();

        if (defaultCsps.Count == 0)
            return null;

        return defaultCsps.All(csp => csp.Contains("DSS", StringComparison.OrdinalIgnoreCase))
            ? "DSA"
            : "RSA";
    }
}

/// <summary>
/// Result of submitting a certificate request to the CA.
/// </summary>
public sealed record SubmitResult(
    int RequestId,
    SubmitStatus Status,
    string? Message = null);

/// <summary>
/// Status of a certificate request submission.
/// </summary>
public enum SubmitStatus
{
    /// <summary>Certificate was issued immediately.</summary>
    Issued,

    /// <summary>Request is pending CA manager approval.</summary>
    Pending,

    /// <summary>Request was denied.</summary>
    Denied,

    /// <summary>An error occurred during submission.</summary>
    Error
}

/// <summary>
/// Result of retrieving a certificate from the CA.
/// </summary>
public sealed record CertificateResult(
    int RequestId,
    CertificateStatus Status,
    byte[]? CertificateDer = null,
    string? CertificatePem = null);

/// <summary>
/// Status of a certificate in the CA database.
/// </summary>
public enum CertificateStatus
{
    Issued,
    Pending,
    Denied,
    Revoked,
    Failed
}

/// <summary>
/// Summary information about a certificate from the CA database.
/// </summary>
public sealed record CertificateInfo(
    int RequestId,
    string SerialNumber,
    string Subject,
    string? SubjectAlternativeNames,
    string TemplateName,
    DateTime NotBefore,
    DateTime NotAfter,
    CertificateStatus Status,
    string? Requestor,
    DateTime RequestDate,
    DateTime? RevokedWhen = null,
    int? RevokedReason = null);

/// <summary>
/// Query parameters for searching the CA certificate database.
/// </summary>
public sealed record CertificateQuery(
    string? TemplateName = null,
    string? SubjectContains = null,
    CertificateStatus? Status = null,
    DateTime? ExpiringBefore = null,
    int Skip = 0,
    int Take = 50);
