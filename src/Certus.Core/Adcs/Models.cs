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
/// The algorithm the template requires, read out of
/// <c>msPKI-RA-Application-Policies</c> on templates that carry the CNG
/// triples, or inferred from the legacy <c>pKIDefaultCSPs</c> list on the
/// older schemas that have no algorithm field at all. See
/// <see cref="RaApplicationPolicies"/> for which is which, and note that
/// <c>msPKI-Asymmetric-Algorithm</c> is a property inside that attribute and
/// not an attribute of its own: reading it as one is what made every ECDSA
/// template report RSA (issue #213).
/// <c>null</c> means the algorithm could not be determined and no guess was
/// substituted. Callers must not read that as RSA.
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
        int? schemaVersion,
        int? privateKeyFlags,
        IReadOnlyList<string> raApplicationPolicies,
        IReadOnlyList<string> defaultCsps,
        int? minimalKeySize)
    {
        return new TemplateAcmeViability(
            RequiresManagerApproval: enrollmentFlags is { } ef ? (ef & PendAllRequestsFlag) != 0 : null,
            RequiresRaSignatures: raSignatureCount is { } ra ? ra > 0 : null,
            SubjectSuppliedInRequest: certificateNameFlags is { } nf ? (nf & EnrolleeSuppliesSubjectFlag) != 0 : null,
            KeyAlgorithm: ResolveKeyAlgorithm(schemaVersion, privateKeyFlags, raApplicationPolicies, defaultCsps),
            MinimalKeySize: minimalKeySize);
    }

    /// <summary>
    /// Resolve the algorithm from whichever of the two sources this template's
    /// schema actually uses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A template carrying the CNG triples is answered from those alone. When
    /// they hold no algorithm the answer is <c>null</c>, deliberately: the
    /// legacy CSP inference below cannot see an elliptic curve, so falling
    /// through to it would answer "RSA" for a template we simply failed to
    /// read. That substitution is the whole of issue #213, and an honest
    /// "could not determine" is what the wizard and the enroller are built to
    /// handle.
    /// </para>
    /// <para>
    /// The older schemas have no algorithm field at all, so their CSP names
    /// are the only signal there has ever been. Every CryptoAPI provider of
    /// that era is RSA except the DSS ones, and none of them is elliptic
    /// curve, so the inference is sound there in a way it is not above.
    /// </para>
    /// </remarks>
    internal static string? ResolveKeyAlgorithm(
        int? schemaVersion,
        int? privateKeyFlags,
        IReadOnlyList<string> raApplicationPolicies,
        IReadOnlyList<string> defaultCsps)
    {
        if (RaApplicationPolicies.UsesCngTripleSyntax(schemaVersion, privateKeyFlags))
        {
            return RaApplicationPolicies.TryGetAsymmetricAlgorithm(raApplicationPolicies, out var algorithm)
                ? algorithm
                : null;
        }

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
/// <param name="Message">
/// The CA's own account of what it decided, verbatim. Do not assume it explains
/// anything: the lab CA answers a template Enroll denial with the bare string
/// "Denied by Policy Module" and no reason after it, which is the whole of issue
/// #356. <paramref name="StatusCode"/> is where the reason actually lives.
/// </param>
/// <param name="StatusCode">
/// The HRESULT the CA recorded against the request, from
/// <c>ICertRequest::GetLastStatus</c>. The same value
/// <c>certutil -view -restrict "RequestId=N" -out "Request.StatusCode"</c>
/// reports and the same one <see cref="CertificateInfo.StatusCode"/> carries out
/// of the CA view, so one refusal reads the same whichever way it is read back.
/// Interpret it through <see cref="CaStatusCode"/>.
///
/// Null in three cases, and no caller may distinguish them: the request was not
/// refused, so nothing was asked for; the CA recorded zero, which means success
/// and never carries information; or the read failed. The third is deliberate.
/// Reading this is a diagnostic, and a diagnostic that could turn a decided
/// request into a failed one would cost more than it buys.
///
/// "Not refused" covers pending as well as issued. A pending request is waiting
/// on a person rather than failing, so there is no reason behind it to report,
/// and both pending arms say so in their own words instead.
/// </param>
public sealed record SubmitResult(
    int RequestId,
    SubmitStatus Status,
    string? Message = null,
    int? StatusCode = null);

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
/// What the CA recorded against one request, read back from the CA view by
/// request id (issue #365).
///
/// The read side counterpart to the pair <see cref="SubmitResult"/> carries. A
/// submit learns why a request was refused from
/// <c>ICertRequest::GetLastStatus</c>, which reflects only that call; a refusal
/// discovered later, by the pending issuance sweep, has to read the same two
/// values out of the request row instead. They are the same values
/// <c>certutil -view -restrict "RequestId=N"
/// -out "Request.DispositionMessage,Request.StatusCode"</c> reports, so one
/// refusal reads the same whichever way it is discovered.
/// </summary>
/// <param name="DispositionMessage">
/// The CA's own account of what happened to the request, verbatim and
/// sanitized. Null on issued and revoked rows, where the CA supplies no
/// explanation worth showing, and null when it recorded none.
/// </param>
/// <param name="StatusCode">
/// The HRESULT the CA recorded against the request. Null on issued and revoked
/// rows, and null when the CA recorded zero, which means success and never
/// carries information. Interpret it through <see cref="CaStatusCode"/>.
/// </param>
public sealed record CaRequestStatus(
    int RequestId,
    CertificateStatus Status,
    string? DispositionMessage = null,
    int? StatusCode = null);

/// <summary>
/// Cryptographic detail read out of a certificate's DER encoding by
/// <see cref="CertificateDerParser"/>. Every member is nullable: a certificate
/// need not carry an EKU or key usage extension, and an algorithm whose
/// strength is not a modulus or curve size has no key size to report.
///
/// Codes are stored exactly as the certificate carries them (OIDs, the RFC 5280
/// key usage bit field) and are labelled for display in the dashboard, the same
/// way revocation reason codes are. Persisting resolved names instead would bake
/// the CA host's Windows locale into the database, because Oid.FriendlyName
/// answers from the operating system's OID table.
/// </summary>
/// <param name="KeyAlgorithm">
/// A short stable token for the subject public key algorithm ("RSA", "ECDSA"),
/// or the raw algorithm OID when it is not one we name.
/// </param>
/// <param name="KeySizeBits">Key size in bits, or null when it does not apply.</param>
/// <param name="SignatureAlgorithmOid">The signature algorithm OID.</param>
/// <param name="Sha256Thumbprint">Uppercase hex SHA-256 thumbprint, not the SHA-1 one.</param>
/// <param name="ExtendedKeyUsageOids">EKU OIDs in certificate order, joined with ", ".</param>
/// <param name="KeyUsage">The raw X509KeyUsageFlags bit field.</param>
public sealed record CertificateCryptoDetail(
    string? KeyAlgorithm,
    int? KeySizeBits,
    string? SignatureAlgorithmOid,
    string? Sha256Thumbprint,
    string? ExtendedKeyUsageOids,
    int? KeyUsage);

/// <summary>
/// Summary information about a certificate from the CA database.
/// </summary>
/// <param name="CryptoDetail">
/// Detail parsed from the certificate's own DER, which the CA view already
/// returns in its RawCertificate column, so populating it costs no extra CA
/// round trip. Null when the row carried no certificate blob or the blob did
/// not decode; the sync treats that as "nothing new to say" and leaves any
/// detail it captured on an earlier pass alone.
/// </param>
/// <param name="DispositionMessage">
/// The CA's own explanation of what happened to the request, verbatim. Null on
/// issued and revoked rows, where the CA supplies no explanation worth showing.
/// </param>
/// <param name="StatusCode">
/// The HRESULT the CA recorded against the request. Null on issued and revoked
/// rows, and null when the CA recorded zero, which means success.
/// </param>
/// <param name="RawCertificate">
/// The certificate's DER encoding, the same bytes <paramref name="CryptoDetail"/>
/// was parsed from, carried through so the sync can persist them for the single
/// certificate download (issue #158). Non null only when those bytes decoded as
/// a certificate, so an undecodable blob is never stored. Null exactly when
/// <paramref name="CryptoDetail"/> is null, and treated the same way: nothing
/// new to say, leave whatever an earlier pass captured alone.
/// </param>
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
    int? RevokedReason = null,
    CertificateCryptoDetail? CryptoDetail = null,
    string? DispositionMessage = null,
    int? StatusCode = null,
    byte[]? RawCertificate = null);

/// <summary>
/// Query parameters for searching the CA certificate database.
/// </summary>
/// <param name="SubmittedAfter">
/// Restricts the view to requests submitted at or after this instant. The
/// certificate sync uses it to bound how far back the pending pass reaches,
/// since that disposition accumulates without limit on a busy CA while the
/// issued inventory is what the dashboard is actually for.
/// </param>
/// <param name="ResolvedAfter">
/// Restricts the view to requests the CA decided at or after this instant.
/// The sync bounds its denied and failed passes on this rather than
/// <paramref name="SubmittedAfter"/> (issue #187): a request submitted before
/// the history window and denied inside it is invisible to a SubmittedWhen
/// bound, so its local row would say Pending forever. A pending request has
/// no ResolvedWhen yet, so this bound must never be applied to the pending
/// pass or it returns nothing.
/// </param>
/// <param name="AlreadyDetailed">
/// CA request IDs for which the caller already holds everything the
/// certificate's own DER would yield, so the client may skip decoding and
/// parsing that row's RawCertificate blob (issue #184). A row named here comes
/// back with null SubjectAlternativeNames, null CryptoDetail and null
/// RawCertificate, which is the same "this pass had nothing to say" shape a row
/// whose blob was absent has always produced, and which every writer in
/// <c>CertificateSyncService.UpdateEntity</c> already guards against.
///
/// It is the caller's job to be sure of that claim. The sync derives the set
/// from the columns the parse feeds rather than from a single sentinel, because
/// those columns arrived in separate migrations and a row can legitimately hold
/// some but not others; see <c>CertificateSyncService.ReadAlreadyDetailedAsync</c>.
///
/// Ignored when <paramref name="SubjectContains"/> is set. That filter runs on
/// the mapped subject, and the parse is the last link in the subject fallback
/// chain, so honouring both would let a search see a different subject for a
/// skipped row than for an unskipped one.
///
/// Null, the default, means parse every row.
/// </param>
public sealed record CertificateQuery(
    string? TemplateName = null,
    string? SubjectContains = null,
    CertificateStatus? Status = null,
    DateTime? ExpiringBefore = null,
    int Skip = 0,
    int Take = 50,
    DateTime? SubmittedAfter = null,
    DateTime? ResolvedAfter = null,
    IReadOnlySet<int>? AlreadyDetailed = null);
