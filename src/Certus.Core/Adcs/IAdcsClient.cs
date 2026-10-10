namespace Certus.Core.Adcs;

/// <summary>
/// Abstraction over ADCS Certificate Authority operations.
/// Implemented by COM interop in Certus.Adcs and by mocks in tests.
/// </summary>
public interface IAdcsClient
{
    /// <summary>
    /// Gets information about the connected Certificate Authority. This is the
    /// setup wizard's Test Connection. Any other failure still answers with
    /// <see cref="CaInfo.IsAccessible"/> false rather than throwing.
    /// </summary>
    /// <exception cref="CaAccessDeniedException">
    /// The CA refused the service account, carrying
    /// <see cref="CaAccessDeniedException.ConnectPermissionMessage"/> (issue #440).
    /// </exception>
    /// <exception cref="CaUnavailableException">The CA could not be reached, or none is configured.</exception>
    Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists certificate templates available on the CA.
    /// </summary>
    Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Submits a certificate signing request to the CA.
    /// </summary>
    /// <param name="templateName">The ADCS template to issue against.</param>
    /// <param name="csrDer">The DER-encoded PKCS#10 certificate signing request.</param>
    /// <returns>A result containing the request ID and initial status.</returns>
    /// <exception cref="CaUnavailableException">
    /// The CA was not reached, and therefore no request was created for this CSR.
    /// That is a promise about state, not only about connectivity: a caller may
    /// retry the same CSR, and the ACME finalize relies on it to release its claim
    /// on an order rather than invalidate it (issue #324). An implementation whose
    /// submission fails after the CA has accepted the request must throw something
    /// else, so the caller invalidates and logs the orphan instead.
    /// </exception>
    /// <exception cref="CaAccessDeniedException">
    /// The CA was reached and refused this service's own credentials, and therefore
    /// no request was created for this CSR. Carries the identical promise about state
    /// that <see cref="CaUnavailableException"/> does above, for the identical reason:
    /// the ACME finalize releases its claim on the order rather than invalidating it,
    /// so the client can retry the same order once an administrator grants the
    /// permission (issue #336). An implementation must not raise it once the CA has
    /// accepted the request.
    ///
    /// Not the same thing as the CA deciding against a request. A template the account
    /// cannot enroll against is refused by the CA's policy module and comes back as
    /// <see cref="SubmitStatus.Denied"/>, whose message may say very little: the lab CA
    /// answers the bare "Denied by Policy Module". That is still a decision, it is the
    /// commoner case by far, and it must not be raised as this exception.
    /// </exception>
    Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName,
        byte[] csrDer,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves an issued certificate by its CA request ID.
    /// </summary>
    /// <exception cref="CaAccessDeniedException">
    /// The CA was reached and refused this service's credentials, so the certificate
    /// could not be collected. Makes no promise about state and needs none: this call
    /// decides nothing and writes nothing, and the request stays exactly as it was at
    /// the CA. A caller holding an order for it must leave that order alone and let
    /// the pending issuance sweep collect it once the permission is restored; failing
    /// the order instead would strand a live certificate (issue #336).
    /// </exception>
    Task<CertificateResult> GetCertificateAsync(
        int requestId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Queries the CA database for certificates matching the given criteria.
    /// </summary>
    Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// What the CA recorded against one request, by request id (issue #365).
    /// Returns null when the CA has no such row.
    ///
    /// <para>
    /// A diagnostic, and never a basis for a decision. It exists so a refusal
    /// discovered after the submit can be reported with the same detail the
    /// submit's own refusal carries, which
    /// <see cref="SubmitResult.StatusCode"/> reads from
    /// <c>ICertRequest::GetLastStatus</c> and this reads from the request row.
    /// A caller on a decision path must catch everything this can throw and
    /// carry on without the detail, because a diagnostic that could turn a
    /// decided request into an undecided one would cost more than it buys.
    /// </para>
    ///
    /// <para>
    /// A single row identified by its primary key, so no disposition
    /// restriction applies and every disposition is visible. That is the
    /// difference from <see cref="QueryCertificatesAsync"/>, which confines an
    /// unqualified query to issued rows.
    /// </para>
    /// </summary>
    /// <exception cref="CaAccessDeniedException">
    /// The CA was reached and refused this service's credentials. This is a CA
    /// view read, so it needs the same "Read" right the certificate sync needs
    /// and reports it with the same message, not the collection one.
    /// </exception>
    /// <exception cref="CaUnavailableException">
    /// The CA could not be reached, or none is configured.
    /// </exception>
    Task<CaRequestStatus?> GetRequestStatusAsync(
        int requestId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the CA's signing certificate chain as DER blobs, ordered from
    /// the CA's own certificate up to the self signed root (a single element
    /// for a one tier CA). Maps to <c>GetCAProperty</c> with
    /// <c>CR_PROP_CASIGCERTCHAIN</c> for the newest CA certificate. Used by
    /// the settings page trust anchor downloads.
    /// </summary>
    Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a certificate on the CA by its serial number.
    /// Maps to <c>ICertAdmin::RevokeCertificate</c>. RFC 8555 §7.6.
    /// </summary>
    /// <param name="serialNumber">
    /// The certificate serial number in hexadecimal (as the CA database stores it).
    /// </param>
    /// <param name="reason">The CRL revocation reason code (RFC 5280 §5.3.1).</param>
    Task RevokeCertificateAsync(
        string serialNumber,
        int reason,
        CancellationToken cancellationToken = default);
}
