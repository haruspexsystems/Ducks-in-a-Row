namespace Certus.Core.Adcs;

/// <summary>
/// Abstraction over ADCS Certificate Authority operations.
/// Implemented by COM interop in Certus.Adcs and by mocks in tests.
/// </summary>
public interface IAdcsClient
{
    /// <summary>
    /// Gets information about the connected Certificate Authority.
    /// </summary>
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
    Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName,
        byte[] csrDer,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves an issued certificate by its CA request ID.
    /// </summary>
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
