namespace Certus.Core.Data.Entities;

/// <summary>
/// An issued certificate stored for ACME download.
/// Contains the PEM certificate chain returned to ACME clients.
/// </summary>
public class AcmeCertificate
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>Public facing certificate ID used in download URLs.</summary>
    public string CertificateId { get; set; } = string.Empty;

    /// <summary>FK to the order that produced this certificate.</summary>
    public int OrderId { get; set; }

    /// <summary>Navigation property to the order.</summary>
    public AcmeOrder Order { get; set; } = null!;

    /// <summary>
    /// The full PEM certificate chain (leaf + intermediates).
    /// Content-Type: application/pem-certificate-chain
    /// </summary>
    public string CertificatePem { get; set; } = string.Empty;

    /// <summary>The ADCS request ID for cross reference.</summary>
    public int AdcsRequestId { get; set; }

    /// <summary>
    /// The leaf certificate serial number in hexadecimal, as returned by
    /// <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2.SerialNumber"/>
    /// (uppercase, big endian, no separators). Used to locate this row when an ACME client
    /// submits the certificate for revocation (RFC 8555 §7.6), which carries the certificate
    /// itself rather than a certificate ID.
    /// </summary>
    public string SerialNumber { get; set; } = string.Empty;

    public DateTime IssuedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the certificate was revoked, or null while it is still valid. While it is set, a
    /// second revocation attempt returns <c>alreadyRevoked</c> (RFC 8555 §7.6).
    ///
    /// <para>
    /// Only ever written after the CA has confirmed the revocation, which is what lets
    /// <c>CertificateSyncService.ClearReleasedRevocationStampsAsync</c> clear it again on the
    /// one occasion it may be cleared: the CA reporting the certificate released from
    /// CertificateHold (issue #375). Treat it as the CA's answer, not as a local flag.
    /// </para>
    /// </summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// The CRL reason code the certificate was revoked with (RFC 5280 §5.3.1), or null while
    /// it is still valid.
    /// </summary>
    public int? RevokedReason { get; set; }
}
