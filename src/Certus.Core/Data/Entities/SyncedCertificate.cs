namespace Certus.Core.Data.Entities;

/// <summary>
/// A certificate record synced from the ADCS CA database.
/// Provides full visibility into ALL certificates issued by the CA,
/// not just those issued through the ACME proxy.
/// Updated periodically by the CertificateSyncService.
/// </summary>
public class SyncedCertificate
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>
    /// The CA request ID — unique identifier from the ADCS database.
    /// </summary>
    public int RequestId { get; set; }

    /// <summary>Certificate serial number (hex string).</summary>
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>Certificate subject DN (e.g., CN=server.example.com).</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>
    /// Subject Alternative Names, comma separated.
    /// E.g., "dns:server.example.com, dns:www.example.com"
    /// </summary>
    public string? SubjectAlternativeNames { get; set; }

    /// <summary>The ADCS certificate template used to issue this cert.</summary>
    public string TemplateName { get; set; } = string.Empty;

    /// <summary>Certificate validity start date.</summary>
    public DateTime NotBefore { get; set; }

    /// <summary>Certificate expiration date.</summary>
    public DateTime NotAfter { get; set; }

    /// <summary>
    /// Certificate status: Issued, Pending, Denied, Revoked, Failed.
    /// </summary>
    public string Status { get; set; } = string.Empty;

    /// <summary>The user/entity that requested this certificate.</summary>
    public string? Requestor { get; set; }

    /// <summary>When the certificate request was submitted.</summary>
    public DateTime RequestDate { get; set; }

    /// <summary>When the CA revoked this certificate, or null while it is not revoked.</summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>The CRL reason code the CA recorded (RFC 5280 5.3.1), or null.</summary>
    public int? RevokedReason { get; set; }

    /// <summary>When this record was first synced from the CA.</summary>
    public DateTime FirstSyncedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this record was last updated from the CA.</summary>
    public DateTime LastSyncedAt { get; set; } = DateTime.UtcNow;
}
