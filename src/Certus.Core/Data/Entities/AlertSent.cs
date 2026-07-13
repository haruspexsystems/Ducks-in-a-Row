namespace Certus.Core.Data.Entities;

/// <summary>
/// Tracks which alert notifications have been sent for which certificates
/// at which threshold, preventing duplicate notifications.
/// </summary>
public class AlertSent
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>The certificate's internal ID (FK to SyncedCertificate).</summary>
    public int CertificateId { get; set; }

    /// <summary>The threshold (in days before expiry) that triggered this alert.</summary>
    public int ThresholdDays { get; set; }

    /// <summary>When the alert was sent.</summary>
    public DateTime SentAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Channels that were notified: "email", "webhook", "email,webhook".
    /// </summary>
    public string Channels { get; set; } = string.Empty;

    /// <summary>
    /// Whether the alert was sent successfully.
    /// </summary>
    public bool Success { get; set; } = true;

    /// <summary>
    /// Error message if the alert failed to send.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>Navigation property to the certificate.</summary>
    public SyncedCertificate? Certificate { get; set; }
}
