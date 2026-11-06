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
    /// Channels that were attempted: "email", "webhook", "email,webhook".
    /// Every enabled channel is attempted, so this is not what delivered; see
    /// <see cref="DeliveredChannels"/>.
    /// </summary>
    public string Channels { get; set; } = string.Empty;

    /// <summary>
    /// The attempted channels that accepted the alert, in the same form as
    /// <see cref="Channels"/>, and empty when none did (issue #206). A channel
    /// in <see cref="Channels"/> and not here failed.
    ///
    /// Null on a failed row written before this column existed: such a row
    /// records only that at least one channel failed, not which. The migration
    /// fills it from <see cref="Channels"/> on every successful row, because
    /// success then meant every channel delivered.
    /// </summary>
    public string? DeliveredChannels { get; set; }

    /// <summary>
    /// True when every attempted channel delivered. False when at least one
    /// failed, which is not the same as nobody being told:
    /// <see cref="DeliveredChannels"/> says who was.
    /// </summary>
    public bool Success { get; set; } = true;

    /// <summary>
    /// The error of each channel that failed, redacted. With more than one
    /// failure, one line per channel, each starting with the channel name.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>Navigation property to the certificate.</summary>
    public SyncedCertificate? Certificate { get; set; }
}
