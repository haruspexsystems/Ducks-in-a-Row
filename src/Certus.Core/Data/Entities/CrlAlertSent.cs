namespace Certus.Core.Data.Entities;

/// <summary>
/// One alert already sent about one CRL, so it is not sent again.
///
/// Deliberately its own table rather than a nullable certificate on
/// <see cref="AlertSent"/>. That one has a required foreign key to a synced
/// certificate inside a unique index, and making it optional would be an
/// AlterColumn, which SQLite implements as a full table rebuild of live alert
/// history to produce byte identical DDL. See the declared column widths section
/// of CLAUDE.md.
///
/// The identity is the CRL instance, not the CA and not the distribution point:
/// (issuer key, kind, instance, stage). So the same CRL served from a directory
/// and a web server produces one alert naming both, a CRL that is renewed gets a
/// fresh set of thresholds, and a stale copy left behind at one location keeps
/// warning under the number it actually carries.
/// </summary>
public class CrlAlertSent
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>The key identifier of the CA that signed the CRL, as hex.</summary>
    public string IssuerKeyId { get; set; } = string.Empty;

    /// <summary>"base" or "delta".</summary>
    public string Kind { get; set; } = string.Empty;

    /// <summary>
    /// The CRL number, or the publication instant when the CRL carries no
    /// number. A new instance re-arms every stage.
    /// </summary>
    public string InstanceKey { get; set; } = string.Empty;

    /// <summary>
    /// Which warning this was: a threshold in days as a plain number ("30"),
    /// "overdue" when the CA missed its own publication schedule, or "expired".
    /// </summary>
    public string Stage { get; set; } = string.Empty;

    /// <summary>The issuing CA, for display in the history.</summary>
    public string IssuerName { get; set; } = string.Empty;

    /// <summary>When the CRL this alert was about stops being usable.</summary>
    public DateTime? NextUpdate { get; set; }

    /// <summary>When the alert was sent.</summary>
    public DateTime SentAt { get; set; } = DateTime.UtcNow;

    /// <summary>Channels notified: "email", "webhook", "email,webhook".</summary>
    public string Channels { get; set; } = string.Empty;

    /// <summary>Whether every channel accepted it.</summary>
    public bool Success { get; set; } = true;

    /// <summary>The last channel error, redacted and capped.</summary>
    public string? ErrorMessage { get; set; }
}
