namespace Certus.Core.Data.Entities;

/// <summary>
/// One licence alert already sent, so it is not sent again (issue #494,
/// licence design section 13.6).
///
/// The identity is (licence id, stage). A renewed licence carries a new id, so
/// it starts every stage again; restoring an earlier licence brings back an id
/// whose stages are already here, so nothing repeats.
///
/// A row is written whether or not a channel accepted the alert, which is what
/// the CRL and certificate alerts do and for the same reason: a warning that
/// repeats every few minutes while a relay is down is worse than one missed
/// once, and a licence has six stages, so a missed one is followed by the next.
/// No row is written when no channel is configured at all, so a channel added
/// later still gets the warning that is due.
///
/// There is no error message column, unlike <see cref="CrlAlertSent"/>. Nothing
/// reads one, a webhook failure carries the receiving server's own response
/// text, and the service log already records why a channel failed. A nullable
/// column can be added later with AddColumn, which SQLite does in place.
/// </summary>
public class LicenceAlertSent
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>
    /// The licence id, a canonical lower case GUID of 36 characters. The core
    /// checks that shape before an alert is sent, so the width holds.
    /// </summary>
    public string LicenceId { get; set; } = string.Empty;

    /// <summary>
    /// Which warning this was, one of the <c>LicenceAlertStages</c> values:
    /// "days30", "days14", "days7", "days1", "expired" or "grace_ended".
    /// </summary>
    public string Stage { get; set; } = string.Empty;

    /// <summary>When the alert was sent.</summary>
    public DateTime SentAt { get; set; } = DateTime.UtcNow;

    /// <summary>Channels notified: "email", "webhook", "email,webhook".</summary>
    public string Channels { get; set; } = string.Empty;

    /// <summary>Whether every channel accepted it.</summary>
    public bool Success { get; set; } = true;
}
