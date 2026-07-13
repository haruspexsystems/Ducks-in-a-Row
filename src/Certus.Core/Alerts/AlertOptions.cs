namespace Certus.Core.Alerts;

/// <summary>
/// Configuration for certificate expiry alerts.
/// Stored in the "Certus:Alerts" configuration section.
/// </summary>
public sealed class AlertOptions
{
    public const string SectionName = "Certus:Alerts";

    /// <summary>
    /// Whether expiry monitoring is enabled. Defaults to true.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How often (in minutes) to check for expiring certificates.
    /// Defaults to 60 minutes.
    /// </summary>
    public int CheckIntervalMinutes { get; set; } = 60;

    /// <summary>
    /// Thresholds in days before expiry that trigger alerts.
    /// An alert fires the first time a certificate crosses each threshold.
    /// Effective default: 30, 14, 7, 1 days, applied by NormalizeThresholdDays.
    ///
    /// The initializer is deliberately empty: the configuration binder appends
    /// bound array elements onto whatever the property already holds, so a
    /// default of [30, 14, 7, 1] plus the same array in appsettings produced
    /// every threshold twice. Defaults live in NormalizeThresholdDays instead,
    /// wired via PostConfigure in both hosts (same pattern as
    /// CertusOptions.NormalizeDatabasePath).
    /// </summary>
    public int[] ThresholdDays { get; set; } = [];

    /// <summary>
    /// Applies the default thresholds when none were configured and cleans up
    /// whatever was: values must be positive, appear once, and run from the
    /// largest threshold down (the order the expiry monitor evaluates them in).
    /// </summary>
    public void NormalizeThresholdDays()
    {
        ThresholdDays = ThresholdDays is { Length: > 0 }
            ? ThresholdDays.Where(d => d > 0).Distinct().OrderByDescending(d => d).ToArray()
            : [30, 14, 7, 1];
    }

    /// <summary>
    /// SMTP configuration for email alerts. Null = email disabled.
    /// </summary>
    public SmtpOptions? Smtp { get; set; }

    /// <summary>
    /// Webhook configuration for HTTP POST alerts. Null = webhook disabled.
    /// </summary>
    public WebhookOptions? Webhook { get; set; }
}

/// <summary>SMTP configuration for sending email alerts.</summary>
public sealed class SmtpOptions
{
    /// <summary>SMTP server hostname.</summary>
    public string Host { get; set; } = string.Empty;

    /// <summary>
    /// SMTP server port. Defaults to 587 for STARTTLS submission.
    /// Use 465 for implicit TLS.
    /// </summary>
    public int Port { get; set; } = 587;

    /// <summary>
    /// Whether to secure the connection with TLS. Defaults to true.
    /// On port 465 the connection uses implicit TLS. On any other port the
    /// client negotiates STARTTLS and requires it. Set to false only for a
    /// server that has no transport security.
    /// </summary>
    public bool UseSsl { get; set; } = true;

    /// <summary>SMTP username (optional if server allows anonymous relay).</summary>
    public string? Username { get; set; }

    /// <summary>SMTP password.</summary>
    public string? Password { get; set; }

    /// <summary>Sender email address.</summary>
    public string FromAddress { get; set; } = "certus@localhost";

    /// <summary>Sender display name.</summary>
    public string FromName { get; set; } = "Ducks in a Row";

    /// <summary>
    /// Recipient email addresses for alert notifications.
    /// </summary>
    public string[] Recipients { get; set; } = [];
}

/// <summary>Webhook configuration for HTTP POST alert notifications.</summary>
public sealed class WebhookOptions
{
    /// <summary>The URL to POST alert payloads to.</summary>
    public string Url { get; set; } = string.Empty;

    /// <summary>
    /// Optional secret for HMAC-SHA256 signature in X-Certus-Signature header.
    /// </summary>
    public string? Secret { get; set; }

    /// <summary>
    /// Optional custom headers to include in webhook requests.
    /// </summary>
    public Dictionary<string, string> Headers { get; set; } = new();
}
