using Certus.Core.Data.Entities;

namespace Certus.Core.Alerts;

/// <summary>
/// Interface for alert notification channels (email, webhook, etc.).
/// </summary>
public interface IAlertNotifier
{
    /// <summary>The channel name (e.g., "email", "webhook").</summary>
    string Channel { get; }

    /// <summary>Whether this notifier is currently configured and enabled.</summary>
    bool IsEnabled { get; }

    /// <summary>
    /// Send an expiry alert notification for a batch of certificates.
    /// </summary>
    Task<AlertNotificationResult> SendExpiryAlertAsync(
        ExpiryAlertBatch batch,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// A batch of certificates that triggered an alert at a specific threshold.
/// </summary>
public sealed record ExpiryAlertBatch(
    int ThresholdDays,
    IReadOnlyList<CertificateExpiryInfo> Certificates);

/// <summary>
/// Certificate expiry information for alert notifications.
/// </summary>
public sealed record CertificateExpiryInfo(
    int CertificateId,
    string Subject,
    string SerialNumber,
    string TemplateName,
    DateTime NotAfter,
    int DaysRemaining);

/// <summary>
/// Result of sending an alert notification.
/// </summary>
public sealed record AlertNotificationResult(
    bool Success,
    string? ErrorMessage = null);
