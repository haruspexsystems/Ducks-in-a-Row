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

    /// <summary>
    /// Report that automatic renewal of the server's own HTTPS certificate
    /// failed (issue #105). That certificate is deliberately excluded from the
    /// routine expiry thresholds, because the product renews it for itself, so
    /// this is the only thing an operator ever hears about it over these
    /// channels. It fires only on failure, and never on the ordinary
    /// "renewed, waiting for a restart" outcome, which the dashboard carries.
    /// </summary>
    Task<AlertNotificationResult> SendServerCertificateAlertAsync(
        ServerCertificateAlert alert,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Warn about a certificate revocation list (issue #447). A leaf expiring
    /// breaks one service; a CRL expiring breaks revocation checking for
    /// everything the CA that signed it ever signed, and for an offline root
    /// nothing automatic replaces it.
    ///
    /// Its own method, record and webhook event, like the server certificate
    /// alert above, because the subject is not a certificate in the inventory
    /// and has no row there to point at.
    /// </summary>
    Task<AlertNotificationResult> SendCrlAlertAsync(
        CrlAlert alert,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deliver a test message on demand, so an operator can prove the channel
    /// works before trusting it with a real warning (issue #161). SMTP fails
    /// quietly and often, and an alerting system nobody has ever seen work is
    /// one nobody should trust.
    ///
    /// This is a separate method rather than a synthetic <see cref="ExpiryAlertBatch"/>
    /// on purpose: a test that arrives looking exactly like a real expiry warning
    /// is worse than no test at all, because a recipient acts on it.
    /// </summary>
    Task<AlertNotificationResult> SendTestAlertAsync(
        TestAlert alert,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// An operator triggered test delivery.
/// <para>
/// <see cref="TriggeredBy"/> is the Windows account that pressed the button. It
/// belongs in the email body, which goes to the operator's own recipients, and
/// in the audit log. It must <b>never</b> reach the webhook payload: that is
/// POSTed to whatever third party relay the operator configured, and putting a
/// directory account name in it turns a test button into a small username
/// disclosure channel.
/// </para>
/// </summary>
public sealed record TestAlert(
    string TriggeredBy,
    DateTime TriggeredAtUtc);

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
/// A failed automatic renewal of the server's own HTTPS certificate.
/// <see cref="Detail"/> is the certificate authority's own reason where there
/// is one: for a pended or denied request the enroller's message names the
/// exact template setting to change, so it is passed through verbatim.
/// <see cref="DaysRemaining"/> is how long the certificate the server is still
/// serving remains valid, or null when it is no longer in the store.
/// </summary>
public sealed record ServerCertificateAlert(
    string Outcome,
    string? Detail = null,
    string? Template = null,
    int? DaysRemaining = null);

/// <summary>
/// A certificate revocation list that is running out, or has run out.
/// </summary>
/// <param name="Stage">
/// Which warning this is: a threshold in days as a plain number ("30"),
/// "overdue" when a CA missed its own publication schedule, or "expired".
/// </param>
/// <param name="IssuerName">The CA that signed the CRL.</param>
/// <param name="Kind">"base" or "delta".</param>
/// <param name="Scope">
/// "issuing" when the configured CA publishes this CRL itself, "parent" when it
/// covers a certificate above it in the chain. The two need different words:
/// one is a CA that has stopped doing its job, the other is a ceremony nobody
/// has scheduled.
/// </param>
/// <param name="NextUpdate">When the CRL stops being usable.</param>
/// <param name="HoursRemaining">
/// How long that is from now, in hours, negative once it has passed. Hours
/// rather than days because an overdue CRL is often inside its last day.
/// </param>
/// <param name="Sources">
/// Where this copy of the CRL is served from: "ca" for the certificate
/// authority itself, or the distribution point URLs. More than one when the
/// same CRL is published in several places.
/// </param>
/// <param name="CrlNumber">The CRL number, which identifies the instance.</param>
/// <param name="NewerCrlNumber">
/// Set when a newer CRL is being served somewhere else, which is the shape of a
/// renewal that was copied to one location and not another, and the commonest
/// way a root CRL renewal goes wrong.
/// </param>
/// <param name="LastReadAt">
/// When the CRL was last read successfully. Older than the alert itself means
/// the monitor is warning from memory because nothing can reach the CRL now.
/// </param>
public sealed record CrlAlert(
    string Stage,
    string IssuerName,
    string Kind,
    string Scope,
    DateTime NextUpdate,
    double HoursRemaining,
    IReadOnlyList<string> Sources,
    string? CrlNumber = null,
    string? NewerCrlNumber = null,
    DateTime? LastReadAt = null);

/// <summary>
/// Result of sending an alert notification.
/// </summary>
public sealed record AlertNotificationResult(
    bool Success,
    string? ErrorMessage = null);
