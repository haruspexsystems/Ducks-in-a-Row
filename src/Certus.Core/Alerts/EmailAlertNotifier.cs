using System.Text;
using Certus.Core.Security;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Certus.Core.Alerts;

/// <summary>
/// Sends certificate expiry alert emails via SMTP using MailKit.
/// </summary>
public sealed class EmailAlertNotifier : IAlertNotifier
{
    private readonly AlertOptions _options;
    private readonly ISecretProtector _protector;
    private readonly ILogger<EmailAlertNotifier> _logger;

    public string Channel => "email";

    /// <summary>
    /// Email is attempted only with a relay host, at least one recipient, and
    /// a non blank sender address (issue #209). The sender has a code default,
    /// but an explicit null or empty Smtp:FromAddress in appsettings.json
    /// overwrites it through the configuration binder, and without a sender
    /// the message cannot be built, so reporting the channel enabled would
    /// promise sends that can only fail.
    /// </summary>
    public bool IsEnabled => IsDeliverable(_options.Smtp);

    /// <summary>
    /// The one definition of "this SMTP configuration could carry a message",
    /// shared by <see cref="IsEnabled"/> and by the test send's candidate
    /// path, so the two cannot drift.
    /// </summary>
    public static bool IsDeliverable(SmtpOptions? smtp) =>
        smtp is { Host.Length: > 0 } &&
        smtp.Recipients.Length > 0 &&
        !string.IsNullOrWhiteSpace(smtp.FromAddress);

    public EmailAlertNotifier(
        IOptions<AlertOptions> options,
        ISecretProtector protector,
        ILogger<EmailAlertNotifier> logger)
    {
        _options = options.Value;
        _protector = protector;
        _logger = logger;
    }

    public async Task<AlertNotificationResult> SendExpiryAlertAsync(
        ExpiryAlertBatch batch,
        CancellationToken cancellationToken = default)
    {
        var smtp = _options.Smtp;
        if (smtp == null || !IsEnabled)
            return new AlertNotificationResult(false, "SMTP not configured");

        var recipients = ParseRecipients(smtp.Recipients, out var invalid);
        if (invalid.Count > 0)
        {
            _logger.LogWarning(
                "Skipping {InvalidCount} of {TotalCount} configured recipient address(es) that are malformed",
                invalid.Count, smtp.Recipients.Length);
        }

        if (recipients.Count == 0)
        {
            _logger.LogError("No valid recipient addresses are configured for email alerts");
            return new AlertNotificationResult(false, "No valid recipient addresses");
        }

        var description =
            $"{batch.Certificates.Count} certificate(s) at the {batch.ThresholdDays}-day threshold";

        return await SendAsync(
            () => BuildMessage(batch, smtp, recipients),
            smtp, description, recipients.Count, cancellationToken);
    }

    public async Task<AlertNotificationResult> SendServerCertificateAlertAsync(
        ServerCertificateAlert alert,
        CancellationToken cancellationToken = default)
    {
        var smtp = _options.Smtp;
        if (smtp == null || !IsEnabled)
            return new AlertNotificationResult(false, "SMTP not configured");

        var recipients = ParseRecipients(smtp.Recipients, out _);
        if (recipients.Count == 0)
        {
            _logger.LogError("No valid recipient addresses are configured for email alerts");
            return new AlertNotificationResult(false, "No valid recipient addresses");
        }

        return await SendAsync(
            () => BuildServerCertificateMessage(alert, smtp, recipients), smtp,
            $"the server certificate renewal outcome '{alert.Outcome}'", recipients.Count, cancellationToken);
    }

    public async Task<AlertNotificationResult> SendTestAlertAsync(
        TestAlert alert,
        CancellationToken cancellationToken = default)
    {
        var smtp = _options.Smtp;
        if (smtp == null || !IsEnabled)
            return new AlertNotificationResult(false, "SMTP not configured");

        return await SendTestAlertAsync(alert, smtp, cancellationToken);
    }

    /// <summary>
    /// The test send against an explicit SMTP configuration, which is how the
    /// dashboard proves a candidate (typed but not yet saved, or saved but not
    /// yet applied) before committing to a restart. Everything else about the
    /// send is identical to the configured path: same message, same transport
    /// resolution, same password handling.
    /// </summary>
    public async Task<AlertNotificationResult> SendTestAlertAsync(
        TestAlert alert,
        SmtpOptions smtp,
        CancellationToken cancellationToken = default)
    {
        if (!IsDeliverable(smtp))
            return new AlertNotificationResult(false, "SMTP not configured");

        var recipients = ParseRecipients(smtp.Recipients, out _);
        if (recipients.Count == 0)
        {
            _logger.LogError("No valid recipient addresses are configured for email alerts");
            return new AlertNotificationResult(false, "No valid recipient addresses");
        }

        return await SendAsync(
            () => BuildTestMessage(alert, smtp, recipients),
            smtp, "a test alert", recipients.Count, cancellationToken);
    }

    /// <summary>
    /// Build the message, connect, authenticate if credentials are configured,
    /// send, disconnect. Shared by all three alert kinds so the transport
    /// security decision, the credential handling, and the failure reporting stay
    /// identical whatever is being delivered. This mirrors
    /// WebhookAlertNotifier.PostAsync.
    ///
    /// <paramref name="buildMessage"/> is a delegate rather than a built message
    /// so that construction happens inside the try. Passing the message itself
    /// would evaluate the builder at the call site, outside this method, and a
    /// notifier that throws breaks a contract two callers depend on:
    /// ExpiryMonitorService has no per notifier try/catch and would abandon a
    /// whole threshold pass before writing its AlertsSent rows, and
    /// AlertTestService states outright that a notifier never throws.
    /// MimeKit's MailboxAddress constructor throws on a null address, which an
    /// explicit null for Smtp:FromAddress in appsettings.json produces, because
    /// the configuration binder writes that null over the property initializer.
    /// </summary>
    private async Task<AlertNotificationResult> SendAsync(
        Func<MimeMessage> buildMessage,
        SmtpOptions smtp,
        string description,
        int recipientCount,
        CancellationToken cancellationToken)
    {
        // Resolved before connecting: a protected password that cannot be
        // decrypted must fail the send outright, not fall back to an older
        // plaintext value or quietly skip authentication.
        if (!TryResolvePassword(smtp, out var password))
        {
            _logger.LogError(
                "The saved SMTP password could not be decrypted on this machine, so the " +
                "alert email for {Description} was not sent. A data directory restored " +
                "onto another machine cannot decrypt secrets by design; save the " +
                "password again from the Settings page",
                description);
            return new AlertNotificationResult(
                false,
                "The saved SMTP password could not be read on this machine. " +
                "Save it again from the Settings page.");
        }

        try
        {
            var message = buildMessage();

            using var client = new SmtpClient();
            await client.ConnectAsync(smtp.Host, smtp.Port, ResolveSocketOptions(smtp), cancellationToken);

            if (!string.IsNullOrEmpty(smtp.Username) && !string.IsNullOrEmpty(password))
            {
                await client.AuthenticateAsync(smtp.Username, password, cancellationToken);
            }

            await client.SendAsync(message, cancellationToken);
            await client.DisconnectAsync(true, cancellationToken);

            _logger.LogInformation(
                "Alert email sent for {Description} to {RecipientCount} recipient(s)",
                description, recipientCount);

            return new AlertNotificationResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send the alert email for {Description}", description);
            return new AlertNotificationResult(false, ScrubResolvedPassword(ex.Message, password));
        }
    }

    /// <summary>
    /// The password a send should authenticate with. The dashboard's protected
    /// blob wins when present (ApplyOverlay has already stepped aside when a
    /// higher configuration layer supplies the plaintext key); otherwise the
    /// plaintext value from the configuration file or environment, which is
    /// also how a candidate test send carries a just typed password. False
    /// means a blob exists and the keyring could not decrypt it, and the send
    /// must fail closed: EAB credentials fail the same way for the same
    /// reason, a restored data directory.
    /// </summary>
    private bool TryResolvePassword(SmtpOptions smtp, out string? password)
    {
        if (!string.IsNullOrEmpty(smtp.PasswordProtected))
        {
            password = _protector.TryUnprotect(smtp.PasswordProtected);
            return password != null;
        }

        password = smtp.Password;
        return true;
    }

    /// <summary>
    /// The redaction gap only this class can close: the password decrypted
    /// from the protected blob exists in plaintext nowhere but here, so
    /// AlertErrorRedactor's secrets pool (built from the configured options
    /// and a candidate's own fields) cannot know it. Scrub it at the source,
    /// before the failure text leaves the notifier for the history table or
    /// the test send response. The four character floor is the redactor's
    /// MinimumSecretLength rule: replacing a trivially short password turns
    /// the message to noise without protecting anything.
    /// </summary>
    internal static string? ScrubResolvedPassword(string? message, string? password)
    {
        if (string.IsNullOrEmpty(message) || password is not { Length: >= 4 })
            return message;

        return message.Replace(password, "(redacted)", StringComparison.Ordinal);
    }

    private static MimeMessage BuildMessage(ExpiryAlertBatch batch, SmtpOptions smtp, List<MailboxAddress> recipients)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(smtp.FromName, smtp.FromAddress));
        message.To.AddRange(recipients);

        var urgency = batch.ThresholdDays <= 1 ? "CRITICAL" :
                      batch.ThresholdDays <= 7 ? "WARNING" : "NOTICE";

        message.Subject = $"[Ducks in a Row {urgency}] {batch.Certificates.Count} certificate(s) expiring within {batch.ThresholdDays} days";

        var body = new StringBuilder();
        body.AppendLine($"Ducks in a Row Certificate Expiry Alert");
        body.AppendLine(new string('=', 50));
        body.AppendLine();
        body.AppendLine($"Threshold: {batch.ThresholdDays} days");
        body.AppendLine($"Certificates affected: {batch.Certificates.Count}");
        body.AppendLine();
        body.AppendLine("Certificates:");
        body.AppendLine(new string('-', 50));

        foreach (var cert in batch.Certificates)
        {
            body.AppendLine();
            body.AppendLine($"  Subject:   {cert.Subject}");
            body.AppendLine($"  Serial:    {cert.SerialNumber}");
            body.AppendLine($"  Template:  {cert.TemplateName}");
            body.AppendLine($"  Expires:   {cert.NotAfter:yyyy-MM-dd HH:mm} UTC ({cert.DaysRemaining} days remaining)");
        }

        body.AppendLine();
        body.AppendLine(new string('-', 50));
        body.AppendLine("This alert was sent by Ducks in a Row.");
        body.AppendLine("View your certificate inventory in the Ducks in a Row Dashboard.");

        message.Body = new TextPart("plain") { Text = body.ToString() };
        return message;
    }

    /// <summary>
    /// The renewal failure mail. Urgency tracks how long the certificate the
    /// server is still serving has left, not the failure itself: a denial 30
    /// days out is a task, the same denial with a day left is an outage about
    /// to happen.
    /// </summary>
    private static MimeMessage BuildServerCertificateMessage(
        ServerCertificateAlert alert, SmtpOptions smtp, List<MailboxAddress> recipients)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(smtp.FromName, smtp.FromAddress));
        message.To.AddRange(recipients);

        var urgency = alert.DaysRemaining is null ? "WARNING"
            : alert.DaysRemaining <= 1 ? "CRITICAL"
            : alert.DaysRemaining <= 7 ? "WARNING"
            : "NOTICE";

        message.Subject =
            $"[Ducks in a Row {urgency}] Automatic renewal of the server's own certificate failed";

        var body = new StringBuilder();
        body.AppendLine("Ducks in a Row Server Certificate Renewal Alert");
        body.AppendLine(new string('=', 50));
        body.AppendLine();
        body.AppendLine($"Outcome:   {alert.Outcome}");
        if (!string.IsNullOrWhiteSpace(alert.Template))
            body.AppendLine($"Template:  {alert.Template}");
        body.AppendLine(alert.DaysRemaining is null
            ? "Remaining: the certificate is no longer in the machine store"
            : $"Remaining: {alert.DaysRemaining} day(s) on the certificate still being served");
        body.AppendLine();

        if (!string.IsNullOrWhiteSpace(alert.Detail))
        {
            body.AppendLine("Detail:");
            body.AppendLine(new string('-', 50));
            body.AppendLine(alert.Detail);
            body.AppendLine();
        }

        body.AppendLine(new string('-', 50));
        body.AppendLine("The server is still serving its current certificate; nothing was changed.");
        body.AppendLine("Renewal is retried on the next check. Fix the cause, or renew by hand from");
        body.AppendLine("the Settings page of the Ducks in a Row Dashboard.");

        message.Body = new TextPart("plain") { Text = body.ToString() };
        return message;
    }

    /// <summary>
    /// The operator triggered test mail (issue #161).
    ///
    /// Everything here works to stop a recipient mistaking it for a real expiry
    /// warning. TEST leads the subject rather than sitting in the urgency slot,
    /// where CRITICAL and WARNING already live. The first body line says outright
    /// that no certificate is expiring. And the X-Certus-Alert-Kind header lets a
    /// mail rule filter it without parsing the subject.
    ///
    /// The [Ducks in a Row ...] prefix is kept, so an inbox rule an operator has
    /// already written to catch alerts still catches this one. That is the point:
    /// the test proves the path the real alert takes, filters included.
    /// </summary>
    internal static MimeMessage BuildTestMessage(
        TestAlert alert, SmtpOptions smtp, List<MailboxAddress> recipients)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(smtp.FromName, smtp.FromAddress));
        message.To.AddRange(recipients);
        message.Headers.Add("X-Certus-Alert-Kind", "test");

        message.Subject = "[Ducks in a Row TEST] Test alert, no action needed";

        var body = new StringBuilder();
        body.AppendLine("This is a test. No certificate is expiring and there is nothing to do.");
        body.AppendLine(new string('=', 50));
        body.AppendLine();
        body.AppendLine($"Triggered by: {alert.TriggeredBy}");
        body.AppendLine($"Triggered at: {alert.TriggeredAtUtc:yyyy-MM-dd HH:mm} UTC");
        body.AppendLine();
        body.AppendLine("It was sent from the Alerts card on the Settings page of the Ducks in a");
        body.AppendLine("Row Dashboard, to confirm that alert email reaches this address.");
        body.AppendLine();
        body.AppendLine(new string('-', 50));
        body.AppendLine("Receiving this proves delivery only. It does not mean expiry monitoring is");
        body.AppendLine("switched on, and it does not mean any certificate has been checked.");

        message.Body = new TextPart("plain") { Text = body.ToString() };
        return message;
    }

    /// <summary>
    /// Maps the SMTP options to a MailKit transport security mode. An explicit
    /// <see cref="SmtpOptions.TlsMode"/> decides outright; with none chosen the
    /// legacy derivation below applies, so an install configured before the
    /// mode existed keeps exactly the behaviour it had.
    /// </summary>
    internal static SecureSocketOptions ResolveSocketOptions(SmtpOptions smtp) =>
        smtp.TlsMode switch
        {
            SmtpTlsMode.None => SecureSocketOptions.None,
            SmtpTlsMode.Implicit => SecureSocketOptions.SslOnConnect,
            SmtpTlsMode.StartTls => SecureSocketOptions.StartTls,
            _ => ResolveSocketOptions(smtp.UseSsl, smtp.Port),
        };

    /// <summary>
    /// The legacy derivation, in force whenever no explicit mode was chosen.
    /// Port 465 uses implicit TLS where the session is encrypted on connect.
    /// Any other port negotiates STARTTLS and requires it, so the session never
    /// falls back to plaintext. When TLS is turned off, no transport security is
    /// used. Must stay in step with <c>SmtpTlsModes.Derive</c>, which reports
    /// this rule's answer to the dashboard.
    /// </summary>
    internal static SecureSocketOptions ResolveSocketOptions(bool useSsl, int port)
    {
        if (!useSsl)
            return SecureSocketOptions.None;

        return port == 465
            ? SecureSocketOptions.SslOnConnect
            : SecureSocketOptions.StartTls;
    }

    /// <summary>
    /// Validates the configured recipient addresses, returning the ones that parse and
    /// reporting the rest through <paramref name="invalid"/>. A malformed address is
    /// skipped so that one bad entry does not fail delivery to the valid recipients.
    /// </summary>
    internal static List<MailboxAddress> ParseRecipients(string[] recipients, out List<string> invalid)
    {
        var valid = new List<MailboxAddress>(recipients.Length);
        invalid = new List<string>();

        foreach (var recipient in recipients)
        {
            if (!string.IsNullOrWhiteSpace(recipient) && MailboxAddress.TryParse(recipient, out var address))
                valid.Add(address);
            else
                invalid.Add(recipient);
        }

        return valid;
    }
}
