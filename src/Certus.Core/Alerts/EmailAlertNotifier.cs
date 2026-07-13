using System.Text;
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
    private readonly ILogger<EmailAlertNotifier> _logger;

    public string Channel => "email";

    public bool IsEnabled =>
        _options.Smtp is { Host.Length: > 0 } &&
        _options.Smtp.Recipients.Length > 0;

    public EmailAlertNotifier(
        IOptions<AlertOptions> options,
        ILogger<EmailAlertNotifier> logger)
    {
        _options = options.Value;
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

        try
        {
            var message = BuildMessage(batch, smtp, recipients);

            using var client = new SmtpClient();
            await client.ConnectAsync(smtp.Host, smtp.Port, ResolveSocketOptions(smtp.UseSsl, smtp.Port), cancellationToken);

            if (!string.IsNullOrEmpty(smtp.Username) && !string.IsNullOrEmpty(smtp.Password))
            {
                await client.AuthenticateAsync(smtp.Username, smtp.Password, cancellationToken);
            }

            await client.SendAsync(message, cancellationToken);
            await client.DisconnectAsync(true, cancellationToken);

            _logger.LogInformation(
                "Expiry alert email sent for {Count} certificates ({Threshold}-day threshold) to {RecipientCount} recipient(s)",
                batch.Certificates.Count, batch.ThresholdDays, recipients.Count);

            return new AlertNotificationResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send expiry alert email");
            return new AlertNotificationResult(false, ex.Message);
        }
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
    /// Maps the SMTP options to a MailKit transport security mode.
    /// Port 465 uses implicit TLS where the session is encrypted on connect.
    /// Any other port negotiates STARTTLS and requires it, so the session never
    /// falls back to plaintext. When TLS is turned off, no transport security is used.
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
