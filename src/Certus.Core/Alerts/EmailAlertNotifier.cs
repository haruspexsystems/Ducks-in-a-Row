using System.Globalization;
using System.Text;
using Certus.Core.Crl;
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
    private readonly ISmtpSecretProtector _protector;
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
        ISmtpSecretProtector protector,
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

    public async Task<AlertNotificationResult> SendCrlAlertAsync(
        CrlAlert alert,
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
            () => BuildCrlMessage(alert, smtp, recipients), smtp,
            $"the {alert.Stage} CRL warning for {alert.IssuerName}", recipients.Count, cancellationToken);
    }

    public async Task<AlertNotificationResult> SendLicenceAlertAsync(
        LicenceAlert alert,
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
            () => BuildLicenceMessage(alert, smtp, recipients), smtp,
            $"the licence {alert.Stage} alert", recipients.Count, cancellationToken);
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
    /// send, disconnect. Shared by every alert kind so the transport
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
            // Redacted at the source (issue #635), so the history row and the
            // test send response never hold the relay host, the account name
            // or the password: the password only this class can know is
            // scrubbed first, then the values in the options in use, which
            // for a candidate send are the candidate's own.
            var error = AlertErrorRedactor.Redact(
                ScrubResolvedPassword(ex.Message, password), _options, smtp);
            _logger.LogError(
                "Failed to send the alert email for {Description}: {ExceptionType}: {Error}",
                description, ex.GetType().Name, error);
            return new AlertNotificationResult(false, error);
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
    /// to happen. It carries the full detail, which for a denial names the
    /// computer account to grant Enroll to, because this goes to the operator's
    /// own recipients; the webhook carries the account free form (issue #485).
    /// </summary>
    internal static MimeMessage BuildServerCertificateMessage(
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
    /// The CRL mail (issue #447).
    ///
    /// It says what lapses, not just that something expires, because the whole
    /// reason this feature exists is that the consequence is not obvious: a
    /// lapsed CRL does not break the CA, it breaks revocation checking for every
    /// certificate that CA ever signed, all at once, on clients that were
    /// working a minute earlier. And it names the remedy, because the outages
    /// this was reported from happened at a client where, in the words of the
    /// report, nobody knew how to renew the root CRL.
    /// </summary>
    internal static MimeMessage BuildCrlMessage(
        CrlAlert alert, SmtpOptions smtp, List<MailboxAddress> recipients)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(smtp.FromName, smtp.FromAddress));
        message.To.AddRange(recipients);

        var urgency = alert.Stage == CrlAlertRules.ExpiredStage ? "CRITICAL"
            : alert.HoursRemaining <= 24 ? "CRITICAL"
            : alert.HoursRemaining <= 7 * 24 ? "WARNING"
            : "NOTICE";

        message.Subject = alert.Stage switch
        {
            CrlAlertRules.ExpiredStage =>
                $"[Ducks in a Row {urgency}] The CRL from {alert.IssuerName} has EXPIRED",
            CrlAlertRules.OverdueStage =>
                $"[Ducks in a Row {urgency}] {alert.IssuerName} has not published a new CRL on schedule",
            _ =>
                $"[Ducks in a Row {urgency}] The CRL from {alert.IssuerName} expires in {DescribeRemaining(alert.HoursRemaining)}",
        };

        var body = new StringBuilder();
        body.AppendLine("Ducks in a Row Certificate Revocation List Alert");
        body.AppendLine(new string('=', 50));
        body.AppendLine();
        body.AppendLine($"Issuer:     {alert.IssuerName}");
        body.AppendLine($"CRL:        {alert.Kind}{(alert.CrlNumber is null ? "" : $", number {alert.CrlNumber}")}");
        body.AppendLine($"Expires:    {alert.NextUpdate:yyyy-MM-dd HH:mm} UTC"
            + (alert.HoursRemaining < 0
                ? $" ({DescribeRemaining(-alert.HoursRemaining)} ago)"
                : $" (in {DescribeRemaining(alert.HoursRemaining)})"));
        body.AppendLine("Published:  " + string.Join(", ", alert.Sources));
        if (alert.NewerCrlNumber is not null)
            body.AppendLine($"Newer CRL:  number {alert.NewerCrlNumber} is already published elsewhere");
        if (alert.LastReadAt is not null)
            body.AppendLine($"Last read:  {alert.LastReadAt:yyyy-MM-dd HH:mm} UTC");
        body.AppendLine();

        body.AppendLine("What happens when it lapses:");
        body.AppendLine(new string('-', 50));
        body.AppendLine("Every certificate this CA signed stops validating on any client that");
        body.AppendLine("checks revocation, all at once. That includes domain controllers, VPN and");
        body.AppendLine("wireless authentication, and the certificate authority's own service.");
        body.AppendLine();

        body.AppendLine("What to do:");
        body.AppendLine(new string('-', 50));
        if (alert.NewerCrlNumber is not null)
        {
            body.AppendLine("A newer CRL exists already, so this location was missed when it was");
            body.AppendLine("published. Copy the current CRL to it.");
        }
        else if (alert.Scope == "parent")
        {
            body.AppendLine("This CRL is published by a CA above the one Ducks in a Row is connected");
            body.AppendLine("to, which on most estates is an offline root. Start it, publish a fresh");
            body.AppendLine("CRL with 'certutil -crl', then copy the new file to every location the");
            body.AppendLine("line above names, including 'certutil -dspublish -f <file> <CA name>'");
            body.AppendLine("for a directory location.");
        }
        else
        {
            body.AppendLine("This CRL is published by the certificate authority Ducks in a Row is");
            body.AppendLine("connected to, which normally replaces it on a timer. Check that the");
            body.AppendLine("Active Directory Certificate Services service is running, and that it");
            body.AppendLine("can write to every location it publishes to.");
        }

        body.AppendLine();
        body.AppendLine(new string('-', 50));
        body.AppendLine("This alert was sent by Ducks in a Row.");

        message.Body = new TextPart("plain") { Text = body.ToString() };
        return message;
    }

    /// <summary>
    /// The licence mail (issue #494, licence design section 13.6).
    ///
    /// Every word here is the core's own. The alert carries a validated licence
    /// id, a validated tier and the module's dates and day count, and nothing
    /// else, so there is no field a module could use to put text in front of an
    /// administrator, and the licensee's name is never in it.
    ///
    /// It is never CRITICAL (Sean's decision of 2026-10-14): a lapse switches
    /// paid features off and leaves every certificate alone, so CRITICAL stays
    /// for the alerts that mean something is about to break. The sentences match
    /// what the Settings card and the banner say for the same state
    /// (src/frontend/src/lib/licence.ts), and the last line is the one every
    /// negative licence state ends with.
    /// </summary>
    internal static MimeMessage BuildLicenceMessage(
        LicenceAlert alert, SmtpOptions smtp, List<MailboxAddress> recipients)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(smtp.FromName, smtp.FromAddress));
        message.To.AddRange(recipients);
        message.Headers.Add("X-Certus-Alert-Kind", "licence");

        var urgency = alert.Kind == LicenceAlertKind.Expiring
            && alert.Stage is LicenceAlertStages.Days30 or LicenceAlertStages.Days14
                ? "NOTICE"
                : "WARNING";

        var ends = LicenceDate(alert.ValidUntil);
        var graceEnds = LicenceDate(alert.GraceUntil);
        var days = LicenceDaysPhrase(alert.DaysRemaining);

        message.Subject = alert.Kind switch
        {
            LicenceAlertKind.Expiring =>
                $"[Ducks in a Row {urgency}] Your licence expires {days ?? StageDaysPhrase(alert.Stage)}",
            LicenceAlertKind.Grace =>
                $"[Ducks in a Row {urgency}] Your licence has expired; paid features switch off on {graceEnds}",
            _ =>
                $"[Ducks in a Row {urgency}] Your licence has lapsed; paid features are off",
        };

        var body = new StringBuilder();
        body.AppendLine("Ducks in a Row Licence Alert");
        body.AppendLine(new string('=', 50));
        body.AppendLine();
        body.AppendLine(alert.Kind switch
        {
            LicenceAlertKind.Expiring =>
                $"Your licence expires on {ends}{(days is null ? "" : $", {days}")}.",
            LicenceAlertKind.Grace =>
                $"Your licence expired on {ends}. Paid features switch off on {graceEnds}{(days is null ? "" : $", {days}")}.",
            _ =>
                $"Your licence lapsed on {graceEnds}. Paid features are off.",
        });
        body.AppendLine();
        body.AppendLine($"Licence:      {alert.LicenceId}");
        body.AppendLine($"Tier:         {TierName(alert.Tier)}");
        body.AppendLine($"Ends:         {ends}");
        if (alert.GraceUntil is not null)
            body.AppendLine($"Grace until:  {graceEnds}");
        body.AppendLine();

        body.AppendLine("What to do:");
        body.AppendLine(new string('-', 50));
        switch (alert.Kind)
        {
            case LicenceAlertKind.Expiring:
                body.AppendLine("Install the renewed licence file when it arrives, from the Licence card");
                body.AppendLine("on the Settings page of the Ducks in a Row Dashboard.");
                break;
            case LicenceAlertKind.Grace:
                body.AppendLine($"Install a renewed licence file before {graceEnds}, from the Licence card");
                body.AppendLine("on the Settings page of the Ducks in a Row Dashboard, and paid features");
                body.AppendLine("stay on.");
                break;
            default:
                body.AppendLine("Install a renewed licence file from the Licence card on the Settings page");
                body.AppendLine("of the Ducks in a Row Dashboard. A lapse deletes nothing and reconfigures");
                body.AppendLine("nothing, so a renewed licence switches everything back on as it was.");
                break;
        }
        body.AppendLine("Quote the licence id above when you ask Haruspex Systems about a renewal.");

        body.AppendLine();
        body.AppendLine(new string('-', 50));
        body.AppendLine("This alert was sent by Ducks in a Row.");
        body.AppendLine("Certificate issuance and renewal are not affected.");

        message.Body = new TextPart("plain") { Text = body.ToString() };
        return message;
    }

    /// <summary>
    /// A licence date as the card shows it: year first, in UTC, always in the
    /// Gregorian calendar whatever the server's culture is.
    /// </summary>
    private static string LicenceDate(DateTimeOffset? value) =>
        value?.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "an unknown date";

    /// <summary>
    /// The module's day count as words, mirroring daysPhrase in the dashboard.
    /// The module rounds down to whole days, so 0 means less than a day is left,
    /// which is what the 1 day stage normally carries.
    /// </summary>
    private static string? LicenceDaysPhrase(int? days) => days switch
    {
        null => null,
        <= 0 => "in less than a day",
        1 => "in 1 day",
        _ => $"in {days.Value.ToString(CultureInfo.InvariantCulture)} days",
    };

    /// <summary>What a stage promises, for a warning that somehow arrived without a day count.</summary>
    private static string StageDaysPhrase(string stage) => stage switch
    {
        LicenceAlertStages.Days30 => "within 30 days",
        LicenceAlertStages.Days14 => "within 14 days",
        LicenceAlertStages.Days7 => "within 7 days",
        LicenceAlertStages.Days1 => "within 1 day",
        _ => "soon",
    };

    /// <summary>A tier as the licence names it ("standard"), as a reader expects it ("Standard").</summary>
    private static string TierName(string? tier) =>
        string.IsNullOrEmpty(tier)
            ? "unknown"
            : char.ToUpperInvariant(tier[0]) + tier[1..];

    /// <summary>Hours, or days once there are enough of them to be worth rounding.</summary>
    private static string DescribeRemaining(double hours) =>
        hours >= 48
            ? $"{(int)Math.Floor(hours / 24)} days"
            : $"{(int)Math.Floor(hours)} hours";

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
