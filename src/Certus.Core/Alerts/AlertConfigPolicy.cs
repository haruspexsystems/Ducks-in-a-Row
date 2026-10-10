using Certus.Core.Configuration;
using MimeKit;

namespace Certus.Core.Alerts;

/// <summary>
/// What the dashboard is allowed to save into the alert configuration, and what
/// it should be warned about (issue #162).
///
/// <para>
/// Pure, with no host or database behind it, the same stance as
/// <c>AllowedDomainsPolicy.ValidateAndNormalize</c> and
/// <c>CertificateAlertLadder</c>. The controller is wiring; the rules are here so
/// they can be tested directly.
/// </para>
///
/// <para>
/// <b>Errors refuse the write, warnings do not.</b> An error means the input
/// cannot be stored as a working configuration. A warning means it stores fine
/// but will not deliver anything, which is a legitimate state to pass through on
/// the way somewhere else: an operator moving from email to a webhook clears the
/// recipients first, and refusing that would make the card fight them. The card
/// shows warnings; nothing is silently swallowed either way.
/// </para>
/// </summary>
public static class AlertConfigPolicy
{
    /// <summary>
    /// A check every minute is already far more often than a certificate's
    /// expiry changes, and the monitor floors the value at 1 anyway. The ceiling
    /// is a day: past that the interval starts skipping the narrow thresholds
    /// entirely, so a 1 day warning would never fire.
    /// </summary>
    public const int MinCheckIntervalMinutes = 1;

    public const int MaxCheckIntervalMinutes = 1440;

    /// <summary>Ten years, comfortably past any certificate lifetime a CA will issue.</summary>
    public const int MaxThresholdDays = 3650;

    /// <summary>
    /// Bounds on list length. Not security limits so much as a guard against a
    /// paste accident becoming a stored configuration that mails a thousand
    /// addresses at every threshold.
    /// </summary>
    public const int MaxThresholds = 20;

    public const int MaxRecipients = 50;

    /// <summary>
    /// Length caps on the credential and display fields. Generous rather than
    /// clever: RFC 5321 allows longer local parts than anyone uses, and the
    /// point is to stop a paste accident from storing a novel, not to police
    /// address grammar.
    /// </summary>
    public const int MaxUsernameLength = 256;

    public const int MaxPasswordLength = 1024;

    public const int MaxFromNameLength = 128;

    /// <summary>
    /// Validate and normalize one save. <paramref name="webhookDeliverable"/>
    /// comes from the webhook notifier rather than from the input, because the
    /// webhook is not writable here and yet decides whether an empty recipient
    /// list actually silences anything. <paramref name="hasStoredPassword"/>
    /// and <paramref name="hasStoredUsername"/> come from the overlay and the
    /// bound options, because whether authentication will actually happen
    /// depends on two values this input only carries when they are being
    /// changed. The username joined the password in that position in issue
    /// #261, when the config endpoint stopped returning it.
    /// </summary>
    public static AlertConfigValidation Validate(
        AlertConfigInput input,
        bool webhookDeliverable,
        bool hasStoredPassword = false,
        bool hasStoredUsername = false)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        if (input.CheckIntervalMinutes is < MinCheckIntervalMinutes or > MaxCheckIntervalMinutes)
        {
            errors.Add(
                $"The check interval must be between {MinCheckIntervalMinutes} and " +
                $"{MaxCheckIntervalMinutes} minutes.");
        }

        var thresholds = NormalizeThresholds(input.ThresholdDays, errors);
        var host = NormalizeHost(input.SmtpHost, errors);
        var fromAddress = NormalizeAddress(
            input.SmtpFromAddress, "The sender address", errors);
        var recipients = NormalizeRecipients(input.SmtpRecipients, errors);
        var port = NormalizePort(input.SmtpPort, errors);
        var tlsMode = NormalizeTlsMode(input.SmtpTlsMode, errors);
        var fromName = NormalizeFromName(input.SmtpFromName, errors);
        ValidatePasswordChange(input, errors);
        ValidateUsernameChange(input, errors);

        // A blank sender is legitimate only when email is switched off entirely.
        // With a relay host set it would break alerting: every save writes this
        // key, so a blank one overwrites the certus@localhost initializer
        // default with an empty string. Since issue #209
        // EmailAlertNotifier.IsEnabled also refuses a blank sender, so the
        // runtime no longer sends anything and the card explains the state
        // instead of claiming the channel works. This save time check stays on
        // top of that: refusing the write with a message beats letting an
        // administrator save a configuration that silently disables the
        // channel they are standing in front of.
        if (host.Length > 0 && fromAddress.Length == 0)
        {
            errors.Add(
                "A sender address is required when an SMTP relay host is set. Alert email is " +
                "sent from it, and a relay will refuse a message that has no sender.");
        }

        if (errors.Count > 0)
            return new AlertConfigValidation(errors, warnings, null);

        var passwordAfterSave = input.SmtpClearPassword
            ? false
            : !string.IsNullOrEmpty(input.SmtpPassword) || hasStoredPassword;

        // The same three arms as the password, and for the same reason: the
        // request carries a username only when it is being changed, so what
        // will be in force afterwards is a question about the stored value too.
        var usernameAfterSave = input.SmtpClearUsername
            ? false
            : !string.IsNullOrWhiteSpace(input.SmtpUsername) || hasStoredUsername;

        AddWarnings(input, host, recipients, webhookDeliverable, warnings);
        AddCredentialWarnings(usernameAfterSave, passwordAfterSave, warnings);

        // Every writable field is written on every save, so the overlay always
        // holds the complete writable set once an administrator has saved once.
        // A partial write would leave some fields reading from appsettings.json
        // and others from here, which is exactly the split the ownership report
        // exists to make legible; keeping it whole keeps that report simple.
        //
        // The transport fields (port, TLS mode, from name) are the exception,
        // written only when the request carries them: a stale dashboard from
        // before they were writable omits them, and turning that omission into
        // "reset to defaults" would rewrite a transport the operator configured
        // in the file. The current dashboard always sends those three.
        //
        // Neither half of the credential is decided here. PasswordProtected
        // never was, because protecting a secret is not a pure computation, and
        // since issue #261 the username is resolved the same way: the caller
        // lays both onto this record from inside the store's locked mutate,
        // with ResolvePasswordBlob and ResolveUsername. Both need the value on
        // disk at write time rather than a snapshot, and a null here would be
        // written as "the dashboard does not manage this field", which for a
        // username an administrator saved is a wipe, not a carry forward.
        var normalized = new SettingsOverlay.AlertOverlaySettings(
            Enabled: input.Enabled,
            CheckIntervalMinutes: input.CheckIntervalMinutes,
            ThresholdDays: thresholds,
            Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                Host: host,
                FromAddress: fromAddress,
                Recipients: recipients,
                Port: port,
                TlsMode: tlsMode,
                Username: null,
                FromName: fromName));

        return new AlertConfigValidation(errors, warnings, normalized);
    }

    /// <summary>
    /// What the overlay's password blob should hold after this save: the newly
    /// protected value when one was typed, an empty string when the operator
    /// removed it, and otherwise whatever is stored today. The carry forward arm
    /// is the load bearing one: every save rewrites the whole alert block, so
    /// forgetting it would wipe the saved password on any ordinary edit of an
    /// unrelated field. <paramref name="protect"/> is a delegate so this stays
    /// pure and testable; the caller passes ISecretProtector.Protect.
    ///
    /// <para>
    /// An explicit removal stores an empty string rather than null, the same
    /// three state vocabulary <see cref="ResolveUsername"/> uses: empty means
    /// the dashboard owns this field and holds no password, while null means
    /// the dashboard does not own it at all and appsettings.json decides.
    /// Returning null for a removal made the two indistinguishable, and every
    /// reader that falls back to the in force value when the overlay is silent
    /// then honoured a removal for the username and ignored it for the password
    /// (issue #286). The empty blob is inert everywhere it lands:
    /// <c>EmailAlertNotifier.TryResolvePassword</c> and every presence check
    /// guard with IsNullOrEmpty, so it reads as no password rather than as a
    /// blob that will not decrypt.
    /// </para>
    ///
    /// <para>
    /// What a removal does not touch is a plaintext
    /// <c>Certus:Alerts:Smtp:Password</c> from appsettings.json or the
    /// environment. <c>AlertOptions.ApplyOverlay</c> writes only the blob, so
    /// after a restart the file's password still authenticates, exactly as
    /// before. The dashboard has never owned that key and removing its own
    /// saved secret is not a claim about the file's.
    /// </para>
    /// </summary>
    public static string? ResolvePasswordBlob(
        string? requestPassword,
        bool clearPassword,
        string? currentBlob,
        Func<string, string> protect)
    {
        if (clearPassword)
            return string.Empty;
        if (!string.IsNullOrEmpty(requestPassword))
            return protect(requestPassword);
        return currentBlob;
    }

    /// <summary>
    /// The same rules <see cref="AlertOptions.NormalizeThresholdDays"/> applies,
    /// but refusing rather than quietly dropping. A value silently discarded on
    /// the way into the file is a threshold the operator believes is armed.
    /// </summary>
    private static int[] NormalizeThresholds(IReadOnlyList<int>? thresholdDays, List<string> errors)
    {
        if (thresholdDays == null || thresholdDays.Count == 0)
        {
            // Refused whether or not monitoring is switched on. An empty array
            // has never been a state the alerting engine tolerates, so it is not
            // storable either way, and the message must not offer switching
            // monitoring off as a way to satisfy this, because it is not one.
            errors.Add(
                "Add at least one warning threshold. An empty list means no warning is ever sent.");
            return [];
        }

        if (thresholdDays.Count > MaxThresholds)
        {
            errors.Add($"There is a limit of {MaxThresholds} warning thresholds.");
            return [];
        }

        var invalid = thresholdDays.Where(d => d < 1 || d > MaxThresholdDays).ToList();
        if (invalid.Count > 0)
        {
            errors.Add(
                $"A warning threshold must be between 1 and {MaxThresholdDays} days. " +
                $"Not usable: {string.Join(", ", invalid)}.");
            return [];
        }

        return thresholdDays.Distinct().OrderByDescending(d => d).ToArray();
    }

    /// <summary>
    /// The relay host. An empty value is legitimate and means email is off, so
    /// only a non-empty value is checked. <see cref="Uri.CheckHostName"/> accepts
    /// a DNS name, an IPv4 address or an IPv6 literal and rejects anything
    /// carrying a scheme, a port, a path or whitespace, which is the whole set of
    /// ways an operator might paste a URL into a host box.
    /// </summary>
    private static string NormalizeHost(string? smtpHost, List<string> errors)
    {
        var host = smtpHost?.Trim() ?? string.Empty;
        if (host.Length == 0)
            return string.Empty;

        if (Uri.CheckHostName(host) == UriHostNameType.Unknown)
        {
            errors.Add(
                $"\"{host}\" is not a usable SMTP host name. Enter a host name or an IP " +
                "address on its own, with no scheme, port or path.");
        }

        return host;
    }

    /// <summary>
    /// A plain address and nothing else. MimeKit would accept a display name
    /// form ("Alerts &lt;alerts@example.com&gt;") and encode it safely, but a
    /// stored value that is only ever an address is one less thing for a reader
    /// of this configuration to have to reason about, and the sender display name
    /// already has its own setting.
    /// </summary>
    private static string NormalizeAddress(string? value, string label, List<string> errors)
    {
        var address = value?.Trim() ?? string.Empty;
        if (address.Length == 0)
            return string.Empty;

        if (!MailboxAddress.TryParse(address, out var parsed) ||
            !string.Equals(parsed.Address, address, StringComparison.Ordinal))
        {
            errors.Add(
                $"{label} \"{address}\" is not a usable email address. Enter one plain " +
                "address such as alerts@example.com, with no display name.");
        }

        return address;
    }

    /// <summary>
    /// The relay port. Null means the request did not carry one (a stale
    /// dashboard) and nothing is stored, keeping whatever the file says.
    /// </summary>
    private static int? NormalizePort(int? port, List<string> errors)
    {
        if (port is { } value && value is < 1 or > 65535)
        {
            errors.Add("The SMTP port must be between 1 and 65535.");
            return null;
        }

        return port;
    }

    /// <summary>
    /// The transport security mode, strictly parsed the way the EAB
    /// enforcement endpoint parses its mode: a value that is not one of the
    /// canonical names is refused rather than corrected, because a typo that
    /// silently became "starttls" would change how a credential travels.
    /// Null means the request did not carry one and nothing is stored.
    /// </summary>
    private static string? NormalizeTlsMode(string? tlsMode, List<string> errors)
    {
        if (tlsMode == null)
            return null;

        if (!SmtpTlsModes.TryParse(tlsMode, out var mode))
        {
            errors.Add(
                $"\"{tlsMode}\" is not a TLS mode. Use one of: " +
                $"{string.Join(", ", SmtpTlsModes.Names)}.");
            return null;
        }

        return SmtpTlsModes.Canonical(mode);
    }

    /// <summary>
    /// What the overlay's username should hold after this save, resolved the
    /// way <see cref="ResolvePasswordBlob"/> resolves the password: the newly
    /// typed name when one arrived, an empty string when the operator removed
    /// it, and otherwise whatever is stored today.
    ///
    /// <para>
    /// The carry forward arm is the load bearing one, for the same reason it is
    /// on the password: every save rewrites the whole alert block, and the
    /// overlay writer omits nulls, so returning null on an ordinary edit of an
    /// unrelated field would drop the saved username out of the file entirely.
    /// Before issue #261 the form could post the value back unchanged because
    /// the config endpoint returned it. It no longer does, so the server has to
    /// remember it instead.
    /// </para>
    ///
    /// <para>
    /// An explicit removal stores an empty string rather than null. The two are
    /// different states: empty means the dashboard owns this field and the
    /// relay is contacted anonymously, while null means the dashboard does not
    /// own it at all and appsettings.json decides.
    /// </para>
    /// </summary>
    public static string? ResolveUsername(
        string? requestUsername, bool clearUsername, string? currentUsername)
    {
        if (clearUsername)
            return string.Empty;
        if (!string.IsNullOrWhiteSpace(requestUsername))
            return requestUsername.Trim();
        return currentUsername;
    }

    /// <summary>
    /// A username change request must be one thing at a time, exactly like the
    /// password: typing a new name and ticking "remove the saved username" in
    /// the same save has no single honest reading, so it is refused rather than
    /// ranked.
    /// </summary>
    private static void ValidateUsernameChange(AlertConfigInput input, List<string> errors)
    {
        if (input.SmtpClearUsername && !string.IsNullOrWhiteSpace(input.SmtpUsername))
        {
            errors.Add(
                "Choose one: set a new SMTP username or remove the saved one, not both.");
        }

        if (input.SmtpUsername is { } username && username.Trim().Length > MaxUsernameLength)
            errors.Add($"The SMTP username is limited to {MaxUsernameLength} characters.");
    }

    private static string? NormalizeFromName(string? fromName, List<string> errors)
    {
        if (fromName == null)
            return null;

        var trimmed = fromName.Trim();
        if (trimmed.Length > MaxFromNameLength)
            errors.Add($"The sender display name is limited to {MaxFromNameLength} characters.");

        return trimmed;
    }

    /// <summary>
    /// A password change request must be one thing at a time: typing a new
    /// password and ticking "remove the saved password" in the same save has
    /// no single honest reading, so it is refused rather than ranked.
    /// </summary>
    private static void ValidatePasswordChange(AlertConfigInput input, List<string> errors)
    {
        if (input.SmtpClearPassword && !string.IsNullOrEmpty(input.SmtpPassword))
        {
            errors.Add(
                "Choose one: set a new SMTP password or remove the saved one, not both.");
        }

        if (input.SmtpPassword is { Length: > MaxPasswordLength })
            errors.Add($"The SMTP password is limited to {MaxPasswordLength} characters.");

        if (input.SmtpPassword is { } password && password.Length > 0 &&
            string.IsNullOrWhiteSpace(password))
        {
            errors.Add("The SMTP password cannot be only whitespace.");
        }
    }

    /// <summary>
    /// Authentication happens only when both halves are present; a save that
    /// leaves exactly one configured contacts the relay anonymously, which is
    /// legal but almost never what was meant.
    ///
    /// <para>
    /// Both arms describe the state after the save rather than what the request
    /// carried. They used to differ: the username arm was suppressed unless the
    /// request actually sent the field, so a stale dashboard that omitted it was
    /// not scolded for a value it never touched. Since issue #261 omitting the
    /// username is the normal case rather than the stale one, so that guard
    /// would have silenced the warning almost always. Reporting the effective
    /// state is both simpler and the honest answer: the relay either will
    /// authenticate after this save or it will not.
    /// </para>
    /// </summary>
    private static void AddCredentialWarnings(
        bool usernameAfterSave, bool passwordAfterSave, List<string> warnings)
    {
        if (usernameAfterSave && !passwordAfterSave)
        {
            warnings.Add(
                "A username is set but no password is stored, so the relay will be " +
                "contacted without authentication. Set a password to authenticate.");
        }
        else if (!usernameAfterSave && passwordAfterSave)
        {
            warnings.Add(
                "A password is stored but the username is blank, so the relay will be " +
                "contacted without authentication. Set a username to authenticate.");
        }
    }

    private static string[] NormalizeRecipients(IReadOnlyList<string>? values, List<string> errors)
    {
        if (values == null || values.Count == 0)
            return [];

        if (values.Count > MaxRecipients)
        {
            errors.Add($"There is a limit of {MaxRecipients} recipients.");
            return [];
        }

        var recipients = new List<string>(values.Count);
        foreach (var value in values)
        {
            var address = NormalizeAddress(value, "The recipient", errors);
            if (address.Length == 0)
            {
                errors.Add("A recipient address cannot be blank. Remove the empty entry.");
                continue;
            }

            // Deduplicated rather than refused: the same address twice is a
            // paste slip, not a decision, and the second copy would only mean a
            // duplicate mail.
            if (!recipients.Contains(address, StringComparer.OrdinalIgnoreCase))
                recipients.Add(address);
        }

        return [.. recipients];
    }

    /// <summary>
    /// The states worth saying out loud. All of them save; none of them deliver
    /// what the operator probably expects.
    /// </summary>
    private static void AddWarnings(
        AlertConfigInput input,
        string host,
        IReadOnlyList<string> recipients,
        bool webhookDeliverable,
        List<string> warnings)
    {
        var emailDeliverable = host.Length > 0 && recipients.Count > 0;

        if (!input.Enabled)
        {
            warnings.Add(
                "Expiry monitoring is switched off, so no certificate is checked and no " +
                "warning is sent, whatever else is set here.");
            return;
        }

        if (!emailDeliverable && !webhookDeliverable)
        {
            warnings.Add(
                host.Length > 0
                    ? "A relay host is set but nobody is listed to receive, and no webhook " +
                      "is configured, so every warning goes nowhere. Add at least one recipient."
                    : recipients.Count > 0
                        ? "Recipients are listed but no relay host is set, and no webhook is " +
                          "configured, so every warning goes nowhere. Add an SMTP host."
                        : "Nothing is configured to send over, so every warning goes nowhere. " +
                          "Add an SMTP host with at least one recipient, or configure a webhook " +
                          "in the Certus:Alerts:Webhook section of appsettings.json.");
            return;
        }

        if (!emailDeliverable && recipients.Count == 0 && host.Length > 0)
        {
            warnings.Add(
                "No recipient is listed, so no alert email will be sent. The webhook is " +
                "still delivering.");
        }
    }
}

/// <summary>
/// One save of the writable alert settings. The webhook block is absent from
/// this type entirely rather than present and ignored, so there is no shape in
/// which a webhook URL could reach the overlay through this path.
/// <see cref="SmtpPassword"/> and <see cref="SmtpUsername"/> are both write
/// only: they arrive here to be stored, and since issue #261 no read path
/// carries either back out. The nullable transport fields mean "the request did
/// not carry this field" (a stale dashboard), and nothing is stored for them.
///
/// <para>
/// The two credential fields read that absence differently from the rest. For
/// them a blank or missing value means "leave what is stored alone", and the
/// matching <see cref="SmtpClearPassword"/> and <see cref="SmtpClearUsername"/>
/// flags are the only way to empty one. A form that cannot show a value must
/// not be able to destroy it by submitting the blank box it had to render.
/// </para>
/// </summary>
public sealed record AlertConfigInput(
    bool Enabled,
    int CheckIntervalMinutes,
    IReadOnlyList<int>? ThresholdDays,
    string? SmtpHost,
    string? SmtpFromAddress,
    IReadOnlyList<string>? SmtpRecipients,
    int? SmtpPort = null,
    string? SmtpTlsMode = null,
    string? SmtpUsername = null,
    string? SmtpFromName = null,
    string? SmtpPassword = null,
    bool SmtpClearPassword = false,
    bool SmtpClearUsername = false);

/// <summary>
/// The verdict on one save. <see cref="Normalized"/> is null exactly when
/// <see cref="Errors"/> is non-empty, so a caller cannot persist a rejected
/// input by mistake.
/// </summary>
public sealed record AlertConfigValidation(
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    SettingsOverlay.AlertOverlaySettings? Normalized)
{
    public bool IsValid => Errors.Count == 0;
}
