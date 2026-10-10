using System.Text.Json.Serialization;
using Certus.Core.Configuration;

namespace Certus.Core.Alerts;

/// <summary>
/// The alert configuration as the dashboard is allowed to see it (issue #161).
///
/// <para>
/// A pure projection with no dependencies, following the CertificateAlertLadder
/// precedent: the rules live somewhere that can be tested without standing up a
/// database, and AlertQueryService is only the wiring that hands it its inputs.
/// </para>
///
/// <para>
/// <b>What is deliberately not here.</b> The SMTP username and password, and the
/// webhook URL and its custom header names. The webhook URL is treated as
/// sensitive because it routinely embeds a bearer token (that is how Slack and
/// Teams authenticate), and a password is a password. The username joined them
/// in issue #261: it is the account half of a relay credential, and several
/// providers derive it from a real key rather than a name (AWS SES uses an IAM
/// access key id), so the endpoint reports only whether one is set. Presence
/// flags are all that is said about any of them.
/// </para>
///
/// <para>
/// <b>Everything else about the SMTP transport is shown in the clear.</b> The
/// host and from address came back in issue #162; the port, TLS mode and from
/// name followed when the transport became fully dashboard writable. The rule
/// for those has not changed: a field an administrator can set from the
/// dashboard is one they must be able to read there, because a field nobody can
/// read is a field nobody can safely edit.
/// </para>
///
/// <para>
/// The username is the one field that is writable and unreadable at once, and
/// the write side pays for that with an explicit clearUsername flag. Omitting
/// the field on a save means "keep what is stored", never "blank it", so a form
/// that cannot show the value also cannot destroy it. Before issue #261 the
/// opposite was true: an omitted-looking empty string meant anonymous, which is
/// why the value had to be returned for the form to post back unchanged.
/// </para>
/// </summary>
/// <param name="ManagedFields">
/// The writable fields an administrator has saved from the dashboard, which the
/// settings overlay now owns. An operator who edits those keys in
/// appsettings.json will see nothing happen, and the card has to say so: this is
/// the issue #93 "I edited the file and nothing changed" problem arriving at a
/// second surface. <see cref="From"/> leaves this empty; the controller fills it
/// in, because only it knows what the overlay currently holds.
/// </param>
/// <param name="OutrankedFields">
/// Writable fields an environment variable or command line switch supplies.
/// Saving those from the dashboard cannot take effect while the override stands,
/// so the card refuses to pretend otherwise.
/// </param>
/// <param name="OverlayUnreadable">
/// True when settings.json exists but could not be parsed. The values above are
/// then whatever appsettings.json says, and anything previously saved from the
/// dashboard is not in force.
/// </param>
/// <param name="RestartPending">
/// True when the overlay holds a value the running process is not using, so a
/// restart is owed. Derived by the server rather than remembered by the browser:
/// a restart stays owed until it happens, which outlives the session that
/// saved, and an operator who closes the tab and comes back must not be shown
/// the old values with no sign that a save is waiting.
/// </param>
public sealed record AlertConfigView(
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("checkIntervalMinutes")] int CheckIntervalMinutes,
    [property: JsonPropertyName("thresholdDays")] IReadOnlyList<int> ThresholdDays,
    [property: JsonPropertyName("expiryWarningDays")] int ExpiryWarningDays,
    [property: JsonPropertyName("smtp")] AlertSmtpView? Smtp,
    [property: JsonPropertyName("webhook")] AlertWebhookView? Webhook,
    [property: JsonPropertyName("managedFields")] IReadOnlyList<string> ManagedFields,
    [property: JsonPropertyName("outrankedFields")] IReadOnlyList<string> OutrankedFields,
    [property: JsonPropertyName("overlayUnreadable")] bool OverlayUnreadable,
    [property: JsonPropertyName("restartPending")] bool RestartPending)
{
    /// <summary>
    /// The writable field names, as the dashboard form addresses them. Shared by
    /// <see cref="ManagedFields"/>, <see cref="OutrankedFields"/> and the write
    /// endpoint so the three cannot disagree about what is writable.
    /// </summary>
    public static class Fields
    {
        public const string Enabled = "enabled";
        public const string CheckIntervalMinutes = "checkIntervalMinutes";
        public const string ThresholdDays = "thresholdDays";
        public const string SmtpHost = "smtp.host";
        public const string SmtpPort = "smtp.port";
        public const string SmtpTlsMode = "smtp.tlsMode";
        public const string SmtpUsername = "smtp.username";
        public const string SmtpPassword = "smtp.password";
        public const string SmtpFromAddress = "smtp.fromAddress";
        public const string SmtpFromName = "smtp.fromName";
        public const string SmtpRecipients = "smtp.recipients";
    }

    /// <summary>
    /// The configuration key behind each writable field, for turning the
    /// outranked key set from <c>SettingsOverlay.FindOutrankedKeys</c> back into
    /// field names the dashboard understands. Only the scalar keys appear: an
    /// array cannot be outranked, because the overlay owns it outright once
    /// saved (see <c>AlertOptions.ApplyOverlay</c>).
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> FieldsByConfigKey =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [AlertOptions.EnabledKey] = Fields.Enabled,
            [AlertOptions.CheckIntervalMinutesKey] = Fields.CheckIntervalMinutes,
            [AlertOptions.SmtpHostKey] = Fields.SmtpHost,
            [AlertOptions.SmtpPortKey] = Fields.SmtpPort,
            [AlertOptions.SmtpTlsModeKey] = Fields.SmtpTlsMode,
            [AlertOptions.SmtpUsernameKey] = Fields.SmtpUsername,
            [AlertOptions.SmtpPasswordKey] = Fields.SmtpPassword,
            [AlertOptions.SmtpFromAddressKey] = Fields.SmtpFromAddress,
            [AlertOptions.SmtpFromNameKey] = Fields.SmtpFromName,
        };

    /// <summary>
    /// Builds the view from the bound options and the registered notifiers.
    ///
    /// The per channel <c>enabled</c> flags come from the notifiers themselves,
    /// not from "the configuration block is present". That is the fact worth
    /// owning here: a configuration block can be present and still deliver
    /// nothing, and only the notifier knows its own rule for that.
    ///
    /// The three ownership fields are left empty here and filled in by the
    /// controller. They describe the configuration file layering rather than the
    /// bound options, so this stays the pure projection it was built to be.
    /// </summary>
    public static AlertConfigView From(AlertOptions options, IEnumerable<IAlertNotifier> notifiers)
    {
        var byChannel = notifiers.ToDictionary(n => n.Channel, n => n.IsEnabled, StringComparer.Ordinal);

        return new AlertConfigView(
            Enabled: options.Enabled,
            CheckIntervalMinutes: options.CheckIntervalMinutes,
            ThresholdDays: options.ThresholdDays,
            // The derived window, not just the raw array (issue #152). The
            // backend owns the derivation so the dashboard cannot drift from it
            // by recomputing the rule in TypeScript.
            ExpiryWarningDays: options.ExpiryWarningDays,
            Smtp: options.Smtp == null ? null : new AlertSmtpView(
                Enabled: byChannel.GetValueOrDefault("email"),
                HasHost: !string.IsNullOrEmpty(options.Smtp.Host),
                Host: options.Smtp.Host,
                Port: options.Smtp.Port,
                // The effective mode: the explicit choice when one is stored,
                // otherwise what the legacy UseSsl and port derivation will do,
                // so the form's dropdown always shows what a send would use.
                TlsMode: SmtpTlsModes.Canonical(
                    options.Smtp.TlsMode
                    ?? SmtpTlsModes.Derive(options.Smtp.UseSsl, options.Smtp.Port)),
                // Whitespace counts as absent, matching the notifier's own
                // IsEnabled rule, so the two flags cannot disagree about one
                // value.
                HasFromAddress: !string.IsNullOrWhiteSpace(options.Smtp.FromAddress),
                FromAddress: options.Smtp.FromAddress,
                FromName: options.Smtp.FromName,
                Recipients: options.Smtp.Recipients,
                // The only thing said about the relay account name since issue
                // #261. The value itself never leaves the server.
                HasCredentials: !string.IsNullOrEmpty(options.Smtp.Username),
                // Either source counts: the dashboard's protected blob or a
                // password from the configuration file or environment. The
                // form only needs to know whether authentication has a second
                // half, never what it is.
                HasPassword: !string.IsNullOrEmpty(options.Smtp.PasswordProtected) ||
                             !string.IsNullOrEmpty(options.Smtp.Password)),
            Webhook: options.Webhook == null ? null : new AlertWebhookView(
                Enabled: byChannel.GetValueOrDefault("webhook"),
                HasSecret: !string.IsNullOrEmpty(options.Webhook.Secret),
                HeaderCount: options.Webhook.Headers.Count),
            ManagedFields: [],
            OutrankedFields: [],
            OverlayUnreadable: false,
            RestartPending: false);
    }

    /// <summary>
    /// Whether the overlay holds a writable value this process is not running
    /// on, which is exactly the condition a restart clears.
    ///
    /// <para>
    /// Compared field by field against the bound options rather than tracked as
    /// a flag, because a flag would have to be stored somewhere and kept true
    /// across restarts of the very process that clears it. Comparing is also the
    /// honest answer when someone edits settings.json by hand.
    /// </para>
    ///
    /// <para>
    /// An outranked key is skipped. The overlay can never win for those, so a
    /// difference there is permanent and no restart would resolve it; reporting
    /// it would leave the card demanding a restart forever.
    /// </para>
    /// </summary>
    public static bool HasUnappliedChanges(
        AlertOptions inForce,
        SettingsOverlay.AlertOverlaySettings? saved,
        IReadOnlySet<string> outrankedKeys)
    {
        if (saved == null)
            return false;

        bool Applies(string configKey) => !outrankedKeys.Contains(configKey);

        if (saved.Enabled is { } enabled &&
            Applies(AlertOptions.EnabledKey) &&
            enabled != inForce.Enabled)
        {
            return true;
        }

        if (saved.CheckIntervalMinutes is { } interval &&
            Applies(AlertOptions.CheckIntervalMinutesKey) &&
            interval != inForce.CheckIntervalMinutes)
        {
            return true;
        }

        // Normalized on both sides (the policy sorts and dedupes on the way in,
        // NormalizeThresholdDays does the same on the way out), so order is
        // meaningful and SequenceEqual is the right comparison.
        if (saved.ThresholdDays is { } thresholds &&
            !thresholds.SequenceEqual(inForce.ThresholdDays))
        {
            return true;
        }

        var smtp = saved.Smtp;
        if (smtp == null)
            return false;

        if (smtp.Host is { } host &&
            Applies(AlertOptions.SmtpHostKey) &&
            !string.Equals(host, inForce.Smtp?.Host ?? string.Empty, StringComparison.Ordinal))
        {
            return true;
        }

        if (smtp.Port is { } port &&
            Applies(AlertOptions.SmtpPortKey) &&
            port != (inForce.Smtp?.Port ?? 587))
        {
            return true;
        }

        // Compared against the explicit in-force mode only. A saved mode that
        // merely spells out what the legacy derivation already does still owes
        // a restart: after it, TlsMode is what decides, and reporting that
        // honestly is simpler than proving the two paths equivalent here.
        if (smtp.TlsMode is { } tlsMode &&
            Applies(AlertOptions.SmtpTlsModeKey) &&
            !string.Equals(
                tlsMode,
                inForce.Smtp?.TlsMode is { } mode ? SmtpTlsModes.Canonical(mode) : null,
                StringComparison.Ordinal))
        {
            return true;
        }

        if (smtp.Username is { } username &&
            Applies(AlertOptions.SmtpUsernameKey) &&
            !string.Equals(username, inForce.Smtp?.Username ?? string.Empty, StringComparison.Ordinal))
        {
            return true;
        }

        // The blobs compare as opaque strings. Data Protection ciphertext is
        // nondeterministic, but the in-force copy is the very string the
        // overlay held when this process started, so equal strings mean the
        // saved password is in force and different strings mean it is not.
        if (Applies(AlertOptions.SmtpPasswordKey) &&
            !string.Equals(
                smtp.PasswordProtected,
                inForce.Smtp?.PasswordProtected,
                StringComparison.Ordinal))
        {
            return true;
        }

        if (smtp.FromAddress is { } fromAddress &&
            Applies(AlertOptions.SmtpFromAddressKey) &&
            !string.Equals(fromAddress, inForce.Smtp?.FromAddress ?? string.Empty, StringComparison.Ordinal))
        {
            return true;
        }

        if (smtp.FromName is { } fromName &&
            Applies(AlertOptions.SmtpFromNameKey) &&
            !string.Equals(fromName, inForce.Smtp?.FromName ?? string.Empty, StringComparison.Ordinal))
        {
            return true;
        }

        return smtp.Recipients is { } recipients &&
            !recipients.SequenceEqual(inForce.Smtp?.Recipients ?? [], StringComparer.Ordinal);
    }

    /// <summary>
    /// The writable fields the settings overlay currently owns, in the order the
    /// dashboard form shows them. A field counts as managed the moment the
    /// overlay carries a value for it, whether or not that value differs from
    /// the file's: what matters to the operator is which layer wins, not whether
    /// the two happen to agree today.
    /// </summary>
    public static IReadOnlyList<string> DescribeManagedFields(
        SettingsOverlay.AlertOverlaySettings? saved)
    {
        if (saved == null)
            return [];

        var managed = new List<string>(11);

        if (saved.Enabled is not null)
            managed.Add(Fields.Enabled);
        if (saved.CheckIntervalMinutes is not null)
            managed.Add(Fields.CheckIntervalMinutes);
        if (saved.ThresholdDays is not null)
            managed.Add(Fields.ThresholdDays);
        if (saved.Smtp?.Host is not null)
            managed.Add(Fields.SmtpHost);
        if (saved.Smtp?.Port is not null)
            managed.Add(Fields.SmtpPort);
        if (saved.Smtp?.TlsMode is not null)
            managed.Add(Fields.SmtpTlsMode);
        if (saved.Smtp?.Username is not null)
            managed.Add(Fields.SmtpUsername);
        if (saved.Smtp?.PasswordProtected is not null)
            managed.Add(Fields.SmtpPassword);
        if (saved.Smtp?.FromAddress is not null)
            managed.Add(Fields.SmtpFromAddress);
        if (saved.Smtp?.FromName is not null)
            managed.Add(Fields.SmtpFromName);
        if (saved.Smtp?.Recipients is not null)
            managed.Add(Fields.SmtpRecipients);

        return managed;
    }

    /// <summary>
    /// The outranked configuration keys, as dashboard field names. Keys with no
    /// field are dropped rather than passed through: the card can only speak
    /// about fields it renders.
    /// </summary>
    public static IReadOnlyList<string> DescribeOutrankedFields(IEnumerable<string> outrankedConfigKeys) =>
        outrankedConfigKeys
            .Select(key => FieldsByConfigKey.GetValueOrDefault(key))
            .OfType<string>()
            .ToList();
}

/// <summary>
/// Email alerting, as much of it as may be shown.
///
/// Null instead of this object means no SMTP block is configured at all, which
/// is a different state from a block that is present but incomplete, and the
/// dashboard says different things about each.
///
/// <see cref="HasHost"/> exists so the card can tell "a relay is configured but
/// nobody is listed to receive" apart from "recipients are listed but there is
/// no relay to send through". Both report <see cref="Enabled"/> false and they
/// need opposite advice. It is kept alongside <see cref="Host"/> rather than
/// replaced by it, because the two answer different questions and the card
/// branches on the presence check in several places.
///
/// <see cref="HasFromAddress"/> follows the same design for the third
/// incomplete state (issue #209): a relay and recipients are set but the
/// sender is blank, which an explicit null for Smtp:FromAddress in
/// appsettings.json produces. Without it that install reads as fully
/// configured while every send fails at the relay, so the card needs the
/// sender's presence reported on its own to give that case its own advice.
///
/// Most writable transport settings are returned in the clear so the form can
/// show what it is editing: the host and sender address (issue #162), and the
/// port, TLS mode and sender display name since the transport became fully
/// dashboard configurable. A field an administrator can set but cannot see is
/// one they cannot safely edit; none of these is a secret, and the error
/// redactor keeps the host out of failure text shown wider than this
/// admin-only endpoint. <see cref="TlsMode"/> is always the effective mode,
/// whether chosen explicitly or derived from the legacy UseSsl and port rule.
///
/// Both halves of the relay credential are the exception, and neither appears
/// here in any form. <see cref="HasPassword"/> is all that is said about the
/// password, and it counts one from either source (the dashboard's protected
/// blob or the configuration file). <see cref="HasCredentials"/> keeps its
/// issue #161 name and meaning, presence of a username, and since issue #261
/// it is the only thing said about it: the value used to be returned alongside
/// this flag so the form could post it back unchanged, which
/// <c>AlertErrorRedactor</c> had already contradicted by treating the username
/// as a value that must never reach an error message. The write side now
/// carries that weight instead, through the clearUsername flag that lets an
/// omitted field mean "keep".
/// </summary>
public sealed record AlertSmtpView(
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("hasHost")] bool HasHost,
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("tlsMode")] string TlsMode,
    [property: JsonPropertyName("hasFromAddress")] bool HasFromAddress,
    [property: JsonPropertyName("fromAddress")] string FromAddress,
    [property: JsonPropertyName("fromName")] string FromName,
    [property: JsonPropertyName("recipients")] IReadOnlyList<string> Recipients,
    [property: JsonPropertyName("hasCredentials")] bool HasCredentials,
    [property: JsonPropertyName("hasPassword")] bool HasPassword);

/// <summary>
/// Webhook alerting, presence only. The URL never appears here.
/// <see cref="HeaderCount"/> replaces the header name list: a count is enough to
/// confirm custom headers are configured, and names can themselves be revealing.
/// </summary>
public sealed record AlertWebhookView(
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("hasSecret")] bool HasSecret,
    [property: JsonPropertyName("headerCount")] int HeaderCount);
