using Certus.Core.Configuration;

namespace Certus.Core.Alerts;

/// <summary>
/// Configuration for certificate expiry alerts.
/// Stored in the "Certus:Alerts" configuration section.
/// </summary>
public sealed class AlertOptions
{
    public const string SectionName = "Certus:Alerts";

    // ── The keys an administrator may write from the dashboard (issue #162) ──
    //
    // Named once here so the apply step, the sanitized view and the write
    // endpoint cannot drift about which keys are in the writable set.

    public const string EnabledKey = SectionName + ":" + nameof(Enabled);
    public const string CheckIntervalMinutesKey = SectionName + ":" + nameof(CheckIntervalMinutes);
    public const string ThresholdDaysKey = SectionName + ":" + nameof(ThresholdDays);
    public const string SmtpHostKey = SectionName + ":Smtp:" + nameof(SmtpOptions.Host);
    public const string SmtpPortKey = SectionName + ":Smtp:" + nameof(SmtpOptions.Port);
    public const string SmtpTlsModeKey = SectionName + ":Smtp:" + nameof(SmtpOptions.TlsMode);
    public const string SmtpUsernameKey = SectionName + ":Smtp:" + nameof(SmtpOptions.Username);
    public const string SmtpPasswordKey = SectionName + ":Smtp:" + nameof(SmtpOptions.Password);
    public const string SmtpFromAddressKey = SectionName + ":Smtp:" + nameof(SmtpOptions.FromAddress);
    public const string SmtpFromNameKey = SectionName + ":Smtp:" + nameof(SmtpOptions.FromName);
    public const string SmtpRecipientsKey = SectionName + ":Smtp:" + nameof(SmtpOptions.Recipients);

    /// <summary>
    /// The writable keys a higher precedence configuration layer can outrank,
    /// which is the scalar ones. Arrays are excluded on purpose: see
    /// <see cref="ApplyOverlay"/>. The password key is here for one reason:
    /// an environment variable or command line switch supplying
    /// Certus:Alerts:Smtp:Password must beat the dashboard's protected blob,
    /// and the blob apply below checks this set to honour that.
    /// </summary>
    public static readonly string[] OutrankableKeys =
        [EnabledKey, CheckIntervalMinutesKey, SmtpHostKey, SmtpPortKey, SmtpTlsModeKey,
         SmtpUsernameKey, SmtpPasswordKey, SmtpFromAddressKey, SmtpFromNameKey];

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
    /// The widest alert threshold to fall back on when none was configured, and
    /// the window every expiry surface used to hardcode independently.
    /// </summary>
    public const int DefaultExpiryWarningDays = 30;

    /// <summary>
    /// Certificate revocation list monitoring (issue #447). On by default: it
    /// is the reason to install rather than a revenue feature, and an estate
    /// that does not want it can switch it off in one key.
    ///
    /// A nested block like Smtp and Webhook, and like Webhook it is not editable
    /// from the dashboard. Unlike both, it is never null: an absent block means
    /// the defaults, not off.
    ///
    /// The accessor defends that rather than trusting the initializer. The
    /// configuration binder applies an explicit JSON null over a C# initializer,
    /// which is the trap the configuration binding section of CLAUDE.md records
    /// against `Certus:DatabasePath`, and here it would be a null reference on
    /// every pass of the monitor rather than a wrong default.
    /// </summary>
    public CrlAlertOptions Crl
    {
        get => _crl ??= new CrlAlertOptions();
        set => _crl = value ?? new CrlAlertOptions();
    }

    private CrlAlertOptions? _crl;

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
    /// The single "expiring soon" window the whole product uses, in days: the
    /// widest configured alert threshold (issue #152). The dashboard stat card,
    /// the fleet health donut, the list badge, and the table's amber cutoff all
    /// read this, so an operator who alerts at 60 days sees a 60 day dashboard
    /// instead of one that reports zero expiring while the emails go out.
    ///
    /// Enabled is deliberately not consulted. NormalizeThresholdDays guarantees
    /// a non-empty array, so this is 30 on any default or unconfigured install;
    /// an operator who explicitly configured a window keeps it even with
    /// delivery switched off, rather than silently getting 30 back.
    ///
    /// The length guard covers an instance that never went through
    /// NormalizeThresholdDays, such as a bare `new AlertOptions()` or a
    /// `.Get&lt;AlertOptions&gt;()` bind that skipped PostConfigure. Max() on an
    /// empty array throws.
    /// </summary>
    public int ExpiryWarningDays =>
        ThresholdDays.Length > 0 ? ThresholdDays.Max() : DefaultExpiryWarningDays;

    /// <summary>
    /// Applies the default thresholds when none were configured and cleans up
    /// whatever was: values must be positive, appear once, and run from the
    /// largest threshold down (the order the expiry monitor evaluates them in).
    /// </summary>
    public void NormalizeThresholdDays()
    {
        ThresholdDays = ThresholdDays is { Length: > 0 }
            ? ThresholdDays.Where(d => d > 0).Distinct().OrderByDescending(d => d).ToArray()
            : [DefaultExpiryWarningDays, 14, 7, 1];
    }

    /// <summary>
    /// Lay whatever an administrator saved from the dashboard over the values
    /// the configuration binder produced (issue #162). Call this before
    /// <see cref="NormalizeThresholdDays"/>, never after.
    ///
    /// <para>
    /// <b>Why this exists rather than letting the binder do it.</b> The overlay
    /// is a JSON configuration source, and .NET flattens a JSON array into
    /// indexed keys that merge across providers one index at a time. The shipped
    /// appsettings.json carries <c>ThresholdDays: [30, 14, 7, 1]</c>, so an
    /// overlay saving <c>[60, 30]</c> supplies only index 0 and 1 and the merged
    /// result binds to <c>[60, 30, 7, 1]</c>. Nothing downstream can detect
    /// that: <see cref="NormalizeThresholdDays"/> sees four positive, distinct,
    /// correctly ordered values. Through the binder alone the threshold list can
    /// only ever grow, which is why every array here is replaced <b>wholesale</b>
    /// instead.
    /// </para>
    ///
    /// <para>
    /// <b>Precedence.</b> A null member means the dashboard does not manage that
    /// key, so the bound value stands and an install that never saved behaves
    /// exactly as it did before. For scalars, an environment variable or command
    /// line switch still outranks a saved value, which is the ordering
    /// <c>SettingsOverlay.AddSettingsOverlay</c> documents;
    /// <paramref name="outrankedKeys"/> carries that answer from
    /// <c>SettingsOverlay.FindOutrankedKeys</c>. Arrays are exempt and are owned
    /// outright by the overlay once saved, because honouring the layering for an
    /// array means honouring it per index, which is the merge this method exists
    /// to defeat.
    /// </para>
    /// </summary>
    public void ApplyOverlay(
        SettingsOverlay.AlertOverlaySettings? overlay,
        IReadOnlySet<string> outrankedKeys)
    {
        if (overlay == null)
            return;

        if (overlay.Enabled is { } enabled && !outrankedKeys.Contains(EnabledKey))
            Enabled = enabled;

        if (overlay.CheckIntervalMinutes is { } interval &&
            !outrankedKeys.Contains(CheckIntervalMinutesKey))
        {
            CheckIntervalMinutes = interval;
        }

        if (overlay.ThresholdDays is { } thresholds)
            ThresholdDays = thresholds;

        var smtp = overlay.Smtp;
        if (smtp == null)
            return;

        // Only materialize an SmtpOptions when the overlay actually carries a
        // value for one. A block that exists but is empty is a different state
        // from no block at all, and AlertConfigView gives the two opposite
        // advice, so an all null overlay block must not turn "not configured"
        // into "configured but incomplete". Every member of the overlay's SMTP
        // slice must appear here: a member missing from this guard makes an
        // overlay that manages only that member silently no-op.
        if (smtp.Host == null && smtp.FromAddress == null && smtp.Recipients == null &&
            smtp.Port == null && smtp.TlsMode == null && smtp.Username == null &&
            smtp.FromName == null && smtp.PasswordProtected == null)
        {
            return;
        }

        // The shipped appsettings.json has "Smtp": null, so this is the step
        // that lets an administrator turn email on without touching the file.
        Smtp ??= new SmtpOptions();

        if (smtp.Host is { } host && !outrankedKeys.Contains(SmtpHostKey))
            Smtp.Host = host;

        if (smtp.Port is { } port && !outrankedKeys.Contains(SmtpPortKey))
            Smtp.Port = port;

        // Stored canonical by the policy; an unrecognized hand edit is skipped
        // rather than guessed at, leaving the legacy UseSsl and port derivation
        // in force.
        if (smtp.TlsMode is { } tlsMode && !outrankedKeys.Contains(SmtpTlsModeKey) &&
            SmtpTlsModes.TryParse(tlsMode, out var mode))
        {
            Smtp.TlsMode = mode;
        }

        if (smtp.Username is { } username && !outrankedKeys.Contains(SmtpUsernameKey))
            Smtp.Username = username;

        // The dashboard's password, protected at rest. An environment variable
        // or command line Certus:Alerts:Smtp:Password outranks it, exactly like
        // the plaintext scalars: with the key outranked the blob is not even
        // copied in, so the notifier's "blob wins over plaintext" rule cannot
        // shadow the higher layer.
        if (smtp.PasswordProtected is { } blob && !outrankedKeys.Contains(SmtpPasswordKey))
            Smtp.PasswordProtected = blob;

        if (smtp.FromAddress is { } fromAddress && !outrankedKeys.Contains(SmtpFromAddressKey))
            Smtp.FromAddress = fromAddress;

        if (smtp.FromName is { } fromName && !outrankedKeys.Contains(SmtpFromNameKey))
            Smtp.FromName = fromName;

        if (smtp.Recipients is { } recipients)
            Smtp.Recipients = recipients;
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
    /// server that has no transport security. Consulted only when
    /// <see cref="TlsMode"/> is null: an explicit mode replaces this whole
    /// derivation.
    /// </summary>
    public bool UseSsl { get; set; } = true;

    /// <summary>
    /// The explicit transport security mode. Null means not chosen, and the
    /// legacy derivation from <see cref="UseSsl"/> and <see cref="Port"/>
    /// decides, so an install configured before this setting existed keeps
    /// exactly the behaviour it had. The dashboard always saves an explicit
    /// mode; <c>SmtpTlsModes</c> owns the canonical names.
    /// </summary>
    public SmtpTlsMode? TlsMode { get; set; }

    /// <summary>SMTP username (optional if server allows anonymous relay).</summary>
    public string? Username { get; set; }

    /// <summary>
    /// SMTP password in the clear, from appsettings.json, an environment
    /// variable, or the command line. The configuration file path that always
    /// existed; <see cref="PasswordProtected"/> is the dashboard's.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// The dashboard saved SMTP password, protected with ISecretProtector
    /// (the Data Protection keyring, DPAPI machine scope). Never plaintext,
    /// never returned by any endpoint. Unprotected at send time by
    /// EmailAlertNotifier, which fails the send closed when the blob cannot
    /// be decrypted (a data directory restored onto another machine), rather
    /// than falling back to an older password or sending unauthenticated.
    /// When present it wins over <see cref="Password"/> unless a higher
    /// configuration layer supplies that key: ApplyOverlay skips copying the
    /// blob in that case, so precedence is decided before options are built.
    /// </summary>
    public string? PasswordProtected { get; set; }

    /// <summary>Sender email address.</summary>
    public string FromAddress { get; set; } = "ducks@localhost";

    /// <summary>Sender display name.</summary>
    public string FromName { get; set; } = "Ducks in a Row";

    /// <summary>
    /// Recipient email addresses for alert notifications.
    /// </summary>
    public string[] Recipients { get; set; } = [];
}

/// <summary>
/// The explicit SMTP transport security modes the dashboard offers.
/// </summary>
public enum SmtpTlsMode
{
    /// <summary>No transport security. Only for a relay that has none.</summary>
    None,

    /// <summary>Negotiate STARTTLS and require it; never fall back to plaintext.</summary>
    StartTls,

    /// <summary>Implicit TLS: the session is encrypted from the first byte (classically port 465).</summary>
    Implicit,
}

/// <summary>
/// The one home for the SMTP TLS mode names as they travel through the
/// overlay file and the API: lowercase strings, parsed strictly. The overlay
/// stores the string rather than the enum so a hand edit that misspells a
/// mode is skipped (legacy derivation stands) instead of binding to a wrong
/// enum default.
/// </summary>
public static class SmtpTlsModes
{
    public const string NoneName = "none";
    public const string StartTlsName = "starttls";
    public const string ImplicitName = "implicit";

    /// <summary>Every canonical name, for error messages and the API contract.</summary>
    public static readonly string[] Names = [NoneName, StartTlsName, ImplicitName];

    public static bool TryParse(string? value, out SmtpTlsMode mode)
    {
        switch (value?.Trim().ToLowerInvariant())
        {
            case NoneName:
                mode = SmtpTlsMode.None;
                return true;
            case StartTlsName:
                mode = SmtpTlsMode.StartTls;
                return true;
            case ImplicitName:
                mode = SmtpTlsMode.Implicit;
                return true;
            default:
                mode = SmtpTlsMode.StartTls;
                return false;
        }
    }

    public static string Canonical(SmtpTlsMode mode) => mode switch
    {
        SmtpTlsMode.None => NoneName,
        SmtpTlsMode.Implicit => ImplicitName,
        _ => StartTlsName,
    };

    /// <summary>
    /// The mode the legacy UseSsl and port derivation produces, so the
    /// dashboard can show the effective mode for an install that never chose
    /// one. Must stay in step with EmailAlertNotifier.ResolveSocketOptions.
    /// </summary>
    public static SmtpTlsMode Derive(bool useSsl, int port) =>
        !useSsl ? SmtpTlsMode.None
        : port == 465 ? SmtpTlsMode.Implicit
        : SmtpTlsMode.StartTls;
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
