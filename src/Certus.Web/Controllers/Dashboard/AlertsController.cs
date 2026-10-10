using System.Text.Json;
using System.Text.Json.Serialization;
using Certus.Core.Alerts;
using Certus.Core.Security;
using Certus.Core.Setup;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Options;

namespace Certus.Web.Controllers.Dashboard;

/// <summary>
/// Dashboard API: alert configuration and history.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class AlertsController : ControllerBase
{
    private readonly AlertQueryService _alertQueryService;
    private readonly AlertTestService _alertTestService;
    private readonly AlertConfigStore _configStore;
    private readonly IServiceRestarter _serviceRestarter;
    private readonly IEnumerable<IAlertNotifier> _notifiers;
    private readonly IOptions<AlertOptions> _alertOptions;
    private readonly ISecretProtector _protector;
    private readonly ILogger<AlertsController> _logger;

    /// <param name="alertOptions">
    /// The options this process is running on, for comparing against what the
    /// overlay holds. IOptions, not IOptionsMonitor, for the reason
    /// AlertQueryService documents: the expiry monitor snapshots its options at
    /// construction, so this is the snapshot every consumer shares.
    /// </param>
    /// <param name="protector">
    /// Protects an incoming SMTP password before it reaches the overlay, and
    /// only that: this controller never unprotects anything, so a blob can
    /// travel through here but a plaintext password can only travel in.
    /// </param>
    public AlertsController(
        AlertQueryService alertQueryService,
        AlertTestService alertTestService,
        AlertConfigStore configStore,
        IServiceRestarter serviceRestarter,
        IEnumerable<IAlertNotifier> notifiers,
        IOptions<AlertOptions> alertOptions,
        ISecretProtector protector,
        ILogger<AlertsController> logger)
    {
        _alertQueryService = alertQueryService;
        _alertTestService = alertTestService;
        _configStore = configStore;
        _serviceRestarter = serviceRestarter;
        _notifiers = notifiers;
        _alertOptions = alertOptions;
        _protector = protector;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/alerts/history: paginated alert notification history.
    /// </summary>
    [HttpGet("history")]
    public async Task<IActionResult> GetHistory(
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50,
        CancellationToken ct = default)
    {
        take = Math.Clamp(take, 1, 200);
        skip = Math.Max(0, skip);

        var result = await _alertQueryService.GetHistoryAsync(skip, take, ct);
        return Ok(result);
    }

    /// <summary>
    /// GET /api/alerts/certificate/{id}: the alert ladder for one certificate,
    /// for its detail page (issue #160). Every configured threshold with what
    /// happened at it, plus why the certificate is or is not covered at all.
    ///
    /// 404 rather than an empty ladder for an unknown certificate: an empty
    /// ladder means "nothing was ever sent", which is a different answer.
    /// </summary>
    [HttpGet("certificate/{certificateId:int}")]
    public async Task<IActionResult> GetForCertificate(int certificateId, CancellationToken ct)
    {
        var history = await _alertQueryService.GetForCertificateAsync(certificateId, ct);
        return history == null ? NotFound() : Ok(history);
    }

    /// <summary>
    /// GET /api/alerts/summary: alert statistics summary.
    /// </summary>
    [HttpGet("summary")]
    public async Task<IActionResult> GetSummary(CancellationToken ct)
    {
        var summary = await _alertQueryService.GetSummaryAsync(ct);
        return Ok(summary);
    }

    /// <summary>
    /// GET /api/alerts/config: the alert configuration the dashboard is allowed
    /// to see. Presence only for anything sensitive: see
    /// <see cref="AlertConfigView"/> for what is withheld and why.
    ///
    /// The values are the ones this process is running on, never what is sitting
    /// unapplied in the overlay. A saved change shows up here only after the
    /// restart that puts it in force, which is what lets the card render "saved"
    /// and "in force" as the different things they are.
    /// </summary>
    [HttpGet("config")]
    public IActionResult GetConfig() => Ok(Describe());

    /// <summary>
    /// PUT /api/alerts/config: change the operational parts of alerting
    /// (issue #162, extended to the whole SMTP transport).
    ///
    /// <para>
    /// <b>The writable set is the request type.</b> The webhook block has no
    /// member on <see cref="UpdateAlertConfigRequest"/>, and the type is
    /// annotated <c>JsonUnmappedMemberHandling.Disallow</c>, so sending one is a
    /// 400 rather than a silent no-op. Without that attribute System.Text.Json
    /// ignores unknown members, and an operator who posted a webhook URL would
    /// be told it was saved. Both halves of the SMTP credential are writable but
    /// strictly write only: they arrive on
    /// <see cref="UpdateAlertSmtpRequest.Password"/> and
    /// <see cref="UpdateAlertSmtpRequest.Username"/>, the password is protected
    /// before it touches the overlay, and no response, list, log line or error
    /// body ever carries either back.
    /// </para>
    ///
    /// <para>
    /// <b>Applied by a restart, and it says so.</b> The overlay is registered
    /// with reload switched off, and every alert consumer snapshots its options
    /// at construction, so nothing here reaches the running engine. The response
    /// carries <c>restartPending</c> and the card must not show a saved value as
    /// though it were in force. No restart is scheduled from here, unlike the
    /// external URL: that change is rare and structural, this one is routine
    /// tuning, and an operator adjusting three fields should restart once when
    /// they choose rather than three times.
    /// </para>
    ///
    /// Admin only and CSRF protected by the class attribute and the global
    /// middleware, like every other mutating dashboard endpoint.
    /// </summary>
    [HttpPut("config")]
    public IActionResult UpdateConfig([FromBody] UpdateAlertConfigRequest request)
    {
        // Read once here only to answer the "will authentication actually
        // happen after this save" warning. The warning tolerates a racing
        // write; the carry forward does not, which is why the blob used for
        // the save itself is read inside the store's locked mutate below,
        // never from this snapshot.
        var state = _configStore.Read();
        // Both halves read the same way: the overlay wins outright when it has
        // an opinion, and only its silence falls through to the bound options.
        // An empty saved value is an opinion, not silence. It means an
        // administrator removed that half of the credential, and the bound
        // options still carry the old one until the restart lands, so ORing the
        // two would read a removal as "still stored" and silence the warning
        // that the other half now stands alone, which is exactly the state
        // worth warning about. The username has read this way since issue #261;
        // the password joined it in issue #286, once a removal started storing
        // an empty blob rather than nothing at all.
        var hasStoredPassword =
            (state.Saved?.Smtp?.PasswordProtected is { } savedBlob
                ? savedBlob.Length > 0
                : !string.IsNullOrEmpty(_alertOptions.Value.Smtp?.PasswordProtected))
            // The plaintext key is the one difference between the two halves. It
            // belongs to appsettings.json or the environment, the overlay has no
            // way to blank it, and a restart leaves it authenticating, so it
            // counts however the dashboard's own blob resolved.
            || !string.IsNullOrEmpty(_alertOptions.Value.Smtp?.Password);
        var hasStoredUsername = state.Saved?.Smtp?.Username is { } savedUsername
            ? savedUsername.Length > 0
            : !string.IsNullOrEmpty(_alertOptions.Value.Smtp?.Username);

        var validation = AlertConfigPolicy.Validate(
            new AlertConfigInput(
                Enabled: request.Enabled,
                CheckIntervalMinutes: request.CheckIntervalMinutes,
                ThresholdDays: request.ThresholdDays,
                SmtpHost: request.Smtp?.Host,
                SmtpFromAddress: request.Smtp?.FromAddress,
                SmtpRecipients: request.Smtp?.Recipients,
                SmtpPort: request.Smtp?.Port,
                SmtpTlsMode: request.Smtp?.TlsMode,
                SmtpUsername: request.Smtp?.Username,
                SmtpFromName: request.Smtp?.FromName,
                SmtpPassword: request.Smtp?.Password,
                SmtpClearPassword: request.Smtp?.ClearPassword ?? false,
                SmtpClearUsername: request.Smtp?.ClearUsername ?? false),
            // The webhook is not writable here, but it decides whether an empty
            // recipient list actually silences anything.
            webhookDeliverable: _notifiers.Any(n => n.Channel == "webhook" && n.IsEnabled),
            hasStoredPassword: hasStoredPassword,
            hasStoredUsername: hasStoredUsername);

        if (!validation.IsValid)
        {
            return BadRequest(new
            {
                error = "Some of these settings cannot be saved.",
                problems = validation.Errors,
            });
        }

        // Both halves of the credential are resolved outside the pure policy:
        // set, cleared, or carried forward, with the password protected before
        // it reaches the file. Both resolvers run inside the store's locked
        // mutate, so the values they carry forward are the ones on disk at
        // write time, not a snapshot a racing save could have replaced.
        var normalized = validation.Normalized!;

        try
        {
            _configStore.Save(
                normalized,
                currentBlob => AlertConfigPolicy.ResolvePasswordBlob(
                    request.Smtp?.Password,
                    request.Smtp?.ClearPassword ?? false,
                    currentBlob,
                    _protector.Protect),
                currentUsername => AlertConfigPolicy.ResolveUsername(
                    request.Smtp?.Username,
                    request.Smtp?.ClearUsername ?? false,
                    currentUsername));
        }
        catch (JsonException ex)
        {
            // Refusing beats rewriting: the overlay also holds the CA connection
            // string and the HTTPS certificate thumbprint, and saving over a file
            // that could not be read would drop both and unconfigure the CA at
            // the next start.
            _logger.LogError(ex, "The settings overlay could not be read, so alert settings were not saved");
            return Conflict(new
            {
                error = "The settings file could not be read, so nothing was changed. " +
                        "Check the service log for the file path and repair it by hand.",
            });
        }

        // Deliberately not the recipient list: it is in the request, the file and
        // the API already, and there is no reason for it to be in the log too.
        // Both halves of the credential are logged as a state transition only,
        // never a value. The username joined the password there in issue #261:
        // once a value stops being readable over the API, "who changed it and
        // when" has to be answerable from somewhere, and the log is the only
        // place left.
        _logger.LogInformation(
            "Alert configuration updated from the dashboard by {Actor}: enabled {Enabled}, " +
            "interval {Interval} minutes, thresholds {Thresholds}, {RecipientCount} recipient(s), " +
            "relay host {HostState}, username {UsernameState}, password {PasswordState}",
            User.Identity?.Name ?? "(anonymous)",
            normalized.Enabled,
            normalized.CheckIntervalMinutes,
            string.Join(", ", normalized.ThresholdDays ?? []),
            normalized.Smtp?.Recipients?.Length ?? 0,
            string.IsNullOrEmpty(normalized.Smtp?.Host) ? "cleared" : "set",
            request.Smtp?.ClearUsername == true ? "cleared"
                : !string.IsNullOrWhiteSpace(request.Smtp?.Username) ? "set"
                : "unchanged",
            request.Smtp?.ClearPassword == true ? "cleared"
                : !string.IsNullOrEmpty(request.Smtp?.Password) ? "set"
                : "unchanged");

        // restartPending rides on the config view rather than being asserted
        // here, so the answer the card gets after a save is the same one it gets
        // on a plain reload half an hour later. Saving a value that already
        // matches what is running correctly reports false.
        return Ok(new
        {
            config = Describe(),
            warnings = validation.Warnings,
            message = "Saved. Restart the service to apply the change.",
        });
    }

    /// <summary>
    /// POST /api/alerts/config/apply: restart the service so a saved alert
    /// configuration comes into force. Mirrors
    /// <c>POST /api/settings/https-certificate/apply</c>, including reporting
    /// honestly when no restarter is available (the dev host registers a no-op,
    /// so there the operator restarts the process themselves).
    /// </summary>
    [HttpPost("config/apply")]
    public IActionResult ApplyConfig()
    {
        var restartScheduled = _serviceRestarter.TryScheduleRestart();

        _logger.LogInformation(
            "Alert configuration apply requested by {Actor}; restart scheduled: {RestartScheduled}",
            User.Identity?.Name ?? "(anonymous)",
            restartScheduled);

        return Ok(new
        {
            restartScheduled,
            message = restartScheduled
                ? "The service is restarting to apply the alert settings."
                : "Restart the service to apply the alert settings.",
        });
    }

    /// <summary>
    /// The in-force configuration, decorated with which layer owns each writable
    /// field. <see cref="AlertConfigView.From"/> stays a pure projection of the
    /// bound options; the file layering is known only here.
    /// </summary>
    private AlertConfigView Describe()
    {
        var state = _configStore.Read();

        return _alertQueryService.GetConfig() with
        {
            ManagedFields = AlertConfigView.DescribeManagedFields(state.Saved),
            OutrankedFields = AlertConfigView.DescribeOutrankedFields(_configStore.OutrankedKeys),
            OverlayUnreadable = state.Unreadable,
            RestartPending = AlertConfigView.HasUnappliedChanges(
                _alertOptions.Value, state.Saved, _configStore.OutrankedKeys),
        };
    }

    /// <summary>
    /// POST /api/alerts/test: deliver a test alert over every configured
    /// channel and report what each one did (issue #161).
    ///
    /// SMTP configuration fails quietly, so an operator needs to see the channel
    /// work once before trusting it with a real expiry warning.
    ///
    /// The body is optional. Without one, the test uses the settings the
    /// service is running on, as it always has. With a candidate SMTP block,
    /// the email channel sends with those values instead, the same
    /// candidate-in-body shape as the wizard's CA connection test: SMTP changes
    /// only apply at a restart, so without this an operator could not prove a
    /// typed port, TLS mode or credential until after restarting on it. The
    /// candidate password travels one way; when it is omitted the stored one is
    /// used, and nothing about either comes back in the response.
    ///
    /// Nothing is persisted. AlertsSent cannot represent a test row without
    /// consuming a real certificate's slot in its unique index, which would
    /// permanently suppress that certificate's real warning. The service log
    /// carries the audit line instead.
    ///
    /// Admin only and CSRF protected by the class attribute and the global
    /// middleware, like every other mutating dashboard endpoint.
    /// </summary>
    [HttpPost("test")]
    public async Task<IActionResult> SendTest(
        [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] SendTestAlertRequest? request,
        CancellationToken ct)
    {
        // Negotiate always yields a name for an authorized admin; the fallback
        // covers the Development only Auth:Mode=Disabled escape hatch.
        var actor = User.Identity?.Name ?? "(anonymous)";

        SmtpOptions? candidate = null;
        if (request?.Smtp is { } smtp)
        {
            if (smtp.Port is { } port && port is < 1 or > 65535)
                return BadRequest(new { error = "The SMTP port must be between 1 and 65535." });

            SmtpTlsMode? tlsMode = null;
            if (smtp.TlsMode is { } rawMode)
            {
                if (!SmtpTlsModes.TryParse(rawMode, out var parsed))
                {
                    return BadRequest(new
                    {
                        error = $"\"{rawMode}\" is not a TLS mode. Use one of: " +
                                $"{string.Join(", ", SmtpTlsModes.Names)}.",
                    });
                }

                tlsMode = parsed;
            }

            candidate = new SmtpOptions
            {
                Host = smtp.Host?.Trim() ?? string.Empty,
                Port = smtp.Port ?? 587,
                TlsMode = tlsMode,
                FromAddress = smtp.FromAddress?.Trim() ?? string.Empty,
                Recipients = smtp.Recipients ?? [],
            };
            if (smtp.FromName is { } fromName)
                candidate.FromName = fromName.Trim();

            // Read once for whichever half of the credential the form did not
            // retype. A test send tolerates a racing write, unlike a save's
            // carry forward, so one snapshot serves both.
            var saved = _configStore.Read().Saved;

            // The username falls back exactly like the password below, and for
            // the reason issue #261 created: the form no longer knows the
            // stored value, so a candidate that omits it means "test what is
            // configured", never "test anonymously". Reading it the other way
            // would report a pass for an anonymous connection while the real
            // transport authenticates, which is the one answer a test send must
            // never give. The save path's resolver is the same rule with the
            // clear flag held off, so it is reused rather than restated: a test
            // send has no way to ask for anonymous, only to type a name.
            candidate.Username = AlertConfigPolicy.ResolveUsername(
                smtp.Username,
                clearUsername: false,
                currentUsername: saved?.Smtp?.Username ?? _alertOptions.Value.Smtp?.Username);

            if (!string.IsNullOrEmpty(smtp.Password))
            {
                // A just typed password, used directly and never stored.
                candidate.Password = smtp.Password;
            }
            else
            {
                // The stored one, resolved by the same three states as the
                // username above. A blob is the freshest saved password; an
                // empty string is a removal an administrator saved and has not
                // restarted onto yet, which stops the fall through so the test
                // proves the pending state rather than the old password; null
                // is the overlay saying nothing, and only then do the bound
                // options answer. Before issue #286 a removal stored null too,
                // so it fell through and the test authenticated with a password
                // that was on its way out while the username beside it was
                // already anonymous: a pairing that would never actually run.
                //
                // The plaintext value rides along whatever the blob resolved
                // to. It comes from appsettings.json or the environment, the
                // overlay cannot blank it, and a restart leaves it in force.
                // The notifier resolves the precedence between the two and
                // fails closed on an undecryptable blob.
                candidate.PasswordProtected = saved?.Smtp?.PasswordProtected
                    ?? _alertOptions.Value.Smtp?.PasswordProtected;
                candidate.Password = _alertOptions.Value.Smtp?.Password;
            }

            if (!EmailAlertNotifier.IsDeliverable(candidate))
            {
                return BadRequest(new
                {
                    error = "The SMTP settings to test are incomplete. A test needs a relay " +
                            "host, a sender address, and at least one recipient.",
                });
            }
        }

        var result = await _alertTestService.SendAsync(actor, candidate, ct);

        switch (result.Status)
        {
            case AlertTestStatus.NoChannelsEnabled:
                // 409 rather than 400: there is no request body to have got
                // wrong. The refusal is about the state of the server, the same
                // shape as applying an HTTPS certificate with none pending.
                return Conflict(new
                {
                    error = "No alert channel is configured, so there is nothing to test. " +
                            "Configure an SMTP host with a sender address and at least one " +
                            "recipient, or a webhook URL, in the Certus:Alerts section of " +
                            "appsettings.json.",
                });

            case AlertTestStatus.Throttled:
                Response.Headers.RetryAfter = result.RetryAfterSeconds.ToString();
                return StatusCode(429, new
                {
                    error = $"A test alert was sent in the last {AlertTestThrottle.CooldownSeconds} seconds. " +
                            "The cooldown is shared by everyone signed in, so another administrator " +
                            "may have sent it.",
                    retryAfterSeconds = result.RetryAfterSeconds,
                });

            default:
                // 200 even when a channel failed. The request was carried out;
                // the per channel result is the answer, and a 5xx here would
                // read as "Ducks is broken" when the truth is "your relay is".
                return Ok(new
                {
                    attemptedAt = DateTime.UtcNow,
                    results = result.Results,
                });
        }
    }
}

/// <summary>
/// The writable alert settings, as the dashboard sends them (issue #162).
///
/// <para>
/// <b>This type is the security boundary.</b> The webhook block has no member
/// here at all, so there is no shape in which a webhook URL or a set of custom
/// headers could reach the overlay through this endpoint. The <c>Disallow</c>
/// annotation turns sending an unknown member into a 400: System.Text.Json
/// ignores them by default, and an operator who posted one would otherwise be
/// told the save succeeded.
/// </para>
///
/// <para>
/// <b>PUT replaces the whole writable set.</b> An omitted <see cref="Smtp"/>
/// block means "no email configuration", not "leave email alone". That is what
/// PUT means, and it keeps the overlay holding a complete writable set once an
/// administrator has saved once, which is what makes the ownership report the
/// card shows simple to reason about. A save that clears delivery this way is
/// reported back in the warnings rather than passing silently. The password is
/// the deliberate exception (write only, three states), and the transport
/// fields tolerate omission for the sake of a stale dashboard.
/// </para>
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateAlertConfigRequest
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; }

    [JsonPropertyName("checkIntervalMinutes")]
    public int CheckIntervalMinutes { get; init; }

    [JsonPropertyName("thresholdDays")]
    public int[]? ThresholdDays { get; init; }

    [JsonPropertyName("smtp")]
    public UpdateAlertSmtpRequest? Smtp { get; init; }
}

/// <summary>
/// The writable SMTP block: the whole transport. A null transport field means
/// the request did not carry it (a stale dashboard from before it was
/// writable) and nothing is stored for it; the current dashboard always sends
/// every field except the two credential ones.
///
/// <para>
/// <see cref="Password"/> is write only with three states: a non empty value
/// sets a new password (protected before storage), <see cref="ClearPassword"/>
/// removes the stored one, and neither means the stored password is kept.
/// Setting and clearing in one request is refused. No password, in any state,
/// ever appears in a response.
/// </para>
///
/// <para>
/// <see cref="Username"/> has had exactly the same three states since issue
/// #261, when the config endpoint stopped returning it: a non empty value sets
/// a new one, <see cref="ClearUsername"/> removes the stored one so the relay
/// is contacted anonymously, and neither keeps what is stored. The third arm is
/// the one that matters. The dashboard renders an empty username box because it
/// has nothing to render, and before this the empty string it submitted meant
/// "contact the relay anonymously", so saving an unrelated field would have
/// dropped relay authentication with no error and no way to notice.
/// </para>
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateAlertSmtpRequest
{
    [JsonPropertyName("host")]
    public string? Host { get; init; }

    [JsonPropertyName("port")]
    public int? Port { get; init; }

    [JsonPropertyName("tlsMode")]
    public string? TlsMode { get; init; }

    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("clearUsername")]
    public bool ClearUsername { get; init; }

    [JsonPropertyName("password")]
    public string? Password { get; init; }

    [JsonPropertyName("clearPassword")]
    public bool ClearPassword { get; init; }

    [JsonPropertyName("fromAddress")]
    public string? FromAddress { get; init; }

    [JsonPropertyName("fromName")]
    public string? FromName { get; init; }

    [JsonPropertyName("recipients")]
    public string[]? Recipients { get; init; }
}

/// <summary>
/// The optional body of a test send. Absent entirely for the classic "test
/// what is running" behaviour; carrying <see cref="Smtp"/> makes the email
/// channel prove the candidate values instead.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record SendTestAlertRequest
{
    [JsonPropertyName("smtp")]
    public TestSmtpCandidateRequest? Smtp { get; init; }
}

/// <summary>
/// A candidate SMTP configuration to prove with a test send. The same shape
/// the form holds: every transport field, with the password optional, where
/// omitted means "authenticate with the stored password". Nothing here is
/// stored, and the candidate's values are redacted out of any failure text
/// exactly like the configured ones.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record TestSmtpCandidateRequest
{
    [JsonPropertyName("host")]
    public string? Host { get; init; }

    [JsonPropertyName("port")]
    public int? Port { get; init; }

    [JsonPropertyName("tlsMode")]
    public string? TlsMode { get; init; }

    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("password")]
    public string? Password { get; init; }

    [JsonPropertyName("fromAddress")]
    public string? FromAddress { get; init; }

    [JsonPropertyName("fromName")]
    public string? FromName { get; init; }

    [JsonPropertyName("recipients")]
    public string[]? Recipients { get; init; }
}
