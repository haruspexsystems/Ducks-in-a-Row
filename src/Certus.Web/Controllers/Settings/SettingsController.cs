using System.Reflection;
using System.Text.Json;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Certus.Web.Controllers.Settings;

/// <summary>
/// Runtime settings API for the dashboard (issue #93). Lives apart from the
/// setup wizard on purpose: setup endpoints are one time and locked once
/// setup is effectively complete (SEC-G1), while this surface exists exactly
/// from that point on. Admin only with no anonymous carve outs.
///
/// Changes are persisted to the settings overlay (settings.json in the data
/// directory) and applied by a service restart, the same mechanism the setup
/// wizard uses.
/// </summary>
[ApiController]
[Route("api/settings")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class SettingsController : ControllerBase
{
    private readonly SetupService _setupService;
    private readonly IServiceRestarter _serviceRestarter;
    private readonly HttpsCertificateRenewalService _renewal;
    private readonly HttpsCertificateAutoRenewalService _autoRenewal;
    private readonly IHttpsCertificateStore _certificateStore;
    private readonly CertusOptions _certusOptions;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SettingsController> _logger;

    public SettingsController(
        SetupService setupService,
        IServiceRestarter serviceRestarter,
        HttpsCertificateRenewalService renewal,
        HttpsCertificateAutoRenewalService autoRenewal,
        IHttpsCertificateStore certificateStore,
        IOptions<CertusOptions> certusOptions,
        IConfiguration configuration,
        ILogger<SettingsController> logger)
    {
        _setupService = setupService;
        _serviceRestarter = serviceRestarter;
        _renewal = renewal;
        _autoRenewal = autoRenewal;
        _certificateStore = certificateStore;
        _certusOptions = certusOptions.Value;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/settings/info returns the running application version and the
    /// commit it was built from, for the Settings page. Reads
    /// AssemblyInformationalVersion, which carries the full release string
    /// ("0.10.0-beta.1") from Directory.Build.props' VersionPrefix and
    /// VersionSuffix combined, plus a "+&lt;sha&gt;" stamp when build.ps1
    /// resolved a commit (issue #112). BuildVersionInfo splits the two so the
    /// page can show a clean version and keep the sha as its own field.
    ///
    /// The MSI's ProductVersion is a separate, strictly numeric value WiX
    /// requires (see build.ps1). It carries neither the prerelease label nor
    /// the commit, and cannot: Windows Installer versions are four numeric
    /// fields. This endpoint is the only place either shows up at runtime.
    ///
    /// commit is null on a build with no stamp, which is a supported build
    /// (the release source snapshot has no .git). The page hides the row.
    /// </summary>
    [HttpGet("info")]
    public IActionResult GetInfo()
    {
        var informationalVersion = typeof(SettingsController).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        var (version, commit) = BuildVersionInfo.Split(informationalVersion);

        if (string.IsNullOrEmpty(version))
        {
            version = typeof(SettingsController).Assembly.GetName().Version?.ToString()
                ?? "unknown";
        }

        return Ok(new { version, commit });
    }

    /// <summary>
    /// GET /api/settings/external-url — the external URL in force in this
    /// process plus where each configuration layer stands, so the dashboard
    /// can show the effective value and explain a pending or outranked one.
    /// effectiveUrl comes from the bound options (what ACME URLs use right
    /// now); overlayUrl is read fresh from the overlay file, so a value saved
    /// but not yet applied by a restart shows up as restartPending. When a
    /// higher precedence source (environment variable or command line)
    /// supplies the value, restartPending stays false: no restart can make
    /// the overlay win, and claiming one is pending would mislead.
    /// </summary>
    [HttpGet("external-url")]
    public IActionResult GetExternalUrl()
    {
        var report = SettingsOverlay.InspectExternalUrl(_configuration);

        string? overlayUrl;
        try
        {
            overlayUrl = SettingsOverlay.Load(_setupService.SettingsOverlayPath).ExternalUrl;
        }
        catch (JsonException ex)
        {
            return OverlayUnreadable(ex);
        }

        var effectiveUrl = string.IsNullOrEmpty(_certusOptions.ExternalUrl)
            ? null
            : _certusOptions.ExternalUrl;

        return Ok(new
        {
            effectiveUrl,
            overlayUrl,
            appSettingsUrl = report.AppSettingsValue,
            effectiveSource = report.EffectiveSource,
            restartPending = overlayUrl is not null &&
                !string.Equals(overlayUrl, effectiveUrl, StringComparison.Ordinal) &&
                report.EffectiveSource != ExternalUrlLayerReport.SourceOther,
        });
    }

    /// <summary>
    /// PUT /api/settings/external-url — change the external URL after setup.
    /// Validates like the wizard (static checks plus the issue #89
    /// reachability probe), persists to the overlay with the CA connection
    /// string preserved, and schedules the restart that applies it. An
    /// unreachable URL is refused with 422 and the probe outcome until the
    /// request carries the explicit confirmation flag, mirroring setup
    /// completion — reverse proxy and hairpin NAT deployments can be
    /// legitimately unreachable from the server itself. When a higher
    /// precedence source outranks the overlay, the value is saved but no
    /// restart is scheduled: it would drop live connections and change
    /// nothing.
    /// </summary>
    [HttpPut("external-url")]
    public async Task<IActionResult> UpdateExternalUrl(
        [FromBody] UpdateExternalUrlRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Url))
            return BadRequest(new { error = "URL is required" });

        // Before setup the wizard is the single write path for the overlay;
        // this endpoint exists for the life of the install after it.
        var status = _setupService.GetStatus();
        if (!status.SetupCompleted || !_setupService.IsCaEffectivelyConfigured)
            return Conflict(new { error = "Setup has not been completed. Configure the external URL in the setup wizard." });

        var validation = await _setupService.ValidateExternalUrlAsync(
            request.Url, status.EnabledTemplates.FirstOrDefault(), ct);

        if (!validation.Valid)
            return BadRequest(new { error = validation.ErrorMessage ?? "External URL is invalid" });

        if (validation.Probe is { Attempted: true, Reachable: false }
            && !request.ConfirmUnreachableExternalUrl)
        {
            return UnprocessableEntity(new
            {
                reason = "externalUrlUnreachable",
                message = "The external URL did not answer when probed from the server. " +
                          "Confirm the URL to save it anyway.",
                probe = validation.Probe,
            });
        }

        try
        {
            _setupService.UpdateExternalUrl(request.Url);
        }
        catch (JsonException ex)
        {
            return OverlayUnreadable(ex);
        }
        _logger.LogInformation("External URL updated from the dashboard settings page");

        // A restart applies the overlay; when an environment variable or
        // command line value outranks it, restarting drops live connections
        // and changes nothing, so skip it and say why.
        var report = SettingsOverlay.InspectExternalUrl(_configuration);
        if (report.EffectiveSource == ExternalUrlLayerReport.SourceOther)
        {
            return Ok(new
            {
                externalUrl = request.Url,
                restartScheduled = false,
                message = "External URL saved, but an environment variable or command line " +
                          "setting outranks it. The change takes effect once that override " +
                          "is removed and the service restarts.",
            });
        }

        var restartScheduled = _serviceRestarter.TryScheduleRestart();
        return Ok(new
        {
            externalUrl = request.Url,
            restartScheduled,
            message = restartScheduled
                ? "External URL saved. The service is restarting to apply the change."
                : "External URL saved. Restart the service to apply the change.",
        });
    }

    /// <summary>
    /// GET /api/settings/allowed-domains: the domain restriction in force,
    /// read fresh from the wizard status file (which is where a PUT writes
    /// it and where the issuance policy hot reads it), plus the machine's AD
    /// domain as the suggestion behind the "Add my AD domain" button.
    /// adDomain is null on a machine that is not domain joined.
    /// </summary>
    [HttpGet("allowed-domains")]
    public IActionResult GetAllowedDomains()
    {
        var status = _setupService.GetStatus();
        return Ok(new
        {
            enabled = status.AllowedDomainsEnabled,
            domains = status.AllowedDomains,
            adDomain = AdDomainSuggestion.Get(),
        });
    }

    /// <summary>
    /// PUT /api/settings/allowed-domains: change the domain restriction
    /// after setup. Entries are validated and normalized (lowercase punycode
    /// A labels, bare domains only, no wildcards), and turning the
    /// restriction on requires at least one usable entry, so the fail open
    /// state the issuance policy tolerates in hand edited files can never be
    /// written through this API. Applies immediately: AllowedDomainsPolicy
    /// hot reads the file, so unlike the external URL no restart is
    /// involved.
    /// </summary>
    [HttpPut("allowed-domains")]
    public IActionResult UpdateAllowedDomains([FromBody] UpdateAllowedDomainsRequest request)
    {
        // Before setup the wizard is the single write path for the status
        // file; this endpoint exists for the life of the install after it.
        var status = _setupService.GetStatus();
        if (!status.SetupCompleted || !_setupService.IsCaEffectivelyConfigured)
            return Conflict(new { error = "Setup has not been completed. Configure allowed domains in the setup wizard." });

        var (normalized, invalid) = AllowedDomainsPolicy.ValidateAndNormalize(request.Domains ?? []);

        if (invalid.Count > 0)
            return BadRequest(new
            {
                error = "Some entries are not usable domain names.",
                invalidEntries = invalid
                    .Select(i => new { entry = i.Entry, reason = i.Reason })
                    .ToList(),
            });

        if (request.Enabled && normalized.Count == 0)
            return BadRequest(new { error = "Add at least one domain, or turn the restriction off." });

        if (!_setupService.UpdateAllowedDomains(request.Enabled, normalized))
            return Conflict(new
            {
                error = "The wizard status file could not be read back as completed, " +
                        "so nothing was changed. Check the service log for the file path.",
            });

        _logger.LogInformation("Allowed domains updated from the dashboard settings page");

        return Ok(new
        {
            enabled = request.Enabled,
            domains = normalized,
            message = "Saved. New orders use the updated policy immediately.",
        });
    }

    /// <summary>
    /// GET /api/settings/revocation-scope: the dashboard revocation scope,
    /// read fresh from the wizard status file (which is where a PUT writes
    /// it and where the eligibility gate hot reads it). enabledTemplates
    /// rides along so the card can say what ducks-managed covers.
    /// </summary>
    [HttpGet("revocation-scope")]
    public IActionResult GetRevocationScope()
    {
        var status = _setupService.GetStatus();
        var mode = RevocationScopePolicy.TryParseMode(status.RevocationScope, out var parsed)
            ? parsed
            : RevocationScopeMode.DucksManaged;
        return Ok(new
        {
            mode = RevocationScopePolicy.ModeName(mode),
            customTemplates = status.RevocableTemplates,
            enabledTemplates = status.EnabledTemplates,
        });
    }

    /// <summary>
    /// PUT /api/settings/revocation-scope: change which certificates the
    /// dashboard may revoke, always under the TLS capability ceiling, which
    /// no mode can widen. Template names are validated for the characters
    /// the ADCS attribute rules refuse, with the validator's own reason per
    /// refused entry; blank entries are dropped rather than refused, because
    /// the card's checkbox flow cannot produce them and a hand written call
    /// gains nothing from the failure. Names the CA does not currently
    /// publish are stored as given, because the CA may be unreachable at
    /// save time and the list must survive (the card flags unmatched
    /// entries). An empty custom list is allowed and means dashboard
    /// revocation is disabled entirely, which fails safe. Applies
    /// immediately: RevocationScopePolicy hot reads the file.
    /// </summary>
    [HttpPut("revocation-scope")]
    public IActionResult UpdateRevocationScope([FromBody] UpdateRevocationScopeRequest request)
    {
        // Before setup the wizard is the single write path for the status
        // file; this endpoint exists for the life of the install after it.
        // Guard first, then validate, the UpdateAllowedDomains order.
        var status = _setupService.GetStatus();
        if (!status.SetupCompleted || !_setupService.IsCaEffectivelyConfigured)
            return Conflict(new { error = "Setup has not been completed. Finish the setup wizard first." });

        if (!RevocationScopePolicy.TryParseMode(request.Mode, out var mode))
            return BadRequest(new { error = "Mode must be one of: ducks-managed, custom, all." });

        var templates = (request.CustomTemplates ?? [])
            .Select(t => t?.Trim() ?? string.Empty)
            .Where(t => t.Length > 0)
            .ToList();
        var invalid = new List<object>();
        foreach (var template in templates)
        {
            if (!AdcsRequestAttributes.TryValidateTemplateName(template, out var reason))
                invalid.Add(new { entry = template, reason = reason ?? "Not a usable template name." });
        }
        if (invalid.Count > 0)
        {
            return BadRequest(new
            {
                error = "Some entries are not usable template names.",
                invalidEntries = invalid,
            });
        }

        if (!_setupService.UpdateRevocationScope(mode, templates))
            return Conflict(new
            {
                error = "The wizard status file could not be read back as completed, " +
                        "so nothing was changed. Check the service log for the file path.",
            });

        _logger.LogInformation("Revocation scope updated from the dashboard settings page");

        return Ok(new
        {
            mode = RevocationScopePolicy.ModeName(mode),
            customTemplates = templates,
            message = "Saved. The scope applies to the next revocation immediately.",
        });
    }

    /// <summary>
    /// GET /api/settings/https-certificate — the webserver certificate the
    /// settings overlay points at, with its store presence, names, validity
    /// window, the template it was enrolled with, and the template a renewal
    /// would use (the recorded one, or the first enabled template for
    /// installs that predate the recorded field). restartPending is true when
    /// the overlay thumbprint differs from the one this process serves.
    /// </summary>
    [HttpGet("https-certificate")]
    public IActionResult GetHttpsCertificate()
    {
        SettingsOverlay.OverlaySettings overlay;
        try
        {
            overlay = SettingsOverlay.Load(_setupService.SettingsOverlayPath);
        }
        catch (JsonException ex)
        {
            return OverlayUnreadable(ex);
        }

        var thumbprint = overlay.HttpsCertificateThumbprint;
        if (string.IsNullOrWhiteSpace(thumbprint))
        {
            // Nothing was ever enrolled, so the service is on its self signed
            // fallback. Hand the dashboard the template a first provision would
            // use (the recorded one, or the first enabled template) so the
            // settings page can offer enrollment instead of pointing at the
            // wizard, which SEC-G1 has locked on a completed install.
            return Ok(new
            {
                configured = false,
                renewTemplate = overlay.HttpsCertificateTemplate
                    ?? _setupService.GetStatus().EnabledTemplates.FirstOrDefault(),
            });
        }

        var status = _setupService.GetStatus();
        var restartPending = !string.Equals(
            thumbprint, _certusOptions.HttpsCertificateThumbprint,
            StringComparison.OrdinalIgnoreCase);

        // While a restart is pending the overlay names the new certificate and
        // the process is still serving the old one, so report both: the
        // dashboard's escalating notice keys on how long the *served*
        // certificate has left, not the one waiting in the wings.
        using var certificate = _certificateStore.Find(thumbprint);
        using var servedCertificate = restartPending
            && !string.IsNullOrWhiteSpace(_certusOptions.HttpsCertificateThumbprint)
                ? _certificateStore.Find(_certusOptions.HttpsCertificateThumbprint)
                : null;

        var attempt = _autoRenewal.LastAttempt;

        return Ok(new
        {
            configured = true,
            thumbprint,
            inStore = certificate is not null,
            subject = certificate?.Subject,
            subjectNames = certificate is null
                ? null
                : TlsCertificateEnroller.GetSubjectNames(certificate),
            notBefore = certificate?.NotBefore,
            notAfter = certificate?.NotAfter,
            template = overlay.HttpsCertificateTemplate,
            renewTemplate = overlay.HttpsCertificateTemplate
                ?? status.EnabledTemplates.FirstOrDefault(),
            restartPending,
            servedThumbprint = _certusOptions.HttpsCertificateThumbprint,
            servedNotAfter = servedCertificate?.NotAfter,
            autoRenewal = new
            {
                enabled = _autoRenewal.Enabled,
                windowDays = _autoRenewal.RenewalWindowDays,
                lastAttemptAt = attempt?.AttemptedAt,
                lastOutcome = attempt is null ? null : Describe(attempt.Outcome),
                lastMessage = attempt?.Message,
                // A failure the operator should act on, as opposed to the
                // routine "nothing to do" passes, which also record an attempt.
                failed = attempt is not null
                    && attempt.Outcome != HttpsCertificateRenewalOutcome.Installed
                    && attempt.Outcome != HttpsCertificateRenewalOutcome.NotApplicable,
            },
        });
    }

    /// <summary>The camelCase outcome name the dashboard switches on.</summary>
    private static string Describe(HttpsCertificateRenewalOutcome outcome) => outcome switch
    {
        HttpsCertificateRenewalOutcome.Installed => "installed",
        HttpsCertificateRenewalOutcome.SanMismatch => "sanMismatch",
        HttpsCertificateRenewalOutcome.Pending => "pending",
        HttpsCertificateRenewalOutcome.Denied => "denied",
        HttpsCertificateRenewalOutcome.NotApplicable => "notApplicable",
        _ => "failed",
    };

    /// <summary>
    /// POST /api/settings/https-certificate/renew — re enroll the webserver
    /// certificate from the configured CA with the template recorded at
    /// setup, install it, point the overlay at it, remove the superseded
    /// certificate from the store, and schedule the restart that applies it.
    ///
    /// Unlike the wizard flow there is no "apply anyway" for a certificate
    /// that stops covering the external URL host: that is a template
    /// regression to fix (Subject Name tab), not a state to accept, so the
    /// freshly enrolled certificate is removed again and the response says
    /// what was issued. The enroller's Pending/Denied messages carry their
    /// exact fixes and flow through unchanged.
    /// </summary>
    [HttpPost("https-certificate/renew")]
    public async Task<IActionResult> RenewHttpsCertificate(CancellationToken ct)
    {
        HttpsCertificateRenewalResult result;
        try
        {
            result = await _renewal.RenewAsync(Request.Host.Host, ct);
        }
        catch (JsonException ex)
        {
            return OverlayUnreadable(ex);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "Certificate renewal: the CA is unavailable");
            return StatusCode(503, new { error = true, message = "The certificate authority is unavailable. Try again shortly." });
        }
        catch (CaAccessDeniedException ex)
        {
            // The renew button's half of issue #336, matching the wizard's arm. An
            // administrator authenticated surface, so it carries the remediation in
            // full rather than the generic sentence the ACME wire gets.
            _logger.LogError(ex, "Certificate renewal: the CA denied access");
            return StatusCode(503, new { error = true, message = ex.Message });
        }

        switch (result.Outcome)
        {
            case HttpsCertificateRenewalOutcome.NotApplicable:
                return result.Blocker == HttpsCertificateRenewalBlocker.MockCa
                    ? BadRequest(new { error = result.Message })
                    : Conflict(new { error = result.Message });

            case HttpsCertificateRenewalOutcome.Pending:
            case HttpsCertificateRenewalOutcome.Denied:
            case HttpsCertificateRenewalOutcome.Failed:
                return Ok(new
                {
                    outcome = result.Outcome switch
                    {
                        HttpsCertificateRenewalOutcome.Pending => "pending",
                        HttpsCertificateRenewalOutcome.Denied => "denied",
                        _ => "failed",
                    },
                    requestId = result.RequestId,
                    message = result.Message,
                });

            case HttpsCertificateRenewalOutcome.SanMismatch:
                return Ok(new
                {
                    outcome = "sanMismatch",
                    issuedNames = result.IssuedNames,
                    requestId = result.RequestId,
                    message = result.Message,
                });
        }

        // The overlay now points at the new certificate, so the superseded
        // one only clutters the store. Safe here and only here: this endpoint
        // restarts immediately, so the process stops serving the superseded
        // certificate within seconds. The background renewal service must
        // never do this, because its host keeps serving that certificate
        // until an administrator applies the new one.
        var previousThumbprint = result.PreviousThumbprint;
        if (!string.IsNullOrWhiteSpace(previousThumbprint) &&
            !string.Equals(previousThumbprint, result.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            _renewal.TryRemoveFromStore(previousThumbprint, "the superseded certificate");
        }

        var restartScheduled = _serviceRestarter.TryScheduleRestart();
        _logger.LogInformation(
            "Webserver certificate renewed with template {Template}: {Thumbprint} replaces {Previous}",
            result.Template, result.Thumbprint, previousThumbprint ?? "(none)");

        return Ok(new
        {
            outcome = "installed",
            thumbprint = result.Thumbprint,
            restartScheduled,
            currentHostCovered = result.CurrentHostCovered,
        });
    }

    /// <summary>
    /// POST /api/settings/https-certificate/apply — schedule the restart that
    /// starts serving a certificate the background renewal already enrolled
    /// and wrote into the overlay (issue #105). Writes nothing: the overlay
    /// already points at the new certificate, so this only applies what is
    /// recorded. Refused when nothing is pending, so the button can never
    /// bounce the service for no reason.
    /// </summary>
    [HttpPost("https-certificate/apply")]
    public IActionResult ApplyHttpsCertificate()
    {
        string? overlayThumbprint;
        try
        {
            overlayThumbprint = SettingsOverlay.Load(_setupService.SettingsOverlayPath)
                .HttpsCertificateThumbprint;
        }
        catch (JsonException ex)
        {
            return OverlayUnreadable(ex);
        }

        if (string.IsNullOrWhiteSpace(overlayThumbprint) ||
            string.Equals(overlayThumbprint, _certusOptions.HttpsCertificateThumbprint,
                StringComparison.OrdinalIgnoreCase))
        {
            return Conflict(new
            {
                error = "No renewed certificate is waiting to be applied.",
            });
        }

        var restartScheduled = _serviceRestarter.TryScheduleRestart();
        _logger.LogInformation(
            "Applying renewed webserver certificate {Thumbprint} from the dashboard; " +
            "restart scheduled: {RestartScheduled}",
            overlayThumbprint, restartScheduled);

        return Ok(new
        {
            thumbprint = overlayThumbprint,
            restartScheduled,
            message = restartScheduled
                ? "The service is restarting to serve the renewed certificate."
                : "Restart the service to serve the renewed certificate.",
        });
    }

    /// <summary>
    /// The overlay exists but cannot be parsed. Fail loudly with the path:
    /// rewriting the file from scratch could silently drop the CA connection
    /// string, and a bare 500 would leave the admin no clue which file to fix.
    /// </summary>
    private ObjectResult OverlayUnreadable(JsonException ex)
    {
        var path = _setupService.SettingsOverlayPath;
        _logger.LogError(ex, "The settings overlay at {Path} could not be parsed", path);
        return StatusCode(500, new
        {
            error = $"The settings overlay at {path} is not valid JSON and must be " +
                    "fixed by hand before the external URL can be managed here.",
        });
    }
}

/// <summary>
/// Request body for changing the external URL.
/// ConfirmUnreachableExternalUrl is the explicit acknowledgement that the URL
/// did not answer the probe and the administrator wants it saved anyway.
/// </summary>
public sealed record UpdateExternalUrlRequest(
    string Url,
    bool ConfirmUnreachableExternalUrl = false);

/// <summary>
/// Request body for changing the allowed domain policy. Domains may be null
/// or empty when Enabled is false (turning the restriction off keeps no
/// list); turning it on requires at least one usable entry.
/// </summary>
public sealed record UpdateAllowedDomainsRequest(
    bool Enabled,
    List<string>? Domains = null);

/// <summary>
/// Request body for changing the revocation scope. CustomTemplates is kept
/// whatever the mode, so toggling away from custom and back does not lose
/// the list; an empty list under custom disables dashboard revocation
/// entirely, which fails safe.
/// </summary>
public sealed record UpdateRevocationScopeRequest(
    string? Mode,
    List<string>? CustomTemplates = null);
