using System.Reflection;
using System.Text.Json;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Web.Audit;
using Certus.Web.Authentication;
using Certus.Web.Configuration;
using Certus.Web.Controllers.Dashboard;
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
    private readonly CertusInstanceMode _instanceMode;
    private readonly ReleaseAgeOptions _releaseAge;
    private readonly TimeProvider _time;
    private readonly ILogger<SettingsController> _logger;

    public SettingsController(
        SetupService setupService,
        IServiceRestarter serviceRestarter,
        HttpsCertificateRenewalService renewal,
        HttpsCertificateAutoRenewalService autoRenewal,
        IHttpsCertificateStore certificateStore,
        IOptions<CertusOptions> certusOptions,
        IConfiguration configuration,
        CertusInstanceMode instanceMode,
        IOptions<ReleaseAgeOptions> releaseAge,
        ILogger<SettingsController> logger,
        TimeProvider? timeProvider = null)
    {
        _setupService = setupService;
        _serviceRestarter = serviceRestarter;
        _renewal = renewal;
        _autoRenewal = autoRenewal;
        _certificateStore = certificateStore;
        _certusOptions = certusOptions.Value;
        _configuration = configuration;
        _instanceMode = instanceMode;
        _releaseAge = releaseAge.Value;
        // Both hosts register TimeProvider.System through AddCertusModuleHost;
        // the fallback keeps a bare test host working and is never a fake.
        _time = timeProvider ?? TimeProvider.System;
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
    ///
    /// mode is "full" or "monitor" (issue #470). It is the one place the
    /// dashboard learns the mode, which it uses for its badge and to hide the
    /// controls that would write to the CA. Reported, never accepted: the mode
    /// is a local administrator's registry value and no endpoint changes it.
    ///
    /// The release age fields (issue #623) are the one in product aid against
    /// staying on an old release that the no internet rule allows. commitDate
    /// is the date of the commit the build was stamped from (null without a
    /// stamp, like commit), releaseAgeDays how old that is by this server's
    /// clock, releaseAgeWarningDays the threshold in force (0 when disabled),
    /// and releaseOutdated whether the age passed it. runtimeVersion and
    /// aspNetCoreVersion name the shared frameworks the process runs on,
    /// which Windows Update patches independently of the installer. Nothing
    /// here is fetched from anywhere: every value is read off the process.
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

        var commitDate = InstalledRelease.ReadCommitDate(typeof(SettingsController).Assembly);
        var warningDays = _releaseAge.EffectiveWarningDays;
        var age = InstalledRelease.Evaluate(commitDate, _time.GetUtcNow(), warningDays);

        return Ok(new
        {
            version,
            commit,
            mode = _instanceMode.WireName,
            commitDate = commitDate?.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            releaseAgeDays = age.AgeDays,
            releaseAgeWarningDays = warningDays,
            releaseOutdated = age.Outdated,
            runtimeVersion = InstalledRelease.RuntimeVersion(),
            aspNetCoreVersion = InstalledRelease.AspNetCoreVersion(),
        });
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
    [AdminAudit("settings.external-url.changed")]
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
            // The audit row first, then the file (issue #634): a crash between
            // the two leaves a record of what was about to change rather than
            // a changed file nobody is on record for.
            var previousUrl = SettingsOverlay.Load(_setupService.SettingsOverlayPath).ExternalUrl;
            await this.AdminAudit().RecordBeforeFileWriteAsync(
                "Certus:ExternalUrl", previousUrl ?? "(not set)", request.Url, ct);
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
    [AdminAudit("settings.allowed-domains.changed")]
    public async Task<IActionResult> UpdateAllowedDomains(
        [FromBody] UpdateAllowedDomainsRequest request, CancellationToken ct)
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

        // The audit row before the file write (issue #634); the filter appends
        // a "not applied" row if the write below is refused.
        await this.AdminAudit().RecordBeforeFileWriteAsync(
            "allowed domains",
            DescribeAllowedDomains(status.AllowedDomainsEnabled, status.AllowedDomains),
            DescribeAllowedDomains(request.Enabled, normalized), ct);

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
    [AdminAudit("settings.revocation-scope.changed")]
    public async Task<IActionResult> UpdateRevocationScope(
        [FromBody] UpdateRevocationScopeRequest request, CancellationToken ct)
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

        var previousMode = RevocationScopePolicy.TryParseMode(status.RevocationScope, out var parsedPrevious)
            ? parsedPrevious
            : RevocationScopeMode.DucksManaged;
        await this.AdminAudit().RecordBeforeFileWriteAsync(
            "revocation scope",
            DescribeRevocationScope(previousMode, status.RevocableTemplates),
            DescribeRevocationScope(mode, templates), ct);

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
    ///
    /// installedByService says who owns the certificate (issue #535): true when
    /// it carries this service's friendly name, false when somebody else
    /// installed it, null when it is not in the store and the question cannot
    /// be asked. autoRenewal.renewsThisCertificate is the automatic renewal's
    /// own rule applied to it: switched on, and not a certificate somebody else
    /// installed. A missing certificate counts as renewed, because the renewal
    /// replaces it.
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
        bool? installedByService = certificate is null
            ? null
            : HttpsCertificateOwnership.InstalledByService(certificate);

        return Ok(new
        {
            configured = true,
            thumbprint,
            inStore = certificate is not null,
            installedByService,
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
                renewsThisCertificate = _autoRenewal.Enabled && installedByService != false,
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

    private ObjectResult RefuseRenewalInMonitorMode()
    {
        _logger.LogWarning(
            "Refused an HTTPS certificate renewal from the settings page: this server runs in monitor mode");
        return MonitorModeProblem.Refuse(this,
            "This server runs in monitor mode, so it never enrolls or renews a certificate. " +
            "Renew it at the certification authority and select it by thumbprint instead.");
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
    /// On a certificate this service did not install, typically one picked in
    /// monitor mode, this is how an administrator hands renewal to the service
    /// (issue #535): from then on the automatic renewal renews the certificate
    /// enrolled here. The certificate it replaces is not removed, because it is
    /// not this service's to delete.
    ///
    /// Unlike the wizard flow there is no "apply anyway" for a certificate
    /// that stops covering the external URL host: that is a template
    /// regression to fix (Subject Name tab), not a state to accept, so the
    /// freshly enrolled certificate is removed again and the response says
    /// what was issued. The enroller's Pending/Denied messages carry their
    /// exact fixes and flow through unchanged.
    /// </summary>
    [HttpPost("https-certificate/renew")]
    [AdminAudit("settings.https-certificate.renewal-requested")]
    public async Task<IActionResult> RenewHttpsCertificate(CancellationToken ct)
    {
        // First (issue #470). The renewal core refuses on its own too, with the
        // MonitorMode blocker mapped below; this answers before it is asked.
        if (_instanceMode.IsMonitor)
            return RefuseRenewalInMonitorMode();

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
                if (result.Blocker == HttpsCertificateRenewalBlocker.MonitorMode)
                    return RefuseRenewalInMonitorMode();
                return result.Blocker == HttpsCertificateRenewalBlocker.MockCa
                    ? BadRequest(new { error = result.Message })
                    : Conflict(new { error = result.Message });

            case HttpsCertificateRenewalOutcome.Pending:
            case HttpsCertificateRenewalOutcome.Denied:
            case HttpsCertificateRenewalOutcome.Failed:
                // A 200 that enrolled nothing (issue #634): the CA's answer is
                // the record, and the row says so rather than claiming a renewal.
                this.AdminAudit().Describe(
                    $"template {result.Template}",
                    after: $"renewal requested, CA answered {result.Outcome.ToString().ToLowerInvariant()}: {result.Message}");
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
                this.AdminAudit().Describe(
                    $"template {result.Template}",
                    after: $"renewal issued {result.Thumbprint} but it does not cover the external URL host, so it was removed again");
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
        // until an administrator applies the new one. Only a certificate this
        // service installed goes (issue #535): one picked in monitor mode is
        // somebody else's, so it stays, with its key.
        var previousThumbprint = result.PreviousThumbprint;
        if (!string.IsNullOrWhiteSpace(previousThumbprint) &&
            !string.Equals(previousThumbprint, result.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            _renewal.TryRemoveSuperseded(previousThumbprint);
        }

        var restartScheduled = _serviceRestarter.TryScheduleRestart();
        _logger.LogInformation(
            "Webserver certificate renewed with template {Template}: {Thumbprint} replaces {Previous}",
            result.Template, result.Thumbprint, previousThumbprint ?? "(none)");
        this.AdminAudit().Describe(
            "HTTPS certificate",
            before: previousThumbprint ?? "(none)",
            after: $"{result.Thumbprint}, enrolled with template {result.Template}");

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
    [AdminAudit("settings.https-certificate.applied")]
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
        this.AdminAudit().Describe(
            "HTTPS certificate",
            before: _certusOptions.HttpsCertificateThumbprint ?? "(none)",
            after: $"{overlayThumbprint}, restart scheduled: {restartScheduled}");

        return Ok(new
        {
            thumbprint = overlayThumbprint,
            restartScheduled,
            message = restartScheduled
                ? "The service is restarting to serve the renewed certificate."
                : "Restart the service to serve the renewed certificate.",
        });
    }

    /// <summary>The allowed domain policy in the words the audit trail records (issue #634).</summary>
    internal static string DescribeAllowedDomains(bool enabled, IReadOnlyList<string> domains) =>
        enabled ? $"on: {string.Join(", ", domains)}" : "off";

    /// <summary>The revocation scope in the words the audit trail records (issue #634).</summary>
    internal static string DescribeRevocationScope(RevocationScopeMode mode, IReadOnlyList<string> customTemplates) =>
        mode == RevocationScopeMode.Custom
            ? $"custom: {(customTemplates.Count == 0 ? "(no templates, dashboard revocation disabled)" : string.Join(", ", customTemplates))}"
            : RevocationScopePolicy.ModeName(mode);

    /// <summary>
    /// The overlay exists but cannot be parsed, or a save would set one
    /// configuration key twice (issue #550). Shared by the external URL, the
    /// HTTPS certificate card, its Renew button and its Apply button, so the
    /// sentence names none of them (issue #553). Fail loudly with the path:
    /// rewriting the file from scratch could silently drop the CA connection
    /// string, and a bare 500 would leave the admin no clue which file to fix.
    /// </summary>
    private ObjectResult OverlayUnreadable(JsonException ex)
    {
        var path = _setupService.SettingsOverlayPath;
        _logger.LogError(ex, "The settings overlay at {Path} could not be read or saved", path);
        return StatusCode(500, new
        {
            error = $"The settings overlay at {path} is not valid JSON, or would set a " +
                    "configuration key twice, and must be fixed by hand before this setting " +
                    "can be changed here. The service log names the problem.",
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
