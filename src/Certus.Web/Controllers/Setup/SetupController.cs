using System.Text.Json;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.ServiceRights;
using Certus.Core.Setup;
using Certus.Web.Audit;
using Certus.Web.Authentication;
using Certus.Web.Controllers.Dashboard;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.Setup;

/// <summary>
/// Setup wizard API: CA discovery, connectivity testing, template listing,
/// and configuration persistence. Used by the browser based setup wizard.
/// Admin-only except for the reduced status endpoint, which the SPA needs to
/// route before authentication (issue #27, SEC-F2, SEC-G1).
///
/// Connectivity tests and template listing take the candidate CA connection
/// string explicitly and probe through a transient client; the DI bound
/// client during setup is the unconfigured client (or the mock) and would
/// test the wrong thing.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class SetupController : ControllerBase
{
    private readonly SetupService _setupService;
    private readonly IServiceRestarter _serviceRestarter;
    private readonly TlsCertificateEnroller _tlsEnroller;
    private readonly IHttpsCertificateStore _certificateStore;
    private readonly ServiceRightsCheck _serviceRightsCheck;
    private readonly IConfiguration _configuration;
    private readonly CertusInstanceMode _instanceMode;
    private readonly ILogger<SetupController> _logger;

    /// <summary>
    /// Why a reopened wizard is open: a server that finished setup in monitor
    /// mode was switched to full and has no template yet (issue #471).
    /// </summary>
    internal const string ReopenReasonIssuanceEnabled = "issuanceEnabled";

    internal const string MonitorModeRecordsNoTemplate =
        "This server runs in monitor mode, so setup records no certificate template. " +
        "Remove the templates from the request.";

    public SetupController(
        SetupService setupService,
        IServiceRestarter serviceRestarter,
        TlsCertificateEnroller tlsEnroller,
        IHttpsCertificateStore certificateStore,
        ServiceRightsCheck serviceRightsCheck,
        IConfiguration configuration,
        CertusInstanceMode instanceMode,
        ILogger<SetupController> logger)
    {
        _setupService = setupService;
        _serviceRestarter = serviceRestarter;
        _tlsEnroller = tlsEnroller;
        _certificateStore = certificateStore;
        _serviceRightsCheck = serviceRightsCheck;
        _configuration = configuration;
        _instanceMode = instanceMode;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/setup/status — check if setup has been completed and taken
    /// effect. Anonymous so the SPA can route to the wizard before
    /// authentication, but reduced to the boolean only: CA configuration
    /// details are admin-only (SEC-F2) and live on GET /api/setup/config.
    /// Reports false when the wizard file says complete but no CA is actually
    /// configured (an install stranded by the old silent mock fallback), so
    /// such installs return to the wizard.
    /// </summary>
    [HttpGet("status")]
    [AllowAnonymous]
    public IActionResult GetStatus()
    {
        return Ok(new
        {
            setupCompleted = _setupService.IsSetupEffectivelyComplete(),
        });
    }

    /// <summary>
    /// GET /api/setup/config — full setup configuration for the wizard to
    /// prefill once the admin is authenticated, plus the effective CA mode
    /// ("real", "mock", "unconfigured") for the wizard and dashboard banner.
    /// The suggested external URL (machine DNS name plus the port the service
    /// listens on) seeds the Server URL field when nothing was saved before.
    /// The wizard step from a saved draft and the state of an already
    /// enrolled TLS certificate ride along so a reopened wizard (cross origin
    /// continue link, F5 during the mid wizard restart) resumes where it was
    /// instead of starting over at Welcome.
    ///
    /// The instance mode rides along too (issue #471), because the wizard has a
    /// different shape in monitor mode and must know which before it renders a
    /// step. A full mode server that finished setup in monitor mode reopens at
    /// the Templates step, and <c>reopenReason</c> says why.
    /// </summary>
    [HttpGet("config")]
    public IActionResult GetConfig()
    {
        var status = _setupService.GetStatus();
        var awaitsTemplateChoice = _setupService.AwaitsTemplateChoice(status);
        return Ok(new
        {
            setupCompleted = _setupService.IsSetupEffectivelyComplete(),
            mode = _instanceMode.WireName,
            reopenReason = awaitsTemplateChoice ? ReopenReasonIssuanceEnabled : null,
            wizardCompleted = status.SetupCompleted,
            caMode = _setupService.CaMode,
            completedAt = status.CompletedAt,
            caConnectionString = status.CaConnectionString,
            enabledTemplates = status.EnabledTemplates,
            externalUrl = status.ExternalUrl,
            suggestedExternalUrl = ServerUrlSuggestion.Build(_configuration),
            allowedDomainsEnabled = status.AllowedDomainsEnabled,
            allowedDomains = status.AllowedDomains,
            suggestedAllowedDomain = AdDomainSuggestion.Get(),
            // The recorded mode, "off" for an install upgraded from before the
            // field, and the fresh install default (required) when nothing was
            // ever recorded (issue #631).
            eabEnforcement = _setupService.EabEnforcementPrefill(),
            wizardStep = awaitsTemplateChoice ? "templates"
                : status.SetupCompleted ? null
                : status.WizardStep,
            tlsCertificate = DescribeConfiguredTlsCertificate(),
        });
    }

    /// <summary>
    /// The TLS certificate the settings overlay points at, if any, for the
    /// wizard's External URL step to recognize an enrollment that already
    /// happened. Best effort: an unreadable overlay reads as "none" here —
    /// the wizard can live without it, and the settings endpoints own the
    /// loud complaint about a broken overlay.
    /// </summary>
    private object? DescribeConfiguredTlsCertificate()
    {
        string? thumbprint;
        try
        {
            thumbprint = SettingsOverlay.Load(_setupService.SettingsOverlayPath).HttpsCertificateThumbprint;
        }
        catch (Exception)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(thumbprint))
            return null;

        using var certificate = _certificateStore.Find(thumbprint);
        return new
        {
            thumbprint,
            installed = certificate is not null,
            names = certificate is null ? null : TlsCertificateEnroller.GetSubjectNames(certificate),
            notAfter = certificate?.NotAfter,
        };
    }

    /// <summary>
    /// POST /api/setup/draft — persist the wizard's current selections and
    /// step without completing setup, so a plain reload resumes where it was.
    /// Locked once setup is effectively complete (SEC-G1, mirrors the
    /// completion lock): a completed install must never have its recorded
    /// state rewritten by an anonymous draft. Since issue #101 an emptied
    /// template set fails closed, so the exposure risk became an availability
    /// risk, but the lock stands either way.
    /// </summary>
    [HttpPost("draft")]
    [AdminAudit("setup.draft.saved")]
    public async Task<IActionResult> SaveDraft(
        [FromBody] SaveWizardDraftRequest request, CancellationToken ct)
    {
        if (_setupService.IsSetupEffectivelyComplete())
            return Conflict(new { error = "Setup already completed" });

        // A draft writes the same EnabledTemplates field completion does, and
        // EnabledTemplatesPolicy does not consult SetupCompleted (issue #101), so
        // a draft set is live for ACME matching and is logged the moment the
        // policy loads it. Check every entry here too, or the draft is an
        // unguarded second writer to a field the completion endpoint guards.
        foreach (var draftTemplate in request.EnabledTemplates ?? [])
        {
            if (!AdcsRequestAttributes.TryValidateTemplateName(draftTemplate, out var draftError))
                return BadRequest(new { error = draftError });
        }

        // Which is also why monitor mode refuses one outright (issue #471): a
        // template drafted on a monitor mode server would go live for ACME the
        // moment the server is switched to full, without anyone choosing it there.
        if (_instanceMode.IsMonitor && request.EnabledTemplates is { Count: > 0 })
            return BadRequest(new { error = MonitorModeRecordsNoTemplate });

        // A draft records the CA the wizard will later be completed against, and
        // every CA call logs that string verbatim, so the draft is a second
        // writer to it exactly as it is to the template set (issue #220). A
        // missing value passes: the wizard saves whatever it has at each step.
        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var draftCaError))
            return BadRequest(new { error = draftCaError });

        // A draft writes the same eabEnforcement field completion does, and
        // EabEnforcementPolicy reads it whatever SetupCompleted says, so it is
        // parsed as strictly here as at completion.
        if (!TryParseEabChoice(request.EabEnforcement, out var draftEab, out var draftEabError))
            return BadRequest(new { error = draftEabError });

        var draft = new SetupConfiguration(
            CaConnectionString: request.CaConnectionString ?? string.Empty,
            EnabledTemplates: request.EnabledTemplates ?? new List<string>(),
            ExternalUrl: request.ExternalUrl ?? string.Empty,
            AllowedDomainsEnabled: request.AllowedDomainsEnabled,
            AllowedDomains: request.AllowedDomains,
            EabEnforcement: draftEab);

        // The audit row before the file write (issue #634).
        await this.AdminAudit().RecordBeforeFileWriteAsync(
            $"wizard step {request.WizardStep ?? "(none)"}", null, DescribeSetup(draft), ct);
        _setupService.SaveWizardDraft(draft, request.WizardStep);

        return Ok(new { saved = true });
    }

    /// <summary>
    /// GET /api/setup/discover-cas — enumerate the enterprise CAs published in
    /// Active Directory. Best effort: an empty list means the wizard falls
    /// back to manual entry.
    /// </summary>
    [HttpGet("discover-cas")]
    public async Task<IActionResult> DiscoverCas(CancellationToken ct)
    {
        var cas = await _setupService.DiscoverCasAsync(ct);
        return Ok(cas);
    }

    /// <summary>
    /// POST /api/setup/test-connection — test connectivity to a candidate CA.
    /// </summary>
    [HttpPost("test-connection")]
    [AdminAuditExempt("asks the candidate CA whether it answers and changes nothing")]
    public async Task<IActionResult> TestConnection(
        [FromBody] TestConnectionRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });
        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var caError))
            return BadRequest(new { error = caError });

        var result = await _setupService.TestConnectivityAsync(request.CaConnectionString, ct);
        return Ok(result);
    }

    /// <summary>
    /// POST /api/setup/service-rights: what the service's own account may do on
    /// a candidate CA and on the given templates (issue #440). Read only, so like
    /// test-connection it stays open after setup completes. The wizard calls it
    /// with no templates after Test Connection passes, and with the chosen ones
    /// on the Review step.
    /// </summary>
    [HttpPost("service-rights")]
    [AdminAuditExempt("reads the service account's rights at the candidate CA and changes nothing")]
    public async Task<IActionResult> CheckServiceRights(
        [FromBody] ServiceRightsRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });
        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var caError))
            return BadRequest(new { error = caError });

        var templates = request.Templates ?? [];
        if (templates.Count > ServiceRightsCheck.MaxTemplates)
            return BadRequest(new { error = $"At most {ServiceRightsCheck.MaxTemplates} templates can be checked at once." });
        foreach (var template in templates)
        {
            if (!AdcsRequestAttributes.TryValidateTemplateName(template, out var templateError))
                return BadRequest(new { error = templateError });
        }

        var report = await _serviceRightsCheck.RunAsync(request.CaConnectionString, templates, ct);
        return Ok(report.ToWire(_instanceMode));
    }

    /// <summary>
    /// POST /api/setup/templates — list certificate templates the wizard can
    /// offer from a candidate CA, restricted to those that can issue usable
    /// ACME server certificates; the response carries how many published
    /// templates were hidden and the wizard explains why. When EKU cannot be
    /// verified (host not domain joined or AD unreachable), all templates are
    /// returned flagged as unverified rather than an empty list. A POST
    /// because the candidate CA travels in the body, like test-connection.
    /// </summary>
    [HttpPost("templates")]
    [AdminAuditExempt("lists the candidate CA's templates; a POST only because it carries the connection string")]
    public async Task<IActionResult> GetTemplates(
        [FromBody] TestConnectionRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });
        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var caError))
            return BadRequest(new { error = caError });

        try
        {
            var result = await _setupService.GetSetupTemplatesAsync(request.CaConnectionString, ct);
            return Ok(result);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "Setup templates: the CA is unavailable");
            return StatusCode(503, new { error = true, message = "The certificate authority is unavailable. Try again shortly." });
        }
        catch (CaAccessDeniedException ex)
        {
            // Above the general arm, which would otherwise answer a missing right
            // with "failed to retrieve templates" and no remedy (issue #476). The
            // message is carried in full, as the TLS enrollment arm below does.
            _logger.LogError(ex, "Setup templates: the CA denied access");
            return StatusCode(503, new { error = true, message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Setup templates: failed to retrieve templates from the CA");
            return StatusCode(503, new { error = true, message = "Failed to retrieve templates from the certificate authority." });
        }
    }

    /// <summary>
    /// POST /api/setup/validate-url — validate a proposed external URL:
    /// static checks plus an active reachability probe (issue #89). The probe
    /// outcome rides in the response; a failed probe keeps the URL valid and
    /// the wizard asks for an explicit confirmation instead of blocking. When
    /// a template name is supplied the probe targets that template's ACME
    /// directory, the same URL the wizard tells clients to use. When it is
    /// omitted (the dashboard settings card, issue #93), the first enabled
    /// template from the wizard state is used, matching what the settings
    /// update endpoint probes.
    /// </summary>
    [HttpPost("validate-url")]
    [AdminAuditExempt("probes the external URL and changes nothing")]
    public async Task<IActionResult> ValidateUrl(
        [FromBody] ValidateUrlRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Url))
            return BadRequest(new { error = "URL is required" });

        var templateName = request.TemplateName
            ?? _setupService.GetStatus().EnabledTemplates.FirstOrDefault();

        var result = await _setupService.ValidateExternalUrlAsync(request.Url, templateName, ct);
        return Ok(result);
    }

    /// <summary>
    /// POST /api/setup/complete — finalize the setup wizard: persist the
    /// configuration to the settings overlay and schedule the service restart
    /// that applies it. Locked once setup is effectively complete (SEC-G1);
    /// an install whose wizard file says complete but which has no CA in
    /// effect may run the wizard again (that is the recovery path for
    /// installs stranded by the old silent mock fallback).
    ///
    /// The external URL is probed once more here (issue #89): validation at
    /// the URL step does not stop a stale or since broken URL from being
    /// saved. An unreachable URL is refused with 422 and the probe outcome
    /// until the request carries the explicit confirmation flag; it is never
    /// refused outright, because reverse proxy and hairpin NAT deployments
    /// can be legitimately unreachable from the server itself.
    /// </summary>
    [HttpPost("complete")]
    [AdminAudit("setup.completed")]
    public async Task<IActionResult> CompleteSetup(
        [FromBody] CompleteSetupRequest request, CancellationToken ct)
    {
        if (_setupService.IsSetupEffectivelyComplete())
            return Conflict(new { error = "Setup already completed" });

        if (string.IsNullOrWhiteSpace(request.ExternalUrl))
            return BadRequest(new { error = "External URL is required" });

        // Monitor mode never issues, so its setup completes without a template,
        // and refuses one (issue #471): a recorded template would be exposed over
        // ACME the moment the server is switched to full, without anyone having
        // chosen it in full mode. Recording none instead is what reopens the
        // wizard at the Templates step after that switch.
        if (_instanceMode.IsMonitor)
        {
            if (request.EnabledTemplates is { Count: > 0 })
                return BadRequest(new { error = MonitorModeRecordsNoTemplate });
        }
        else if (request.EnabledTemplates == null || request.EnabledTemplates.Count == 0)
        {
            return BadRequest(new { error = "At least one template must be enabled" });
        }

        // The recorded set is what the ACME template policy matches against and
        // where the webserver certificate renewal reads its template from, so
        // no entry may carry a character that could smuggle an extra ADCS
        // request attribute once it is submitted (issue #175).
        foreach (var enabledTemplate in request.EnabledTemplates)
        {
            if (!AdcsRequestAttributes.TryValidateTemplateName(enabledTemplate, out var templateError))
                return BadRequest(new { error = templateError });
        }

        if (_setupService.CaMode != "mock" && string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });

        // The recorded connection string is written verbatim into the service
        // log on every CA call, so no character may forge a log line or disguise
        // which CA is being addressed (issue #220). Unconditional, including in
        // mock mode: completion keeps the value out of the settings overlay
        // there, but it still writes it to the wizard status file and logs it
        // either way.
        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var caError))
            return BadRequest(new { error = caError });

        if (!TryParseEabChoice(request.EabEnforcement, out var eabEnforcement, out var eabError))
            return BadRequest(new { error = eabError });

        // Record the CA's own name for each template, not whichever of the two
        // forms the browser sent (issue #271). Every consumer that submits to the
        // CA resolves again anyway (PR #270); this is what makes the dashboard and
        // the settings page show one form. It runs before the URL probe, so an
        // unpublished template or a CA outage is answered before the five second
        // probe and its confirmation loop. The mock CA has no published list.
        var enabledTemplates = request.EnabledTemplates ?? [];
        if (enabledTemplates.Count > 0 && _setupService.CaMode != "mock")
        {
            try
            {
                var resolved = await _setupService.ResolvePublishedTemplateNamesAsync(
                    request.CaConnectionString!, enabledTemplates, ct);
                if (resolved.Any(name => name is null))
                {
                    // The name is not echoed: it is request body text, and the
                    // wizard only ever offers names the CA published a moment ago.
                    return BadRequest(new
                    {
                        error = "A selected certificate template is not published by the CA. " +
                                "Pick the templates again from the template list.",
                    });
                }

                enabledTemplates = resolved.Select(name => name!).ToList();
            }
            catch (CaUnavailableException ex)
            {
                // A string error, unlike the TLS endpoints' { error: true, message }:
                // completeSetup() in the wizard shows body.error as the reason.
                _logger.LogWarning(ex, "Setup completion: the CA is unavailable");
                return StatusCode(503, new { error = "The certificate authority is unavailable. Try again shortly." });
            }
            catch (CaAccessDeniedException ex)
            {
                _logger.LogError(ex, "Setup completion: the CA denied access");
                return StatusCode(503, new { error = ex.Message });
            }
        }

        // The display name and the programmatic name of one template resolve to
        // the same name, which is recorded once.
        enabledTemplates = enabledTemplates.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var validation = await _setupService.ValidateExternalUrlAsync(
            request.ExternalUrl, enabledTemplates.FirstOrDefault(), ct);

        if (!validation.Valid)
            return BadRequest(new { error = validation.ErrorMessage ?? "External URL is invalid" });

        if (validation.Probe is { Attempted: true, Reachable: false }
            && !request.ConfirmUnreachableExternalUrl)
        {
            return UnprocessableEntity(new
            {
                reason = "externalUrlUnreachable",
                message = "The external URL did not answer when probed from the server. " +
                          "Confirm the URL to complete setup anyway.",
                probe = validation.Probe,
            });
        }

        // Same validation rules as PUT /api/settings/allowed-domains, through
        // the same shared helper: the enabled flag never completes without at
        // least one usable entry.
        var allowedDomains = new List<string>();
        if (request.AllowedDomainsEnabled)
        {
            var (normalized, invalid) =
                AllowedDomainsPolicy.ValidateAndNormalize(request.AllowedDomains ?? []);
            if (invalid.Count > 0)
            {
                var (entry, reason) = invalid[0];
                return BadRequest(new { error = $"Allowed domain '{entry}': {reason}" });
            }

            if (normalized.Count == 0)
                return BadRequest(new { error = "Add at least one allowed domain, or turn the restriction off." });

            allowedDomains = normalized;
        }

        var config = new SetupConfiguration(
            CaConnectionString: request.CaConnectionString ?? string.Empty,
            EnabledTemplates: enabledTemplates,
            ExternalUrl: request.ExternalUrl,
            AllowedDomainsEnabled: request.AllowedDomainsEnabled,
            AllowedDomains: allowedDomains,
            EabEnforcement: eabEnforcement);

        // CompleteSetup writes the overlay first, so a refusal there leaves the
        // wizard exactly where it was (issue #553). Before this arm it was a bare
        // 500 from the wizard's last step, and since issue #550 a valid file can
        // cause it: a top level "Certus:ExternalUrl" or "Certus:CaConnectionString".
        // The audit row before the file writes (issue #634).
        await this.AdminAudit().RecordBeforeFileWriteAsync(
            "setup", null, DescribeSetup(config, _setupService.EabEnforcementAtCompletion(config)), ct);

        SetupStatus status;
        try
        {
            status = _setupService.CompleteSetup(config);
        }
        catch (JsonException ex)
        {
            return OverlayUnreadable(ex);
        }

        var restartScheduled = _serviceRestarter.TryScheduleRestart();
        return Ok(new
        {
            setupCompleted = status.SetupCompleted,
            completedAt = status.CompletedAt,
            restartScheduled,
            message = restartScheduled
                ? "Setup completed. The service is restarting to apply the configuration."
                : "Setup completed. Restart the service to apply the configuration.",
        });
    }

    /// <summary>
    /// POST /api/setup/tls-certificate — enroll a TLS certificate for this
    /// server from the candidate CA using the wizard's selected template, and
    /// install it into LocalMachine\My. When the issued certificate covers
    /// the external URL host, the thumbprint is written to the settings
    /// overlay, a wizard draft is saved (so a browser that has to change
    /// origin can resume the wizard), and the restart that applies it is
    /// scheduled. When it does not (a template that builds the subject from
    /// AD), nothing is configured and the wizard shows an explicit confirm.
    ///
    /// This is also the end to end test of the template: the service submits
    /// every ACME order as the same computer account this enrollment uses.
    /// </summary>
    [HttpPost("tls-certificate")]
    [AdminAudit("setup.https-certificate.enrolment-requested")]
    public async Task<IActionResult> ProvisionTlsCertificate(
        [FromBody] ProvisionTlsCertificateRequest request, CancellationToken ct)
    {
        var guard = GuardTlsProvisioning();
        if (guard is not null)
            return guard;

        if (string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });
        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var caError))
            return BadRequest(new { error = caError });
        if (string.IsNullOrWhiteSpace(request.TemplateName))
            return BadRequest(new { error = "Template name is required" });

        var urlValidation = _setupService.ValidateExternalUrl(request.ExternalUrl);
        if (!urlValidation.Valid)
            return BadRequest(new { error = urlValidation.ErrorMessage ?? "External URL is invalid" });

        try
        {
            // Enrollment interpolates the template name into the ADCS request
            // attribute string, so resolve the request body value to the CA's
            // own published name and enroll with that. Without this step the
            // wizard would be the one caller that hands ADCS a client supplied
            // string verbatim (issue #175, the CVE-2026-54121 smuggling class).
            var templateName = await _setupService.ResolvePublishedTemplateNameAsync(
                request.CaConnectionString, request.TemplateName, ct);
            if (templateName is null)
            {
                return BadRequest(new
                {
                    error = "That certificate template is not published by the CA. " +
                            "Pick one from the template list.",
                });
            }

            // Refuse before enrolling, never after (issue #553). The apply step below
            // records the thumbprint and template in settings.json, and the overlay
            // refuses a record that would set a key twice: a key it writes also
            // written by hand in the colon form at the top level. Found there, the CA
            // had already issued and the store installed a certificate nothing names,
            // one more on every click. A failed outcome, as the CA's own refusals are,
            // because that is the shape the wizard shows the message of.
            try
            {
                _setupService.EnsureHttpsCertificateCanBeRecorded(templateName);
            }
            catch (SettingsOverlayConflictException ex)
            {
                _logger.LogWarning(ex,
                    "TLS certificate enrollment: refused before enrolling, because the settings " +
                    "overlay could not record the certificate");
                return Ok(new
                {
                    outcome = "failed",
                    message = ex.Message + " Nothing was enrolled, so no certificate was issued or installed.",
                });
            }
            catch (JsonException ex)
            {
                return OverlayUnreadable(ex);
            }

            var result = await _tlsEnroller.EnrollAsync(
                request.CaConnectionString,
                templateName,
                request.ExternalUrl,
                Request.Host.Host,
                ct);

            if (result.Status != TlsEnrollmentStatus.Installed)
            {
                // A 200 that installed nothing (issue #634): the CA's answer is
                // the record, and the row says so rather than claiming an enrolment.
                this.AdminAudit().Describe(
                    $"template {templateName}",
                    after: $"enrolment requested, CA answered {result.Status.ToString().ToLowerInvariant()}: {result.Message}");
                return Ok(new
                {
                    outcome = result.Status switch
                    {
                        TlsEnrollmentStatus.Pending => "pending",
                        TlsEnrollmentStatus.Denied => "denied",
                        _ => "failed",
                    },
                    requestId = result.RequestId,
                    message = result.Message,
                });
            }

            if (!result.ExternalHostCovered)
            {
                // Installed in the store but deliberately not configured: the
                // certificate does not cover the external URL host, so every
                // ACME client would fail TLS. The wizard shows what was
                // issued and asks for an explicit decision.
                this.AdminAudit().Describe(
                    $"template {templateName}",
                    after: $"enrolled {result.Thumbprint} into the store; it does not cover the external URL host, so it awaits a decision");
                return Ok(new
                {
                    outcome = "sanMismatch",
                    thumbprint = result.Thumbprint,
                    issuedNames = result.IssuedNames,
                    requestId = result.RequestId,
                });
            }

            return ApplyEnrolledCertificate(
                request.CaConnectionString, templateName, request.ExternalUrl,
                result.Thumbprint!, result.CurrentHostCovered);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "TLS certificate enrollment: the CA is unavailable");
            return StatusCode(503, new { error = true, message = "The certificate authority is unavailable. Try again shortly." });
        }
        catch (CaAccessDeniedException ex)
        {
            // The second CA exception the enroller propagates (issue #336). Without
            // this arm it faults to a bare 500 with no body, on the surface most
            // likely to meet it: a freshly built CA, where the wizard is the first
            // thing to submit anything and the service account's rights are the
            // likeliest thing to be wrong. The message is carried in full, as the
            // dashboard already does for this exception; this is an administrator
            // authenticated surface, and the remediation is the entire value.
            _logger.LogError(ex, "TLS certificate enrollment: the CA denied access");
            return StatusCode(503, new { error = true, message = ex.Message });
        }
    }

    /// <summary>
    /// POST /api/setup/tls-certificate/apply — the explicit confirmation for
    /// the SAN mismatch outcome: configure and restart with a certificate
    /// that is already installed in the store.
    /// </summary>
    [HttpPost("tls-certificate/apply")]
    [AdminAudit("setup.https-certificate.applied")]
    public async Task<IActionResult> ApplyTlsCertificate(
        [FromBody] ApplyTlsCertificateRequest request, CancellationToken ct)
    {
        var guard = GuardTlsProvisioning();
        if (guard is not null)
            return guard;

        if (string.IsNullOrWhiteSpace(request.Thumbprint))
            return BadRequest(new { error = "Thumbprint is required" });

        // Apply had no connection string check of its own, which left it the
        // second unguarded writer alongside the draft endpoint (issue #220): the
        // value reaches the CA through the template resolution below and is then
        // recorded into the wizard draft, from where completion carries it into
        // the settings overlay.
        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var caError))
            return BadRequest(new { error = caError });

        using var certificate = _certificateStore.Find(request.Thumbprint);
        if (certificate is null)
            return NotFound(new { error = "No certificate with that thumbprint is installed" });

        // Resolve exactly as the enrollment endpoint does. Nothing is submitted
        // here, but this name is recorded into the wizard draft and the settings
        // overlay, and the renewal path submits it verbatim later with no
        // resolution of its own. The wizard restores its template selection from
        // the recorded set, which EnabledTemplatesPolicy documents may hold a
        // display name, so recording an unresolved name is how a display name
        // reaches ADCS and fails every future renewal (the issue #17 bug).
        string templateName;
        try
        {
            var resolved = await _setupService.ResolvePublishedTemplateNameAsync(
                request.CaConnectionString, request.TemplateName, ct);
            if (resolved is null)
            {
                return BadRequest(new
                {
                    error = "That certificate template is not published by the CA. " +
                            "Pick one from the template list.",
                });
            }

            templateName = resolved;
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "TLS certificate apply: the CA is unavailable");
            return StatusCode(503, new { error = true, message = "The certificate authority is unavailable. Try again shortly." });
        }
        catch (CaAccessDeniedException ex)
        {
            // The resolution reads the template list, which the CA can refuse
            // (issue #476). Without this arm the refusal faulted to a bare 500,
            // where the enrollment endpoint above already answers it like this.
            _logger.LogError(ex, "TLS certificate apply: the CA denied access");
            return StatusCode(503, new { error = true, message = ex.Message });
        }

        var currentHostCovered = TlsCertificateEnroller.CoversHost(
            TlsCertificateEnroller.GetSubjectNames(certificate), Request.Host.Host);

        return ApplyEnrolledCertificate(
            request.CaConnectionString, templateName, request.ExternalUrl,
            request.Thumbprint, currentHostCovered);
    }

    /// <summary>
    /// POST /api/setup/tls-certificate/discard — the decline path for the
    /// SAN mismatch outcome: remove the enrolled certificate from the store
    /// again (the issued certificate stays in the CA's log, as any issued
    /// certificate does).
    /// </summary>
    [HttpPost("tls-certificate/discard")]
    [AdminAudit("setup.https-certificate.discarded")]
    public IActionResult DiscardTlsCertificate([FromBody] DiscardTlsCertificateRequest request)
    {
        var guard = GuardTlsProvisioning();
        if (guard is not null)
            return guard;

        if (string.IsNullOrWhiteSpace(request.Thumbprint))
            return BadRequest(new { error = "Thumbprint is required" });

        var removed = _certificateStore.Remove(request.Thumbprint);
        this.AdminAudit().Describe(
            $"certificate {request.Thumbprint}",
            after: removed ? "removed from LocalMachine\\My" : "was not in LocalMachine\\My");
        return Ok(new { removed });
    }

    /// <summary>
    /// GET /api/setup/existing-certificates — the certificates already in
    /// LocalMachine\My the service could serve HTTPS with, for the monitor mode
    /// wizard (issue #471). Monitor mode never enrols the server's own certificate,
    /// so an existing one is how it gets a trusted one. Rows covering the external
    /// URL's host come first. Only eligible certificates are listed (see
    /// <see cref="MachineCertificateChoices.IsEligible"/>).
    /// </summary>
    [HttpGet("existing-certificates")]
    public IActionResult ListExistingCertificates([FromQuery] string? externalUrl)
    {
        var guard = GuardExistingCertificates();
        if (guard is not null)
            return guard;

        var urlValidation = _setupService.ValidateExternalUrl(externalUrl ?? string.Empty);
        if (!urlValidation.Valid)
            return BadRequest(new { error = urlValidation.ErrorMessage ?? "External URL is invalid" });

        var externalHost = new Uri(externalUrl!, UriKind.Absolute).Host;
        var configuredThumbprint = ReadConfiguredThumbprint();

        var certificates = _certificateStore.ListCertificates();
        try
        {
            return Ok(new
            {
                externalHost,
                configuredThumbprint,
                certificates = MachineCertificateChoices.Describe(
                    certificates, externalHost, configuredThumbprint, DateTimeOffset.UtcNow),
            });
        }
        finally
        {
            foreach (var certificate in certificates)
                certificate.Dispose();
        }
    }

    /// <summary>
    /// POST /api/setup/existing-certificates/use — pin the service to a
    /// certificate already in LocalMachine\My and restart to serve it, in monitor
    /// mode (issue #471). Eligibility is decided again here, on the server, rather
    /// than trusted from the list the browser saw: a certificate the service could
    /// not use would stop it binding HTTPS after the restart. A certificate that
    /// does not cover the external URL's host needs an explicit confirmation, the
    /// same decision the full mode SAN mismatch path asks for.
    /// </summary>
    [HttpPost("existing-certificates/use")]
    [AdminAudit("setup.https-certificate.chosen")]
    public IActionResult UseExistingCertificate([FromBody] UseExistingCertificateRequest request)
    {
        var guard = GuardExistingCertificates();
        if (guard is not null)
            return guard;

        // The draft written below records this CA, and every CA call logs it
        // verbatim (issue #220).
        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var caError))
            return BadRequest(new { error = caError });

        var urlValidation = _setupService.ValidateExternalUrl(request.ExternalUrl ?? string.Empty);
        if (!urlValidation.Valid)
            return BadRequest(new { error = urlValidation.ErrorMessage ?? "External URL is invalid" });

        if (string.IsNullOrWhiteSpace(request.Thumbprint))
            return BadRequest(new { error = "Thumbprint is required" });

        var wanted = HttpsCertificateFollow.NormalizeThumbprint(request.Thumbprint);
        var now = DateTimeOffset.UtcNow;
        var certificates = _certificateStore.ListCertificates();
        try
        {
            var chosen = certificates.FirstOrDefault(c =>
                string.Equals(HttpsCertificateFollow.NormalizeThumbprint(c.Thumbprint), wanted, StringComparison.Ordinal)
                && MachineCertificateChoices.IsEligible(c, now));
            if (chosen is null)
            {
                return NotFound(new
                {
                    error = "No certificate the service can serve HTTPS with has that thumbprint " +
                            "in LocalMachine\\My. Pick one from the list.",
                });
            }

            var names = TlsCertificateEnroller.GetSubjectNames(chosen);
            var externalHost = new Uri(request.ExternalUrl!, UriKind.Absolute).Host;
            if (!TlsCertificateEnroller.CoversHost(names, externalHost) && !request.AcceptNameMismatch)
            {
                return UnprocessableEntity(new
                {
                    reason = "nameMismatch",
                    externalHost,
                    names,
                });
            }

            return ApplyRecordedCertificate(
                request.CaConnectionString ?? string.Empty,
                [],
                request.ExternalUrl!,
                chosen.Thumbprint,
                templateName: null,
                TlsCertificateEnroller.CoversHost(names, Request.Host.Host));
        }
        finally
        {
            foreach (var certificate in certificates)
                certificate.Dispose();
        }
    }

    /// <summary>
    /// POST /api/setup/existing-certificates/keep-self-signed — the monitor mode
    /// wizard's "keep the self signed certificate" choice (issue #471). Nothing to
    /// do unless an earlier pick recorded a thumbprint; then it is cleared and the
    /// service restarts to serve the self signed certificate again.
    /// </summary>
    [HttpPost("existing-certificates/keep-self-signed")]
    [AdminAudit("setup.https-certificate.self-signed-kept")]
    public IActionResult KeepSelfSignedCertificate([FromBody] KeepSelfSignedCertificateRequest request)
    {
        var guard = GuardExistingCertificates();
        if (guard is not null)
            return guard;

        if (!AdcsCaConnectionString.TryValidate(request.CaConnectionString, out var caError))
            return BadRequest(new { error = caError });

        // The draft below records this URL, so it gets the checks the use route
        // gives it.
        var urlValidation = _setupService.ValidateExternalUrl(request.ExternalUrl ?? string.Empty);
        if (!urlValidation.Valid)
            return BadRequest(new { error = urlValidation.ErrorMessage ?? "External URL is invalid" });

        var configuredThumbprint = ReadConfiguredThumbprint();
        if (string.IsNullOrWhiteSpace(configuredThumbprint))
        {
            // Nothing recorded, nothing cleared: no row (issue #634).
            this.AdminAudit().Suppress();
            return Ok(new { outcome = "unchanged" });
        }

        this.AdminAudit().Describe(
            "HTTPS certificate", before: configuredThumbprint, after: "(none), the self signed certificate is served again");

        // Save the draft first, so the wizard that reloads after the restart
        // resumes at this step with what it had.
        SaveDraftAtUrlStep(request.CaConnectionString ?? string.Empty, [], request.ExternalUrl!);
        _setupService.ClearHttpsCertificateThumbprint();

        return Ok(new
        {
            outcome = "selfSigned",
            restartScheduled = _serviceRestarter.TryScheduleRestart(),
        });
    }

    /// <summary>
    /// Refusals for the existing certificate endpoints. They exist for monitor mode
    /// only (issue #471), where the service never enrols its own certificate, so a
    /// full mode server answers 404, as if they were not there. Like every wizard
    /// write they lock once setup is effectively complete. The mock CA is no reason
    /// to refuse, since nothing here reaches a CA.
    /// </summary>
    private IActionResult? GuardExistingCertificates()
    {
        if (!_instanceMode.IsMonitor)
        {
            return NotFound(new
            {
                error = "Choosing a certificate already in the machine store is offered in monitor " +
                        "mode. In full mode the wizard enrolls one from your CA.",
            });
        }

        if (_setupService.IsSetupEffectivelyComplete())
            return Conflict(new { error = "Setup already completed" });

        return null;
    }

    /// <summary>
    /// A wizard configuration in the words the audit trail records (issue #634).
    /// The CA connection string is recorded as the wizard received it, the same
    /// value every CA call logs. A completion passes the binding mode it is about
    /// to write, so a request without a choice still records what took effect
    /// (issue #631); a draft that made none records that it made none.
    /// </summary>
    internal static string DescribeSetup(SetupConfiguration config, string? eabWritten = null) =>
        $"CA {(string.IsNullOrEmpty(config.CaConnectionString) ? "(none)" : config.CaConnectionString)}, " +
        $"templates {(config.EnabledTemplates.Count == 0 ? "(none)" : string.Join(", ", config.EnabledTemplates))}, " +
        $"external URL {(string.IsNullOrEmpty(config.ExternalUrl) ? "(none)" : config.ExternalUrl)}, " +
        $"allowed domains {(config.AllowedDomainsEnabled ? "on: " + string.Join(", ", config.AllowedDomains ?? []) : "off")}, " +
        $"external account binding {(config.EabEnforcement is { } eab ? EabEnforcementPolicy.ModeName(eab) : eabWritten is null ? "(not chosen)" : eabWritten + " (not chosen)")}";

    /// <summary>
    /// The wizard's binding choice (issue #631). Absent is no choice, which keeps
    /// the recorded mode or, on a fresh install, completes as required. A present
    /// value must name a mode: a typo is refused rather than read as off, the same
    /// strictness as the settings page's enforcement endpoint.
    /// </summary>
    private static bool TryParseEabChoice(string? value, out EabEnforcementMode? mode, out string? error)
    {
        mode = null;
        error = null;
        if (value is null)
            return true;

        if (EabEnforcementPolicy.TryParseMode(value, out var parsed))
        {
            mode = parsed;
            return true;
        }

        error = "External account binding must be off, optional or required.";
        return false;
    }

    /// <summary>The thumbprint the overlay records, or null; best effort.</summary>
    private string? ReadConfiguredThumbprint()
    {
        try
        {
            return SettingsOverlay.Load(_setupService.SettingsOverlayPath).HttpsCertificateThumbprint;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Common refusals for the TLS provisioning endpoints: monitor mode never
    /// enrolls (issue #470), the mock CA cannot issue a real certificate (and
    /// the demo probe never surfaces the offer), and after setup the wizard
    /// endpoints are locked (SEC-G1) — certificate changes then belong to the
    /// settings page. Monitor mode is checked first so it answers whatever
    /// else is true; only the enrolment itself writes to the CA, but its apply
    /// and discard steps have nothing to act on without it.
    /// </summary>
    private IActionResult? GuardTlsProvisioning()
    {
        if (_instanceMode.IsMonitor)
        {
            _logger.LogWarning(
                "Refused a setup wizard HTTPS certificate request: this server runs in monitor mode");
            return MonitorModeProblem.Refuse(this,
                "This server runs in monitor mode, so it never enrolls a certificate. Keep the " +
                "self signed certificate, or point the server at a certificate already in the " +
                "machine store.");
        }

        if (_setupService.CaMode == "mock")
            return BadRequest(new { error = "TLS certificate enrollment is not available with the mock CA" });

        if (_setupService.IsSetupEffectivelyComplete())
            return Conflict(new { error = "Setup already completed" });

        return null;
    }

    /// <summary>
    /// Shared apply step: persist the wizard draft (so a wizard reopened at
    /// another origin prefills), record the thumbprint in the settings
    /// overlay, and schedule the restart. The continue URL is only offered
    /// when the certificate does not cover the host the browser is on —
    /// after the restart that session's fetches would fail the TLS handshake
    /// and the wizard would appear to hang.
    /// </summary>
    private IActionResult ApplyEnrolledCertificate(
        string caConnectionString,
        string templateName,
        string externalUrl,
        string thumbprint,
        bool? currentHostCovered) =>
        ApplyRecordedCertificate(
            caConnectionString, [templateName], externalUrl, thumbprint, templateName, currentHostCovered);

    /// <summary>
    /// The draft every certificate choice saves before the restart it schedules, so
    /// a wizard reopened afterwards (at this origin or another) resumes at the URL
    /// step. The request carries only the CA, the templates and the URL, but the
    /// draft overwrites the whole status file, so the allowed domain choice is read
    /// back and carried through, or the restart would wipe what the domains step
    /// saved.
    /// </summary>
    private void SaveDraftAtUrlStep(string caConnectionString, IReadOnlyList<string> templates, string externalUrl)
    {
        var current = _setupService.GetStatus();
        _setupService.SaveWizardDraft(
            new SetupConfiguration(
                CaConnectionString: caConnectionString,
                EnabledTemplates: templates,
                ExternalUrl: externalUrl,
                AllowedDomainsEnabled: current.AllowedDomainsEnabled,
                AllowedDomains: current.AllowedDomains),
            wizardStep: "url");
    }

    /// <summary>
    /// The apply step every wizard certificate choice shares: an enrolled one in
    /// full mode, with its template, or an existing one in monitor mode, with
    /// none (issue #471).
    ///
    /// <para>
    /// A settings overlay that refuses the record answers with the file named
    /// rather than a bare 500 (issue #553), and schedules no restart, since there is
    /// nothing new to apply. The enrolment endpoint asks the overlay before it
    /// enrolls, so from there this arm means a hand edit landed in between; the
    /// two others enroll nothing.
    /// </para>
    /// </summary>
    private IActionResult ApplyRecordedCertificate(
        string caConnectionString,
        IReadOnlyList<string> templates,
        string externalUrl,
        string thumbprint,
        string? templateName,
        bool? currentHostCovered)
    {
        this.AdminAudit().Describe(
            "HTTPS certificate",
            before: ReadConfiguredThumbprint() ?? "(none)",
            after: templateName is null
                ? $"{thumbprint}, chosen from LocalMachine\\My"
                : $"{thumbprint}, enrolled with template {templateName}");

        SaveDraftAtUrlStep(caConnectionString, templates, externalUrl);
        try
        {
            _setupService.SetHttpsCertificateThumbprint(thumbprint, templateName);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(
                "The HTTPS certificate {Thumbprint} is in LocalMachine\\My but could not be " +
                "recorded in the settings overlay", thumbprint);
            return OverlayUnreadable(ex);
        }

        var restartScheduled = _serviceRestarter.TryScheduleRestart();

        string? continueUrl = null;
        if (currentHostCovered == false &&
            Uri.TryCreate(externalUrl, UriKind.Absolute, out var uri))
        {
            continueUrl = uri.GetLeftPart(UriPartial.Authority) + "/setup";
        }

        return Ok(new
        {
            outcome = "installed",
            thumbprint,
            restartScheduled,
            currentHostCovered,
            continueUrl,
        });
    }

    /// <summary>
    /// The settings overlay cannot be read, or a change would set one configuration
    /// key twice (issues #550 and #553). The wizard's answer is the settings page's
    /// (<c>SettingsController.OverlayUnreadable</c>): the file named in a string
    /// <c>error</c>, which is what the wizard shows, rather than a bare 500 that
    /// leaves an administrator no clue which file to fix.
    /// </summary>
    private ObjectResult OverlayUnreadable(JsonException ex)
    {
        var path = _setupService.SettingsOverlayPath;
        _logger.LogError(ex, "The settings overlay at {Path} could not be read or saved", path);
        return StatusCode(500, new
        {
            error = $"The settings overlay at {path} is not valid JSON, or would set a " +
                    "configuration key twice, and must be fixed by hand before setup can " +
                    "continue. The service log names the problem.",
        });
    }
}

/// <summary>Request body carrying a candidate CA connection string.</summary>
public sealed record TestConnectionRequest(string CaConnectionString);

/// <summary>
/// Request body for the service rights check: a candidate CA and the templates to
/// weigh, by either name form. No templates checks the CA alone.
/// </summary>
public sealed record ServiceRightsRequest(string CaConnectionString, List<string>? Templates = null);

/// <summary>
/// Request body for URL validation. The optional template name points the
/// reachability probe at that template's ACME directory.
/// </summary>
public sealed record ValidateUrlRequest(string Url, string? TemplateName = null);

/// <summary>
/// Request body for completing setup. ConfirmUnreachableExternalUrl is the
/// explicit acknowledgement that the external URL did not answer the probe
/// and the administrator wants it saved anyway (reverse proxy or hairpin NAT
/// deployments).
/// </summary>
public sealed record CompleteSetupRequest(
    string? CaConnectionString,
    List<string> EnabledTemplates,
    string ExternalUrl,
    bool ConfirmUnreachableExternalUrl = false,
    bool AllowedDomainsEnabled = false,
    List<string>? AllowedDomains = null,
    string? EabEnforcement = null);

/// <summary>
/// Request body for enrolling the server's own TLS certificate. Carries the
/// candidate CA and template from the wizard state, like test-connection —
/// during setup the DI bound client cannot reach the CA.
/// </summary>
public sealed record ProvisionTlsCertificateRequest(
    string CaConnectionString,
    string TemplateName,
    string ExternalUrl);

/// <summary>
/// Request body for the SAN mismatch confirmation: configure and restart
/// with the already installed certificate. The wizard state rides along so
/// the draft saved before the restart is complete.
/// </summary>
public sealed record ApplyTlsCertificateRequest(
    string CaConnectionString,
    string TemplateName,
    string ExternalUrl,
    string Thumbprint);

/// <summary>Request body for discarding an enrolled but unconfigured certificate.</summary>
public sealed record DiscardTlsCertificateRequest(string Thumbprint);

/// <summary>
/// Request body for pinning the service to a certificate already in the machine
/// store (monitor mode, issue #471). The wizard state rides along for the draft
/// saved before the restart. AcceptNameMismatch confirms a certificate that does
/// not cover the external URL's host.
/// </summary>
public sealed record UseExistingCertificateRequest(
    string? CaConnectionString,
    string? ExternalUrl,
    string? Thumbprint,
    bool AcceptNameMismatch = false);

/// <summary>Request body for going back to the self signed certificate (monitor mode).</summary>
public sealed record KeepSelfSignedCertificateRequest(
    string? CaConnectionString,
    string? ExternalUrl);

/// <summary>
/// Request body for saving a wizard draft. Lenient on purpose: the wizard
/// saves whatever it has at each step, and missing values become empty.
/// </summary>
public sealed record SaveWizardDraftRequest(
    string? CaConnectionString,
    List<string>? EnabledTemplates,
    string? ExternalUrl,
    string? WizardStep,
    bool AllowedDomainsEnabled = false,
    List<string>? AllowedDomains = null,
    string? EabEnforcement = null);
