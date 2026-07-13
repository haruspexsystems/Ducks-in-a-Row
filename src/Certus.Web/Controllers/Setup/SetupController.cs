using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Certus.Web.Authentication;
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
    private readonly IConfiguration _configuration;
    private readonly ILogger<SetupController> _logger;

    public SetupController(
        SetupService setupService,
        IServiceRestarter serviceRestarter,
        TlsCertificateEnroller tlsEnroller,
        IHttpsCertificateStore certificateStore,
        IConfiguration configuration,
        ILogger<SetupController> logger)
    {
        _setupService = setupService;
        _serviceRestarter = serviceRestarter;
        _tlsEnroller = tlsEnroller;
        _certificateStore = certificateStore;
        _configuration = configuration;
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
    /// </summary>
    [HttpGet("config")]
    public IActionResult GetConfig()
    {
        var status = _setupService.GetStatus();
        return Ok(new
        {
            setupCompleted = _setupService.IsSetupEffectivelyComplete(),
            wizardCompleted = status.SetupCompleted,
            caMode = _setupService.CaMode,
            completedAt = status.CompletedAt,
            caConnectionString = status.CaConnectionString,
            enabledTemplates = status.EnabledTemplates,
            externalUrl = status.ExternalUrl,
            suggestedExternalUrl = ServerUrlSuggestion.Build(_configuration),
            wizardStep = status.SetupCompleted ? null : status.WizardStep,
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
    /// completion lock): a completed install must never be reverted to a
    /// draft, which would drop the enabled template restriction.
    /// </summary>
    [HttpPost("draft")]
    public IActionResult SaveDraft([FromBody] SaveWizardDraftRequest request)
    {
        if (_setupService.IsSetupEffectivelyComplete())
            return Conflict(new { error = "Setup already completed" });

        _setupService.SaveWizardDraft(
            new SetupConfiguration(
                CaConnectionString: request.CaConnectionString ?? string.Empty,
                EnabledTemplates: request.EnabledTemplates ?? new List<string>(),
                ExternalUrl: request.ExternalUrl ?? string.Empty),
            request.WizardStep);

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
    public async Task<IActionResult> TestConnection(
        [FromBody] TestConnectionRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });

        var result = await _setupService.TestConnectivityAsync(request.CaConnectionString, ct);
        return Ok(result);
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
    public async Task<IActionResult> GetTemplates(
        [FromBody] TestConnectionRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });

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
    public async Task<IActionResult> CompleteSetup(
        [FromBody] CompleteSetupRequest request, CancellationToken ct)
    {
        if (_setupService.IsSetupEffectivelyComplete())
            return Conflict(new { error = "Setup already completed" });

        if (string.IsNullOrWhiteSpace(request.ExternalUrl))
            return BadRequest(new { error = "External URL is required" });

        if (request.EnabledTemplates == null || request.EnabledTemplates.Count == 0)
            return BadRequest(new { error = "At least one template must be enabled" });

        if (_setupService.CaMode != "mock" && string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });

        var validation = await _setupService.ValidateExternalUrlAsync(
            request.ExternalUrl, request.EnabledTemplates[0], ct);

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

        var config = new SetupConfiguration(
            CaConnectionString: request.CaConnectionString ?? string.Empty,
            EnabledTemplates: request.EnabledTemplates,
            ExternalUrl: request.ExternalUrl);

        var status = _setupService.CompleteSetup(config);

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
    public async Task<IActionResult> ProvisionTlsCertificate(
        [FromBody] ProvisionTlsCertificateRequest request, CancellationToken ct)
    {
        var guard = GuardTlsProvisioning();
        if (guard is not null)
            return guard;

        if (string.IsNullOrWhiteSpace(request.CaConnectionString))
            return BadRequest(new { error = "CA connection string is required" });
        if (string.IsNullOrWhiteSpace(request.TemplateName))
            return BadRequest(new { error = "Template name is required" });

        var urlValidation = _setupService.ValidateExternalUrl(request.ExternalUrl);
        if (!urlValidation.Valid)
            return BadRequest(new { error = urlValidation.ErrorMessage ?? "External URL is invalid" });

        try
        {
            var result = await _tlsEnroller.EnrollAsync(
                request.CaConnectionString,
                request.TemplateName,
                request.ExternalUrl,
                Request.Host.Host,
                ct);

            if (result.Status != TlsEnrollmentStatus.Installed)
            {
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
                return Ok(new
                {
                    outcome = "sanMismatch",
                    thumbprint = result.Thumbprint,
                    issuedNames = result.IssuedNames,
                    requestId = result.RequestId,
                });
            }

            return Ok(ApplyEnrolledCertificate(
                request.CaConnectionString, request.TemplateName, request.ExternalUrl,
                result.Thumbprint!, result.CurrentHostCovered));
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "TLS certificate enrollment: the CA is unavailable");
            return StatusCode(503, new { error = true, message = "The certificate authority is unavailable. Try again shortly." });
        }
    }

    /// <summary>
    /// POST /api/setup/tls-certificate/apply — the explicit confirmation for
    /// the SAN mismatch outcome: configure and restart with a certificate
    /// that is already installed in the store.
    /// </summary>
    [HttpPost("tls-certificate/apply")]
    public IActionResult ApplyTlsCertificate([FromBody] ApplyTlsCertificateRequest request)
    {
        var guard = GuardTlsProvisioning();
        if (guard is not null)
            return guard;

        if (string.IsNullOrWhiteSpace(request.Thumbprint))
            return BadRequest(new { error = "Thumbprint is required" });

        using var certificate = _certificateStore.Find(request.Thumbprint);
        if (certificate is null)
            return NotFound(new { error = "No certificate with that thumbprint is installed" });

        var currentHostCovered = TlsCertificateEnroller.CoversHost(
            TlsCertificateEnroller.GetSubjectNames(certificate), Request.Host.Host);

        return Ok(ApplyEnrolledCertificate(
            request.CaConnectionString, request.TemplateName, request.ExternalUrl,
            request.Thumbprint, currentHostCovered));
    }

    /// <summary>
    /// POST /api/setup/tls-certificate/discard — the decline path for the
    /// SAN mismatch outcome: remove the enrolled certificate from the store
    /// again (the issued certificate stays in the CA's log, as any issued
    /// certificate does).
    /// </summary>
    [HttpPost("tls-certificate/discard")]
    public IActionResult DiscardTlsCertificate([FromBody] DiscardTlsCertificateRequest request)
    {
        var guard = GuardTlsProvisioning();
        if (guard is not null)
            return guard;

        if (string.IsNullOrWhiteSpace(request.Thumbprint))
            return BadRequest(new { error = "Thumbprint is required" });

        var removed = _certificateStore.Remove(request.Thumbprint);
        return Ok(new { removed });
    }

    /// <summary>
    /// Common refusals for the TLS provisioning endpoints: the mock CA
    /// cannot issue a real certificate (and the demo probe never surfaces
    /// the offer), and after setup the wizard endpoints are locked (SEC-G1)
    /// — certificate changes then belong to the settings page.
    /// </summary>
    private IActionResult? GuardTlsProvisioning()
    {
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
    private object ApplyEnrolledCertificate(
        string caConnectionString,
        string templateName,
        string externalUrl,
        string thumbprint,
        bool? currentHostCovered)
    {
        _setupService.SaveWizardDraft(
            new SetupConfiguration(
                CaConnectionString: caConnectionString,
                EnabledTemplates: new List<string> { templateName },
                ExternalUrl: externalUrl),
            wizardStep: "url");
        _setupService.SetHttpsCertificateThumbprint(thumbprint, templateName);

        var restartScheduled = _serviceRestarter.TryScheduleRestart();

        string? continueUrl = null;
        if (currentHostCovered == false &&
            Uri.TryCreate(externalUrl, UriKind.Absolute, out var uri))
        {
            continueUrl = uri.GetLeftPart(UriPartial.Authority) + "/setup";
        }

        return new
        {
            outcome = "installed",
            thumbprint,
            restartScheduled,
            currentHostCovered,
            continueUrl,
        };
    }
}

/// <summary>Request body carrying a candidate CA connection string.</summary>
public sealed record TestConnectionRequest(string CaConnectionString);

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
    bool ConfirmUnreachableExternalUrl = false);

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
/// Request body for saving a wizard draft. Lenient on purpose: the wizard
/// saves whatever it has at each step, and missing values become empty.
/// </summary>
public sealed record SaveWizardDraftRequest(
    string? CaConnectionString,
    List<string>? EnabledTemplates,
    string? ExternalUrl,
    string? WizardStep);
