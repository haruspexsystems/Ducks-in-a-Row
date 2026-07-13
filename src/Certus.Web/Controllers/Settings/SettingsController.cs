using System.Reflection;
using System.Text.Json;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
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
    private readonly TlsCertificateEnroller _tlsEnroller;
    private readonly IHttpsCertificateStore _certificateStore;
    private readonly CertusOptions _certusOptions;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SettingsController> _logger;

    public SettingsController(
        SetupService setupService,
        IServiceRestarter serviceRestarter,
        TlsCertificateEnroller tlsEnroller,
        IHttpsCertificateStore certificateStore,
        IOptions<CertusOptions> certusOptions,
        IConfiguration configuration,
        ILogger<SettingsController> logger)
    {
        _setupService = setupService;
        _serviceRestarter = serviceRestarter;
        _tlsEnroller = tlsEnroller;
        _certificateStore = certificateStore;
        _certusOptions = certusOptions.Value;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/settings/info — the running application version, for the
    /// Settings page. Reads AssemblyInformationalVersion, which carries the
    /// full release string ("0.9.0-beta.1") from Directory.Build.props'
    /// VersionPrefix and VersionSuffix combined. The MSI's ProductVersion is
    /// a separate, strictly numeric value WiX requires (see build.ps1); this
    /// endpoint is the only place the prerelease label is meant to show up
    /// at runtime.
    /// </summary>
    [HttpGet("info")]
    public IActionResult GetInfo()
    {
        var version = typeof(SettingsController).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            ?? typeof(SettingsController).Assembly.GetName().Version?.ToString()
            ?? "unknown";

        return Ok(new { version });
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
            return Ok(new { configured = false });

        var status = _setupService.GetStatus();
        using var certificate = _certificateStore.Find(thumbprint);

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
            restartPending = !string.Equals(
                thumbprint, _certusOptions.HttpsCertificateThumbprint,
                StringComparison.OrdinalIgnoreCase),
        });
    }

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
        var status = _setupService.GetStatus();
        if (!status.SetupCompleted || !_setupService.IsCaEffectivelyConfigured)
            return Conflict(new { error = "Setup has not been completed. Enroll the certificate in the setup wizard." });

        if (_setupService.CaMode == "mock")
            return BadRequest(new { error = "Certificate renewal is not available with the mock CA" });

        var caConnectionString = _certusOptions.CaConnectionString;
        if (string.IsNullOrWhiteSpace(caConnectionString))
            return Conflict(new { error = "No CA connection string is in effect" });

        SettingsOverlay.OverlaySettings overlay;
        try
        {
            overlay = SettingsOverlay.Load(_setupService.SettingsOverlayPath);
        }
        catch (JsonException ex)
        {
            return OverlayUnreadable(ex);
        }

        var externalUrl = string.IsNullOrEmpty(_certusOptions.ExternalUrl)
            ? overlay.ExternalUrl
            : _certusOptions.ExternalUrl;
        if (string.IsNullOrWhiteSpace(externalUrl))
            return Conflict(new { error = "No external URL is configured. Set it in the External URL section first." });

        var template = overlay.HttpsCertificateTemplate ?? status.EnabledTemplates.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(template))
            return Conflict(new { error = "No template is recorded for the webserver certificate and none is enabled." });

        var previousThumbprint = overlay.HttpsCertificateThumbprint;

        TlsEnrollmentResult result;
        try
        {
            result = await _tlsEnroller.EnrollAsync(
                caConnectionString, template, externalUrl, Request.Host.Host, ct);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "Certificate renewal: the CA is unavailable");
            return StatusCode(503, new { error = true, message = "The certificate authority is unavailable. Try again shortly." });
        }

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
            TryRemoveFromStore(result.Thumbprint!, "the freshly issued certificate");
            _logger.LogWarning(
                "Certificate renewal with template {Template} issued names ({Names}) that do not " +
                "cover the external URL host; the certificate was removed again",
                template, string.Join(", ", result.IssuedNames ?? []));
            return Ok(new
            {
                outcome = "sanMismatch",
                issuedNames = result.IssuedNames,
                requestId = result.RequestId,
                message = "The CA issued a certificate that does not cover the external URL host, " +
                          "so it was not applied. Check the Subject Name tab of the " +
                          $"{template} template (\"Supply in the request\").",
            });
        }

        _setupService.SetHttpsCertificateThumbprint(result.Thumbprint!, template);

        // The overlay now points at the new certificate, so the superseded
        // one only clutters the store. Best effort in truth, not just in
        // comment: a store failure here (a transient AV or ACL lock on
        // LocalMachine\My) must not turn an otherwise successful renewal
        // into an unhandled error, and must not skip scheduling the restart
        // that applies the new certificate the overlay already points at.
        if (!string.IsNullOrWhiteSpace(previousThumbprint) &&
            !string.Equals(previousThumbprint, result.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            TryRemoveFromStore(previousThumbprint, "the superseded certificate");
        }

        var restartScheduled = _serviceRestarter.TryScheduleRestart();
        _logger.LogInformation(
            "Webserver certificate renewed with template {Template}: {Thumbprint} replaces {Previous}",
            template, result.Thumbprint, previousThumbprint ?? "(none)");

        return Ok(new
        {
            outcome = "installed",
            thumbprint = result.Thumbprint,
            restartScheduled,
            currentHostCovered = result.CurrentHostCovered,
        });
    }

    /// <summary>
    /// Remove a certificate from the store without letting a store failure
    /// (a transient AV or ACL lock) turn into an unhandled 500 partway
    /// through a renewal that has already succeeded. A leftover certificate
    /// is only visible in certlm.msc; a swallowed exception here must never
    /// stop the caller from scheduling the restart that applies the new one.
    /// </summary>
    private void TryRemoveFromStore(string thumbprint, string description)
    {
        try
        {
            _certificateStore.Remove(thumbprint);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not remove {Description} ({Thumbprint}) from the certificate store; " +
                "it will remain until removed by hand",
                description, thumbprint);
        }
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
