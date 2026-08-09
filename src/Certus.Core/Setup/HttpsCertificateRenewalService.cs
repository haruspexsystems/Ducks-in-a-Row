using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Setup;

/// <summary>
/// Re enrolls the server's own HTTPS certificate from the connected CA and
/// points the settings overlay at the result. Shared by the two callers that
/// renew it: the settings page button (which then restarts straight away) and
/// the background renewal service (which does not).
///
/// What this class does is exactly the part both callers agree on: check the
/// preconditions, enroll with the recorded template, refuse a certificate that
/// stops covering the external URL host, and swap the overlay thumbprint. What
/// it deliberately leaves out is the part where they differ:
///
/// <list type="bullet">
///   <item>removing the superseded certificate from the store. The background
///   caller must not: the running process is still serving that certificate,
///   and removing it deletes its key container.</item>
///   <item>scheduling the restart that applies the new certificate. Only the
///   settings page does that, because an administrator asked for it.</item>
/// </list>
///
/// <see cref="System.Text.Json.JsonException"/> (a torn or hand broken overlay)
/// and <see cref="Adcs.CaUnavailableException"/> propagate to the caller
/// unchanged: both callers already handle them, and papering over an unreadable
/// overlay here would risk rewriting it from an empty record.
/// </summary>
public sealed class HttpsCertificateRenewalService
{
    private readonly SetupService _setupService;
    private readonly TlsCertificateEnroller _enroller;
    private readonly IHttpsCertificateStore _certificateStore;
    private readonly CertusOptions _certusOptions;
    private readonly ILogger<HttpsCertificateRenewalService> _logger;

    public HttpsCertificateRenewalService(
        SetupService setupService,
        TlsCertificateEnroller enroller,
        IHttpsCertificateStore certificateStore,
        IOptions<CertusOptions> certusOptions,
        ILogger<HttpsCertificateRenewalService> logger)
    {
        _setupService = setupService;
        _enroller = enroller;
        _certificateStore = certificateStore;
        _certusOptions = certusOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Everything the renewal needs, or the reason it cannot run. Read as one
    /// step so a caller that only wants to know whether renewal is possible
    /// (the background service's cheap skip) does not have to duplicate the
    /// guard order.
    /// </summary>
    public HttpsCertificateRenewalContext ReadContext()
    {
        var status = _setupService.GetStatus();
        if (!status.SetupCompleted || !_setupService.IsCaEffectivelyConfigured)
        {
            return HttpsCertificateRenewalContext.Blocked(
                HttpsCertificateRenewalBlocker.SetupIncomplete,
                "Setup has not been completed. Enroll the certificate in the setup wizard.");
        }

        if (_setupService.CaMode == "mock")
        {
            return HttpsCertificateRenewalContext.Blocked(
                HttpsCertificateRenewalBlocker.MockCa,
                "Certificate renewal is not available with the mock CA");
        }

        var caConnectionString = _certusOptions.CaConnectionString;
        if (string.IsNullOrWhiteSpace(caConnectionString))
        {
            return HttpsCertificateRenewalContext.Blocked(
                HttpsCertificateRenewalBlocker.NoCaConnectionString,
                "No CA connection string is in effect");
        }

        var overlay = SettingsOverlay.Load(_setupService.SettingsOverlayPath);

        var externalUrl = string.IsNullOrEmpty(_certusOptions.ExternalUrl)
            ? overlay.ExternalUrl
            : _certusOptions.ExternalUrl;
        if (string.IsNullOrWhiteSpace(externalUrl))
        {
            return HttpsCertificateRenewalContext.Blocked(
                HttpsCertificateRenewalBlocker.NoExternalUrl,
                "No external URL is configured. Set it in the External URL section first.");
        }

        var template = overlay.HttpsCertificateTemplate ?? status.EnabledTemplates.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(template))
        {
            return HttpsCertificateRenewalContext.Blocked(
                HttpsCertificateRenewalBlocker.NoTemplate,
                "No template is recorded for the webserver certificate and none is enabled.");
        }

        // A name recorded before the template name guard shipped, or hand edited
        // into the overlay, would throw out of AdcsRequestAttributes deep inside
        // the enroller. That exception would escape the structured result the
        // auto renewal service raises its admin alert from, so refuse it here as
        // an ordinary blocker and keep every failure on one path.
        if (!AdcsRequestAttributes.TryValidateTemplateName(template, out var templateError))
        {
            return HttpsCertificateRenewalContext.Blocked(
                HttpsCertificateRenewalBlocker.NoTemplate,
                $"The recorded webserver certificate template cannot be used. {templateError}");
        }

        return new HttpsCertificateRenewalContext(
            HttpsCertificateRenewalBlocker.None,
            Message: null,
            CaConnectionString: caConnectionString,
            ExternalUrl: externalUrl,
            Template: template,
            OverlayThumbprint: overlay.HttpsCertificateThumbprint);
    }

    /// <summary>
    /// Enroll a fresh certificate and point the overlay at it.
    /// <paramref name="currentHost"/> is the host the caller's browser is on,
    /// so the result can say whether that session survives the restart; the
    /// background caller passes null.
    /// </summary>
    public async Task<HttpsCertificateRenewalResult> RenewAsync(
        string? currentHost,
        CancellationToken cancellationToken = default)
    {
        var context = ReadContext();
        if (context.Blocker != HttpsCertificateRenewalBlocker.None)
        {
            return new HttpsCertificateRenewalResult(
                HttpsCertificateRenewalOutcome.NotApplicable,
                Blocker: context.Blocker,
                Message: context.Message);
        }

        return await RenewAsync(context, currentHost, cancellationToken);
    }

    /// <summary>
    /// Renew against a context the caller already read. Saves a second status
    /// and overlay read for a caller that inspected the context first.
    /// </summary>
    public async Task<HttpsCertificateRenewalResult> RenewAsync(
        HttpsCertificateRenewalContext context,
        string? currentHost,
        CancellationToken cancellationToken = default)
    {
        if (context.Blocker != HttpsCertificateRenewalBlocker.None)
        {
            return new HttpsCertificateRenewalResult(
                HttpsCertificateRenewalOutcome.NotApplicable,
                Blocker: context.Blocker,
                Message: context.Message);
        }

        var template = context.Template!;
        var result = await _enroller.EnrollAsync(
            context.CaConnectionString!, template, context.ExternalUrl!, currentHost, cancellationToken);

        if (result.Status != TlsEnrollmentStatus.Installed)
        {
            return new HttpsCertificateRenewalResult(
                result.Status switch
                {
                    TlsEnrollmentStatus.Pending => HttpsCertificateRenewalOutcome.Pending,
                    TlsEnrollmentStatus.Denied => HttpsCertificateRenewalOutcome.Denied,
                    _ => HttpsCertificateRenewalOutcome.Failed,
                },
                PreviousThumbprint: context.OverlayThumbprint,
                Template: template,
                RequestId: result.RequestId,
                Message: result.Message);
        }

        if (!result.ExternalHostCovered)
        {
            // A certificate that does not cover the external URL host is a
            // template regression to fix (Subject Name tab), not a state to
            // accept. It was never referenced by the overlay, so removing it
            // here is safe for both callers and leaves no litter in the store.
            TryRemoveFromStore(result.Thumbprint!, "the freshly issued certificate");
            _logger.LogWarning(
                "Certificate renewal with template {Template} issued names ({Names}) that do not " +
                "cover the external URL host; the certificate was removed again",
                template, string.Join(", ", result.IssuedNames ?? []));

            return new HttpsCertificateRenewalResult(
                HttpsCertificateRenewalOutcome.SanMismatch,
                PreviousThumbprint: context.OverlayThumbprint,
                Template: template,
                RequestId: result.RequestId,
                IssuedNames: result.IssuedNames,
                Message: "The CA issued a certificate that does not cover the external URL host, " +
                         "so it was not applied. Check the Subject Name tab of the " +
                         $"{template} template (\"Supply in the request\").");
        }

        // SetHttpsCertificateThumbprint writes through SettingsOverlay.Save,
        // which is a temp file then move, so a crash mid write cannot leave a
        // torn overlay that stops the next start.
        _setupService.SetHttpsCertificateThumbprint(result.Thumbprint!, template);

        return new HttpsCertificateRenewalResult(
            HttpsCertificateRenewalOutcome.Installed,
            Thumbprint: result.Thumbprint,
            PreviousThumbprint: context.OverlayThumbprint,
            Template: template,
            RequestId: result.RequestId,
            IssuedNames: result.IssuedNames,
            CurrentHostCovered: result.CurrentHostCovered);
    }

    /// <summary>
    /// Remove a certificate from the store without letting a store failure
    /// (a transient AV or ACL lock) turn into an unhandled error partway
    /// through a renewal. A leftover certificate is only visible in
    /// certlm.msc; a swallowed exception here must never stop the caller from
    /// applying the new one.
    /// </summary>
    public void TryRemoveFromStore(string thumbprint, string description)
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
}

/// <summary>Why a renewal cannot run, or <see cref="None"/> when it can.</summary>
public enum HttpsCertificateRenewalBlocker
{
    /// <summary>Nothing is in the way.</summary>
    None,

    /// <summary>The wizard has not completed, or no CA is in effect.</summary>
    SetupIncomplete,

    /// <summary>The mock CA is active; its certificates are fake.</summary>
    MockCa,

    /// <summary>No CA connection string is configured.</summary>
    NoCaConnectionString,

    /// <summary>No external URL is configured, so there is no name to request.</summary>
    NoExternalUrl,

    /// <summary>No template is recorded and none is enabled.</summary>
    NoTemplate,
}

/// <summary>How a renewal attempt ended.</summary>
public enum HttpsCertificateRenewalOutcome
{
    /// <summary>Issued, installed, and the overlay now points at it.</summary>
    Installed,

    /// <summary>Issued but it does not cover the external URL host; discarded.</summary>
    SanMismatch,

    /// <summary>The CA pended the request for manager approval.</summary>
    Pending,

    /// <summary>The CA denied the request.</summary>
    Denied,

    /// <summary>Any other enrollment failure.</summary>
    Failed,

    /// <summary>A precondition refused the attempt; see <see cref="HttpsCertificateRenewalResult.Blocker"/>.</summary>
    NotApplicable,
}

/// <summary>
/// The inputs a renewal needs, or the blocker that stops it. The thumbprint is
/// the one the overlay records right now, which is the certificate a successful
/// renewal supersedes.
/// </summary>
public sealed record HttpsCertificateRenewalContext(
    HttpsCertificateRenewalBlocker Blocker,
    string? Message = null,
    string? CaConnectionString = null,
    string? ExternalUrl = null,
    string? Template = null,
    string? OverlayThumbprint = null)
{
    public static HttpsCertificateRenewalContext Blocked(
        HttpsCertificateRenewalBlocker blocker, string message) => new(blocker, message);
}

/// <summary>Outcome of <see cref="HttpsCertificateRenewalService.RenewAsync(string?, CancellationToken)"/>.</summary>
public sealed record HttpsCertificateRenewalResult(
    HttpsCertificateRenewalOutcome Outcome,
    string? Thumbprint = null,
    string? PreviousThumbprint = null,
    string? Template = null,
    int? RequestId = null,
    IReadOnlyList<string>? IssuedNames = null,
    bool? CurrentHostCovered = null,
    string? Message = null,
    HttpsCertificateRenewalBlocker Blocker = HttpsCertificateRenewalBlocker.None);
