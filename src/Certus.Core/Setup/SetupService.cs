using System.Runtime.InteropServices;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Setup;

/// <summary>
/// Orchestrates the setup wizard workflow: CA discovery, connectivity testing,
/// template listing, and configuration persistence.
///
/// Probes run through <see cref="IAdcsClientFactory"/> against the candidate
/// connection string the administrator picked, never through the DI bound
/// singleton client — during setup that singleton is the unconfigured client
/// (or the mock), so it cannot witness the CA being configured.
///
/// Completing setup persists the CA connection string and external URL to the
/// settings overlay (settings.json in the data directory) that the service
/// host loads at startup, then the caller restarts the service to apply them.
/// The wizard status file remains separate wizard state.
/// </summary>
public sealed class SetupService
{
    private readonly IAdcsClientFactory _clientFactory;
    private readonly ICaDiscoveryService _caDiscovery;
    private readonly IExternalUrlProbe _externalUrlProbe;
    private readonly CertusOptions _certusOptions;
    private readonly ILogger<SetupService> _logger;

    /// <summary>HRESULT for "class not registered" COM activation failures.</summary>
    private const int RegdbClassNotRegistered = unchecked((int)0x80040154);

    public SetupService(
        IAdcsClientFactory clientFactory,
        ICaDiscoveryService caDiscovery,
        IExternalUrlProbe externalUrlProbe,
        IOptions<CertusOptions> certusOptions,
        ILogger<SetupService> logger)
    {
        _clientFactory = clientFactory;
        _caDiscovery = caDiscovery;
        _externalUrlProbe = externalUrlProbe;
        _certusOptions = certusOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Get the path to the setup status file (next to the database).
    /// </summary>
    public string GetSetupStatusPath()
    {
        return SetupStatus.GetStatusPath(_certusOptions);
    }

    /// <summary>
    /// The settings overlay path in effect: the configured override (used by
    /// tests) or the data directory default. The single resolver for every
    /// overlay read and write, so a reader can never watch a different file
    /// than the writer wrote.
    /// </summary>
    public string SettingsOverlayPath =>
        _certusOptions.SettingsOverlayPath ?? CertusPaths.SettingsOverlayPath;

    /// <summary>
    /// The raw wizard status file. Says whether the wizard was walked through,
    /// not whether the service is actually configured — use
    /// <see cref="IsSetupEffectivelyComplete"/> for that.
    /// </summary>
    public SetupStatus GetStatus()
    {
        return SetupStatus.Load(GetSetupStatusPath());
    }

    /// <summary>
    /// True when a CA is actually in effect: a connection string is configured
    /// or the mock was explicitly enabled.
    /// </summary>
    public bool IsCaEffectivelyConfigured =>
        _certusOptions.UseMockCa || !string.IsNullOrEmpty(_certusOptions.CaConnectionString);

    /// <summary>
    /// The effective CA mode, for the wizard and the dashboard banner:
    /// "real", "mock", or "unconfigured".
    /// </summary>
    public string CaMode =>
        _certusOptions.UseMockCa ? "mock"
        : !string.IsNullOrEmpty(_certusOptions.CaConnectionString) ? "real"
        : "unconfigured";

    /// <summary>
    /// Setup counts as complete only when the wizard finished AND a CA is in
    /// effect. Installs that once "completed" setup while the service silently
    /// ran the mock (the pre fix behavior) report incomplete here, so the
    /// wizard opens again — prefilled from the previously saved value — instead
    /// of leaving them stranded.
    /// </summary>
    public bool IsSetupEffectivelyComplete()
    {
        return GetStatus().SetupCompleted && IsCaEffectivelyConfigured;
    }

    /// <summary>
    /// Enumerate the enterprise CAs published in AD for the wizard's pick
    /// list. Best effort: empty means manual entry.
    /// </summary>
    public Task<IReadOnlyList<DiscoveredCa>> DiscoverCasAsync(CancellationToken cancellationToken = default)
    {
        return _caDiscovery.DiscoverAsync(cancellationToken);
    }

    /// <summary>
    /// Test connectivity to a candidate CA through a transient client built
    /// for exactly that connection string.
    /// Returns CA info if accessible, or error details if not.
    /// </summary>
    public async Task<ConnectivityTestResult> TestConnectivityAsync(
        string caConnectionString,
        CancellationToken cancellationToken = default)
    {
        var client = _clientFactory.Create(caConnectionString);
        try
        {
            var caInfo = await client.GetCaInfoAsync(cancellationToken);
            return new ConnectivityTestResult(
                Success: caInfo.IsAccessible,
                CaName: caInfo.Name,
                CaDnsName: caInfo.DnsName,
                CaDisplayName: caInfo.DisplayName,
                ErrorMessage: caInfo.IsAccessible ? null : "CA is not accessible");
        }
        catch (COMException ex) when (ex.HResult == RegdbClassNotRegistered)
        {
            _logger.LogWarning(ex, "CA connectivity test failed: ADCS COM classes are not registered");
            return new ConnectivityTestResult(
                Success: false,
                ErrorMessage:
                    "The ADCS COM classes are not registered on this server. Install the ADCS " +
                    "Remote Administration Tools (Install-WindowsFeature RSAT-ADCS-Mgmt) and try again.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CA connectivity test failed for {Ca}", caConnectionString);
            return new ConnectivityTestResult(
                Success: false,
                ErrorMessage: ex.Message);
        }
        finally
        {
            (client as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// The Extended Key Usage OID for Server Authentication. A template is viable
    /// for ACME (it can issue a usable TLS certificate) when its EKU set contains
    /// this OID. Additional EKUs, such as Client Authentication
    /// (1.3.6.1.5.5.7.3.2) for mutual TLS, do not disqualify it.
    /// </summary>
    public const string ServerAuthEku = "1.3.6.1.5.5.7.3.1";

    /// <summary>
    /// List certificate templates for the setup wizard from a candidate CA,
    /// restricted to those that can issue usable ACME server certificates.
    ///
    /// Template attributes are read from Active Directory and are best effort
    /// (see <c>AdcsTemplateDirectoryLookup</c>). When EKU could be verified
    /// for at least one template, a template is hidden when it lacks the
    /// server authentication EKU, or when its subject is verifiably built
    /// from AD instead of the request (Domain Controller, Machine, Kerberos
    /// Authentication): the CA would ignore every name an ACME client asks
    /// for. Hidden templates are reported through
    /// <see cref="SetupTemplatesResult.ExcludedCount"/> so the wizard can say
    /// why they are absent. An unverifiable subject flag never hides a
    /// template; only a definite "built from AD" does.
    ///
    /// When EKU could not be verified for any template (host not domain
    /// joined, AD unreachable, or insufficient rights), every template is
    /// returned with <see cref="SetupTemplateView.EkuVerified"/> set to false
    /// so the wizard can show all of them with an "unverified" notice rather
    /// than an empty list. That fallback is CA wide: if even one template on
    /// the CA verified, a different template whose own AD object could not
    /// be read (renamed, an ACL denies the service account, an orphaned
    /// object) still reads as EkuVerified false for itself and gets hidden
    /// and counted alongside the templates that genuinely fail the checks.
    /// The wizard's copy for <see cref="SetupTemplatesResult.ExcludedCount"/>
    /// accounts for this by naming "could not be checked" as a third
    /// possible reason, not just the two definite ones.
    /// </summary>
    public async Task<SetupTemplatesResult> GetSetupTemplatesAsync(
        string caConnectionString,
        CancellationToken cancellationToken = default)
    {
        var client = _clientFactory.Create(caConnectionString);
        try
        {
            var all = await client.GetTemplatesAsync(cancellationToken);

            var views = all.Select(t => new SetupTemplateView(
                Name: t.Name,
                DisplayName: t.DisplayName,
                Oid: t.Oid,
                HasServerAuthEku: t.ExtendedKeyUsages?.Contains(ServerAuthEku) == true,
                EkuVerified: t.ExtendedKeyUsages != null,
                Viability: t.Viability)).ToList();

            if (!views.Any(v => v.EkuVerified))
                return new SetupTemplatesResult(views, ExcludedCount: 0);

            var usable = views
                .Where(v => v.HasServerAuthEku
                    && v.Viability?.SubjectSuppliedInRequest != false)
                .ToList();

            return new SetupTemplatesResult(usable, ExcludedCount: views.Count - usable.Count);
        }
        finally
        {
            (client as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// Static checks on a proposed external URL for the ACME server: format,
    /// scheme, host, and warnings that can be read off the URL itself. This
    /// does not test reachability; <see cref="ValidateExternalUrlAsync"/>
    /// adds the active probe.
    /// </summary>
    public ExternalUrlValidation ValidateExternalUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return new ExternalUrlValidation(false, "URL is required");

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return new ExternalUrlValidation(false, "Invalid URL format");

        if (uri.Scheme != "https" && uri.Scheme != "http")
            return new ExternalUrlValidation(false, "URL must use http or https scheme");

        if (string.IsNullOrEmpty(uri.Host))
            return new ExternalUrlValidation(false, "URL must include a hostname");

        var warnings = new List<string>();
        if (uri.Scheme == "http")
            warnings.Add("HTTP is not recommended for production. ACME clients may require HTTPS.");

        if (uri.Host == "localhost" || uri.Host == "127.0.0.1")
            warnings.Add("localhost URL will only work for clients on this machine.");

        // The issue #89 trap: a URL with no port sends every ACME client to
        // the scheme default, which the service does not listen on unless a
        // proxy forwards it. Make the effective port explicit.
        if (uri.IsDefaultPort)
            warnings.Add(
                $"No port was given, so clients will connect to {uri.Host}:{uri.Port}. " +
                $"Include the port when the service listens elsewhere, for example " +
                $"{uri.Scheme}://{uri.Host}:{(uri.Scheme == "https" ? 5001 : 5000)}.");

        return new ExternalUrlValidation(true, Warnings: warnings.Count > 0 ? warnings : null);
    }

    /// <summary>
    /// Full validation for the wizard: the static checks plus an active
    /// reachability probe of the URL (issue #89). The probe is advisory. A
    /// failed probe does not invalidate the URL, because reverse proxy and
    /// hairpin NAT deployments can be legitimately unreachable from the
    /// server itself; the wizard warns and asks for an explicit confirmation
    /// instead of blocking. In mock CA mode (the demo walkthrough) the probe
    /// is skipped entirely.
    /// </summary>
    public async Task<ExternalUrlValidation> ValidateExternalUrlAsync(
        string url,
        string? templateName = null,
        CancellationToken cancellationToken = default)
    {
        var result = ValidateExternalUrl(url);
        if (!result.Valid)
            return result;

        var uri = new Uri(url, UriKind.Absolute);
        var authority = $"{uri.Host}:{uri.Port}";

        if (_certusOptions.UseMockCa)
            return result with { Probe = ExternalUrlProbeResult.Skipped(authority) };

        var probe = await _externalUrlProbe.ProbeAsync(uri, templateName, cancellationToken);

        // The certificate warning stays on the probe result only. The wizard
        // and the settings card render it as its own notice (with the wizard
        // offering to enroll a certificate), so folding it into the generic
        // warnings list would show it twice.
        return result with { Probe = probe };
    }

    /// <summary>
    /// Complete the setup wizard: persist the configuration where the service
    /// actually reads it (the settings overlay), record the wizard state, and
    /// mark setup as done. The caller schedules the restart that applies the
    /// overlay.
    ///
    /// In mock mode the CA connection string is not written to the overlay —
    /// UseMockCa and a connection string are mutually exclusive at startup —
    /// so a demo walkthrough cannot brick the next start.
    /// </summary>
    public SetupStatus CompleteSetup(SetupConfiguration config)
    {
        // Read the overlay back and merge, like UpdateExternalUrl does. A
        // fresh record here would drop the HTTPS certificate thumbprint the
        // wizard's TLS provisioning wrote minutes earlier, and the completion
        // restart would silently fall back to the self signed certificate.
        var overlayPath = SettingsOverlayPath;
        var overlay = SettingsOverlay.Load(overlayPath) with
        {
            CaConnectionString = _certusOptions.UseMockCa ? null : config.CaConnectionString,
            ExternalUrl = config.ExternalUrl,
        };
        SettingsOverlay.Save(overlay, overlayPath);

        var status = new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = DateTime.UtcNow,
            CaConnectionString = config.CaConnectionString,
            EnabledTemplates = config.EnabledTemplates.ToList(),
            ExternalUrl = config.ExternalUrl,
        };

        status.Save(GetSetupStatusPath());

        _logger.LogInformation(
            "Setup completed. CA: {Ca}, Templates: {Templates}, External URL: {Url}; " +
            "configuration written to {Overlay}",
            config.CaConnectionString,
            string.Join(", ", config.EnabledTemplates),
            config.ExternalUrl,
            overlayPath);

        return status;
    }

    /// <summary>
    /// Change the external URL after setup (issue #93). The overlay is read
    /// back and rewritten with only the URL replaced, so the CA connection
    /// string — including its deliberate absence in mock installs — is
    /// preserved exactly as the file has it. Values are never copied in from
    /// options: those can come from environment variables, and freezing a
    /// higher precedence value into the overlay would corrupt the layering.
    /// The caller schedules the restart that applies the change.
    /// </summary>
    public void UpdateExternalUrl(string externalUrl)
    {
        var overlayPath = SettingsOverlayPath;
        var overlay = SettingsOverlay.Load(overlayPath) with { ExternalUrl = externalUrl };
        SettingsOverlay.Save(overlay, overlayPath);

        // Keep the wizard state copy in step so GET /api/setup/config prefills
        // the current URL, not the one setup originally saved. Only rewrite a
        // status that read back as completed: when Load could not read the
        // file (a transient lock, or a torn write) it returns a fresh record,
        // and saving that would wipe the wizard state, drop the enabled
        // template restriction, and reopen the wizard. A stale prefill is the
        // far smaller harm.
        var status = GetStatus();
        if (status.SetupCompleted)
        {
            status.ExternalUrl = externalUrl;
            status.Save(GetSetupStatusPath());
        }
        else
        {
            _logger.LogWarning(
                "External URL changed, but the wizard status file at {Path} did not read " +
                "back as completed; leaving it untouched so its state is not overwritten",
                GetSetupStatusPath());
        }

        _logger.LogInformation(
            "External URL changed to {Url}; configuration written to {Overlay}",
            externalUrl,
            overlayPath);
    }

    /// <summary>
    /// Persist the wizard's current selections without completing setup. The
    /// TLS certificate provisioning restarts the service mid wizard, and when
    /// the admin has to continue at a different origin (the new certificate
    /// does not cover the host the browser is on) the page navigates and the
    /// React state is gone. GET /api/setup/config prefills a reopened wizard
    /// from this draft, exactly like the stranded install recovery path. The
    /// wizard step rides along so the reopened wizard resumes where it was
    /// instead of starting over at Welcome.
    /// </summary>
    public void SaveWizardDraft(SetupConfiguration config, string? wizardStep = null)
    {
        var status = new SetupStatus
        {
            SetupCompleted = false,
            CaConnectionString = config.CaConnectionString,
            EnabledTemplates = config.EnabledTemplates.ToList(),
            ExternalUrl = config.ExternalUrl,
            WizardStep = wizardStep,
        };
        status.Save(GetSetupStatusPath());

        _logger.LogInformation(
            "Wizard draft saved. CA: {Ca}, Templates: {Templates}, External URL: {Url}, Step: {Step}",
            config.CaConnectionString,
            string.Join(", ", config.EnabledTemplates),
            config.ExternalUrl,
            wizardStep);
    }

    /// <summary>
    /// Record the HTTPS certificate the service host should serve, by
    /// thumbprint in the LocalMachine\My store. Read back and merged so the
    /// CA connection string and external URL survive exactly as the overlay
    /// has them. The template the certificate was enrolled with rides along
    /// so a later renewal can reuse it; a null template keeps whatever the
    /// overlay already records rather than erasing it. The caller schedules
    /// the restart that applies it.
    /// </summary>
    public void SetHttpsCertificateThumbprint(string thumbprint, string? templateName = null)
    {
        var overlayPath = SettingsOverlayPath;
        var current = SettingsOverlay.Load(overlayPath);
        var overlay = current with
        {
            HttpsCertificateThumbprint = thumbprint,
            HttpsCertificateTemplate = templateName ?? current.HttpsCertificateTemplate,
        };
        SettingsOverlay.Save(overlay, overlayPath);

        _logger.LogInformation(
            "HTTPS certificate thumbprint {Thumbprint} written to {Overlay}",
            thumbprint,
            overlayPath);
    }
}

/// <summary>Result of a CA connectivity test.</summary>
public sealed record ConnectivityTestResult(
    bool Success,
    string? CaName = null,
    string? CaDnsName = null,
    string? CaDisplayName = null,
    string? ErrorMessage = null);

/// <summary>
/// Result of validating an external URL. <see cref="Probe"/> is present when
/// the async validation ran: it carries the reachability outcome, with
/// <c>Attempted = false</c> when the probe was skipped in mock CA mode.
/// </summary>
public sealed record ExternalUrlValidation(
    bool Valid,
    string? ErrorMessage = null,
    IReadOnlyList<string>? Warnings = null,
    ExternalUrlProbeResult? Probe = null);

/// <summary>Configuration submitted at the end of the setup wizard.</summary>
public sealed record SetupConfiguration(
    string CaConnectionString,
    IReadOnlyList<string> EnabledTemplates,
    string ExternalUrl);

/// <summary>
/// A certificate template as presented by the setup wizard, with the server
/// authentication viability flags derived from its Extended Key Usage set.
/// </summary>
/// <param name="HasServerAuthEku">True when the EKU set contains the Server Authentication OID.</param>
/// <param name="EkuVerified">
/// True when EKU could be read from AD for this template. False means EKU could not be
/// verified, and the wizard shows the template with an "unverified" notice.
/// </param>
/// <param name="Viability">
/// The ACME viability signals behind the wizard's template checklist. Null when the
/// template's AD object could not be read; individual members are null when only
/// that attribute was missing. Advisory only — never gates the wizard.
/// </param>
public sealed record SetupTemplateView(
    string Name,
    string DisplayName,
    string Oid,
    bool HasServerAuthEku,
    bool EkuVerified,
    TemplateAcmeViability? Viability = null);

/// <summary>
/// The setup wizard's template listing: the templates worth offering, plus
/// how many published templates were hidden because they cannot issue a
/// usable ACME server certificate (no server authentication EKU, or the
/// subject is built from AD instead of the request).
/// </summary>
public sealed record SetupTemplatesResult(
    IReadOnlyList<SetupTemplateView> Templates,
    int ExcludedCount);
