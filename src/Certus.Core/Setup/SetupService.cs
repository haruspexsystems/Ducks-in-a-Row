using System.Runtime.InteropServices;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Security;
using Certus.Core.Services;
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

    /// <summary>
    /// DISP_E_MEMBERNOTFOUND, which the troubleshooting guide reports for a
    /// server without RSAT-ADCS-Mgmt, where a class activates and then cannot
    /// resolve its methods.
    /// </summary>
    private const int DispMemberNotFound = unchecked((int)0x80020003);

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
    public string SettingsOverlayPath => SettingsOverlay.ResolvePath(_certusOptions);

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
                ErrorMessage: caInfo.IsAccessible ? null : "CA is not accessible",
                FailureKind: caInfo.IsAccessible ? null : ConnectivityFailureKind.NotAccessible);
        }
        catch (CaAccessDeniedException ex)
        {
            // The CA answered and refused the service's account: a right is
            // missing, which no firewall or DNS check would ever fix.
            _logger.LogWarning(ex, "CA connectivity test for {Ca}: the CA refused the service account", caConnectionString);
            return new ConnectivityTestResult(
                Success: false,
                ErrorMessage: ex.Message,
                FailureKind: ConnectivityFailureKind.AccessDenied);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "CA connectivity test for {Ca}: the CA could not be reached", caConnectionString);
            return new ConnectivityTestResult(
                Success: false,
                ErrorMessage:
                    "The CA could not be reached over RPC. Check that CertSvc is running on the CA, and that " +
                    "TCP 135 and the dynamic RPC range (49152 to 65535) are open from this server to the CA.",
                FailureKind: ConnectivityFailureKind.Unavailable);
        }
        catch (COMException ex) when (ex.HResult is RegdbClassNotRegistered or DispMemberNotFound)
        {
            _logger.LogWarning(ex, "CA connectivity test failed: ADCS COM classes are not registered");
            return new ConnectivityTestResult(
                Success: false,
                ErrorMessage:
                    "The ADCS COM classes are not registered on this server. Install the ADCS " +
                    "Remote Administration Tools (Install-WindowsFeature RSAT-ADCS-Mgmt) and try again.",
                FailureKind: ConnectivityFailureKind.ComponentsMissing);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CA connectivity test failed for {Ca}", caConnectionString);
            return new ConnectivityTestResult(
                Success: false,
                ErrorMessage: ex.Message,
                FailureKind: ConnectivityFailureKind.Other);
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
    ///
    /// One further reason hides a template, and unlike the others it applies
    /// whether or not AD could be read: a programmatic name carrying a control,
    /// line separator, or formatting character. That name comes from the CA's
    /// own published list rather than from AD, so "could not be checked" never
    /// applies to it, and <see cref="AdcsRequestAttributes"/> refuses to build a
    /// request attribute string from it, so no certificate can be requested
    /// against the template on any path. Offering it would walk an administrator
    /// through the rest of the wizard to an opaque refusal at the last click,
    /// because completion character checks the recorded set as well. Those are
    /// counted separately in
    /// <see cref="SetupTemplatesResult.UnusableNameCount"/> so the wizard can
    /// give the real reason rather than widen its existing disjunction.
    ///
    /// A dirty <em>display</em> name does not hide anything. The template still
    /// enrolls, and only the ACME addressing form issue #17 added is lost, so it
    /// is reported per template through
    /// <see cref="SetupTemplateView.DisplayNameWarning"/> and left selectable
    /// (issue #235).
    /// </summary>
    public async Task<SetupTemplatesResult> GetSetupTemplatesAsync(
        string caConnectionString,
        CancellationToken cancellationToken = default)
    {
        var client = _clientFactory.Create(caConnectionString);
        try
        {
            var all = await client.GetTemplatesAsync(cancellationToken);

            // Ahead of the EKU branch below, and applying inside both of its
            // arms, because this does not depend on Active Directory at all.
            // The programmatic name comes from the CA's own CR_PROP_TEMPLATES,
            // so the "could not be checked, show it anyway" fallback has nothing
            // to say about it.
            var inspected = all
                .Select(t => (Template: t, Verdict: TemplateNameUsability.Inspect(t)))
                .ToList();

            // CanEnroll alone, so only the programmatic name can hide a
            // template. A dirty display name costs one addressing form and a
            // dirty OID costs nothing at all, and neither is a reason to
            // withhold a template that issues perfectly well (issues #235,
            // #292). Both are reported per template instead, below.
            var enrollable = inspected.Where(pair => pair.Verdict.CanEnroll).ToList();
            var unusableNames = inspected.Count - enrollable.Count;

            var views = enrollable.Select(pair => new SetupTemplateView(
                Name: pair.Template.Name,
                DisplayName: pair.Template.DisplayName,
                Oid: pair.Template.Oid,
                HasServerAuthEku: pair.Template.ExtendedKeyUsages?.Contains(ServerAuthEku) == true,
                EkuVerified: pair.Template.ExtendedKeyUsages != null,
                Viability: pair.Template.Viability,
                DisplayNameWarning: SetupTemplateNameWarning.From(pair.Verdict.DisplayFault),
                OidWarning: SetupTemplateNameWarning.From(pair.Verdict.OidFault))).ToList();

            if (!views.Any(v => v.EkuVerified))
                return new SetupTemplatesResult(views, unusableNames, unusableNames);

            // The ceiling term catches what HasServerAuthEku alone misses: a
            // template carrying server authentication next to a dangerous
            // usage (code signing, enrollment agent) would mint certificates
            // the finalize leaf guard refuses and revokes, so offering it in
            // the wizard would only set the admin up for failed orders.
            // Zipped against enrollable, not all: views was built from the
            // filtered list above, and zipping against the unfiltered one would
            // pair each view with the wrong template's EKU set.
            var usable = views
                .Zip(enrollable, (view, pair) => (view, pair.Template))
                .Where(pair => pair.view.HasServerAuthEku
                    && pair.view.Viability?.SubjectSuppliedInRequest != false
                    && TlsCapabilityCeiling.Evaluate(new CertificateCapability(
                        pair.Template.ExtendedKeyUsages, null, null)).Allowed)
                .Select(pair => pair.view)
                .ToList();

            return new SetupTemplatesResult(
                usable,
                ExcludedCount: unusableNames + (views.Count - usable.Count),
                UnusableNameCount: unusableNames);
        }
        finally
        {
            (client as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// Resolve a wizard supplied template name against the candidate CA's own
    /// published list, returning the CA's canonical name, or null when nothing
    /// matches.
    ///
    /// Enrollment interpolates this name into the ADCS request attribute string
    /// (see <see cref="AdcsRequestAttributes"/>), so resolving here is what
    /// keeps that string built from CA supplied text rather than request body
    /// text. It mirrors what the ACME path already does through
    /// <see cref="Acme.Services.TemplateService.ResolveAsync"/>: the caller's
    /// value selects a template, it never becomes the value sent to the CA.
    ///
    /// Matches the programmatic name or the display name, case insensitive, the
    /// same dual form the ACME resolver accepts. Deliberately checked against
    /// the full published list rather than the ACME usable subset
    /// <see cref="GetSetupTemplatesAsync"/> returns: the question here is
    /// whether ADCS knows the template, not whether it suits ACME.
    /// </summary>
    public async Task<string?> ResolvePublishedTemplateNameAsync(
        string caConnectionString,
        string templateName,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(templateName))
            return null;

        var client = _clientFactory.Create(caConnectionString);
        try
        {
            var published = await client.GetTemplatesAsync(cancellationToken);
            return published
                .FirstOrDefault(t =>
                    t.Name.Equals(templateName, StringComparison.OrdinalIgnoreCase)
                    || t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase))
                ?.Name;
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
        SettingsOverlay.Mutate(overlayPath, current => current with
        {
            CaConnectionString = _certusOptions.UseMockCa ? null : config.CaConnectionString,
            ExternalUrl = config.ExternalUrl,
        });

        // Completion writes a fresh status record, and the EAB enforcement
        // mode is not part of the wizard's configuration, so carry it forward
        // from the prior file: without this, re-running setup on a stranded
        // install would silently reset enforcement to off. Under the shared
        // write lock so the read, modify, save cannot interleave with a
        // settings page update.
        SetupStatus status;
        lock (StatusFileWriteLock)
        {
            var statusPath = GetSetupStatusPath();
            if (!SetupStatus.TryLoad(statusPath, out var prior))
            {
                // Completion cannot be refused for a transient read failure,
                // but resetting these must never be silent. Both reset to
                // their safe defaults: enforcement to off, the revocation
                // scope to ducks-managed.
                _logger.LogWarning(
                    "The wizard status file could not be read while completing setup; " +
                    "the EAB enforcement mode and the revocation scope could not be " +
                    "carried forward and read as their defaults until an administrator " +
                    "sets them again");
            }
            else if (File.Exists(statusPath) && !TrustedFile.Check(statusPath).IsTrusted)
            {
                // Present but not trusted (issue #489): TryLoad reads an untrusted
                // file as absent, so prior reads as empty and the EAB enforcement
                // mode and the revocation scope are being dropped to their defaults.
                // That reset must not be silent either, the same reason the
                // unreadable arm above warns. An absent file, the ordinary first
                // run, is not this: TryLoad succeeds and the file does not exist.
                _logger.LogWarning(
                    "The wizard status file at {Path} is not trusted while completing " +
                    "setup, so the EAB enforcement mode and the revocation scope could " +
                    "not be carried forward and read as their defaults until an " +
                    "administrator sets them again",
                    statusPath);
            }
            status = new SetupStatus
            {
                SetupCompleted = true,
                CompletedAt = DateTime.UtcNow,
                CaConnectionString = config.CaConnectionString,
                EnabledTemplates = config.EnabledTemplates.ToList(),
                ExternalUrl = config.ExternalUrl,
                AllowedDomainsEnabled = config.AllowedDomainsEnabled,
                AllowedDomains = config.AllowedDomains?.ToList() ?? [],
                EabEnforcement = prior.EabEnforcement,
                RevocationScope = prior.RevocationScope,
                RevocableTemplates = prior.RevocableTemplates.ToList(),
            };

            status.Save(statusPath);
        }

        _logger.LogInformation(
            "Setup completed. CA: {Ca}, Templates: {Templates}, External URL: {Url}, " +
            "Domain restriction: {DomainRestriction}; configuration written to {Overlay}",
            config.CaConnectionString,
            string.Join(", ", config.EnabledTemplates),
            config.ExternalUrl,
            config.AllowedDomainsEnabled
                ? $"on ({string.Join(", ", config.AllowedDomains ?? [])})"
                : "off",
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
        SettingsOverlay.Mutate(overlayPath, current => current with { ExternalUrl = externalUrl });

        // Keep the wizard state copy in step so GET /api/setup/config prefills
        // the current URL, not the one setup originally saved. Only rewrite a
        // status that read back as completed: when Load could not read the
        // file (a transient lock, or a torn write) it returns a fresh record,
        // and saving that would wipe the wizard state, drop the enabled
        // template restriction, and reopen the wizard. A stale prefill is the
        // far smaller harm. Under the shared write lock so this read, modify,
        // save cannot interleave with an allowed domains update and resurrect
        // a list the admin just changed.
        lock (StatusFileWriteLock)
        {
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
        }

        _logger.LogInformation(
            "External URL changed to {Url}; configuration written to {Overlay}",
            externalUrl,
            overlayPath);
    }

    /// <summary>
    /// Serializes every read, modify, save of the wizard status file within
    /// this process (the external URL and allowed domains writers).
    /// SetupService is scoped, so an instance lock would not stop two
    /// concurrent settings requests from interleaving and losing one update.
    /// SetupStatus.Save's temp file and move already prevents torn files;
    /// this lock prevents lost updates.
    /// </summary>
    private static readonly object StatusFileWriteLock = new();

    /// <summary>
    /// Change the allowed domain policy after setup. Unlike the external URL
    /// this lives only in the wizard status file (the overlay is not
    /// involved) and AllowedDomainsPolicy hot reads it, so no restart
    /// follows. The same completed status guard as UpdateExternalUrl
    /// applies, but here a failed read back must fail the request: this file
    /// is the store itself, not a prefill mirror, and saving over an
    /// unreadable status would wipe the wizard state and drop the enabled
    /// template restriction. The caller validates and normalizes the
    /// entries; this method only persists them.
    /// </summary>
    public bool UpdateAllowedDomains(bool enabled, IReadOnlyList<string> normalizedDomains)
    {
        lock (StatusFileWriteLock)
        {
            var status = GetStatus();
            if (!status.SetupCompleted)
            {
                _logger.LogWarning(
                    "Allowed domains change refused: the wizard status file at {Path} did not " +
                    "read back as completed, so writing it would wipe the wizard state",
                    GetSetupStatusPath());
                return false;
            }

            status.AllowedDomainsEnabled = enabled;
            status.AllowedDomains = normalizedDomains.ToList();
            status.Save(GetSetupStatusPath());

            _logger.LogInformation(
                "Allowed domains updated: restriction {State}, {Count} entries ({Domains})",
                enabled ? "on" : "off",
                normalizedDomains.Count,
                string.Join(", ", normalizedDomains));
            return true;
        }
    }

    /// <summary>
    /// Change the external account binding enforcement mode after setup
    /// (RFC 8555 §7.3.4). Lives only in the wizard status file, which
    /// EabEnforcementPolicy hot reads, so no restart follows. The same
    /// completed status guard as UpdateAllowedDomains applies: this file is
    /// the store itself, and saving over an unreadable status would wipe the
    /// wizard state.
    /// </summary>
    public bool UpdateEabEnforcement(EabEnforcementMode mode)
    {
        lock (StatusFileWriteLock)
        {
            var status = GetStatus();
            if (!status.SetupCompleted)
            {
                _logger.LogWarning(
                    "EAB enforcement change refused: the wizard status file at {Path} did not " +
                    "read back as completed, so writing it would wipe the wizard state",
                    GetSetupStatusPath());
                return false;
            }

            status.EabEnforcement = EabEnforcementPolicy.ModeName(mode);
            status.Save(GetSetupStatusPath());

            _logger.LogInformation(
                "EAB enforcement mode updated: {Mode}",
                EabEnforcementPolicy.ModeName(mode));
            return true;
        }
    }

    /// <summary>
    /// Change the dashboard revocation scope after setup. Lives only in the
    /// wizard status file, which RevocationScopePolicy hot reads, so no
    /// restart follows. The same completed status guard as
    /// UpdateAllowedDomains applies: this file is the store itself, and
    /// saving over an unreadable status would wipe the wizard state. The
    /// caller validates the template names; this method only persists them.
    /// </summary>
    public bool UpdateRevocationScope(RevocationScopeMode mode, IReadOnlyList<string> customTemplates)
    {
        lock (StatusFileWriteLock)
        {
            var status = GetStatus();
            if (!status.SetupCompleted)
            {
                _logger.LogWarning(
                    "Revocation scope change refused: the wizard status file at {Path} did not " +
                    "read back as completed, so writing it would wipe the wizard state",
                    GetSetupStatusPath());
                return false;
            }

            status.RevocationScope = RevocationScopePolicy.ModeName(mode);
            status.RevocableTemplates = customTemplates.ToList();
            status.Save(GetSetupStatusPath());

            _logger.LogInformation(
                "Revocation scope updated: {Mode}, {Count} custom templates",
                RevocationScopePolicy.ModeName(mode), customTemplates.Count);
            return true;
        }
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
        lock (StatusFileWriteLock)
        {
            // The draft rewrites the whole status file, and neither the EAB
            // enforcement mode nor the revocation scope is wizard state
            // (they cannot ride through SetupConfiguration the way the
            // allowed domain choice does), so carry both forward from the
            // prior file exactly like CompleteSetup. Without this, a draft
            // saved while recovering a stranded install would silently reset
            // them to their defaults.
            var prior = GetStatus();
            var status = new SetupStatus
            {
                SetupCompleted = false,
                CaConnectionString = config.CaConnectionString,
                EnabledTemplates = config.EnabledTemplates.ToList(),
                ExternalUrl = config.ExternalUrl,
                AllowedDomainsEnabled = config.AllowedDomainsEnabled,
                AllowedDomains = config.AllowedDomains?.ToList() ?? [],
                EabEnforcement = prior.EabEnforcement,
                RevocationScope = prior.RevocationScope,
                RevocableTemplates = prior.RevocableTemplates.ToList(),
                WizardStep = wizardStep,
            };
            status.Save(GetSetupStatusPath());
        }

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
    /// so a later renewal can reuse it; a blank template keeps whatever the
    /// overlay already records rather than erasing it. The caller schedules
    /// the restart that applies it.
    ///
    /// Neither value may be written blank, and the two fail differently. A
    /// blank thumbprint is refused outright: an empty string persists where a
    /// null is stripped by WhenWritingNull, and it then reads as "no
    /// certificate configured" at every call site, so the next start falls
    /// back to the self signed certificate with only the generic warning in
    /// the log. A blank template is treated as "none supplied" instead,
    /// because an empty string there is worse than no value at all:
    /// HttpsCertificateRenewalService resolves the template as the recorded
    /// one ?? the first enabled one, so a stored empty string is not null,
    /// the fallback never runs, and every renewal blocks on NoTemplate.
    /// </summary>
    public void SetHttpsCertificateThumbprint(string thumbprint, string? templateName = null)
    {
        if (string.IsNullOrWhiteSpace(thumbprint))
        {
            throw new ArgumentException(
                "The HTTPS certificate thumbprint cannot be blank. A blank value persists in " +
                "the overlay, reads as no certificate configured everywhere it is used, and " +
                "silently drops the service back to its self signed certificate at the next start.",
                nameof(thumbprint));
        }

        var overlayPath = SettingsOverlayPath;
        SettingsOverlay.Mutate(overlayPath, current => current with
        {
            HttpsCertificateThumbprint = thumbprint,
            HttpsCertificateTemplate = string.IsNullOrWhiteSpace(templateName)
                ? current.HttpsCertificateTemplate
                : templateName,
        });

        _logger.LogInformation(
            "HTTPS certificate thumbprint {Thumbprint} written to {Overlay}",
            thumbprint,
            overlayPath);
    }
}

/// <summary>Result of a CA connectivity test.</summary>
/// <param name="FailureKind">
/// Why the test failed, one of the <see cref="ConnectivityFailureKind"/> names,
/// so the wizard can give the hint that fits rather than one generic line. Null
/// when the test passed.
/// </param>
public sealed record ConnectivityTestResult(
    bool Success,
    string? CaName = null,
    string? CaDnsName = null,
    string? CaDisplayName = null,
    string? ErrorMessage = null,
    string? FailureKind = null);

/// <summary>
/// The wire names of <see cref="ConnectivityTestResult.FailureKind"/>. Strings
/// rather than an enum because the API serialises enums as numbers.
/// </summary>
public static class ConnectivityFailureKind
{
    /// <summary>The CA answered and refused the service's account.</summary>
    public const string AccessDenied = "accessDenied";

    /// <summary>The CA could not be reached over RPC.</summary>
    public const string Unavailable = "unavailable";

    /// <summary>The ADCS COM classes are missing on this server (RSAT-ADCS-Mgmt).</summary>
    public const string ComponentsMissing = "componentsMissing";

    /// <summary>The CA answered with some other failure.</summary>
    public const string NotAccessible = "notAccessible";

    /// <summary>Anything else.</summary>
    public const string Other = "other";
}

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
    string ExternalUrl,
    bool AllowedDomainsEnabled = false,
    IReadOnlyList<string>? AllowedDomains = null);

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
/// <param name="DisplayNameWarning">
/// Set when the display name carries a character the URL guard refuses, so an
/// ACME client addressing this template by its display name is refused with a
/// 400 before routing (issue #235). Null on a clean template.
///
/// There is deliberately no matching member for the programmatic name. A
/// template whose programmatic name carries one is never listed at all, so such
/// a member could not be anything but null on the wire.
/// </param>
/// <param name="OidWarning">
/// Set when the template OID carries such a character (issue #292). Unlike the
/// other two this costs nothing: the template issues and is addressed exactly
/// as before, and it is reported only because the wizard prints the OID on
/// every template row, where an override in it reorders the text around it.
/// Null on a clean template.
/// </param>
public sealed record SetupTemplateView(
    string Name,
    string DisplayName,
    string Oid,
    bool HasServerAuthEku,
    bool EkuVerified,
    TemplateAcmeViability? Viability = null,
    SetupTemplateNameWarning? DisplayNameWarning = null,
    SetupTemplateNameWarning? OidWarning = null);

/// <summary>
/// Why one of a template's values cannot be shown or used as published, for a
/// surface that has to explain it. The class as the noun the sentence needs,
/// plus the position and code point an operator can look up. Never the value
/// and never the character: a bidirectional override in a JSON body would
/// reorder the page reporting it, which is the fault this exists to report.
///
/// Named for the two names it was written for, and since issue #292 it carries
/// the template OID as well. The shape is right for all three, and a second
/// record with the same three members would only give the frontend a second
/// key layout to keep straight.
/// </summary>
public sealed record SetupTemplateNameWarning(string Kind, int Position, int CodePoint)
{
    /// <summary>
    /// Projects a fault onto the wire. Carries the class as its noun rather
    /// than as an enum, so a caller composes its sentence without learning a
    /// numeric value, and carries no template text at all.
    ///
    /// It lives here rather than on the one service that first needed it
    /// because the setup wizard and the dashboard's template endpoint both
    /// report a fault now, and one composer is what stops the two wire shapes
    /// drifting apart.
    /// </summary>
    public static SetupTemplateNameWarning? From(TemplateNameFault? fault) =>
        fault is { } f
            ? new SetupTemplateNameWarning(f.ClassNoun, f.Character.Position, f.Character.CodePoint)
            : null;
}

/// <summary>
/// The setup wizard's template listing: the templates worth offering, plus
/// how many published templates were hidden because they cannot issue a
/// usable ACME server certificate (no server authentication EKU, or the
/// subject is built from AD instead of the request).
/// </summary>
/// <param name="UnusableNameCount">
/// The subset of <paramref name="ExcludedCount"/> hidden because the
/// programmatic name itself carries a control, line separator, or formatting
/// character, so nothing can be enrolled against the template on any path. Held
/// apart from the rest because its fix is a different one: the programmatic
/// name is fixed when a template is created, so the template has to be
/// duplicated under a clean name.
/// </param>
public sealed record SetupTemplatesResult(
    IReadOnlyList<SetupTemplateView> Templates,
    int ExcludedCount,
    int UnusableNameCount = 0);
