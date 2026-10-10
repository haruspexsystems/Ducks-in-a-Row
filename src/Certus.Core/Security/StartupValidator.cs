using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Security;

/// <summary>
/// Validates configuration at startup. Logs warnings for common
/// misconfigurations or security concerns, and refuses to start (throws) for
/// configurations that must never reach a real CA.
/// </summary>
public sealed class StartupValidator
{
    private readonly CertusOptions _options;
    private readonly AuthOptions _authOptions;
    private readonly AcmeRateLimitOptions _rateLimitOptions;
    private readonly AcmeOptions _acmeOptions;
    private readonly RevocationScopePolicy _revocationScope;
    private readonly IConfiguration _configuration;
    private readonly ILogger<StartupValidator> _logger;

    public StartupValidator(
        IOptions<CertusOptions> options,
        IOptions<AuthOptions> authOptions,
        IOptions<AcmeRateLimitOptions> rateLimitOptions,
        IOptions<AcmeOptions> acmeOptions,
        RevocationScopePolicy revocationScope,
        IConfiguration configuration,
        ILogger<StartupValidator> logger)
    {
        _options = options.Value;
        _authOptions = authOptions.Value;
        _rateLimitOptions = rateLimitOptions.Value;
        _acmeOptions = acmeOptions.Value;
        _revocationScope = revocationScope;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Run all startup validation checks. Returns the number of warnings.
    /// Throws <see cref="InvalidOperationException"/> when authentication is
    /// disabled while a real CA is configured (issue #27, SEC-F1): the
    /// development bypass must never expose a production CA inventory.
    /// </summary>
    public int Validate()
    {
        if (_authOptions.IsDisabled && !string.IsNullOrEmpty(_options.CaConnectionString))
        {
            throw new InvalidOperationException(
                "Auth:Mode=Disabled while Certus:CaConnectionString is configured. " +
                "The authentication bypass is for local development against the mock " +
                "ADCS client only and must never front a real CA. Set Auth:Mode=Negotiate " +
                "or remove the CA connection string.");
        }

        if (_options.UseMockCa && !string.IsNullOrEmpty(_options.CaConnectionString))
        {
            throw new InvalidOperationException(
                "Certus:UseMockCa=true while Certus:CaConnectionString is configured. " +
                "The two are mutually exclusive: remove the CA connection string to run " +
                "against the mock, or remove UseMockCa to use the real CA.");
        }

        var warnings = 0;

        // Check database path
        if (string.IsNullOrEmpty(_options.DatabasePath) || _options.DatabasePath == CertusPaths.InMemoryDatabase)
        {
            _logger.LogWarning("Database is using memory only mode — data will be lost on restart");
            warnings++;
        }

        // Check external URL
        if (string.IsNullOrEmpty(_options.ExternalUrl))
        {
            _logger.LogWarning("ExternalUrl is not configured — ACME directory URLs will use relative paths");
            warnings++;
        }
        else if (_options.ExternalUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("ExternalUrl uses HTTP — ACME clients may require HTTPS for production use");
            warnings++;
        }

        // Say which layer supplies the URL, and call out the silent case where
        // an appsettings.json edit is outranked by the settings overlay
        // (issue #93) — otherwise "my change had no effect" is undiagnosable.
        var urlLayers = SettingsOverlay.InspectExternalUrl(_configuration);
        if (urlLayers.EffectiveValue is not null)
        {
            _logger.LogInformation(
                "ExternalUrl in effect: {Url} (from {Source})",
                urlLayers.EffectiveValue,
                urlLayers.EffectiveSource);
        }

        if (urlLayers.AppSettingsValueOverridden)
        {
            if (urlLayers.EffectiveSource == ExternalUrlLayerReport.SourceOverlay)
            {
                _logger.LogWarning(
                    "appsettings.json sets ExternalUrl to {AppSettingsUrl}, but {EffectiveUrl} " +
                    "from the settings overlay outranks it. Change the URL on the dashboard " +
                    "Settings page (or edit settings.json in the data directory); edits to " +
                    "appsettings.json have no effect while the overlay holds a value.",
                    urlLayers.AppSettingsValue,
                    urlLayers.EffectiveValue);
            }
            else
            {
                _logger.LogWarning(
                    "appsettings.json sets ExternalUrl to {AppSettingsUrl}, but a higher " +
                    "precedence source (an environment variable or command line argument) " +
                    "outranks it with {EffectiveUrl}. Neither appsettings.json nor the " +
                    "dashboard Settings page can take effect until that override is removed.",
                    urlLayers.AppSettingsValue,
                    urlLayers.EffectiveValue ?? "an empty value");
            }
            warnings++;
        }

        // Check CA connection. An empty connection string no longer falls back
        // to the mock: the service runs unconfigured and CA operations return
        // 503 until the setup wizard connects a CA.
        if (_options.UseMockCa)
        {
            _logger.LogWarning(
                "Certus:UseMockCa=true — the mock ADCS client is active and every certificate " +
                "is fake (development and demos only)");
            warnings++;
        }
        else if (string.IsNullOrEmpty(_options.CaConnectionString))
        {
            _logger.LogWarning(
                "CaConnectionString is not configured — the service is unconfigured; complete " +
                "the setup wizard to connect a Certificate Authority");
            warnings++;
        }

        // The setup wizard refuses a connection string that could forge log
        // lines, but a value recorded before that guard shipped, or hand edited
        // into settings.json or appsettings.json, is still in effect and is
        // written verbatim on every CA call (issue #220). Warn rather than
        // throw: the two refusals above exist because a bypass must never front
        // a real CA, while this is an audit integrity problem and turning it
        // into a failed boot would be the larger harm. The warning reports the
        // position and code point only, so it cannot forge the line it reports.
        if (!AdcsCaConnectionString.TryValidate(_options.CaConnectionString, out var caError))
        {
            _logger.LogWarning(
                "The configured CA connection string cannot be recorded safely and is written " +
                "to this log on every CA call. {Reason} Correct it in the data directory's " +
                "settings.json.",
                caError);
            warnings++;
        }

        // Check the ACME template exposure override (issue #101). The template
        // policy fails closed without it, so the open posture must be visible
        // on every boot, not only on the first ACME request.
        if (_acmeOptions.ExposeAllTemplates)
        {
            _logger.LogWarning(
                "Certus:Acme:ExposeAllTemplates is true — every CA published template is " +
                "exposed via ACME regardless of the wizard's template selection");
            warnings++;
        }

        // The revocation scope's wide posture must be as visible as the
        // template override above: in all mode any certificate the TLS
        // capability ceiling allows is revocable from the dashboard. Custom
        // with an empty list is the opposite extreme (dashboard revocation
        // disabled entirely); it fails safe, so an Information line rather
        // than a warning.
        var revocationScope = _revocationScope.GetSnapshot();
        if (revocationScope.Mode == RevocationScopeMode.All)
        {
            _logger.LogWarning(
                "The revocation scope is all: every certificate the TLS capability " +
                "ceiling allows is revocable from the dashboard. Narrow it on the " +
                "Settings page unless this is deliberate");
            warnings++;
        }
        else if (revocationScope.Mode == RevocationScopeMode.Custom &&
                 revocationScope.CustomTemplates.Count == 0)
        {
            _logger.LogInformation(
                "The revocation scope is custom with an empty template list, so " +
                "dashboard revocation is disabled entirely");
        }

        // Check sync interval
        if (_options.SyncIntervalMinutes < CertusOptions.MinSyncIntervalMinutes)
        {
            _logger.LogWarning(
                "SyncIntervalMinutes is below the minimum; the certificate sync service will use {Min} minute(s)",
                CertusOptions.MinSyncIntervalMinutes);
            warnings++;
        }

        // Check ACME rate limit values. A non positive limit or window makes the
        // sliding window limiter throw when a request first hits the policy, so
        // warn loudly here instead. The segment count is clamped rather than
        // fatal, so its warning reports a value being overridden. Skip when
        // disabled: the limiter is never registered, so the values are inert.
        if (_rateLimitOptions.Enabled)
        {
            if (_rateLimitOptions.NewAccountLimit < 1)
            {
                _logger.LogWarning("Certus:RateLimiting:NewAccountLimit is less than 1 — ACME new account requests will be rejected while rate limiting is enabled");
                warnings++;
            }

            if (_rateLimitOptions.NewOrderLimit < 1)
            {
                _logger.LogWarning("Certus:RateLimiting:NewOrderLimit is less than 1 — ACME new order requests will be rejected while rate limiting is enabled");
                warnings++;
            }

            if (_rateLimitOptions.GeneralLimit < 1)
            {
                _logger.LogWarning("Certus:RateLimiting:GeneralLimit is less than 1 — general ACME requests will be rejected while rate limiting is enabled");
                warnings++;
            }

            if (_rateLimitOptions.PollLimit < 1)
            {
                _logger.LogWarning("Certus:RateLimiting:PollLimit is less than 1 — ACME authorization and order polling requests will be rejected while rate limiting is enabled");
                warnings++;
            }

            if (_rateLimitOptions.WindowSeconds < 1)
            {
                _logger.LogWarning("Certus:RateLimiting:WindowSeconds is less than 1 — the rate limit window must be at least 1 second");
                warnings++;
            }

            if (_rateLimitOptions.SegmentsPerWindow < 1)
            {
                _logger.LogWarning("Certus:RateLimiting:SegmentsPerWindow is less than 1 — the sliding window limiter requires at least 1 segment, so 1 is being used instead");
                warnings++;
            }

            // Not a warning. Partitioning on the source address is correct for a
            // direct deployment, which is the common one, so counting this as a
            // fault would put a permanent warning on every healthy install. But it
            // fails silently behind a proxy: UseCertusForwardedHeaders is a no-op
            // while TrustedProxies is empty, so every client arrives as the proxy
            // and shares one partition. Say so once, plainly (issue #263).
            if (_authOptions.TrustedProxies.Length == 0)
            {
                _logger.LogInformation(
                    "ACME rate limits partition on the caller's source IP address, and " +
                    "Auth:TrustedProxies is empty — if Certus sits behind a reverse proxy or " +
                    "NAT gateway, every ACME client counts as one caller against a shared limit. " +
                    "Set Auth:TrustedProxies to the proxy's address so the real client address is used.");
            }
        }

        // Check authentication configuration
        if (!string.Equals(_authOptions.Mode, AuthOptions.ModeNegotiate, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(_authOptions.Mode, AuthOptions.ModeDisabled, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "Auth:Mode '{Mode}' is not recognized (valid values: Negotiate, Disabled) — falling back to Negotiate",
                _authOptions.Mode);
            warnings++;
        }

        if (_authOptions.IsDisabled)
        {
            _logger.LogWarning("Auth:Mode is Disabled — dashboard and setup APIs accept anonymous requests (development only)");
            warnings++;
        }

        if (!_authOptions.RequireHttps)
        {
            _logger.LogWarning("Auth:RequireHttps is false — HSTS and HTTPS redirection are not enforced");
            warnings++;
        }

        if (!string.IsNullOrEmpty(_authOptions.AdminGroup) &&
            OperatingSystem.IsWindows() &&
            !CanResolveGroup(_authOptions.AdminGroup))
        {
            _logger.LogWarning(
                "Auth:AdminGroup '{Group}' cannot be resolved to a security identifier — " +
                "all dashboard authorization will fail until it is corrected",
                _authOptions.AdminGroup);
            warnings++;
        }

        foreach (var proxy in _authOptions.TrustedProxies)
        {
            if (!IPAddress.TryParse(proxy, out _))
            {
                _logger.LogWarning(
                    "Auth:TrustedProxies entry '{Entry}' is not a valid IP address — it will be " +
                    "ignored, so X-Forwarded-For from that proxy is not trusted",
                    proxy);
                warnings++;
            }
        }

        if (warnings == 0)
        {
            _logger.LogInformation("Configuration validation passed — no issues found");
        }
        else
        {
            _logger.LogInformation("Configuration validation completed with {Count} warning(s)", warnings);
        }

        return warnings;
    }

    [SupportedOSPlatform("windows")]
    private static bool CanResolveGroup(string group)
    {
        try
        {
            new NTAccount(group).Translate(typeof(SecurityIdentifier));
            return true;
        }
        catch (SystemException)
        {
            // Unresolvable: either the name does not map to a SID
            // (IdentityNotMappedException) or translation failed because no domain
            // controller is reachable. Both derive from SystemException; treat as
            // unresolvable and warn rather than crash.
            return false;
        }
    }
}
