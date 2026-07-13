using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;
using Certus.Core.Configuration;
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
    private readonly IConfiguration _configuration;
    private readonly ILogger<StartupValidator> _logger;

    public StartupValidator(
        IOptions<CertusOptions> options,
        IOptions<AuthOptions> authOptions,
        IOptions<AcmeRateLimitOptions> rateLimitOptions,
        IConfiguration configuration,
        ILogger<StartupValidator> logger)
    {
        _options = options.Value;
        _authOptions = authOptions.Value;
        _rateLimitOptions = rateLimitOptions.Value;
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

        // Check sync interval
        if (_options.SyncIntervalMinutes < CertusOptions.MinSyncIntervalMinutes)
        {
            _logger.LogWarning(
                "SyncIntervalMinutes is below the minimum; the certificate sync service will use {Min} minute(s)",
                CertusOptions.MinSyncIntervalMinutes);
            warnings++;
        }

        // Check ACME rate limit values — a non positive limit or window makes the
        // fixed window limiter throw when a request first hits the policy, so warn
        // loudly here instead. Skip when disabled: the limiter is never registered,
        // so the values are inert.
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

            if (_rateLimitOptions.WindowSeconds < 1)
            {
                _logger.LogWarning("Certus:RateLimiting:WindowSeconds is less than 1 — the rate limit window must be at least 1 second");
                warnings++;
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
