using Certus.Core.Adcs;
using Certus.Core.Security;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Outcome of resolving an ACME template identifier.
/// </summary>
public enum TemplateAccess
{
    /// <summary>No CA published template matches the identifier.</summary>
    Unknown,

    /// <summary>The template exists but the administrator has not enabled it for ACME.</summary>
    Disabled,

    /// <summary>The template exists and is enabled for ACME.</summary>
    Enabled,

    /// <summary>
    /// The template is enabled but its verified AD metadata violates the TLS
    /// capability ceiling, so its certificates could never be delivered.
    /// Unverified metadata never lands here: the AD lookup is best effort,
    /// and the finalize leaf check is the hard guarantee behind this state.
    /// </summary>
    BlockedByCeiling,
}

/// <summary>
/// Result of <see cref="TemplateService.ResolveAsync"/>. <see cref="Template"/>
/// is set for both <see cref="TemplateAccess.Enabled"/> and
/// <see cref="TemplateAccess.Disabled"/> so callers can log or report the match.
/// </summary>
public sealed record TemplateResolution(TemplateAccess Access, TemplateInfo? Template);

/// <summary>
/// Resolves ACME template identifiers against the available ADCS templates and
/// the administrator's enabled set. Each template maps to an ACME directory
/// endpoint. Resolution is policy aware (issue #85): every ACME endpoint that
/// takes a template from the route must go through <see cref="ResolveAsync"/>
/// so disabled templates cannot be reached by naming them directly.
/// </summary>
public sealed class TemplateService
{
    private readonly IAdcsClient _adcsClient;
    private readonly EnabledTemplatesPolicy _enabledTemplates;
    private readonly ILogger<TemplateService> _logger;
    private IReadOnlyList<TemplateInfo>? _cachedTemplates;
    private DateTime _cacheExpiry = DateTime.MinValue;
    private readonly SemaphoreSlim _cacheLock = new(1, 1);

    public TemplateService(
        IAdcsClient adcsClient,
        EnabledTemplatesPolicy enabledTemplates,
        ILogger<TemplateService> logger)
    {
        _adcsClient = adcsClient;
        _enabledTemplates = enabledTemplates;
        _logger = logger;
    }

    /// <summary>
    /// Resolves a template identifier to the canonical <see cref="TemplateInfo"/>
    /// and its ACME access state. Accepts either the programmatic name (AD
    /// <c>cn</c>) or the display name (AD <c>displayName</c>). Issue #17: ACME
    /// clients are commonly configured with the display name, which contains
    /// spaces; the programmatic name does not. Callers that need the
    /// programmatic name to pass to ADCS must use <see cref="TemplateInfo.Name"/>
    /// from the result, not the input value.
    /// </summary>
    public async Task<TemplateResolution> ResolveAsync(
        string templateNameOrDisplayName,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(templateNameOrDisplayName))
            return new TemplateResolution(TemplateAccess.Unknown, null);

        var templates = await GetTemplatesAsync(cancellationToken);
        var match = templates.FirstOrDefault(t =>
            t.Name.Equals(templateNameOrDisplayName, StringComparison.OrdinalIgnoreCase) ||
            t.DisplayName.Equals(templateNameOrDisplayName, StringComparison.OrdinalIgnoreCase));

        if (match == null)
            return new TemplateResolution(TemplateAccess.Unknown, null);

        if (!_enabledTemplates.IsEnabled(match))
            return new TemplateResolution(TemplateAccess.Disabled, match);

        // The TLS capability ceiling over the template's verified AD
        // metadata. Absent metadata passes deliberately (the AD lookup is
        // best effort and must not take issuance down with it); the finalize
        // leaf check is the hard guarantee behind this early refusal.
        if (match.ExtendedKeyUsages != null)
        {
            var verdict = TlsCapabilityCeiling.Evaluate(
                new CertificateCapability(match.ExtendedKeyUsages, null, null));
            if (!verdict.Allowed)
            {
                _logger.LogWarning(
                    "Template {Template} is enabled but refused by the TLS capability ceiling: {Reason}",
                    match.Name, verdict.Message);
                return new TemplateResolution(TemplateAccess.BlockedByCeiling, match);
            }
        }

        return new TemplateResolution(TemplateAccess.Enabled, match);
    }

    /// <summary>
    /// Gets all CA published templates (cached). Deliberately unfiltered by the
    /// enabled set: the dashboard is an administrator surface and shows what
    /// the CA offers, not what ACME exposes.
    /// </summary>
    public async Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(
        CancellationToken cancellationToken = default)
    {
        if (_cachedTemplates != null && DateTime.UtcNow < _cacheExpiry)
            return _cachedTemplates;

        await _cacheLock.WaitAsync(cancellationToken);
        try
        {
            // Check again after acquiring the lock
            if (_cachedTemplates != null && DateTime.UtcNow < _cacheExpiry)
                return _cachedTemplates;

            _cachedTemplates = await _adcsClient.GetTemplatesAsync(cancellationToken);
            _cacheExpiry = DateTime.UtcNow.AddMinutes(5);

            _logger.LogDebug("Refreshed template cache: {Count} templates", _cachedTemplates.Count);
            return _cachedTemplates;
        }
        finally
        {
            _cacheLock.Release();
        }
    }
}
