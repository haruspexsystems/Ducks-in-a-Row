using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Services;

/// <summary>
/// Whether the dashboard may revoke one inventory row, and when not, why.
/// BlockedKind is "guardrail" for a TLS capability ceiling refusal and
/// "out-of-scope" for a revocation scope refusal; Detail is the human
/// message the API response and the disabled revoke button both render.
/// </summary>
public sealed record RevocationEligibility(
    bool Allowed,
    string? BlockedKind,
    string? Detail);

/// <summary>
/// Decides whether the dashboard may revoke one inventory row. The single
/// evaluator under both the enforcement in
/// <see cref="CertificateRevocationService"/> and the detail response's
/// disabled button reason, so the refusal an admin reads and the refusal the
/// API enforces cannot drift apart.
///
/// Two gates, in order. First the TLS capability ceiling over the
/// certificate itself, built from the strongest evidence the row carries:
/// the stored DER (the only source that can see BasicConstraints), then the
/// parsed EKU and key usage columns, and with neither present the row is
/// refused outright. Undetermined capability always refuses; nothing here
/// fails open. Then the configured revocation scope
/// (<see cref="RevocationScopePolicy"/>), which only ever narrows within
/// the ceiling. The ceiling runs first so that when both would refuse, the
/// admin reads the reason no settings change can fix.
/// </summary>
public sealed class RevocationEligibilityService
{
    private readonly CertusDbContext _db;
    private readonly TemplateService _templates;
    private readonly RevocationScopePolicy _scope;
    private readonly ILogger<RevocationEligibilityService> _logger;

    public RevocationEligibilityService(
        CertusDbContext db,
        TemplateService templates,
        RevocationScopePolicy scope,
        ILogger<RevocationEligibilityService> logger)
    {
        _db = db;
        _templates = templates;
        _scope = scope;
        _logger = logger;
    }

    public async Task<RevocationEligibility> EvaluateAsync(
        SyncedCertificate entity, CancellationToken cancellationToken = default)
    {
        var capability = BuildCapability(entity, out var undeterminedDetail);
        if (capability == null)
            return new RevocationEligibility(false, "guardrail", undeterminedDetail);

        var verdict = TlsCapabilityCeiling.Evaluate(capability);
        if (!verdict.Allowed)
        {
            return new RevocationEligibility(false, "guardrail",
                $"The TLS certificate guardrail refuses this certificate. {verdict.Message}");
        }

        // The scope, from one snapshot per decision so a settings save mid
        // request cannot mix an old mode with a new list.
        var scope = _scope.GetSnapshot();
        switch (scope.Mode)
        {
            case RevocationScopeMode.All:
                return new RevocationEligibility(true, null, null);

            case RevocationScopeMode.Custom:
                if (await TemplateInSetAsync(entity.TemplateName, scope.CustomTemplates, cancellationToken))
                    return new RevocationEligibility(true, null, null);
                return new RevocationEligibility(false, "out-of-scope",
                    $"Template {entity.TemplateName} is not in the revocable template list. " +
                    "The revocation scope is custom; edit the list in Settings if this " +
                    "certificate should be revocable from here.");

            default:
                // Ducks managed, the union: certificates Ducks issued through
                // ACME (the provenance leg, lookup free), plus certificates on
                // the currently enabled ACME templates.
                if (await _db.AcmeCertificates.AnyAsync(
                        a => a.AdcsRequestId == entity.RequestId, cancellationToken))
                    return new RevocationEligibility(true, null, null);
                if (await TemplateInSetAsync(entity.TemplateName, scope.EnabledTemplates, cancellationToken))
                    return new RevocationEligibility(true, null, null);
                return new RevocationEligibility(false, "out-of-scope",
                    $"This certificate was not issued by Ducks and its template " +
                    $"({entity.TemplateName}) is not in the ACME enabled set. The revocation " +
                    "scope is ducks-managed; change it in Settings if this certificate " +
                    "should be revocable from here.");
        }
    }

    /// <summary>
    /// Whether a row's template belongs to a stored template name set. Raw
    /// form first: the set holds whatever the wizard or the admin stored
    /// (canonical names, or display forms from a hand edit), matched case
    /// insensitively. On a miss, map through the CA's published list and
    /// accept either form (the issue #17 dual form rule), because the row
    /// stores the resolved display name while the wizard writes canonical
    /// names. The CA being unreachable degrades to the raw answer: while the
    /// CA is down the revocation itself would fail anyway, so a conservative
    /// scope answer costs nothing and can never widen.
    /// </summary>
    private async Task<bool> TemplateInSetAsync(
        string templateName, IReadOnlyList<string> set, CancellationToken cancellationToken)
    {
        if (set.Count == 0)
            return false;

        if (set.Contains(templateName, StringComparer.OrdinalIgnoreCase))
            return true;

        try
        {
            var templates = await _templates.GetTemplatesAsync(cancellationToken);
            var match = templates.FirstOrDefault(t =>
                t.Name.Equals(templateName, StringComparison.OrdinalIgnoreCase) ||
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
            if (match == null)
                return false;

            return set.Contains(match.Name, StringComparer.OrdinalIgnoreCase) ||
                   set.Contains(match.DisplayName, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex,
                "Template list unavailable while checking the revocation scope; " +
                "matched on the stored name alone");
            return false;
        }
    }

    /// <summary>
    /// The ceiling's view of the row, or null with a detail message when the
    /// capability cannot be determined at all, which the caller refuses.
    /// </summary>
    private static CertificateCapability? BuildCapability(
        SyncedCertificate entity, out string undeterminedDetail)
    {
        undeterminedDetail = string.Empty;

        if (entity.RawCertificate != null)
        {
            var capability = CertificateDerParser.ParseCapability(entity.RawCertificate);
            if (capability == null)
            {
                undeterminedDetail =
                    "The stored certificate could not be parsed, so its TLS capability " +
                    "cannot be verified.";
            }
            return capability;
        }

        // Rows synced before the raw blob column existed still carry the
        // parsed columns; they only exist when a DER once decoded, so they
        // are trustworthy. BasicConstraints is unknowable from them, which
        // the ceiling treats as not a CA; the EKU rule remains the gate.
        if (entity.ExtendedKeyUsageOids != null || entity.KeyUsage != null)
        {
            var ekus = entity.ExtendedKeyUsageOids?
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return new CertificateCapability(
                ExtendedKeyUsageOids: ekus is { Length: > 0 } ? ekus : null,
                KeyUsage: entity.KeyUsage is { } keyUsage
                    ? (System.Security.Cryptography.X509Certificates.X509KeyUsageFlags)keyUsage
                    : null,
                IsCa: null);
        }

        undeterminedDetail =
            "No certificate detail is stored for this row, so its TLS capability " +
            "cannot be verified. Refresh the inventory and try again.";
        return null;
    }
}
