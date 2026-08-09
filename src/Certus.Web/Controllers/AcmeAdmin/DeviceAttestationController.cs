using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data.Entities;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.AcmeAdmin;

/// <summary>
/// Device attestation administration for the ACME dashboard tab (the issue
/// #129 admin pattern, applied to device-attest-01). A profile is the explicit
/// act that turns the feature on for a template: with no profile a template
/// answers a permanent-identifier order with the same invisible refusal a
/// server without the feature returns. All writes hot apply to the ACME
/// surface on the next request, because the protocol path reads these tables
/// per request. Admin only with no anonymous carve outs, like the rest of the
/// dashboard API; the CSRF header guard covers every mutation.
/// </summary>
[ApiController]
[Route("api/acme/device-attestation")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class DeviceAttestationController : ControllerBase
{
    private readonly DeviceAttestationAdminService _adminService;
    private readonly TemplateService _templateService;

    public DeviceAttestationController(
        DeviceAttestationAdminService adminService,
        TemplateService templateService)
    {
        _adminService = adminService;
        _templateService = templateService;
    }

    // ---- Profiles ----

    /// <summary>GET /profiles: every device attestation profile, newest first.</summary>
    [HttpGet("profiles")]
    public async Task<IActionResult> ListProfiles(CancellationToken ct)
    {
        return Ok(new { profiles = await _adminService.ListProfilesAsync(ct) });
    }

    /// <summary>
    /// POST /profiles: turn device-attest-01 on for a template. The template
    /// must be published by the CA and enabled for ACME (a device order routes
    /// through the same template directory, so a profile on a template clients
    /// cannot reach would be dead). One profile per template; a second is 409.
    /// </summary>
    [HttpPost("profiles")]
    public async Task<IActionResult> CreateProfile(
        [FromBody] CreateDeviceProfileRequest request, CancellationToken ct)
    {
        var (templateError, templateName) = await ResolveEnabledTemplateAsync(request.TemplateId, ct);
        if (templateError != null)
            return templateError;

        if (!TryNormalizeGateMode(request.GateMode, out var gateMode, out var gateError))
            return BadRequest(new { error = gateError });
        if (!TryNormalizeBinding(request.CsrIdentifierBinding, out var binding, out var bindingError))
            return BadRequest(new { error = bindingError });

        var result = await _adminService.CreateProfileAsync(
            templateName!, gateMode, binding, request.Enabled ?? true, ct);

        return result.Outcome switch
        {
            DeviceProfileOutcome.DuplicateTemplate =>
                Conflict(new { error = $"Template '{templateName}' already has a device attestation profile." }),
            // No Location header: the profile list is the read surface, there
            // is no GET for a single profile to point at.
            _ => StatusCode(201, result.Profile),
        };
    }

    /// <summary>
    /// PUT /profiles/{id}: replace a profile's gate mode, CSR binding, and
    /// enabled flag. The template is the profile's identity and is not changed
    /// here. The change applies to the next device order immediately.
    /// </summary>
    [HttpPut("profiles/{id:int}")]
    public async Task<IActionResult> UpdateProfile(
        int id, [FromBody] UpdateDeviceProfileRequest request, CancellationToken ct)
    {
        if (!TryNormalizeGateMode(request.GateMode, out var gateMode, out var gateError))
            return BadRequest(new { error = gateError });
        if (!TryNormalizeBinding(request.CsrIdentifierBinding, out var binding, out var bindingError))
            return BadRequest(new { error = bindingError });

        var result = await _adminService.UpdateProfileAsync(
            id, gateMode, binding, request.Enabled ?? true, ct);

        return result.Outcome switch
        {
            DeviceProfileOutcome.NotFound =>
                NotFound(new { error = "No device attestation profile has this id." }),
            _ => Ok(result.Profile),
        };
    }

    /// <summary>
    /// DELETE /profiles/{id}: turn device-attest-01 off for the template. The
    /// allowlist goes with it (cascade); the template answers the invisible
    /// refusal again. Idempotent from the client's view: an unknown id is 404.
    /// </summary>
    [HttpDelete("profiles/{id:int}")]
    public async Task<IActionResult> DeleteProfile(int id, CancellationToken ct)
    {
        return await _adminService.DeleteProfileAsync(id, ct)
            ? NoContent()
            : NotFound(new { error = "No device attestation profile has this id." });
    }

    // ---- Allowlist ----

    /// <summary>GET /profiles/{id}/allowlist: the devices admitted by one profile.</summary>
    [HttpGet("profiles/{id:int}/allowlist")]
    public async Task<IActionResult> ListAllowlist(int id, CancellationToken ct)
    {
        var entries = await _adminService.ListAllowlistAsync(id, ct);
        return entries == null
            ? NotFound(new { error = "No device attestation profile has this id." })
            : Ok(new { entries });
    }

    /// <summary>
    /// POST /profiles/{id}/allowlist: admit a device. The identifier value is
    /// the raw permanent-identifier grammar form (serial or UDID, with an
    /// optional "/assigner-OID"); it is compared octet for octet at order time,
    /// so it is stored exactly as given. A device already listed is 409.
    /// </summary>
    [HttpPost("profiles/{id:int}/allowlist")]
    public async Task<IActionResult> AddAllowlistEntry(
        int id, [FromBody] AllowlistEntryRequest request, CancellationToken ct)
    {
        if (!TryNormalizeAllowlistFields(request, out var value, out var note, out var fieldError))
            return BadRequest(new { error = fieldError });

        var result = await _adminService.AddAllowlistEntryAsync(id, value!, note, ct);
        return result.Outcome switch
        {
            AllowlistOutcome.ProfileNotFound =>
                NotFound(new { error = "No device attestation profile has this id." }),
            AllowlistOutcome.Duplicate =>
                Conflict(new { error = "This device is already on the profile's allowlist." }),
            _ => StatusCode(201, result.Entry),
        };
    }

    /// <summary>
    /// PUT /allowlist/{entryId}: replace a listed device's identifier value and
    /// note. A value that collides with another entry on the same profile is
    /// 409.
    /// </summary>
    [HttpPut("allowlist/{entryId:int}")]
    public async Task<IActionResult> UpdateAllowlistEntry(
        int entryId, [FromBody] AllowlistEntryRequest request, CancellationToken ct)
    {
        if (!TryNormalizeAllowlistFields(request, out var value, out var note, out var fieldError))
            return BadRequest(new { error = fieldError });

        var result = await _adminService.UpdateAllowlistEntryAsync(entryId, value!, note, ct);
        return result.Outcome switch
        {
            AllowlistOutcome.EntryNotFound =>
                NotFound(new { error = "No allowlist entry has this id." }),
            AllowlistOutcome.Duplicate =>
                Conflict(new { error = "Another entry on this profile already lists that device." }),
            _ => Ok(result.Entry),
        };
    }

    /// <summary>DELETE /allowlist/{entryId}: remove a listed device. Unknown id is 404.</summary>
    [HttpDelete("allowlist/{entryId:int}")]
    public async Task<IActionResult> DeleteAllowlistEntry(int entryId, CancellationToken ct)
    {
        return await _adminService.DeleteAllowlistEntryAsync(entryId, ct)
            ? NoContent()
            : NotFound(new { error = "No allowlist entry has this id." });
    }

    // ---- Trust anchors ----

    /// <summary>
    /// GET /trust-anchors: the trust anchors, built in roots first (read only),
    /// then any custom anchors. The built in roots are what each format's
    /// verifier pins in code.
    /// </summary>
    [HttpGet("trust-anchors")]
    public async Task<IActionResult> ListTrustAnchors(CancellationToken ct)
    {
        return Ok(new { anchors = await _adminService.ListAnchorsAsync(ct) });
    }

    /// <summary>
    /// POST /trust-anchors: add a custom trust anchor from a pasted PEM
    /// certificate, additive to the built in roots. Used to bridge a vendor
    /// root rotation or to inject a test root. The format must be one this
    /// build can verify, the PEM must parse, and the certificate is deduped by
    /// the SHA-256 of its DER bytes.
    /// </summary>
    [HttpPost("trust-anchors")]
    public async Task<IActionResult> AddTrustAnchor(
        [FromBody] CreateTrustAnchorRequest request, CancellationToken ct)
    {
        var format = request.Format?.Trim() ?? string.Empty;
        var name = request.Name?.Trim() ?? string.Empty;
        var pem = request.CertificatePem?.Trim() ?? string.Empty;

        if (format.Length == 0)
            return BadRequest(new { error = "A trust anchor format is required." });
        if (name.Length == 0)
            return BadRequest(new { error = "A trust anchor name is required." });
        if (name.Length > 200)
            return BadRequest(new { error = "The name must be 200 characters or fewer." });
        if (pem.Length == 0)
            return BadRequest(new { error = "Paste the anchor certificate in PEM form." });

        var result = await _adminService.AddAnchorAsync(format, name, pem, ct);
        return result.Outcome switch
        {
            AnchorOutcome.UnsupportedFormat =>
                BadRequest(new
                {
                    error = "Format must be one of: " +
                            string.Join(", ", _adminService.SupportedFormats) + ".",
                }),
            AnchorOutcome.InvalidPem =>
                BadRequest(new { error = "The certificate did not parse: " + result.Detail }),
            AnchorOutcome.DuplicateBuiltIn =>
                Conflict(new { error = "This certificate is already a built-in trust anchor." }),
            AnchorOutcome.Duplicate =>
                Conflict(new { error = "A trust anchor with this certificate already exists." }),
            _ => StatusCode(201, result.Anchor),
        };
    }

    /// <summary>
    /// DELETE /trust-anchors/{id}: remove a custom trust anchor. The built in
    /// roots carry no id and cannot be targeted; an unknown id is 404.
    /// </summary>
    [HttpDelete("trust-anchors/{id:int}")]
    public async Task<IActionResult> DeleteTrustAnchor(int id, CancellationToken ct)
    {
        return await _adminService.DeleteAnchorAsync(id, ct)
            ? NoContent()
            : NotFound(new { error = "No custom trust anchor has this id." });
    }

    // ---- Helpers ----

    /// <summary>
    /// Resolves the request's template to its canonical name, or returns the
    /// 400 to send. Unknown templates and templates not enabled for ACME are
    /// both refused: a device profile only makes sense on a template a client
    /// can actually reach.
    /// </summary>
    private async Task<(IActionResult? Error, string? TemplateName)> ResolveEnabledTemplateAsync(
        string? templateId, CancellationToken ct)
    {
        var trimmed = templateId?.Trim();
        if (string.IsNullOrEmpty(trimmed))
            return (BadRequest(new { error = "A template is required." }), null);

        var resolution = await _templateService.ResolveAsync(trimmed, ct);
        return resolution.Access switch
        {
            TemplateAccess.Enabled => (null, resolution.Template!.Name),
            TemplateAccess.Disabled => (BadRequest(new
            {
                error = $"Template '{resolution.Template!.DisplayName}' is not enabled for ACME. " +
                        "Enable it on the Settings page first.",
            }), null),
            // Without its own arm this fell into the unknown-template message
            // below, telling the admin a template the CA publishes does not
            // exist. Still a refusal either way; only the sentence changes.
            TemplateAccess.BlockedByCeiling => (BadRequest(new
            {
                error = $"Template '{resolution.Template!.DisplayName}' cannot issue TLS " +
                        "server or client certificates, so device attestation profiles " +
                        "cannot use it.",
            }), null),
            _ => (BadRequest(new
            {
                error = $"No certificate template named '{trimmed}' is published by the CA.",
            }), null),
        };
    }

    private static bool TryNormalizeGateMode(string? raw, out string mode, out string? error)
    {
        // An omitted mode takes the fail closed default; a non-empty typo is a
        // 400, never a silent fallback (the strict parse the plan calls for).
        mode = string.IsNullOrWhiteSpace(raw) ? DeviceAttestationGateModes.Allowlist : raw.Trim();
        if (!DeviceAttestationGateModes.IsValid(mode))
        {
            error = "Gate mode must be one of: allowlist, open.";
            return false;
        }
        error = null;
        return true;
    }

    private static bool TryNormalizeBinding(string? raw, out string mode, out string? error)
    {
        mode = string.IsNullOrWhiteSpace(raw) ? CsrIdentifierBindingModes.CnOrSan : raw.Trim();
        if (!CsrIdentifierBindingModes.IsValid(mode))
        {
            error = "CSR identifier binding must be one of: cn-or-san, san-required, none.";
            return false;
        }
        error = null;
        return true;
    }

    private static bool TryNormalizeAllowlistFields(
        AllowlistEntryRequest request, out string? value, out string? note, out string? error)
    {
        value = null;
        note = null;

        if (!PermanentIdentifierValue.TryParse(request.IdentifierValue?.Trim(), out var parsed, out var parseError))
        {
            error = parseError;
            return false;
        }

        var trimmedNote = request.Note?.Trim();
        if (trimmedNote is { Length: > 500 })
        {
            error = "The note must be 500 characters or fewer.";
            return false;
        }

        value = parsed.Raw;
        note = string.IsNullOrEmpty(trimmedNote) ? null : trimmedNote;
        error = null;
        return true;
    }
}

/// <summary>
/// Request body for creating a profile. Enabled defaults to true when omitted:
/// a nullable bool guards against a missing JSON member binding to false and
/// silently creating a disabled profile.
/// </summary>
public sealed record CreateDeviceProfileRequest(
    string? TemplateId,
    string? GateMode = null,
    string? CsrIdentifierBinding = null,
    bool? Enabled = null);

/// <summary>Request body for updating a profile (the template is not changed).</summary>
public sealed record UpdateDeviceProfileRequest(
    string? GateMode = null,
    string? CsrIdentifierBinding = null,
    bool? Enabled = null);

/// <summary>Request body for an allowlist add or replace.</summary>
public sealed record AllowlistEntryRequest(
    string? IdentifierValue,
    string? Note = null);

/// <summary>Request body for adding a custom trust anchor.</summary>
public sealed record CreateTrustAnchorRequest(
    string? Format,
    string? Name,
    string? CertificatePem);
