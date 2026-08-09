using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Attestation;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Administration of the device attestation tables behind the ACME dashboard
/// tab (issue #129 pattern): the per template profiles, their allowlists, and
/// the custom trust anchors. Every write lands in the same tables the ACME
/// surface reads on each request (<see cref="DeviceAttestationPolicyService"/>,
/// <see cref="AttestationTrustAnchorStore"/>), so a change here applies to the
/// next device order with no restart and no cache to invalidate. The service
/// owns the database outcomes (duplicate, not found); the controller owns the
/// field validation and the status codes, so the two do not drift.
/// </summary>
public sealed class DeviceAttestationAdminService
{
    private readonly CertusDbContext _db;
    private readonly IEnumerable<IAttestationFormatVerifier> _verifiers;
    private readonly ILogger<DeviceAttestationAdminService> _logger;

    public DeviceAttestationAdminService(
        CertusDbContext db,
        IEnumerable<IAttestationFormatVerifier> verifiers,
        ILogger<DeviceAttestationAdminService> logger)
    {
        _db = db;
        _verifiers = verifiers;
        _logger = logger;
    }

    /// <summary>
    /// The attestation formats this build can verify, taken from the registered
    /// verifiers so the admin surface never offers a format the engine cannot
    /// check. Apple only in v1.
    /// </summary>
    public IReadOnlyList<string> SupportedFormats =>
        _verifiers.Select(v => v.Format).Distinct().OrderBy(f => f).ToList();

    // ---- Profiles ----

    /// <summary>Every device attestation profile, newest first, with its allowlist size.</summary>
    public async Task<IReadOnlyList<DeviceAttestationProfileSummary>> ListProfilesAsync(
        CancellationToken cancellationToken = default)
    {
        return await _db.DeviceAttestationProfiles
            .AsNoTracking()
            .OrderByDescending(p => p.CreatedAt)
            .ThenByDescending(p => p.Id)
            .Select(p => new DeviceAttestationProfileSummary(
                p.Id,
                p.TemplateId,
                p.Enabled,
                p.GateMode,
                p.CsrIdentifierBinding,
                p.AllowlistEntries.Count,
                p.CreatedAt,
                p.UpdatedAt))
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Creates a profile for a template, which is the explicit act that turns
    /// device-attest-01 on for that template. The caller passes the canonical
    /// template name it already resolved and the two modes it already parsed;
    /// this method enforces the one profile per template rule and returns
    /// <see cref="DeviceProfileOutcome.DuplicateTemplate"/> when one exists.
    /// </summary>
    public async Task<DeviceProfileResult> CreateProfileAsync(
        string templateId,
        string gateMode,
        string csrIdentifierBinding,
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        var exists = await _db.DeviceAttestationProfiles
            .AnyAsync(p => p.TemplateId == templateId, cancellationToken);
        if (exists)
            return new DeviceProfileResult(DeviceProfileOutcome.DuplicateTemplate, null);

        var profile = new DeviceAttestationProfile
        {
            TemplateId = templateId,
            GateMode = gateMode,
            CsrIdentifierBinding = csrIdentifierBinding,
            Enabled = enabled,
            CreatedAt = DateTime.UtcNow,
        };
        _db.DeviceAttestationProfiles.Add(profile);

        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // The unique index is the real arbiter; a concurrent create for the
            // same template lands here rather than as a second row.
            _db.Entry(profile).State = EntityState.Detached;
            return new DeviceProfileResult(DeviceProfileOutcome.DuplicateTemplate, null);
        }

        _logger.LogInformation(
            "Created device attestation profile for template '{Template}' (gate {Gate}, binding {Binding}, {State})",
            profile.TemplateId, profile.GateMode, profile.CsrIdentifierBinding,
            profile.Enabled ? "enabled" : "disabled");

        return new DeviceProfileResult(DeviceProfileOutcome.Saved, ToSummary(profile, allowlistCount: 0));
    }

    /// <summary>
    /// Replaces a profile's gate mode, CSR binding, and enabled flag. The
    /// template is the profile's identity and does not change here; to move a
    /// profile to a different template, delete this one and create another.
    /// </summary>
    public async Task<DeviceProfileResult> UpdateProfileAsync(
        int id,
        string gateMode,
        string csrIdentifierBinding,
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        var profile = await _db.DeviceAttestationProfiles
            .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
        if (profile == null)
            return new DeviceProfileResult(DeviceProfileOutcome.NotFound, null);

        profile.GateMode = gateMode;
        profile.CsrIdentifierBinding = csrIdentifierBinding;
        profile.Enabled = enabled;
        profile.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);

        var allowlistCount = await _db.DeviceAllowlistEntries
            .CountAsync(e => e.ProfileId == id, cancellationToken);

        _logger.LogInformation(
            "Updated device attestation profile for template '{Template}' (gate {Gate}, binding {Binding}, {State})",
            profile.TemplateId, profile.GateMode, profile.CsrIdentifierBinding,
            profile.Enabled ? "enabled" : "disabled");

        return new DeviceProfileResult(
            DeviceProfileOutcome.Saved, ToSummary(profile, allowlistCount));
    }

    /// <summary>
    /// Deletes a profile and, by the cascade, its allowlist. This turns
    /// device-attest-01 off for the template: permanent-identifier orders on
    /// it answer the same invisible refusal a template that never had a
    /// profile does. Returns false when no profile has this id.
    /// </summary>
    public async Task<bool> DeleteProfileAsync(int id, CancellationToken cancellationToken = default)
    {
        // Include the allowlist so EF deletes the children in this unit rather
        // than leaning on the database FK cascade alone: the delete then holds
        // regardless of whether foreign key enforcement is on, and no orphan
        // rows can survive a profile.
        var profile = await _db.DeviceAttestationProfiles
            .Include(p => p.AllowlistEntries)
            .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
        if (profile == null)
            return false;

        _db.DeviceAttestationProfiles.Remove(profile);
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Deleted the device attestation profile for template '{Template}'; " +
            "the template no longer accepts device orders",
            profile.TemplateId);
        return true;
    }

    // ---- Allowlist ----

    /// <summary>
    /// The devices admitted by one profile, newest first. Returns null when no
    /// profile has this id, so the API can tell an unknown profile from an
    /// empty allowlist.
    /// </summary>
    public async Task<IReadOnlyList<DeviceAllowlistEntrySummary>?> ListAllowlistAsync(
        int profileId, CancellationToken cancellationToken = default)
    {
        var exists = await _db.DeviceAttestationProfiles
            .AnyAsync(p => p.Id == profileId, cancellationToken);
        if (!exists)
            return null;

        return await _db.DeviceAllowlistEntries
            .AsNoTracking()
            .Where(e => e.ProfileId == profileId)
            .OrderByDescending(e => e.CreatedAt)
            .ThenByDescending(e => e.Id)
            .Select(e => new DeviceAllowlistEntrySummary(
                e.Id, e.ProfileId, e.IdentifierValue, e.Note, e.CreatedAt))
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Adds a device to a profile's allowlist. The caller passes the validated
    /// raw permanent-identifier value (octet exact is the protocol comparison,
    /// so it is stored exactly as given). Returns
    /// <see cref="AllowlistOutcome.Duplicate"/> when the device is already
    /// listed on this profile, or <see cref="AllowlistOutcome.ProfileNotFound"/>
    /// for an unknown profile.
    /// </summary>
    public async Task<AllowlistEntryResult> AddAllowlistEntryAsync(
        int profileId,
        string identifierValue,
        string? note,
        CancellationToken cancellationToken = default)
    {
        var exists = await _db.DeviceAttestationProfiles
            .AnyAsync(p => p.Id == profileId, cancellationToken);
        if (!exists)
            return new AllowlistEntryResult(AllowlistOutcome.ProfileNotFound, null);

        var entry = new DeviceAllowlistEntry
        {
            ProfileId = profileId,
            IdentifierValue = identifierValue,
            Note = note,
            CreatedAt = DateTime.UtcNow,
        };
        _db.DeviceAllowlistEntries.Add(entry);

        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            _db.Entry(entry).State = EntityState.Detached;
            return new AllowlistEntryResult(AllowlistOutcome.Duplicate, null);
        }

        return new AllowlistEntryResult(AllowlistOutcome.Saved, ToSummary(entry));
    }

    /// <summary>
    /// Replaces an allowlist entry's identifier value and note. A value that
    /// collides with another entry on the same profile is refused with
    /// <see cref="AllowlistOutcome.Duplicate"/>; an unknown entry id returns
    /// <see cref="AllowlistOutcome.EntryNotFound"/>.
    /// </summary>
    public async Task<AllowlistEntryResult> UpdateAllowlistEntryAsync(
        int entryId,
        string identifierValue,
        string? note,
        CancellationToken cancellationToken = default)
    {
        var entry = await _db.DeviceAllowlistEntries
            .FirstOrDefaultAsync(e => e.Id == entryId, cancellationToken);
        if (entry == null)
            return new AllowlistEntryResult(AllowlistOutcome.EntryNotFound, null);

        entry.IdentifierValue = identifierValue;
        entry.Note = note;

        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            return new AllowlistEntryResult(AllowlistOutcome.Duplicate, null);
        }

        return new AllowlistEntryResult(AllowlistOutcome.Saved, ToSummary(entry));
    }

    /// <summary>Removes one device from an allowlist. Returns false for an unknown entry id.</summary>
    public async Task<bool> DeleteAllowlistEntryAsync(
        int entryId, CancellationToken cancellationToken = default)
    {
        var entry = await _db.DeviceAllowlistEntries
            .FirstOrDefaultAsync(e => e.Id == entryId, cancellationToken);
        if (entry == null)
            return false;

        _db.DeviceAllowlistEntries.Remove(entry);
        await _db.SaveChangesAsync(cancellationToken);
        return true;
    }

    // ---- Trust anchors ----

    /// <summary>
    /// The trust anchors, built in roots first (read only, always enabled),
    /// then the custom anchors newest first. The built in roots are what each
    /// format's verifier pins in code; the admin cannot remove them.
    /// </summary>
    public async Task<IReadOnlyList<TrustAnchorSummary>> ListAnchorsAsync(
        CancellationToken cancellationToken = default)
    {
        var builtIn = BuiltInAttestationAnchors.All
            .Select(a => new TrustAnchorSummary(
                null, a.Format, a.Name, a.Sha256Fingerprint,
                Enabled: true, BuiltIn: true, CreatedAt: null));

        var custom = await _db.AttestationTrustAnchors
            .AsNoTracking()
            .OrderByDescending(a => a.CreatedAt)
            .ThenByDescending(a => a.Id)
            .Select(a => new TrustAnchorSummary(
                a.Id, a.Format, a.Name, a.Sha256Fingerprint,
                a.Enabled, false, a.CreatedAt))
            .ToListAsync(cancellationToken);

        return builtIn.Concat(custom).ToList();
    }

    /// <summary>
    /// Adds a custom trust anchor from a pasted PEM certificate. The format
    /// must be one this build can verify; the PEM must parse; the certificate
    /// is deduped by the SHA-256 of its DER bytes; and a certificate that is
    /// already a built in root is refused as redundant rather than stored a
    /// second time.
    /// </summary>
    public async Task<AnchorResult> AddAnchorAsync(
        string format,
        string name,
        string certificatePem,
        CancellationToken cancellationToken = default)
    {
        if (!SupportedFormats.Contains(format))
            return new AnchorResult(AnchorOutcome.UnsupportedFormat, null);

        X509Certificate2 certificate;
        try
        {
            certificate = X509Certificate2.CreateFromPem(certificatePem);
        }
        catch (CryptographicException ex)
        {
            return new AnchorResult(AnchorOutcome.InvalidPem, null, ex.Message);
        }

        string fingerprint;
        try
        {
            fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant();
        }
        finally
        {
            certificate.Dispose();
        }

        if (BuiltInAttestationAnchors.ContainsFingerprint(fingerprint))
            return new AnchorResult(AnchorOutcome.DuplicateBuiltIn, null);

        var anchor = new AttestationTrustAnchor
        {
            Format = format,
            Name = name,
            CertificatePem = certificatePem,
            Sha256Fingerprint = fingerprint,
            Enabled = true,
            CreatedAt = DateTime.UtcNow,
        };
        _db.AttestationTrustAnchors.Add(anchor);

        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            _db.Entry(anchor).State = EntityState.Detached;
            return new AnchorResult(AnchorOutcome.Duplicate, null);
        }

        _logger.LogInformation(
            "Added custom {Format} attestation trust anchor '{Name}' ({Fingerprint})",
            anchor.Format, anchor.Name, anchor.Sha256Fingerprint);

        return new AnchorResult(AnchorOutcome.Saved, new TrustAnchorSummary(
            anchor.Id, anchor.Format, anchor.Name, anchor.Sha256Fingerprint,
            anchor.Enabled, BuiltIn: false, anchor.CreatedAt));
    }

    /// <summary>
    /// Removes a custom trust anchor. Returns false for an unknown id; the
    /// built in roots carry no numeric id and so can never be targeted here.
    /// </summary>
    public async Task<bool> DeleteAnchorAsync(int id, CancellationToken cancellationToken = default)
    {
        var anchor = await _db.AttestationTrustAnchors
            .FirstOrDefaultAsync(a => a.Id == id, cancellationToken);
        if (anchor == null)
            return false;

        _db.AttestationTrustAnchors.Remove(anchor);
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Removed custom {Format} attestation trust anchor '{Name}' ({Fingerprint})",
            anchor.Format, anchor.Name, anchor.Sha256Fingerprint);
        return true;
    }

    private static DeviceAttestationProfileSummary ToSummary(
        DeviceAttestationProfile profile, int allowlistCount) =>
        new(profile.Id, profile.TemplateId, profile.Enabled, profile.GateMode,
            profile.CsrIdentifierBinding, allowlistCount, profile.CreatedAt, profile.UpdatedAt);

    private static DeviceAllowlistEntrySummary ToSummary(DeviceAllowlistEntry entry) =>
        new(entry.Id, entry.ProfileId, entry.IdentifierValue, entry.Note, entry.CreatedAt);
}

/// <summary>One device attestation profile row for the dashboard list.</summary>
public sealed record DeviceAttestationProfileSummary(
    int Id,
    string TemplateId,
    bool Enabled,
    string GateMode,
    string CsrIdentifierBinding,
    int AllowlistCount,
    DateTime CreatedAt,
    DateTime? UpdatedAt);

/// <summary>One allowlisted device for the profile's allowlist editor.</summary>
public sealed record DeviceAllowlistEntrySummary(
    int Id,
    int ProfileId,
    string IdentifierValue,
    string? Note,
    DateTime CreatedAt);

/// <summary>
/// One trust anchor row for the dashboard. <see cref="Id"/> is null for a
/// built in root, which carries no database row and cannot be deleted.
/// </summary>
public sealed record TrustAnchorSummary(
    int? Id,
    string Format,
    string Name,
    string Sha256Fingerprint,
    bool Enabled,
    bool BuiltIn,
    DateTime? CreatedAt);

/// <summary>How a profile create or update ended.</summary>
public enum DeviceProfileOutcome
{
    /// <summary>The profile was created or updated.</summary>
    Saved,

    /// <summary>No profile has this id.</summary>
    NotFound,

    /// <summary>A profile already exists for the template (one per template).</summary>
    DuplicateTemplate,
}

/// <summary>Result of a profile create or update.</summary>
public sealed record DeviceProfileResult(
    DeviceProfileOutcome Outcome,
    DeviceAttestationProfileSummary? Profile);

/// <summary>How an allowlist add or update ended.</summary>
public enum AllowlistOutcome
{
    /// <summary>The entry was added or updated.</summary>
    Saved,

    /// <summary>No profile has this id.</summary>
    ProfileNotFound,

    /// <summary>No allowlist entry has this id.</summary>
    EntryNotFound,

    /// <summary>The device is already listed on this profile.</summary>
    Duplicate,
}

/// <summary>Result of an allowlist add or update.</summary>
public sealed record AllowlistEntryResult(
    AllowlistOutcome Outcome,
    DeviceAllowlistEntrySummary? Entry);

/// <summary>How a trust anchor add or delete ended.</summary>
public enum AnchorOutcome
{
    /// <summary>The anchor was added.</summary>
    Saved,

    /// <summary>No custom anchor has this id.</summary>
    NotFound,

    /// <summary>An anchor with the same certificate is already stored.</summary>
    Duplicate,

    /// <summary>The certificate is already a built in root, so adding it is redundant.</summary>
    DuplicateBuiltIn,

    /// <summary>The format is not one this build can verify.</summary>
    UnsupportedFormat,

    /// <summary>The pasted text did not parse as a PEM certificate.</summary>
    InvalidPem,
}

/// <summary>
/// Result of a trust anchor add. <see cref="Detail"/> carries the parse error
/// on <see cref="AnchorOutcome.InvalidPem"/>, otherwise null.
/// </summary>
public sealed record AnchorResult(
    AnchorOutcome Outcome,
    TrustAnchorSummary? Anchor,
    string? Detail = null);
