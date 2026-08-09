using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Answers whether a template takes device-attest-01 orders and whether a
/// specific device is admitted. Reads the profile tables directly on every
/// check, so an administrator change applies to the next request with no
/// cache to invalidate (a scoped service over the scoped DbContext).
/// Every unknown state answers closed: no profile, a disabled profile, and
/// a device missing from the allowlist all refuse.
/// </summary>
public sealed class DeviceAttestationPolicyService
{
    private readonly CertusDbContext _db;

    public DeviceAttestationPolicyService(CertusDbContext db)
    {
        _db = db;
    }

    /// <summary>Loads the profile for a template, or null when none exists.</summary>
    public Task<DeviceAttestationProfile?> GetProfileAsync(
        string templateId, CancellationToken cancellationToken = default) =>
        _db.DeviceAttestationProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.TemplateId == templateId, cancellationToken);

    /// <summary>
    /// Checks whether the device named by <paramref name="identifierValue"/>
    /// (raw permanent-identifier grammar form) may order under the template.
    /// </summary>
    public async Task<DeviceAttestationPolicyOutcome> CheckAsync(
        string templateId, string identifierValue, CancellationToken cancellationToken = default)
    {
        var profile = await GetProfileAsync(templateId, cancellationToken);
        if (profile == null)
            return DeviceAttestationPolicyOutcome.NoProfile;
        if (!profile.Enabled)
            return DeviceAttestationPolicyOutcome.Disabled;

        // Only the exact "open" mode admits unlisted devices. Any other stored
        // value, including a future or hand edited one, behaves as "allowlist",
        // so the gate fails closed.
        if (profile.GateMode == DeviceAttestationGateModes.Open)
            return DeviceAttestationPolicyOutcome.AllowedOpen;

        // Octet exact compare, per the draft's identifier comparison rule. The
        // SQL equality runs under SQLite's default BINARY collation, which
        // compares bytes, so a case or length lookalike is never admitted.
        var listed = await _db.DeviceAllowlistEntries
            .AsNoTracking()
            .AnyAsync(
                e => e.ProfileId == profile.Id && e.IdentifierValue == identifierValue,
                cancellationToken);

        return listed
            ? DeviceAttestationPolicyOutcome.AllowedListed
            : DeviceAttestationPolicyOutcome.NotOnAllowlist;
    }
}

/// <summary>Outcome of a device attestation policy check.</summary>
public enum DeviceAttestationPolicyOutcome
{
    /// <summary>The template has no device attestation profile; device orders are not offered.</summary>
    NoProfile,

    /// <summary>The template's profile exists but is disabled; device orders refuse.</summary>
    Disabled,

    /// <summary>The profile is in open (observation) mode; any attested device is admitted.</summary>
    AllowedOpen,

    /// <summary>The device is on the allowlist.</summary>
    AllowedListed,

    /// <summary>The profile is in allowlist mode and the device is not listed.</summary>
    NotOnAllowlist
}
