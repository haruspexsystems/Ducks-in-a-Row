namespace Certus.Core.Data.Entities;

/// <summary>
/// One device admitted by a template's device attestation profile. The
/// identifier value is the full ACME permanent-identifier value in its raw
/// grammar form (value with an optional "/assigner-OID" suffix) and is
/// compared octet for octet against order identifiers, per
/// draft-ietf-acme-device-attest-08 section 3.
/// </summary>
public class DeviceAllowlistEntry
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>FK to the owning profile.</summary>
    public int ProfileId { get; set; }

    /// <summary>Navigation property to the owning profile.</summary>
    public DeviceAttestationProfile Profile { get; set; } = null!;

    /// <summary>
    /// The admitted permanent-identifier value, raw grammar form. For Apple
    /// devices this is the serial number or the UDID, whichever the MDM
    /// deploys as the client identifier.
    /// </summary>
    public string IdentifierValue { get; set; } = string.Empty;

    /// <summary>Optional administrator note (asset tag, owner, location).</summary>
    public string? Note { get; set; }

    /// <summary>When this entry was added.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
