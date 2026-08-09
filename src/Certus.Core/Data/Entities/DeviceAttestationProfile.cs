namespace Certus.Core.Data.Entities;

/// <summary>
/// Per template policy for ACME device-attest-01 issuance
/// (draft-ietf-acme-device-attest-08). A template with no profile does not
/// accept permanent-identifier orders at all, so creating a profile is the
/// explicit act that turns the feature on for a template, and deleting the
/// profile turns it off again. The gate fails closed by design: the default
/// mode admits only devices on the allowlist.
/// </summary>
public class DeviceAttestationProfile
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>
    /// The ACME template this profile applies to (the canonical template
    /// name, the same value AcmeOrder.TemplateId carries). One profile per
    /// template.
    /// </summary>
    public string TemplateId { get; set; } = string.Empty;

    /// <summary>
    /// Whether the profile is active. A disabled profile refuses device
    /// orders exactly like a missing one, but keeps its allowlist so it can
    /// be re enabled without re entry.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Gate mode: "allowlist" admits only devices on the allowlist (the
    /// default), "open" admits any device that passes attestation (an
    /// explicit observation mode). Any other stored value behaves as
    /// "allowlist", so the gate fails closed.
    /// </summary>
    public string GateMode { get; set; } = DeviceAttestationGateModes.Allowlist;

    /// <summary>
    /// How the finalize CSR must carry the device identifier: "cn-or-san"
    /// (default; the subject CN or a PermanentIdentifier SAN must match),
    /// "san-required" (strict draft mode; the PermanentIdentifier SAN must
    /// be present and match), or "none" (privacy mode; the CSR must not name
    /// the identifier at all).
    /// </summary>
    public string CsrIdentifierBinding { get; set; } = CsrIdentifierBindingModes.CnOrSan;

    /// <summary>When this profile was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this profile was last changed.</summary>
    public DateTime? UpdatedAt { get; set; }

    /// <summary>Navigation property to the allowlist entries.</summary>
    public List<DeviceAllowlistEntry> AllowlistEntries { get; set; } = new();
}

/// <summary>
/// The valid <see cref="DeviceAttestationProfile.GateMode"/> values.
/// </summary>
public static class DeviceAttestationGateModes
{
    /// <summary>Only devices on the allowlist are admitted (the default).</summary>
    public const string Allowlist = "allowlist";

    /// <summary>Any device that passes attestation is admitted (observation mode).</summary>
    public const string Open = "open";

    /// <summary>Whether the string is a recognized gate mode.</summary>
    public static bool IsValid(string mode) => mode is Allowlist or Open;
}

/// <summary>
/// The valid <see cref="DeviceAttestationProfile.CsrIdentifierBinding"/> values.
/// </summary>
public static class CsrIdentifierBindingModes
{
    /// <summary>The CSR subject CN or a PermanentIdentifier SAN must carry the identifier.</summary>
    public const string CnOrSan = "cn-or-san";

    /// <summary>The CSR must carry the identifier as a PermanentIdentifier SAN.</summary>
    public const string SanRequired = "san-required";

    /// <summary>The CSR must not name the identifier at all (privacy mode).</summary>
    public const string None = "none";

    /// <summary>Whether the string is a recognized binding mode.</summary>
    public static bool IsValid(string mode) => mode is CnOrSan or SanRequired or None;
}
