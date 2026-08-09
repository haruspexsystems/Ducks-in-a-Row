namespace Certus.Core.Acme.Models;

/// <summary>
/// The ACME identifier types this server knows, in one place so callers do
/// not scatter string comparisons. "dns" is RFC 8555; "permanent-identifier"
/// and "hardware-module" come from draft-ietf-acme-device-attest-08, which
/// registers both in the IANA ACME identifier types registry.
/// </summary>
public static class AcmeIdentifierTypes
{
    /// <summary>RFC 8555 dns identifier (a domain name).</summary>
    public const string Dns = "dns";

    /// <summary>
    /// Device identity identifier (RFC 4043 PermanentIdentifier): a device
    /// serial number or similar, optionally qualified by an assigner OID.
    /// </summary>
    public const string PermanentIdentifier = "permanent-identifier";

    /// <summary>
    /// Hardware cryptographic module identifier (RFC 4108). Recognized
    /// vocabulary only: this server does not take orders for it, and no
    /// verifier format needs it until the TPM work lands.
    /// </summary>
    public const string HardwareModule = "hardware-module";

    /// <summary>Whether this server can take orders for the type.</summary>
    public static bool IsSupported(string type) => type is Dns or PermanentIdentifier;

    /// <summary>
    /// Whether the type names a device rather than a network name, which
    /// routes it through attestation instead of the network challenges.
    /// </summary>
    public static bool IsDeviceType(string type) => type is PermanentIdentifier or HardwareModule;
}
