namespace Certus.Core.Acme.Attestation;

/// <summary>
/// The single home for the Apple attestation constants. Every value here was
/// recorded in tools/DeviceAttestProbe/README.md on 2026-07-17, cross checked
/// between step-ca source and Apple's published PKI; if a live device ever
/// disagrees with the verifier, re-verify against that record first, then
/// correct it here in one place (the synthetic tests share these constants,
/// so they follow automatically).
/// </summary>
public static class AppleAttestationOids
{
    /// <summary>Leaf extension carrying the device serial number.</summary>
    public const string SerialNumber = "1.2.840.113635.100.8.9.1";

    /// <summary>Leaf extension carrying the device UDID.</summary>
    public const string Udid = "1.2.840.113635.100.8.9.2";

    /// <summary>Leaf extension carrying the sepOS version.</summary>
    public const string SepOsVersion = "1.2.840.113635.100.8.10.2";

    /// <summary>
    /// Leaf extension carrying the freshness nonce: SHA-256 over the raw
    /// ACME challenge token string bytes (the draft's external attestation
    /// authority pattern, where attToBeSigned is the token alone rather
    /// than the key authorization).
    /// </summary>
    public const string Nonce = "1.2.840.113635.100.8.11.1";

    /// <summary>
    /// SHA-256 over the DER bytes of the Apple Enterprise Attestation Root
    /// CA (serial 42C0C2BB2C727C5C5EABF6F1A66F1FAC5D798737, valid 2022-02-16
    /// to 2047-02-20), lowercase hex. The certificate is embedded as the
    /// resource next to this file and checked against this pin at load,
    /// failing closed on mismatch. When Apple rotates the root, the bridge
    /// is a custom trust anchor row, followed by a pin update in a patch
    /// release.
    /// </summary>
    public const string RootSha256Fingerprint =
        "ccf59ef8fcb3017d97f8b5fa6fa90e7a3f9283f76b55ac6cf6eda8b8b949f05b";
}
