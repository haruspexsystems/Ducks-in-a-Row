namespace Certus.Core.Acme.Attestation;

/// <summary>
/// A trust anchor embedded in the product and pinned in code. The admin trust
/// anchor view reports these as read only: they cannot be added or removed
/// through the API. A vendor root rotation is bridged with an additive custom
/// anchor row, then a pin update in a patch release retires the old root.
/// </summary>
public sealed record BuiltInAttestationAnchor(
    string Format,
    string Name,
    string Sha256Fingerprint);

/// <summary>
/// The built in attestation roots, one per shipped format. Each format's
/// verifier embeds and pins its own copy of the root (see
/// <see cref="AppleAttestationVerifier"/>); this list exists only so the admin
/// trust anchor view can show what is already trusted without an operator
/// adding anything. When a new format ships, add its built in root here.
/// </summary>
public static class BuiltInAttestationAnchors
{
    /// <summary>Every built in root, in format then name order.</summary>
    public static readonly IReadOnlyList<BuiltInAttestationAnchor> All =
    [
        new(AppleAttestationVerifier.FormatName,
            "Apple Enterprise Attestation Root CA",
            AppleAttestationOids.RootSha256Fingerprint),
    ];

    /// <summary>Whether a DER SHA-256 fingerprint (lowercase hex) names a built in root.</summary>
    public static bool ContainsFingerprint(string sha256Fingerprint) =>
        All.Any(a => string.Equals(
            a.Sha256Fingerprint, sha256Fingerprint, StringComparison.OrdinalIgnoreCase));
}
