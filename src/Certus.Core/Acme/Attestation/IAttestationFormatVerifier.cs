using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Acme.Attestation;

/// <summary>
/// Verifies one attestation format. The draft deliberately leaves per format
/// verification procedures to the server, so the registry is keyed on the
/// CBOR "fmt" string and each format is a plugin: "apple" ships in v1, "tpm"
/// is a later addition, and an unknown format simply finds no verifier and
/// fails the challenge.
/// </summary>
public interface IAttestationFormatVerifier
{
    /// <summary>The CBOR "fmt" string this verifier handles (e.g. "apple").</summary>
    string Format { get; }

    /// <summary>
    /// Verifies the attestation statement and extracts the attested device
    /// identity. Never throws for a bad attestation: every verification
    /// failure is a result with a client safe detail.
    /// </summary>
    Task<AttestationVerificationResult> VerifyAsync(
        AttestationContext context,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// The inputs to one attestation verification.
/// </summary>
/// <param name="Envelope">The parsed attestation object.</param>
/// <param name="Token">
/// The challenge token. For external attestation authority formats (apple)
/// the freshness nonce is derived from the token alone, not from the RFC
/// 8555 key authorization.
/// </param>
/// <param name="ExpectedIdentifierValue">
/// The order's permanent-identifier value in its raw grammar form. The draft
/// compares identifiers octet for octet, so a value carrying an
/// "/assigner-OID" suffix can only match if the device attests exactly that
/// string; Apple devices attest bare serial and UDID values.
/// </param>
/// <param name="AdditionalTrustAnchors">
/// Administrator managed trust anchors for this format, additive to the
/// roots embedded in the product. This is also how tests inject a synthetic
/// root.
/// </param>
public sealed record AttestationContext(
    AttestationEnvelope Envelope,
    string Token,
    string ExpectedIdentifierValue,
    IReadOnlyList<X509Certificate2> AdditionalTrustAnchors);

/// <summary>
/// Outcome of one attestation verification.
/// </summary>
/// <param name="IsValid">True when the attestation verified and the attested identity matches.</param>
/// <param name="ErrorDetail">Client safe failure detail when not valid.</param>
/// <param name="AttestedIdentifierValue">The attested identifier that matched the order identifier.</param>
/// <param name="AttestedSpkiDer">
/// The DER SubjectPublicKeyInfo of the attested key. Persisted at challenge
/// time and compared against the CSR key at finalize (the three way binding
/// in the draft's security model).
/// </param>
/// <param name="AttestedProperties">
/// Format specific attested facts (for apple: serial number, UDID, sepOS
/// version) for the audit trail and the dashboard.
/// </param>
public sealed record AttestationVerificationResult(
    bool IsValid,
    string? ErrorDetail = null,
    string? AttestedIdentifierValue = null,
    byte[]? AttestedSpkiDer = null,
    IReadOnlyDictionary<string, string>? AttestedProperties = null)
{
    /// <summary>The attestation verified and the attested identity matches the order.</summary>
    public static AttestationVerificationResult Success(
        string attestedIdentifierValue,
        byte[] attestedSpkiDer,
        IReadOnlyDictionary<string, string> attestedProperties) =>
        new(true,
            AttestedIdentifierValue: attestedIdentifierValue,
            AttestedSpkiDer: attestedSpkiDer,
            AttestedProperties: attestedProperties);

    /// <summary>The attestation did not verify; the detail is safe to return to the client.</summary>
    public static AttestationVerificationResult Failure(string detail) => new(false, detail);
}
