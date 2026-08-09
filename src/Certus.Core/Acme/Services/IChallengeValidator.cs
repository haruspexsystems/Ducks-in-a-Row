namespace Certus.Core.Acme.Services;

/// <summary>
/// Validates an ACME challenge by checking the client's provisioned response.
/// Different implementations for each challenge type (HTTP-01, DNS-01, TLS-ALPN-01).
/// </summary>
public interface IChallengeValidator
{
    /// <summary>
    /// The challenge type this validator handles (e.g., "http-01").
    /// </summary>
    string ChallengeType { get; }

    /// <summary>
    /// Validates the challenge by checking the client's provisioned response.
    /// </summary>
    /// <param name="context">The inputs describing the challenge being validated.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    Task<ChallengeValidationResult> ValidateAsync(
        ChallengeValidationContext context,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// The inputs to a challenge validation attempt, carried as a record so challenge types
/// with additional inputs (a posted attestation payload, template scoped policy) can be
/// added without changing every validator's signature.
/// </summary>
/// <param name="IdentifierType">The ACME identifier type of the authorization (e.g., "dns").</param>
/// <param name="IdentifierValue">The identifier value being validated. For dns identifiers this is the domain.</param>
/// <param name="Token">The challenge token.</param>
/// <param name="AccountThumbprint">The account's JWK thumbprint for key authorization.</param>
/// <param name="TemplateId">The certificate template of the order this challenge belongs to.</param>
/// <param name="ChallengePayload">
/// The body the client POSTed to the challenge URL, for challenge types that carry one
/// (device-attest-01 posts an attestation object). Null for the network based challenge
/// types, which never read a payload.
/// </param>
public sealed record ChallengeValidationContext(
    string IdentifierType,
    string IdentifierValue,
    string Token,
    string AccountThumbprint,
    string TemplateId,
    string? ChallengePayload = null);

/// <summary>
/// Result of a challenge validation attempt.
/// </summary>
/// <param name="IsValid">True when the client's response was correct.</param>
/// <param name="ErrorDetail">Human readable failure detail when not valid.</param>
/// <param name="Transient">
/// True when the failure was a transport error (connection refused, DNS timeout, TLS reset)
/// rather than a genuine incorrect response. The background worker keeps a transient
/// challenge in "processing" and retries it, per RFC 8555 §8.2, instead of marking it
/// invalid on the first network blip.
/// </param>
public sealed record ChallengeValidationResult(
    bool IsValid,
    string? ErrorDetail = null,
    bool Transient = false)
{
    /// <summary>
    /// The ACME error type URN for the failure, when the challenge type
    /// defines a more specific one than the worker's default
    /// (device-attest-01 fails with badAttestationStatement). Null means
    /// the worker picks incorrectResponse or connection as before.
    /// </summary>
    public string? ErrorType { get; init; }

    /// <summary>
    /// The attested device identity on a successful device-attest-01
    /// validation; the worker copies it onto the authorization so finalize
    /// can bind the CSR key to the attested key. Null for every other
    /// challenge type.
    /// </summary>
    public AttestedDeviceData? Attested { get; init; }

    /// <summary>The client's response was correct.</summary>
    public static ChallengeValidationResult Success() => new(true);

    /// <summary>The client's attestation was correct; carry the attested identity.</summary>
    public static ChallengeValidationResult Success(AttestedDeviceData attested) =>
        new(true) { Attested = attested };

    /// <summary>The client's response was genuinely wrong; do not retry.</summary>
    public static ChallengeValidationResult Invalid(string detail) => new(false, detail);

    /// <summary>A genuinely wrong response with a challenge type specific error type.</summary>
    public static ChallengeValidationResult Invalid(string detail, string errorType) =>
        new(false, detail) { ErrorType = errorType };

    /// <summary>A transport error prevented validation; the worker may retry.</summary>
    public static ChallengeValidationResult TransientFailure(string detail) =>
        new(false, detail, Transient: true);
}

/// <summary>
/// The attested device identity extracted by a successful device-attest-01
/// validation, in the storage shapes of the AcmeAuthorization columns.
/// </summary>
/// <param name="SpkiBase64">Base64 (standard, not base64url) DER SubjectPublicKeyInfo of the attested key.</param>
/// <param name="Format">The attestation format that verified (e.g. "apple").</param>
/// <param name="PropertiesJson">Format specific attested facts as a JSON object, or null when none.</param>
public sealed record AttestedDeviceData(
    string SpkiBase64,
    string Format,
    string? PropertiesJson);
