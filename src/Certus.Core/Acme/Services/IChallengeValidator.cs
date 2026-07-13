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
    /// <param name="domain">The domain being validated.</param>
    /// <param name="token">The challenge token.</param>
    /// <param name="accountThumbprint">The account's JWK thumbprint for key authorization.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if validation succeeds, false otherwise.</returns>
    Task<ChallengeValidationResult> ValidateAsync(
        string domain,
        string token,
        string accountThumbprint,
        CancellationToken cancellationToken = default);
}

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
    /// <summary>The client's response was correct.</summary>
    public static ChallengeValidationResult Success() => new(true);

    /// <summary>The client's response was genuinely wrong; do not retry.</summary>
    public static ChallengeValidationResult Invalid(string detail) => new(false, detail);

    /// <summary>A transport error prevented validation; the worker may retry.</summary>
    public static ChallengeValidationResult TransientFailure(string detail) =>
        new(false, detail, Transient: true);
}
