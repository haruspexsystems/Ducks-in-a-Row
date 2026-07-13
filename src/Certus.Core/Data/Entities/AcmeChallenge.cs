namespace Certus.Core.Data.Entities;

/// <summary>
/// An ACME challenge — a specific method for the client to prove control
/// of an identifier (e.g., HTTP-01, DNS-01, TLS-ALPN-01).
/// RFC 8555 §7.1.5
/// </summary>
public class AcmeChallenge
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>Public facing challenge ID used in URLs.</summary>
    public string ChallengeId { get; set; } = string.Empty;

    /// <summary>FK to the parent authorization.</summary>
    public int AuthorizationId { get; set; }

    /// <summary>Navigation property to the parent authorization.</summary>
    public AcmeAuthorization Authorization { get; set; } = null!;

    /// <summary>
    /// Challenge type: "http-01", "dns-01", or "tls-alpn-01".
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// The challenge token — a random URL safe string.
    /// For HTTP-01, this becomes part of the .well-known URL.
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Challenge status: pending, processing, valid, invalid.
    /// RFC 8555 §7.1.6
    /// </summary>
    public string Status { get; set; } = "pending";

    /// <summary>When the challenge was successfully validated.</summary>
    public DateTime? ValidatedAt { get; set; }

    /// <summary>
    /// Number of validation attempts so far. A transient transport failure increments this
    /// and leaves the challenge in "processing" so the background worker retries it, up to a
    /// configured ceiling, rather than marking it invalid on the first network blip
    /// (RFC 8555 §8.2).
    /// </summary>
    public int ValidationAttempts { get; set; }

    /// <summary>When the most recent validation attempt ran.</summary>
    public DateTime? LastAttemptAt { get; set; }

    /// <summary>ACME error JSON if the challenge failed.</summary>
    public string? ErrorJson { get; set; }
}
