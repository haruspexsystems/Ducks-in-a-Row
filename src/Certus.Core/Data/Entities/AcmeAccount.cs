namespace Certus.Core.Data.Entities;

/// <summary>
/// An ACME account registered with this server.
/// Each account is identified by its public key (JWK).
/// RFC 8555 §7.1.2
/// </summary>
public class AcmeAccount
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>
    /// Public facing account ID used in URLs.
    /// Format: URL safe random string.
    /// </summary>
    public string AccountId { get; set; } = string.Empty;

    /// <summary>
    /// The account's public key in JWK JSON format.
    /// Used to verify JWS signatures on subsequent requests.
    /// </summary>
    public string JwkJson { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 thumbprint of the JWK (RFC 7638).
    /// Used as a unique key to find an account by its public key.
    /// </summary>
    public string JwkThumbprint { get; set; } = string.Empty;

    /// <summary>
    /// Contact URIs (typically mailto: addresses).
    /// Stored as JSON array, e.g. ["mailto:admin@example.com"].
    /// </summary>
    public string? ContactJson { get; set; }

    /// <summary>
    /// Account status: "valid", "deactivated", or "revoked".
    /// RFC 8555 §7.1.6
    /// </summary>
    public string Status { get; set; } = "valid";

    /// <summary>
    /// Whether the client agreed to the terms of service.
    /// </summary>
    public bool TermsOfServiceAgreed { get; set; }

    /// <summary>When this account was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this account was last updated.</summary>
    public DateTime? UpdatedAt { get; set; }
}
