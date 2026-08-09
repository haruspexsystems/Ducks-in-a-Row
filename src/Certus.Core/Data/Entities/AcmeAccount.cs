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
    /// Account status. RFC 8555 §7.1.6 defines "valid", "deactivated", and
    /// "revoked", but only the first two are ever written here: an account is
    /// created valid, and dashboard deactivation is the single mutation.
    /// Nothing revokes an account, so the dashboard offers no such filter.
    /// Add "revoked" back to this list alongside the code that writes it.
    /// </summary>
    public string Status { get; set; } = "valid";

    /// <summary>
    /// Whether the client agreed to the terms of service.
    /// </summary>
    public bool TermsOfServiceAgreed { get; set; }

    /// <summary>
    /// The EAB credential this account is bound to (RFC 8555 §7.3.4), or null
    /// for an account without a binding: registered before EAB existed, or
    /// while enforcement was off or optional. Unbound accounts are
    /// grandfathered; the dashboard flags them.
    /// </summary>
    public int? ExternalAccountCredentialId { get; set; }

    /// <summary>Navigation to the bound EAB credential.</summary>
    public EabCredential? ExternalAccountCredential { get; set; }

    /// <summary>
    /// The externalAccountBinding JWS exactly as received at binding time,
    /// echoed back in the account object (RFC 8555 §7.1.2). After a key
    /// rollover this still holds the registration time account key by design:
    /// it is the historical registration proof, not the current key.
    /// </summary>
    public string? EabJwsJson { get; set; }

    /// <summary>When this account was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this account was last updated.</summary>
    public DateTime? UpdatedAt { get; set; }
}
