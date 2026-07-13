namespace Certus.Core.Data.Entities;

/// <summary>
/// An ACME authorization — represents the server's authorization of an account
/// to represent an identifier (domain name).
/// RFC 8555 §7.1.4
/// </summary>
public class AcmeAuthorization
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>Public facing authorization ID used in URLs.</summary>
    public string AuthorizationId { get; set; } = string.Empty;

    /// <summary>FK to the parent order.</summary>
    public int OrderId { get; set; }

    /// <summary>Navigation property to the parent order.</summary>
    public AcmeOrder Order { get; set; } = null!;

    /// <summary>Identifier type (always "dns" for now).</summary>
    public string IdentifierType { get; set; } = "dns";

    /// <summary>Identifier value (the domain name).</summary>
    public string IdentifierValue { get; set; } = string.Empty;

    /// <summary>
    /// Authorization status: pending, valid, invalid, deactivated, expired, revoked.
    /// RFC 8555 §7.1.6
    /// </summary>
    public string Status { get; set; } = "pending";

    /// <summary>Whether this is a wildcard authorization.</summary>
    public bool Wildcard { get; set; }

    /// <summary>When this authorization was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this authorization expires.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>Navigation property to challenges.</summary>
    public List<AcmeChallenge> Challenges { get; set; } = new();
}
