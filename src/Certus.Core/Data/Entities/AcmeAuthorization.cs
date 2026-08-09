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

    /// <summary>Identifier type ("dns", or "permanent-identifier" for device orders).</summary>
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

    /// <summary>
    /// The attested device public key (base64 DER SubjectPublicKeyInfo), set
    /// when a device-attest-01 challenge validates. Finalize compares the CSR
    /// public key against this value, closing the draft's three way binding:
    /// the key that was attested is the key being certified. Null for dns
    /// authorizations.
    /// </summary>
    public string? AttestedSpki { get; set; }

    /// <summary>
    /// The attestation format that validated this authorization ("apple"),
    /// set together with AttestedSpki.
    /// </summary>
    public string? AttestationFormat { get; set; }

    /// <summary>
    /// Attested device properties as JSON (serial, UDID, and similar, format
    /// specific), for display and audit. Set together with AttestedSpki.
    /// </summary>
    public string? AttestedPropertiesJson { get; set; }

    /// <summary>When this authorization was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this authorization expires.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>Navigation property to challenges.</summary>
    public List<AcmeChallenge> Challenges { get; set; } = new();
}
