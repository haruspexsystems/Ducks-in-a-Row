namespace Certus.Core.Data.Entities;

/// <summary>
/// An external account binding credential (RFC 8555 §7.3.4): a key identifier
/// plus a MAC secret an administrator hands to an ACME client so its account
/// registration can be bound to a known identity. Credentials are multi use:
/// one credential may bind any number of ACME accounts until it is revoked or
/// expires. Revocation is terminal and rows are never hard deleted, because
/// bound accounts keep a foreign key to the credential for attribution.
/// The MAC secret is stored only in protected form and is never returned by
/// any API after creation; losing it means regenerating it.
/// </summary>
public class EabCredential
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>
    /// The key identifier the ACME client sends as the inner JWS "kid"
    /// (RFC 8555 §7.3.4). 32 lowercase hex characters, unique.
    /// </summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>Administrator facing label, for example "web servers".</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// The MAC secret, encrypted at rest by <c>ISecretProtector</c>. The
    /// plaintext (base64url, 32 random bytes) exists only in the create and
    /// regenerate responses.
    /// </summary>
    public string SecretProtected { get; set; } = string.Empty;

    /// <summary>Credential status: "active" or "revoked". Revoked is terminal.</summary>
    public string Status { get; set; } = "active";

    /// <summary>
    /// Optional expiry (UTC). An expired credential rejects new registrations
    /// and suspends new orders from its bound accounts, exactly like a
    /// revoked one, but recovers by itself if the date is moved forward.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// The credential's domain namespace as a JSON string array of normalized
    /// entries (same semantics as the allowed domain list: an entry covers
    /// itself and every subdomain). Empty array means no extra restriction.
    /// Stored from day one; enforcement arrives with the namespace feature.
    /// </summary>
    public string NamespacesJson { get; set; } = "[]";

    /// <summary>
    /// Optional linked Active Directory principal (SDDL SID), for display
    /// and audit only: nothing enforces against it. The name and type are
    /// captured at link time, so the row stays readable when the directory
    /// is unreachable or the principal is later deleted.
    /// </summary>
    public string? AdPrincipalSid { get; set; }

    /// <summary>The linked principal's account name, as resolved at link time.</summary>
    public string? AdPrincipalName { get; set; }

    /// <summary>
    /// The linked principal's type at link time: "user", "computer",
    /// "group", or "service account".
    /// </summary>
    public string? AdPrincipalType { get; set; }

    /// <summary>When this credential was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this credential was last changed.</summary>
    public DateTime? UpdatedAt { get; set; }

    /// <summary>When this credential was revoked.</summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// When the secret was last regenerated. Regeneration keeps the key id
    /// and configuration but invalidates every copy of the old secret.
    /// </summary>
    public DateTime? SecretRegeneratedAt { get; set; }
}
