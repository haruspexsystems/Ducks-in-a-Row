namespace Certus.Core.Data.Entities;

/// <summary>
/// An ACME certificate order.
/// Tracks the lifecycle from request through challenge validation to certificate issuance.
/// RFC 8555 §7.1.3
/// </summary>
public class AcmeOrder
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>Public facing order ID used in URLs.</summary>
    public string OrderId { get; set; } = string.Empty;

    /// <summary>FK to the account that created this order.</summary>
    public int AccountId { get; set; }

    /// <summary>Navigation property to the owning account.</summary>
    public AcmeAccount Account { get; set; } = null!;

    /// <summary>
    /// Order status: pending, ready, processing, valid, invalid.
    /// RFC 8555 §7.1.6
    /// </summary>
    public string Status { get; set; } = "pending";

    /// <summary>
    /// The ADCS certificate template for this order.
    /// </summary>
    public string TemplateId { get; set; } = string.Empty;

    /// <summary>
    /// Requested identifiers as JSON array, e.g. [{"type":"dns","value":"example.com"}].
    /// </summary>
    public string IdentifiersJson { get; set; } = "[]";

    /// <summary>Optional requested notBefore date.</summary>
    public DateTime? NotBefore { get; set; }

    /// <summary>Optional requested notAfter date.</summary>
    public DateTime? NotAfter { get; set; }

    /// <summary>
    /// The base64url-encoded DER CSR submitted during finalization.
    /// </summary>
    public string? CsrDer { get; set; }

    /// <summary>
    /// The ADCS request ID returned when the CSR was submitted.
    /// </summary>
    public int? AdcsRequestId { get; set; }

    /// <summary>
    /// The certificate ID (used in the certificate download URL).
    /// Set when the order transitions to "valid". This is a denormalized mirror of
    /// <see cref="AcmeCertificate.CertificateId"/>; the authoritative link is the FK
    /// AcmeCertificate.OrderId. Nothing enforces that the two copies stay in sync.
    /// </summary>
    public string? CertificateId { get; set; }

    /// <summary>
    /// The serialized <c>AcmeError</c> problem document saying why the order is
    /// invalid, and null on every order that has not failed. Only ever written
    /// alongside "invalid" and committed with it.
    ///
    /// <c>OrderService.ToResponse</c> projects it into the order object's error
    /// member (RFC 8555 section 7.1.3), so this is client facing text and not only
    /// an operator's record. One case is deliberately null: an order invalidated
    /// because a challenge failed carries its reason on the authorization instead,
    /// which is where section 7.1.6 sends the client.
    /// </summary>
    public string? ErrorJson { get; set; }

    /// <summary>
    /// The canonical ARI identifier of the certificate this order replaces
    /// (RFC 9773 §5), null when the client named none. A string rather than a
    /// foreign key because the static ToResponse must reflect it with no
    /// database access, and because it is stored only after
    /// ResolveReplacesAsync verified it octet for octet against the stored
    /// leaf, so it is that certificate's stable identity.
    /// </summary>
    public string? ReplacesCertificateId { get; set; }

    /// <summary>When this order was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When this order expires. Expired orders transition to "invalid".
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>Navigation property to authorizations.</summary>
    public List<AcmeAuthorization> Authorizations { get; set; } = new();
}
