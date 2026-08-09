namespace Certus.Core.Data.Entities;

/// <summary>
/// An administrator managed attestation trust anchor: a CA certificate that
/// attestation chains of one format may verify against, in addition to the
/// roots embedded in the product. Custom anchors are how a vendor root
/// rotation is bridged before a product update ships the new pin, and how
/// tests inject a synthetic root. Rows are additive only: the embedded
/// roots can never be removed through this table.
/// </summary>
public class AttestationTrustAnchor
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>
    /// The attestation format this anchor applies to, as the CBOR "fmt"
    /// string of the attestation object ("apple"; later "tpm").
    /// </summary>
    public string Format { get; set; } = string.Empty;

    /// <summary>Administrator facing label.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The anchor certificate, PEM encoded.</summary>
    public string CertificatePem { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 of the certificate's DER bytes, lowercase hex, unique.
    /// Dedupes re uploads and identifies the anchor in logs without
    /// reparsing the PEM.
    /// </summary>
    public string Sha256Fingerprint { get; set; } = string.Empty;

    /// <summary>Whether the anchor participates in chain verification.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>When this anchor was added.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
