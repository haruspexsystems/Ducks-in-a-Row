namespace Certus.Core.Data.Entities;

/// <summary>
/// A certificate record synced from the ADCS CA database.
/// Provides full visibility into ALL certificates issued by the CA,
/// not just those issued through the ACME proxy.
/// Updated periodically by the CertificateSyncService.
/// </summary>
public class SyncedCertificate
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>
    /// The CA request ID — unique identifier from the ADCS database.
    /// </summary>
    public int RequestId { get; set; }

    /// <summary>Certificate serial number (hex string).</summary>
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>Certificate subject DN (e.g., CN=server.example.com).</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>
    /// Subject Alternative Names, comma separated.
    /// E.g., "dns:server.example.com, dns:www.example.com"
    /// </summary>
    public string? SubjectAlternativeNames { get; set; }

    /// <summary>The ADCS certificate template used to issue this cert.</summary>
    public string TemplateName { get; set; } = string.Empty;

    /// <summary>Certificate validity start date.</summary>
    public DateTime NotBefore { get; set; }

    /// <summary>Certificate expiration date.</summary>
    public DateTime NotAfter { get; set; }

    /// <summary>
    /// Certificate status: Issued, Pending, Denied, Revoked, Failed.
    /// </summary>
    public string Status { get; set; } = string.Empty;

    /// <summary>The user/entity that requested this certificate.</summary>
    public string? Requestor { get; set; }

    /// <summary>When the certificate request was submitted.</summary>
    public DateTime RequestDate { get; set; }

    /// <summary>When the CA revoked this certificate, or null while it is not revoked.</summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>The CRL reason code the CA recorded (RFC 5280 5.3.1), or null.</summary>
    public int? RevokedReason { get; set; }

    // Cryptographic detail parsed from the certificate's own DER, which the CA
    // view already returns alongside every row, so none of it costs an extra CA
    // round trip. All nullable: a row whose certificate blob was absent or did
    // not decode simply carries none of it.
    //
    // These are exposed on the single certificate detail endpoint only. They are
    // deliberately absent from CertificateSummary, from every list column,
    // filter, and sort key, and from every aggregate. Inventory and reporting by
    // key algorithm is a paid tier feature; showing one certificate's own key
    // detail on its own page is what any certificate viewer does.

    /// <summary>
    /// Subject public key algorithm as a short token ("RSA", "ECDSA"), or the
    /// raw algorithm OID when it is not one we name.
    /// </summary>
    public string? KeyAlgorithm { get; set; }

    /// <summary>Key size in bits, or null when the algorithm has no such measure.</summary>
    public int? KeySizeBits { get; set; }

    /// <summary>
    /// The signature algorithm OID. Stored as the OID, not a resolved name,
    /// because Oid.FriendlyName answers from the Windows OID table and is
    /// locale dependent.
    /// </summary>
    public string? SignatureAlgorithmOid { get; set; }

    /// <summary>Uppercase hex SHA-256 thumbprint (not the SHA-1 one).</summary>
    public string? Sha256Thumbprint { get; set; }

    /// <summary>
    /// Extended key usage OIDs in certificate order, comma separated.
    /// E.g., "1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2".
    /// Null means the certificate carries no EKU extension, which is a
    /// different thing from an empty EKU list.
    /// </summary>
    public string? ExtendedKeyUsageOids { get; set; }

    /// <summary>
    /// The RFC 5280 key usage bit field as the raw X509KeyUsageFlags value,
    /// labelled for display in the dashboard the same way RevokedReason is.
    /// </summary>
    public int? KeyUsage { get; set; }

    /// <summary>
    /// The certificate's own DER encoding, exactly as the CA view's
    /// RawCertificate column returned it, or null on a row that carried no
    /// decodable certificate blob. This is the source for the single
    /// certificate download and copy on the detail page (issue #158).
    ///
    /// Stored rather than fetched from the CA on demand, for three reasons the
    /// live path cannot answer. A revoked certificate is unreachable through
    /// ICertRequest: GetIssuedCertificate reports CR_DISP_REVOKED and returns no
    /// bytes at all, so the certificates an admin most often needs to produce
    /// would be the ones that could not be downloaded. A CA that is briefly
    /// unreachable would take the button down with it even though the page
    /// itself renders from the local inventory. And the copy path needs the PEM
    /// as text in the browser, which would otherwise be a CA round trip per
    /// click.
    ///
    /// Write once, enforced in CertificateSyncService.UpdateEntity: a
    /// certificate's own bytes never legitimately change, so the column is
    /// filled on the first pass that carries a decodable blob and never
    /// reassigned. That also gives free backfill of rows synced before this
    /// column existed, and keeps a fresh array per cycle from being compared
    /// against the stored one on every sync.
    ///
    /// Detail surface only, and more strictly than the fields above: this is
    /// never serialized into any response. The detail DTO carries a boolean
    /// saying whether a download exists, and the bytes leave only through the
    /// two single certificate download endpoints.
    /// </summary>
    public byte[]? RawCertificate { get; set; }

    // The CA's own account of a request that never became a certificate. Also
    // detail endpoint only, and for a second reason on top of the one above:
    // this is text authored outside Ducks and partly influenced by whoever
    // submitted the request, so the fewer responses carrying it the better.

    /// <summary>
    /// The CA's own explanation of what happened to the request, verbatim and
    /// sanitized of control characters. Populated only for Pending, Denied, and
    /// Failed rows; null on everything else. Never reworded by Ducks, and always
    /// rendered as text attributed to the CA.
    /// </summary>
    public string? DispositionMessage { get; set; }

    /// <summary>
    /// The HRESULT the CA recorded against the request, or null. Populated only
    /// alongside <see cref="DispositionMessage"/>; a zero code means success and
    /// is stored as null.
    /// </summary>
    public int? StatusCode { get; set; }

    /// <summary>
    /// The later certificate that appears to have replaced this one, or null.
    /// Inferred locally, never reported by the CA (issue #154): the CA database
    /// does not distinguish a renewal from a fresh issuance, so SupersessionLinker
    /// matches on template plus the normalized name set and takes the later
    /// NotBefore as the replacement. Two teams independently asking the same
    /// template for the same hostname look exactly like a renewal here, which is
    /// why every surface that shows this labels it an observation.
    ///
    /// Recomputed in full on every sync, so a stale link cannot survive a cycle.
    /// A plain nullable id and not a foreign key, matching the RequestId to
    /// AdcsRequestId value bridge: nothing here should acquire a navigation
    /// property or a cascade on a table that is rebuilt from the CA.
    ///
    /// Known limits, all of them consequences of what gets stored rather than of
    /// the matching rule. CertificateDerParser truncates the SAN list at 2000
    /// characters mid entry, so two certificates differing only past that point
    /// key identically. Only dns and ip SANs are stored, so a device attestation
    /// certificate carrying just a PermanentIdentifier otherName keys on its
    /// subject CN instead, which for an Apple device holds the serial and works.
    /// A CN containing an escaped comma splits wrongly, exactly as it already
    /// does on the display path. A template renamed or deleted at the CA can
    /// split a lineage until the rows resync.
    /// </summary>
    public int? SupersededByCertificateId { get; set; }

    /// <summary>When this record was first synced from the CA.</summary>
    public DateTime FirstSyncedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this record was last updated from the CA.</summary>
    public DateTime LastSyncedAt { get; set; } = DateTime.UtcNow;
}
