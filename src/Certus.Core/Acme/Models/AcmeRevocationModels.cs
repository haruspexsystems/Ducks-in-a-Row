using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// Request to revoke a certificate.
/// RFC 8555 §7.6
/// </summary>
public sealed class RevokeCertRequest
{
    /// <summary>
    /// The certificate to revoke as base64url DER (no PEM armor).
    /// </summary>
    [JsonPropertyName("certificate")]
    public string Certificate { get; set; } = string.Empty;

    /// <summary>
    /// Optional CRL revocation reason code (RFC 5280 §5.3.1). Absent means "unspecified" (0).
    /// </summary>
    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Reason { get; set; }
}
