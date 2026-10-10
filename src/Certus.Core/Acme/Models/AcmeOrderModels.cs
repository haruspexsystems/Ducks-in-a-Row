using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// Request to create a new ACME order.
/// RFC 8555 §7.4
/// </summary>
public sealed class NewOrderRequest
{
    [JsonPropertyName("identifiers")]
    public AcmeIdentifier[] Identifiers { get; set; } = Array.Empty<AcmeIdentifier>();

    [JsonPropertyName("notBefore")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NotBefore { get; set; }

    [JsonPropertyName("notAfter")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NotAfter { get; set; }

    // RFC 9773 §5: the ARI identifier of the certificate this order replaces.
    [JsonPropertyName("replaces")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Replaces { get; set; }
}

/// <summary>
/// ACME order response object.
/// RFC 8555 §7.1.3
/// </summary>
public sealed class OrderResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("expires")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Expires { get; set; }

    [JsonPropertyName("identifiers")]
    public AcmeIdentifier[] Identifiers { get; set; } = Array.Empty<AcmeIdentifier>();

    [JsonPropertyName("notBefore")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NotBefore { get; set; }

    [JsonPropertyName("notAfter")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NotAfter { get; set; }

    /// <summary>
    /// The ARI identifier of the certificate this order replaces. RFC 9773 §5
    /// requires a server that accepted the field to reflect it in every
    /// response for the order.
    /// </summary>
    [JsonPropertyName("replaces")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Replaces { get; set; }

    /// <summary>
    /// URLs of the authorizations the client must complete.
    /// </summary>
    [JsonPropertyName("authorizations")]
    public string[] Authorizations { get; set; } = Array.Empty<string>();

    /// <summary>
    /// URL to submit the CSR to finalize the order.
    /// </summary>
    [JsonPropertyName("finalize")]
    public string Finalize { get; set; } = string.Empty;

    /// <summary>
    /// URL to download the certificate (only present when status is "valid").
    /// </summary>
    [JsonPropertyName("certificate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Certificate { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeError? Error { get; set; }
}

/// <summary>
/// Account orders list response: the URLs of every order belonging to an account.
/// RFC 8555 §7.1.2.1
/// </summary>
public sealed class OrdersListResponse
{
    [JsonPropertyName("orders")]
    public string[] Orders { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Request to finalize an order by submitting a CSR.
/// RFC 8555 §7.4
/// </summary>
public sealed class FinalizeRequest
{
    /// <summary>
    /// Base64url-encoded DER-format PKCS#10 CSR.
    /// </summary>
    [JsonPropertyName("csr")]
    public string Csr { get; set; } = string.Empty;
}
