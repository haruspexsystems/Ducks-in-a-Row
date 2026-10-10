using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// ACME directory object — the entry point for ACME clients.
/// RFC 8555 §7.1.1
/// </summary>
public sealed class AcmeDirectory
{
    [JsonPropertyName("newNonce")]
    public string NewNonce { get; set; } = string.Empty;

    [JsonPropertyName("newAccount")]
    public string NewAccount { get; set; } = string.Empty;

    [JsonPropertyName("newOrder")]
    public string NewOrder { get; set; } = string.Empty;

    // RFC 9773 §3, a top level member and not part of meta: the base URL for
    // ACME Renewal Information; the client appends "/{certID}" (§4.1).
    [JsonPropertyName("renewalInfo")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RenewalInfo { get; set; }

    [JsonPropertyName("revokeCert")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RevokeCert { get; set; }

    [JsonPropertyName("keyChange")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyChange { get; set; }

    [JsonPropertyName("meta")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeDirectoryMeta? Meta { get; set; }
}

/// <summary>
/// Metadata about the ACME server included in the directory.
/// </summary>
public sealed class AcmeDirectoryMeta
{
    [JsonPropertyName("termsOfService")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TermsOfService { get; set; }

    [JsonPropertyName("website")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Website { get; set; }

    [JsonPropertyName("caaIdentities")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? CaaIdentities { get; set; }

    [JsonPropertyName("externalAccountRequired")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ExternalAccountRequired { get; set; }
}
