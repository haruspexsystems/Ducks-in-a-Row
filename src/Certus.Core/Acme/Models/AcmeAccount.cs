using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// ACME account object returned to clients.
/// RFC 8555 §7.1.2
/// </summary>
public sealed class AcmeAccountResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = "valid";

    [JsonPropertyName("contact")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? Contact { get; set; }

    [JsonPropertyName("termsOfServiceAgreed")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TermsOfServiceAgreed { get; set; }

    [JsonPropertyName("orders")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Orders { get; set; }
}

/// <summary>
/// Payload for new-account requests.
/// RFC 8555 §7.3
/// </summary>
public sealed class NewAccountRequest
{
    [JsonPropertyName("contact")]
    public string[]? Contact { get; set; }

    [JsonPropertyName("termsOfServiceAgreed")]
    public bool TermsOfServiceAgreed { get; set; }

    [JsonPropertyName("onlyReturnExisting")]
    public bool OnlyReturnExisting { get; set; }
}
