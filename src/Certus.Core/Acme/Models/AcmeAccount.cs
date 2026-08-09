using System.Text.Json;
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

    /// <summary>
    /// The externalAccountBinding JWS the account was registered with, echoed
    /// exactly as received (RFC 8555 §7.1.2 makes it part of the account
    /// object). Absent for accounts without a binding.
    /// </summary>
    [JsonPropertyName("externalAccountBinding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? ExternalAccountBinding { get; set; }
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

    /// <summary>
    /// The externalAccountBinding inner JWS (RFC 8555 §7.3.4). Kept as a raw
    /// element: verification decodes it itself, and the account row stores it
    /// verbatim for the response echo.
    /// </summary>
    [JsonPropertyName("externalAccountBinding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? ExternalAccountBinding { get; set; }
}
