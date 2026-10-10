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

/// <summary>
/// Payload for an account update posted to the account URL: a contact change
/// (RFC 8555 §7.3.2) or a deactivation (§7.3.6).
///
/// Every other member of the account object is deliberately absent from this
/// type. §7.3.2 requires the server to ignore updates to "orders",
/// "termsOfServiceAgreed", and any field it does not recognise, and omitting
/// them here IS that behaviour: System.Text.Json drops unknown members, so a
/// client that sends them gets them ignored rather than applied.
/// </summary>
public sealed class AccountUpdateRequest
{
    /// <summary>
    /// The replacement contact list, or null when the payload does not carry
    /// one. The three cases are distinct and all meaningful: absent is no
    /// change, an empty array clears the contacts, and a populated array
    /// replaces them. An explicit JSON null deserializes to null and so reads
    /// as absent, matching how new-account treats an explicit null binding.
    /// </summary>
    [JsonPropertyName("contact")]
    public string[]? Contact { get; set; }

    /// <summary>
    /// The requested status. Only "deactivated" does anything (§7.3.6); every
    /// other value is ignored, because §7.3.2 requires the server to ignore
    /// updates to the status field "except as allowed by Section 7.3.6".
    /// </summary>
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    /// <summary>
    /// Whether this payload is the §7.3.6 deactivation request. Ordinal: the
    /// status vocabulary is a protocol constant, not text in the caller's
    /// culture.
    /// </summary>
    [JsonIgnore]
    public bool IsDeactivation =>
        string.Equals(Status, "deactivated", StringComparison.Ordinal);
}
