using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// ACME authorization response object.
/// RFC 8555 §7.1.4
/// </summary>
public sealed class AuthorizationResponse
{
    [JsonPropertyName("identifier")]
    public AcmeIdentifier Identifier { get; set; } = new();

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("expires")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Expires { get; set; }

    [JsonPropertyName("challenges")]
    public ChallengeResponse[] Challenges { get; set; } = Array.Empty<ChallengeResponse>();

    [JsonPropertyName("wildcard")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Wildcard { get; set; }
}

/// <summary>
/// Payload for a deactivation posted to the authorization URL (RFC 8555 §7.5.2).
///
/// Every other member of the authorization object is deliberately absent, so
/// System.Text.Json drops a client sent "expires", "challenges", or
/// "identifier" rather than letting it near a write.
///
/// The consumer of this type REFUSES a status it does not act on, where
/// <see cref="AccountUpdateRequest"/> ignores one. That divergence is
/// deliberate: §7.3.2 tells the server to ignore an unrecognised status on an
/// account, and §7.5.2 gives no such instruction for an authorization. See
/// AuthorizationController.ApplyAuthorizationUpdateAsync.
/// </summary>
public sealed class AuthorizationUpdateRequest
{
    /// <summary>
    /// The requested status. Only "deactivated" does anything. Null covers both
    /// an absent member and an explicit JSON null, and both read as "no status
    /// change requested", which the handler treats as POST-as-GET.
    /// </summary>
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    /// <summary>
    /// Whether this payload is the §7.5.2 deactivation request. Ordinal: the
    /// status vocabulary is a protocol constant, not text in the caller's
    /// culture.
    /// </summary>
    [JsonIgnore]
    public bool IsDeactivation =>
        string.Equals(Status, "deactivated", StringComparison.Ordinal);
}

/// <summary>
/// The payload a client POSTs to a device-attest-01 challenge URL:
/// {"attObj": base64url(CBOR attestation object)}
/// (draft-ietf-acme-device-attest-08 section 5.1). Deserialization ignores
/// unknown members, which is exactly what the draft requires of the server.
/// </summary>
public sealed class DeviceAttestChallengePayload
{
    [JsonPropertyName("attObj")]
    public string? AttObj { get; set; }
}

/// <summary>
/// ACME challenge response object.
/// RFC 8555 §7.1.5
/// </summary>
public sealed class ChallengeResponse
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("validated")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Validated { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeError? Error { get; set; }
}
