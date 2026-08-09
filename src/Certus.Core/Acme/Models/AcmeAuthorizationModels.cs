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
