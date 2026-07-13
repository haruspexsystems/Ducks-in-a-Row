using System.Text.Json;
using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// Flattened JWS JSON serialization as used by ACME.
/// RFC 8555 §6.2 — requests use application/jose+json with this format.
/// </summary>
public sealed class JwsFlattenedRequest
{
    [JsonPropertyName("protected")]
    public string Protected { get; set; } = string.Empty;

    [JsonPropertyName("payload")]
    public string Payload { get; set; } = string.Empty;

    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;
}

/// <summary>
/// Decoded JWS protected header.
/// RFC 8555 §6.2 — must contain alg, nonce, url, and either jwk or kid.
/// </summary>
public sealed class JwsProtectedHeader
{
    [JsonPropertyName("alg")]
    public string Alg { get; set; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    /// <summary>
    /// JWK — present in new-account requests (when no kid exists yet).
    /// Mutually exclusive with Kid.
    /// </summary>
    [JsonPropertyName("jwk")]
    public JsonElement? Jwk { get; set; }

    /// <summary>
    /// Key ID — the account URL, used after account creation.
    /// Mutually exclusive with Jwk.
    /// </summary>
    [JsonPropertyName("kid")]
    public string? Kid { get; set; }
}
