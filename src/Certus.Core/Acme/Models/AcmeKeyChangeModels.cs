using System.Text.Json;
using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// Payload of the inner JWS of a key-change request. RFC 8555 §7.3.5.
/// The outer JWS is signed by the old account key (kid); its payload is an inner JWS signed
/// by the new key (jwk) whose payload is this object. The inner payload binds the rollover to
/// a specific account and proves the requester knows which key is being replaced.
/// </summary>
public sealed class KeyChangeInnerPayload
{
    /// <summary>
    /// The account URL (the same value as the outer JWS kid). Confirms the new key is being
    /// bound to the account that authenticated the outer request.
    /// </summary>
    [JsonPropertyName("account")]
    public string Account { get; set; } = string.Empty;

    /// <summary>
    /// The account's current (old) public key as a JWK. Must match the authenticated account's
    /// key. Kept as the raw JSON element so its canonical thumbprint can be computed for the
    /// comparison (RFC 7638) without imposing a fixed member order.
    /// </summary>
    [JsonPropertyName("oldKey")]
    public JsonElement OldKey { get; set; }
}
