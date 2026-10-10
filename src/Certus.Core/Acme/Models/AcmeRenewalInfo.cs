using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// A RenewalInfo object (RFC 9773 §4.2): the suggested window in which the
/// client should renew. explanationURL is the only other member the RFC
/// defines and it is optional; we do not serve one.
/// </summary>
public sealed class RenewalInfoResponse
{
    [JsonPropertyName("suggestedWindow")]
    public RenewalInfoSuggestedWindow SuggestedWindow { get; set; } = new();
}

/// <summary>
/// The window bounds, RFC 3339 timestamps. The server MUST NOT serve an end
/// that equals or precedes the start (RFC 9773 §4.2); the policy that builds
/// these guarantees it.
/// </summary>
public sealed class RenewalInfoSuggestedWindow
{
    [JsonPropertyName("start")]
    public string Start { get; set; } = string.Empty;

    [JsonPropertyName("end")]
    public string End { get; set; } = string.Empty;
}
