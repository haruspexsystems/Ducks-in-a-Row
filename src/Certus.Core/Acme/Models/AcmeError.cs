using System.Text.Json.Serialization;

namespace Certus.Core.Acme.Models;

/// <summary>
/// ACME error response per RFC 8555 §6.7 and RFC 7807.
/// Content-Type: application/problem+json
/// </summary>
public sealed class AcmeError
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("detail")]
    public string Detail { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int Status { get; set; }

    [JsonPropertyName("subproblems")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeError[]? Subproblems { get; set; }

    [JsonPropertyName("identifier")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeIdentifier? Identifier { get; set; }

    /// <summary>
    /// The algorithms the server accepts, included on badSignatureAlgorithm
    /// problems as RFC 8555 §6.2 recommends.
    /// </summary>
    [JsonPropertyName("algorithms")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? Algorithms { get; set; }
}

/// <summary>
/// ACME identifier (domain name).
/// </summary>
public sealed class AcmeIdentifier
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "dns";

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;
}

/// <summary>
/// Standard ACME error type URNs per RFC 8555 §6.7.
/// </summary>
public static class AcmeErrorType
{
    private const string Prefix = "urn:ietf:params:acme:error:";

    public const string AccountDoesNotExist = Prefix + "accountDoesNotExist";
    // From RFC 9773 §5, not RFC 8555: the certificate a new-order's "replaces"
    // names has already been marked as replaced by another live order.
    public const string AlreadyReplaced = Prefix + "alreadyReplaced";
    public const string AlreadyRevoked = Prefix + "alreadyRevoked";
    // From draft-ietf-acme-device-attest-08, not RFC 8555: the attestation
    // object of a device-attest-01 challenge did not verify.
    public const string BadAttestationStatement = Prefix + "badAttestationStatement";
    public const string BadCsr = Prefix + "badCSR";
    public const string BadNonce = Prefix + "badNonce";
    public const string BadPublicKey = Prefix + "badPublicKey";
    public const string BadRevocationReason = Prefix + "badRevocationReason";
    public const string BadSignatureAlgorithm = Prefix + "badSignatureAlgorithm";
    public const string Caa = Prefix + "caa";
    public const string Compound = Prefix + "compound";
    public const string Connection = Prefix + "connection";
    public const string Dns = Prefix + "dns";
    public const string ExternalAccountRequired = Prefix + "externalAccountRequired";
    public const string IncorrectResponse = Prefix + "incorrectResponse";
    public const string InvalidContact = Prefix + "invalidContact";
    public const string Malformed = Prefix + "malformed";
    public const string OrderNotReady = Prefix + "orderNotReady";
    public const string RateLimited = Prefix + "rateLimited";
    public const string RejectedIdentifier = Prefix + "rejectedIdentifier";
    public const string ServerInternal = Prefix + "serverInternal";
    public const string ServiceUnavailable = Prefix + "serviceUnavailable";
    public const string Tls = Prefix + "tls";
    public const string Unauthorized = Prefix + "unauthorized";
    public const string UnsupportedContact = Prefix + "unsupportedContact";
    public const string UnsupportedIdentifier = Prefix + "unsupportedIdentifier";
    public const string UserActionRequired = Prefix + "userActionRequired";
}
