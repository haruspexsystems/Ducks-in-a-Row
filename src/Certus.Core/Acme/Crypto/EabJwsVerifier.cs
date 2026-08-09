using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;

namespace Certus.Core.Acme.Crypto;

/// <summary>
/// Structural validation of an externalAccountBinding inner JWS
/// (RFC 8555 §7.3.4), database free so it is unit testable like
/// <see cref="JwsService"/>. The section's checks split in two here:
/// <see cref="Parse"/> covers everything that needs no stored state (well
/// formed JWS, MAC based algorithm, kid present, url equals the outer JWS
/// url, no nonce), and the MAC plus payload key checks run in
/// EabCredentialService once the credential's secret has been looked up,
/// using <see cref="JwsService.VerifyMac"/> and
/// <see cref="PayloadKeyMatchesOuterKey"/>.
/// </summary>
public static class EabJwsVerifier
{
    /// <summary>The structurally validated parts of an EAB inner JWS.</summary>
    public sealed record EabParsed(
        string Alg,
        string KeyId,
        byte[] SigningInput,
        byte[] SignatureBytes,
        byte[] PayloadBytes);

    /// <summary>How a structurally invalid EAB maps to an ACME problem type.</summary>
    public enum EabParseFailure
    {
        /// <summary>Maps to urn:ietf:params:acme:error:malformed.</summary>
        Malformed,

        /// <summary>Maps to urn:ietf:params:acme:error:badSignatureAlgorithm.</summary>
        UnsupportedAlgorithm
    }

    /// <summary>Outcome of <see cref="Parse"/>: either Parsed or Failure plus Error.</summary>
    public sealed record EabParseResult(
        EabParsed? Parsed,
        EabParseFailure Failure,
        string? Error)
    {
        public static EabParseResult Ok(EabParsed parsed) =>
            new(parsed, default, null);

        public static EabParseResult Fail(EabParseFailure failure, string error) =>
            new(null, failure, error);
    }

    /// <summary>
    /// Validates the stateless RFC 8555 §7.3.4 header criteria and decodes the
    /// signing material. <paramref name="expectedUrl"/> is the outer JWS url
    /// the new-account endpoint already validated; both sides are compared in
    /// decoded form, the same resource equivalence rule as
    /// AcmeControllerBase.NormalizeAcmeUrl, so a client that decodes the URL
    /// before signing still interoperates.
    /// </summary>
    public static EabParseResult Parse(JsonElement eab, string expectedUrl)
    {
        JwsFlattenedRequest? jws;
        try
        {
            jws = eab.Deserialize<JwsFlattenedRequest>();
        }
        catch (JsonException)
        {
            return EabParseResult.Fail(EabParseFailure.Malformed,
                "externalAccountBinding is not a flattened JWS object.");
        }

        if (jws == null
            || string.IsNullOrEmpty(jws.Protected)
            || string.IsNullOrEmpty(jws.Payload)
            || string.IsNullOrEmpty(jws.Signature))
        {
            return EabParseResult.Fail(EabParseFailure.Malformed,
                "externalAccountBinding must carry 'protected', 'payload', and 'signature'.");
        }

        JwsProtectedHeader? header;
        byte[] signatureBytes;
        byte[] payloadBytes;
        try
        {
            header = JsonSerializer.Deserialize<JwsProtectedHeader>(
                JwsService.Base64UrlDecode(jws.Protected));
            signatureBytes = JwsService.Base64UrlDecode(jws.Signature);
            payloadBytes = JwsService.Base64UrlDecode(jws.Payload);
        }
        catch (FormatException)
        {
            return EabParseResult.Fail(EabParseFailure.Malformed,
                "externalAccountBinding contains invalid base64url encoding.");
        }
        catch (JsonException)
        {
            return EabParseResult.Fail(EabParseFailure.Malformed,
                "externalAccountBinding protected header is not valid JSON.");
        }

        if (header == null)
            return EabParseResult.Fail(EabParseFailure.Malformed,
                "externalAccountBinding protected header is empty.");

        if (!JwsService.SupportedMacAlgorithms.Contains(header.Alg))
        {
            return EabParseResult.Fail(EabParseFailure.UnsupportedAlgorithm,
                $"externalAccountBinding algorithm '{header.Alg}' is not supported. " +
                "Use one of: " + string.Join(", ", JwsService.SupportedMacAlgorithms) + ".");
        }

        // RFC 8555 §7.3.4: the inner JWS MUST NOT have a nonce.
        if (header.Nonce != null)
        {
            return EabParseResult.Fail(EabParseFailure.Malformed,
                "externalAccountBinding must not carry a nonce.");
        }

        if (Uri.UnescapeDataString(header.Url ?? string.Empty)
            != Uri.UnescapeDataString(expectedUrl))
        {
            return EabParseResult.Fail(EabParseFailure.Malformed,
                "externalAccountBinding 'url' does not match the outer JWS url.");
        }

        if (string.IsNullOrEmpty(header.Kid))
        {
            return EabParseResult.Fail(EabParseFailure.Malformed,
                "externalAccountBinding must carry the key identifier in 'kid'.");
        }

        var signingInput = Encoding.ASCII.GetBytes($"{jws.Protected}.{jws.Payload}");
        return EabParseResult.Ok(new EabParsed(
            header.Alg, header.Kid, signingInput, signatureBytes, payloadBytes));
    }

    /// <summary>
    /// RFC 8555 §7.3.4 final check: the inner JWS payload is the account key
    /// in JWK form and must be the same key that signed the outer JWS.
    /// Compared by RFC 7638 thumbprint so member ordering or whitespace in
    /// either form cannot break the match. A payload that is not a valid JWK
    /// at all also fails here.
    /// </summary>
    public static bool PayloadKeyMatchesOuterKey(byte[] payloadBytes, string outerJwkJson)
    {
        try
        {
            var payloadThumbprint = JwsService.ComputeThumbprint(
                Encoding.UTF8.GetString(payloadBytes));
            return payloadThumbprint == JwsService.ComputeThumbprint(outerJwkJson);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
