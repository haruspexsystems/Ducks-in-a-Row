using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for the stateless externalAccountBinding checks (RFC 8555 §7.3.4):
/// a well formed inner JWS with a MAC based algorithm, a kid, the outer url,
/// and no nonce parses; every structural deviation maps to the right problem
/// type; and the payload key comparison is by RFC 7638 thumbprint so member
/// order cannot break it.
/// </summary>
public class EabJwsVerifierTests
{
    private const string Url = "https://ducks.home.local/acme/WebServer/new-account";
    private const string Kid = "0123456789abcdef0123456789abcdef";
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);

    private static string ExportRsaJwk(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var n = JwsService.Base64UrlEncode(p.Modulus!);
        var e = JwsService.Base64UrlEncode(p.Exponent!);
        return $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
    }

    private static JsonElement BuildEab(
        string payloadJson,
        string alg = "HS256",
        string? kid = Kid,
        string url = Url,
        string? nonce = null,
        byte[]? key = null)
    {
        var header = new Dictionary<string, object?> { ["alg"] = alg, ["url"] = url };
        if (kid != null)
            header["kid"] = kid;
        if (nonce != null)
            header["nonce"] = nonce;

        var protectedB64 = JwsService.Base64UrlEncode(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var macKey = key ?? Key;
        var signature = alg switch
        {
            "HS384" => HMACSHA384.HashData(macKey, signingInput),
            "HS512" => HMACSHA512.HashData(macKey, signingInput),
            // Anything else is refused before the MAC is checked, so the
            // signature bytes only need to exist.
            _ => HMACSHA256.HashData(macKey, signingInput),
        };

        return JsonSerializer.SerializeToElement(new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        });
    }

    // ---- Parse: the happy path ----

    [Theory]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public void Parse_EveryAcceptedMacAlgorithm_SucceedsAndTheMacVerifies(string alg)
    {
        var eab = BuildEab("""{"kty":"RSA","n":"AQAB","e":"AQAB"}""", alg);

        var result = EabJwsVerifier.Parse(eab, Url);

        result.Parsed.Should().NotBeNull();
        result.Parsed!.Alg.Should().Be(alg);
        result.Parsed.KeyId.Should().Be(Kid);
        JwsService.VerifyMac(
                result.Parsed.Alg, Key, result.Parsed.SigningInput, result.Parsed.SignatureBytes)
            .Should().BeTrue();
    }

    [Fact]
    public void Parse_EncodedAndDecodedUrlForms_AreTheSameResource()
    {
        // win-acme decodes the URL before signing; the comparison is by
        // decoded form, the same rule as the outer JWS url check.
        var eab = BuildEab("{}", url: "https://h.local/acme/Web%20Server/new-account");

        var result = EabJwsVerifier.Parse(eab, "https://h.local/acme/Web Server/new-account");

        result.Parsed.Should().NotBeNull();
    }

    // ---- Parse: refusals ----

    [Theory]
    [InlineData("RS256")]
    [InlineData("ES256")]
    [InlineData("none")]
    public void Parse_NonMacAlgorithm_IsUnsupportedAlgorithm(string alg)
    {
        var eab = BuildEab("{}", alg);

        var result = EabJwsVerifier.Parse(eab, Url);

        result.Parsed.Should().BeNull();
        result.Failure.Should().Be(EabJwsVerifier.EabParseFailure.UnsupportedAlgorithm);
        result.Error.Should().Contain("HS256");
    }

    [Fact]
    public void Parse_NoncePresent_IsMalformed()
    {
        // RFC 8555 §7.3.4: the inner JWS MUST NOT have a nonce.
        var eab = BuildEab("{}", nonce: "bogus-nonce");

        var result = EabJwsVerifier.Parse(eab, Url);

        result.Parsed.Should().BeNull();
        result.Failure.Should().Be(EabJwsVerifier.EabParseFailure.Malformed);
        result.Error.Should().Contain("nonce");
    }

    [Fact]
    public void Parse_UrlMismatch_IsMalformed()
    {
        var eab = BuildEab("{}", url: "https://elsewhere.example/acme/WebServer/new-account");

        var result = EabJwsVerifier.Parse(eab, Url);

        result.Parsed.Should().BeNull();
        result.Failure.Should().Be(EabJwsVerifier.EabParseFailure.Malformed);
        result.Error.Should().Contain("url");
    }

    [Fact]
    public void Parse_KidMissing_IsMalformed()
    {
        var eab = BuildEab("{}", kid: null);

        var result = EabJwsVerifier.Parse(eab, Url);

        result.Parsed.Should().BeNull();
        result.Failure.Should().Be(EabJwsVerifier.EabParseFailure.Malformed);
        result.Error.Should().Contain("kid");
    }

    [Fact]
    public void Parse_MissingJwsParts_IsMalformed()
    {
        var eab = JsonSerializer.SerializeToElement(new JwsFlattenedRequest());

        var result = EabJwsVerifier.Parse(eab, Url);

        result.Parsed.Should().BeNull();
        result.Failure.Should().Be(EabJwsVerifier.EabParseFailure.Malformed);
    }

    [Fact]
    public void Parse_NotAJwsObject_IsMalformed()
    {
        var eab = JsonSerializer.SerializeToElement("just a string");

        var result = EabJwsVerifier.Parse(eab, Url);

        result.Parsed.Should().BeNull();
        result.Failure.Should().Be(EabJwsVerifier.EabParseFailure.Malformed);
    }

    [Fact]
    public void Parse_ProtectedNotBase64Url_IsMalformed()
    {
        var eab = JsonSerializer.SerializeToElement(new JwsFlattenedRequest
        {
            Protected = "!!not-base64url!!",
            Payload = "e30",
            Signature = "e30",
        });

        var result = EabJwsVerifier.Parse(eab, Url);

        result.Parsed.Should().BeNull();
        result.Failure.Should().Be(EabJwsVerifier.EabParseFailure.Malformed);
    }

    // ---- The MAC itself ----

    [Fact]
    public void VerifyMac_WrongKey_Fails()
    {
        var eab = BuildEab("{}");
        var parsed = EabJwsVerifier.Parse(eab, Url).Parsed!;
        var wrongKey = RandomNumberGenerator.GetBytes(32);

        JwsService.VerifyMac(parsed.Alg, wrongKey, parsed.SigningInput, parsed.SignatureBytes)
            .Should().BeFalse();
    }

    [Fact]
    public void VerifyMac_UnknownAlgorithm_FailsClosed()
    {
        JwsService.VerifyMac("HS128", Key, [1, 2, 3], [1, 2, 3]).Should().BeFalse();
    }

    // ---- Payload key comparison (RFC 7638 thumbprint) ----

    [Fact]
    public void PayloadKeyMatchesOuterKey_SameKeyDifferentMemberOrder_Matches()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var n = JwsService.Base64UrlEncode(p.Modulus!);
        var e = JwsService.Base64UrlEncode(p.Exponent!);
        var outerJwk = $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
        var reordered = $$"""{"e":"{{e}}","n":"{{n}}","kty":"RSA"}""";

        EabJwsVerifier.PayloadKeyMatchesOuterKey(Encoding.UTF8.GetBytes(reordered), outerJwk)
            .Should().BeTrue();
    }

    [Fact]
    public void PayloadKeyMatchesOuterKey_DifferentKey_DoesNotMatch()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);

        EabJwsVerifier.PayloadKeyMatchesOuterKey(
                Encoding.UTF8.GetBytes(ExportRsaJwk(rsa2)), ExportRsaJwk(rsa1))
            .Should().BeFalse();
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("""{"kty":"RSA"}""")]
    [InlineData("""{"kty":"AES","k":"AQAB"}""")]
    public void PayloadKeyMatchesOuterKey_InvalidPayloadJwk_DoesNotMatch(string payload)
    {
        using var rsa = RSA.Create(2048);

        EabJwsVerifier.PayloadKeyMatchesOuterKey(
                Encoding.UTF8.GetBytes(payload), ExportRsaJwk(rsa))
            .Should().BeFalse();
    }
}
