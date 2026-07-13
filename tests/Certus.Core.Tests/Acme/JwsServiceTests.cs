using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

public class JwsServiceTests
{
    private readonly JwsService _sut = new(NullLogger<JwsService>.Instance);

    [Fact]
    public void Validate_ValidRs256Jws_Succeeds()
    {
        var (jws, _) = CreateSignedJws("RS256", """{"test":"value"}""");

        var result = _sut.Validate(jws);

        result.IsVerified.Should().BeTrue();
        result.Header.Should().NotBeNull();
        result.Header!.Alg.Should().Be("RS256");
        result.PayloadBytes.Should().NotBeNull();

        var payloadJson = Encoding.UTF8.GetString(result.PayloadBytes!);
        payloadJson.Should().Contain("test");
    }

    [Fact]
    public void Validate_ValidEs256Jws_Succeeds()
    {
        var (jws, _) = CreateSignedJws("ES256", """{"test":"value"}""");

        var result = _sut.Validate(jws);

        result.IsVerified.Should().BeTrue();
        result.Header!.Alg.Should().Be("ES256");
    }

    [Fact]
    public void Validate_TamperedPayload_FailsSignature()
    {
        var (jws, _) = CreateSignedJws("RS256", """{"test":"original"}""");

        // Tamper with the payload
        var tampered = JwsService.Base64UrlEncode(
            Encoding.UTF8.GetBytes("""{"test":"tampered"}"""));
        jws.Payload = tampered;

        var result = _sut.Validate(jws);

        result.Status.Should().Be(JwsValidationStatus.Malformed);
        result.ErrorMessage.Should().Contain("signature");
    }

    [Fact]
    public void Validate_UnsupportedAlgorithm_Fails()
    {
        // Create a JWS with an unsupported algorithm header
        var header = new JwsProtectedHeader { Alg = "PS256", Nonce = "test", Url = "http://test" };
        var headerJson = JsonSerializer.Serialize(header);
        // Add a dummy jwk so the header is valid structurally
        var headerObj = JsonSerializer.Deserialize<JsonElement>(headerJson);
        var headerWithJwk = """{"alg":"PS256","nonce":"test","url":"http://test","jwk":{"kty":"RSA","n":"test","e":"AQAB"}}""";

        var jws = new JwsFlattenedRequest
        {
            Protected = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerWithJwk)),
            Payload = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes("{}")),
            Signature = JwsService.Base64UrlEncode(new byte[64])
        };

        var result = _sut.Validate(jws);

        result.Status.Should().Be(JwsValidationStatus.Malformed);
        result.ErrorMessage.Should().Contain("PS256");
    }

    [Fact]
    public void Validate_BothJwkAndKid_Fails()
    {
        var headerJson = """{"alg":"RS256","nonce":"test","url":"http://test","jwk":{"kty":"RSA","n":"a","e":"AQAB"},"kid":"http://test/acct/123"}""";

        var jws = new JwsFlattenedRequest
        {
            Protected = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson)),
            Payload = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes("{}")),
            Signature = JwsService.Base64UrlEncode(new byte[64])
        };

        var result = _sut.Validate(jws);

        result.Status.Should().Be(JwsValidationStatus.Malformed);
        result.ErrorMessage.Should().Contain("either");
    }

    [Fact]
    public void Validate_KidOnly_ReturnsNeedsKeyLookupNotVerified()
    {
        var headerJson = """{"alg":"RS256","nonce":"test","url":"http://test","kid":"http://test/acct/123"}""";

        var jws = new JwsFlattenedRequest
        {
            Protected = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson)),
            Payload = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes("{}")),
            Signature = JwsService.Base64UrlEncode(new byte[64])
        };

        var result = _sut.Validate(jws);

        // A kid request is never "Verified" here — its signature is checked by the caller.
        result.Status.Should().Be(JwsValidationStatus.NeedsKeyLookup);
        result.IsVerified.Should().BeFalse();
        result.RequiresKeyLookup.Should().BeTrue();
        result.Header!.Kid.Should().Be("http://test/acct/123");
    }

    [Fact]
    public void ComputeThumbprint_RsaKey_ReturnsConsistentValue()
    {
        using var rsa = RSA.Create(2048);
        var jwkJson = ExportRsaJwk(rsa);

        var thumb1 = JwsService.ComputeThumbprint(jwkJson);
        var thumb2 = JwsService.ComputeThumbprint(jwkJson);

        thumb1.Should().NotBeNullOrEmpty();
        thumb1.Should().Be(thumb2);
    }

    [Fact]
    public void ComputeThumbprint_EcKey_ReturnsConsistentValue()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwkJson = ExportEcJwk(ecdsa);

        var thumb1 = JwsService.ComputeThumbprint(jwkJson);
        var thumb2 = JwsService.ComputeThumbprint(jwkJson);

        thumb1.Should().NotBeNullOrEmpty();
        thumb1.Should().Be(thumb2);
    }

    [Fact]
    public void ComputeThumbprint_DifferentKeys_ReturnDifferentValues()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);

        var thumb1 = JwsService.ComputeThumbprint(ExportRsaJwk(rsa1));
        var thumb2 = JwsService.ComputeThumbprint(ExportRsaJwk(rsa2));

        thumb1.Should().NotBe(thumb2);
    }

    [Fact]
    public void ValidatePublicKeyStrength_WeakRsa_Rejected()
    {
        using var rsa = RSA.Create(1024);

        var ok = JwsService.ValidatePublicKeyStrength(ExportRsaJwk(rsa), out var error);

        ok.Should().BeFalse();
        error.Should().Contain("2048");
    }

    [Fact]
    public void ValidatePublicKeyStrength_Rsa2048AndEcP256_Accepted()
    {
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        JwsService.ValidatePublicKeyStrength(ExportRsaJwk(rsa), out _).Should().BeTrue();
        JwsService.ValidatePublicKeyStrength(ExportEcJwk(ecdsa), out _).Should().BeTrue();
    }

    [Fact]
    public void ComputeThumbprint_NonP256Ec_Throws()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var p = ecdsa.ExportParameters(false);
        var x = JwsService.Base64UrlEncode(p.Q.X!);
        var y = JwsService.Base64UrlEncode(p.Q.Y!);
        var jwk = $$"""{"kty":"EC","crv":"P-384","x":"{{x}}","y":"{{y}}"}""";

        var act = () => JwsService.ComputeThumbprint(jwk);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ComputeThumbprint_MissingMember_Throws()
    {
        var jwk = """{"kty":"RSA","e":"AQAB"}"""; // missing n

        var act = () => JwsService.ComputeThumbprint(jwk);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Base64UrlEncode_RoundTrip_Succeeds()
    {
        var original = new byte[] { 0, 1, 2, 255, 254, 253 };

        var encoded = JwsService.Base64UrlEncode(original);
        var decoded = JwsService.Base64UrlDecode(encoded);

        decoded.Should().BeEquivalentTo(original);
    }

    [Fact]
    public void VerifyWithStoredKey_CorrectRs256Signature_ReturnsTrue()
    {
        // The kid path: Validate returns NeedsKeyLookup and the caller verifies against the
        // stored JWK via this seam. A correct signature must verify.
        using var rsa = RSA.Create(2048);
        var jwkJson = ExportRsaJwk(rsa);
        var signingInput = Encoding.ASCII.GetBytes("protected.payload");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        _sut.VerifyWithStoredKey("RS256", jwkJson, signingInput, signature).Should().BeTrue();
    }

    [Fact]
    public void VerifyWithStoredKey_TamperedSignature_ReturnsFalse()
    {
        using var rsa = RSA.Create(2048);
        var jwkJson = ExportRsaJwk(rsa);
        var signingInput = Encoding.ASCII.GetBytes("protected.payload");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signature[0] ^= 0xFF; // flip a byte — the stored key must reject it

        _sut.VerifyWithStoredKey("RS256", jwkJson, signingInput, signature).Should().BeFalse();
    }

    [Fact]
    public void VerifyWithStoredKey_CorrectEs256Signature_ReturnsTrue()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwkJson = ExportEcJwk(ecdsa);
        var signingInput = Encoding.ASCII.GetBytes("protected.payload");
        var signature = ecdsa.SignData(signingInput, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        _sut.VerifyWithStoredKey("ES256", jwkJson, signingInput, signature).Should().BeTrue();
    }

    #region Test Helpers

    private static (JwsFlattenedRequest Jws, string JwkJson) CreateSignedJws(
        string alg, string payloadJson)
    {
        string jwkJson;
        byte[] signatureBytes;
        string headerJson;

        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

        if (alg == "RS256")
        {
            using var rsa = RSA.Create(2048);
            jwkJson = ExportRsaJwk(rsa);

            headerJson = $$"""{"alg":"RS256","nonce":"testnonce","url":"http://test","jwk":{{jwkJson}}}""";
            var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");

            signatureBytes = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return (new JwsFlattenedRequest
            {
                Protected = protectedB64,
                Payload = payloadB64,
                Signature = JwsService.Base64UrlEncode(signatureBytes)
            }, jwkJson);
        }
        else // ES256
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            jwkJson = ExportEcJwk(ecdsa);

            headerJson = $$"""{"alg":"ES256","nonce":"testnonce","url":"http://test","jwk":{{jwkJson}}}""";
            var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");

            signatureBytes = ecdsa.SignData(signingInput, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            return (new JwsFlattenedRequest
            {
                Protected = protectedB64,
                Payload = payloadB64,
                Signature = JwsService.Base64UrlEncode(signatureBytes)
            }, jwkJson);
        }
    }

    private static string ExportRsaJwk(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var n = JwsService.Base64UrlEncode(p.Modulus!);
        var e = JwsService.Base64UrlEncode(p.Exponent!);
        return $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
    }

    private static string ExportEcJwk(ECDsa ecdsa)
    {
        var p = ecdsa.ExportParameters(false);
        var x = JwsService.Base64UrlEncode(p.Q.X!);
        var y = JwsService.Base64UrlEncode(p.Q.Y!);
        return $$"""{"kty":"EC","crv":"P-256","x":"{{x}}","y":"{{y}}"}""";
    }

    #endregion
}
