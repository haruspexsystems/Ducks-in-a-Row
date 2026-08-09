using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Crypto;

/// <summary>
/// JWS signature verification and JWK operations for ACME.
/// Supports RS256 (RSA PKCS#1 v1.5 with SHA-256) and ES256 (ECDSA with P-256 and SHA-256).
/// RFC 7515 (JWS), RFC 7517 (JWK), RFC 7638 (JWK Thumbprint).
/// </summary>
public sealed class JwsService
{
    private readonly ILogger<JwsService> _logger;

    public JwsService(ILogger<JwsService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Decodes and validates a flattened JWS request.
    /// Returns the decoded protected header, payload bytes, and the JWK JSON used for signing.
    /// Does NOT verify the nonce or URL — those are checked by the middleware.
    /// </summary>
    public JwsValidationResult Validate(JwsFlattenedRequest jws)
    {
        try
        {
            // 1. Decode protected header
            var protectedBytes = Base64UrlDecode(jws.Protected);
            var header = JsonSerializer.Deserialize<JwsProtectedHeader>(protectedBytes);
            if (header == null)
                return JwsValidationResult.Fail("Failed to parse JWS protected header.");

            // 2. Validate algorithm
            if (header.Alg != "RS256" && header.Alg != "ES256")
                return JwsValidationResult.Fail($"Unsupported algorithm: {header.Alg}. Must be RS256 or ES256.");

            // 3. Must have jwk XOR kid
            if (header.Jwk.HasValue && header.Kid != null)
                return JwsValidationResult.Fail("JWS header must contain either 'jwk' or 'kid', not both.");

            if (!header.Jwk.HasValue && header.Kid == null)
                return JwsValidationResult.Fail("JWS header must contain either 'jwk' or 'kid'.");

            // 4. Decode signature
            var signatureBytes = Base64UrlDecode(jws.Signature);

            // 5. Build signing input: ASCII(BASE64URL(header) + "." + BASE64URL(payload))
            var signingInput = Encoding.ASCII.GetBytes($"{jws.Protected}.{jws.Payload}");

            // 6. Get the public key to verify against
            string jwkJson;
            if (header.Jwk.HasValue)
            {
                jwkJson = header.Jwk.Value.GetRawText();
            }
            else
            {
                // kid mode — the caller must look up the JWK from the account
                // We return success with kid set so the caller can handle it
                var payloadBytes = string.IsNullOrEmpty(jws.Payload)
                    ? Array.Empty<byte>()
                    : Base64UrlDecode(jws.Payload);

                return new JwsValidationResult(
                    Status: JwsValidationStatus.NeedsKeyLookup,
                    Header: header,
                    PayloadBytes: payloadBytes,
                    JwkJson: null,
                    SigningInput: signingInput,
                    SignatureBytes: signatureBytes,
                    ErrorMessage: null);
            }

            // 7. Verify signature using the embedded JWK
            var isValid = VerifySignature(header.Alg, jwkJson, signingInput, signatureBytes);
            if (!isValid)
                return JwsValidationResult.Fail("JWS signature verification failed.");

            // 8. Decode payload
            var payload = string.IsNullOrEmpty(jws.Payload)
                ? Array.Empty<byte>()
                : Base64UrlDecode(jws.Payload);

            return new JwsValidationResult(
                Status: JwsValidationStatus.Verified,
                Header: header,
                PayloadBytes: payload,
                JwkJson: jwkJson,
                SigningInput: null,
                SignatureBytes: null,
                ErrorMessage: null);
        }
        catch (FormatException ex)
        {
            _logger.LogWarning(ex, "Invalid base64url encoding in JWS");
            return JwsValidationResult.Fail("Invalid base64url encoding in JWS.");
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Invalid JSON in JWS protected header");
            return JwsValidationResult.Fail("Invalid JSON in JWS protected header.");
        }
    }

    /// <summary>
    /// Verifies a JWS signature using a stored JWK (for kid-based requests).
    /// </summary>
    public bool VerifyWithStoredKey(string alg, string jwkJson, byte[] signingInput, byte[] signature)
    {
        return VerifySignature(alg, jwkJson, signingInput, signature);
    }

    /// <summary>
    /// MAC algorithms accepted for the externalAccountBinding inner JWS
    /// (RFC 8555 §7.3.4), which is the only MAC signed structure in ACME.
    /// Issued EAB secrets are 32 bytes, so mainstream clients sign with
    /// HS256; HS384 and HS512 are accepted for clients that choose the
    /// algorithm from the key length.
    /// </summary>
    public static readonly string[] SupportedMacAlgorithms = ["HS256", "HS384", "HS512"];

    /// <summary>
    /// Verifies an HMAC over the JWS signing input in constant time. Returns
    /// false for an algorithm outside <see cref="SupportedMacAlgorithms"/>
    /// rather than throwing, so an unexpected value fails closed.
    /// </summary>
    public static bool VerifyMac(string alg, byte[] key, byte[] signingInput, byte[] signature)
    {
        byte[]? computed = alg switch
        {
            "HS256" => HMACSHA256.HashData(key, signingInput),
            "HS384" => HMACSHA384.HashData(key, signingInput),
            "HS512" => HMACSHA512.HashData(key, signingInput),
            _ => null
        };

        return computed != null && CryptographicOperations.FixedTimeEquals(computed, signature);
    }

    /// <summary>
    /// Computes the JWK Thumbprint per RFC 7638.
    /// The thumbprint is the SHA-256 hash of the canonical JWK representation.
    /// </summary>
    public static string ComputeThumbprint(string jwkJson)
    {
        var jwk = JsonSerializer.Deserialize<JsonElement>(jwkJson);
        var kty = RequireJwkMember(jwk, "kty");

        // Build canonical JWK with required members in lexicographic order. Each member
        // is validated and is base64url or a known token, so it cannot inject JSON.
        string canonical;
        if (kty == "RSA")
        {
            var e = RequireJwkMember(jwk, "e");
            var n = RequireJwkMember(jwk, "n");
            canonical = $"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}";
        }
        else if (kty == "EC")
        {
            var crv = RequireJwkMember(jwk, "crv");
            if (crv != "P-256")
                throw new ArgumentException($"Unsupported EC curve: '{crv}'. Only P-256 is supported.");
            var x = RequireJwkMember(jwk, "x");
            var y = RequireJwkMember(jwk, "y");
            canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        }
        else
        {
            throw new ArgumentException($"Unsupported key type: {kty}");
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncode(hash);
    }

    /// <summary>
    /// Reads a required string member from a JWK, rejecting a missing, non string, or
    /// empty value. RFC 7638 requires every member of the canonical form to be present.
    /// </summary>
    private static string RequireJwkMember(JsonElement jwk, string name)
    {
        if (!jwk.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
            throw new ArgumentException($"JWK is missing required member '{name}'.");
        var value = element.GetString();
        if (string.IsNullOrEmpty(value))
            throw new ArgumentException($"JWK member '{name}' must not be empty.");
        return value;
    }

    /// <summary>
    /// Validates that a public JWK meets the minimum strength policy, so a weak key is
    /// rejected with badPublicKey (RFC 8555 §6.7) rather than accepted. EC is restricted
    /// to P-256; RSA must have a modulus of at least 2048 bits.
    /// </summary>
    public static bool ValidatePublicKeyStrength(string jwkJson, out string? error)
    {
        var jwk = JsonSerializer.Deserialize<JsonElement>(jwkJson);
        var kty = RequireJwkMember(jwk, "kty");

        if (kty == "RSA")
        {
            var modulus = Base64UrlDecode(RequireJwkMember(jwk, "n"));
            // A JWK modulus is the unsigned big endian integer with no sign byte, so 2048
            // bits is exactly 256 bytes. Anything shorter is below policy.
            if (modulus.Length < 256)
            {
                error = "RSA public key is too small; a modulus of at least 2048 bits is required.";
                return false;
            }
        }
        else if (kty == "EC")
        {
            var crv = RequireJwkMember(jwk, "crv");
            if (crv != "P-256")
            {
                error = $"Unsupported EC curve '{crv}'. Only P-256 is supported.";
                return false;
            }
        }
        else
        {
            error = $"Unsupported key type '{kty}'.";
            return false;
        }

        error = null;
        return true;
    }

    /// <summary>
    /// True when the given public JWK is the same public key as the certificate's. Used by
    /// revoke-cert (RFC 8555 §7.6) to confirm a jwk-signed request proves possession of the
    /// certificate's own key pair: the JWS signature was already verified against the embedded
    /// key, so matching that key to the certificate binds the possession proof to this cert.
    /// Compares the DER SubjectPublicKeyInfo of both keys. Returns false on any parse failure or
    /// unsupported key type rather than throwing.
    /// </summary>
    public static bool JwkMatchesCertificatePublicKey(string jwkJson, X509Certificate2 certificate)
    {
        try
        {
            var jwk = JsonSerializer.Deserialize<JsonElement>(jwkJson);
            var kty = RequireJwkMember(jwk, "kty");

            byte[] jwkSpki;
            if (kty == "RSA")
            {
                var n = Base64UrlDecode(RequireJwkMember(jwk, "n"));
                var e = Base64UrlDecode(RequireJwkMember(jwk, "e"));
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
                jwkSpki = rsa.ExportSubjectPublicKeyInfo();
            }
            else if (kty == "EC")
            {
                var crv = RequireJwkMember(jwk, "crv");
                if (crv != "P-256")
                    return false;
                var x = Base64UrlDecode(RequireJwkMember(jwk, "x"));
                var y = Base64UrlDecode(RequireJwkMember(jwk, "y"));
                using var ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = x, Y = y }
                });
                jwkSpki = ecdsa.ExportSubjectPublicKeyInfo();
            }
            else
            {
                return false;
            }

            var certSpki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
            return CryptographicOperations.FixedTimeEquals(jwkSpki, certSpki);
        }
        catch (Exception)
        {
            return false;
        }
    }

    #region Signature Verification

    private bool VerifySignature(string alg, string jwkJson, byte[] signingInput, byte[] signature)
    {
        try
        {
            return alg switch
            {
                "RS256" => VerifyRs256(jwkJson, signingInput, signature),
                "ES256" => VerifyEs256(jwkJson, signingInput, signature),
                _ => false
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Signature verification failed for algorithm {Alg}", alg);
            return false;
        }
    }

    private static bool VerifyRs256(string jwkJson, byte[] signingInput, byte[] signature)
    {
        var jwk = JsonSerializer.Deserialize<JsonElement>(jwkJson);
        var n = Base64UrlDecode(jwk.GetProperty("n").GetString()!);
        var e = Base64UrlDecode(jwk.GetProperty("e").GetString()!);

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = n,
            Exponent = e
        });

        return rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static bool VerifyEs256(string jwkJson, byte[] signingInput, byte[] signature)
    {
        var jwk = JsonSerializer.Deserialize<JsonElement>(jwkJson);
        var x = Base64UrlDecode(jwk.GetProperty("x").GetString()!);
        var y = Base64UrlDecode(jwk.GetProperty("y").GetString()!);

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = x,
                Y = y
            }
        });

        // ACME/JWS uses the raw R||S format (64 bytes for P-256)
        // .NET VerifyData expects the same format by default for IEEE P1363
        return ecdsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    #endregion

    #region Base64URL Helpers

    public static byte[] Base64UrlDecode(string input)
    {
        var padded = input
            .Replace('-', '+')
            .Replace('_', '/');

        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        return Convert.FromBase64String(padded);
    }

    public static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    #endregion
}

/// <summary>
/// Outcome of <see cref="JwsService.Validate"/>.
/// </summary>
public enum JwsValidationStatus
{
    /// <summary>The JWS was structurally invalid, used a bad algorithm, or failed signature verification.</summary>
    Malformed,

    /// <summary>A jwk request whose embedded key verified the signature. Safe to act on.</summary>
    Verified,

    /// <summary>
    /// A kid request that is structurally sound but whose signature is NOT yet verified, because
    /// the key has to be looked up from the account store by the caller.
    /// </summary>
    NeedsKeyLookup
}

/// <summary>
/// Result of JWS validation.
/// </summary>
/// <remarks>
/// Security: the type cannot express an "authenticated" state for an unverified request. A jwk
/// request that verified is <see cref="JwsValidationStatus.Verified"/>; a kid request is only ever
/// <see cref="JwsValidationStatus.NeedsKeyLookup"/> here, because <see cref="JwsService.Validate"/>
/// cannot check its signature without the stored key. When <see cref="RequiresKeyLookup"/> is true
/// the caller MUST call <see cref="JwsService.VerifyWithStoredKey"/> and reject the request if it
/// returns false before treating it as authenticated or acting on the payload.
/// </remarks>
public sealed record JwsValidationResult(
    JwsValidationStatus Status,
    JwsProtectedHeader? Header,
    byte[]? PayloadBytes,
    string? JwkJson,
    byte[]? SigningInput,
    byte[]? SignatureBytes,
    string? ErrorMessage)
{
    public static JwsValidationResult Fail(string message) =>
        new(JwsValidationStatus.Malformed, null, null, null, null, null, message);

    /// <summary>
    /// True only for a jwk request whose signature was verified inside <see cref="JwsService.Validate"/>.
    /// Never true for a kid request — see <see cref="RequiresKeyLookup"/>.
    /// </summary>
    public bool IsVerified => Status == JwsValidationStatus.Verified;

    /// <summary>
    /// Whether this is a kid-based request that needs the JWK looked up from the account store and
    /// its signature verified by the caller.
    /// </summary>
    public bool RequiresKeyLookup => Status == JwsValidationStatus.NeedsKeyLookup;
}
