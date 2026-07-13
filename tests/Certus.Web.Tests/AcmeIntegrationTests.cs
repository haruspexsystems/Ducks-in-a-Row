using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for ACME protocol endpoints.
/// Uses CertusWebApplicationFactory with a shared in-memory SQLite database.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class AcmeIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public AcmeIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    #region Directory Tests

    [Fact]
    public async Task Directory_ValidTemplate_ReturnsDirectoryJson()
    {
        var response = await _client.GetAsync("/acme/WebServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/json");

        var json = await response.Content.ReadAsStringAsync();
        var directory = JsonSerializer.Deserialize<AcmeDirectory>(json);

        directory.Should().NotBeNull();
        directory!.NewNonce.Should().Contain("/acme/WebServer/new-nonce");
        directory.NewAccount.Should().Contain("/acme/WebServer/new-account");
        directory.NewOrder.Should().Contain("/acme/WebServer/new-order");

        // Revocation (RFC 8555 §7.6) and key rollover (RFC 8555 §7.3.5) are both implemented, so
        // the directory advertises revokeCert and keyChange, and each URL reaches a live endpoint.
        directory.RevokeCert.Should().NotBeNull("revocation is implemented; the directory must advertise it");
        directory.RevokeCert.Should().Contain("/acme/WebServer/revoke-cert");
        directory.KeyChange.Should().NotBeNull("key rollover is implemented; the directory must advertise it");
        directory.KeyChange.Should().Contain("/acme/WebServer/key-change");
    }

    [Fact]
    public async Task Directory_InvalidTemplate_Returns404()
    {
        var response = await _client.GetAsync("/acme/NonExistent/directory");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);

        var json = await response.Content.ReadAsStringAsync();
        var error = JsonSerializer.Deserialize<AcmeError>(json);
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task Directory_HasReplayNonceHeader()
    {
        var response = await _client.GetAsync("/acme/WebServer/directory");

        response.Headers.Should().ContainKey("Replay-Nonce");
        response.Headers.GetValues("Replay-Nonce").First().Should().NotBeNullOrEmpty();
    }

    #endregion

    #region Nonce Tests

    [Fact]
    public async Task NewNonce_Get_Returns204WithNonce()
    {
        var response = await _client.GetAsync("/acme/WebServer/new-nonce");

        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
        response.Headers.Should().ContainKey("Replay-Nonce");
    }

    [Fact]
    public async Task NewNonce_Head_Returns200WithNonce()
    {
        var request = new HttpRequestMessage(HttpMethod.Head, "/acme/WebServer/new-nonce");
        var response = await _client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Should().ContainKey("Replay-Nonce");
    }

    [Fact]
    public async Task NewNonce_EachRequestReturnsUniqueNonce()
    {
        var nonces = new HashSet<string>();
        for (var i = 0; i < 5; i++)
        {
            var response = await _client.GetAsync("/acme/WebServer/new-nonce");
            var nonce = response.Headers.GetValues("Replay-Nonce").First();
            nonces.Add(nonce);
        }

        nonces.Should().HaveCount(5);
    }

    #endregion

    #region Account Tests

    [Fact]
    public async Task NewAccount_ValidJws_Returns201()
    {
        var nonce = await GetFreshNonce();
        var (jws, _) = CreateNewAccountJws(nonce, new NewAccountRequest
        {
            Contact = new[] { "mailto:admin@example.com" },
            TermsOfServiceAgreed = true
        });

        var response = await PostJws("/acme/WebServer/new-account", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        response.Headers.Should().ContainKey("Location");

        var json = await response.Content.ReadAsStringAsync();
        var account = JsonSerializer.Deserialize<AcmeAccountResponse>(json);
        account!.Status.Should().Be("valid");
        account.Contact.Should().Contain("mailto:admin@example.com");
    }

    [Fact]
    public async Task NewAccount_SameKey_Returns200Existing()
    {
        using var rsa = RSA.Create(2048);

        // First request — create
        var nonce1 = await GetFreshNonce();
        var (jws1, _) = CreateNewAccountJws(nonce1, new NewAccountRequest
        {
            TermsOfServiceAgreed = true
        }, rsa);

        var response1 = await PostJws("/acme/WebServer/new-account", jws1);
        response1.StatusCode.Should().Be(HttpStatusCode.Created);
        var location1 = response1.Headers.GetValues("Location").First();

        // Second request with same key — should return existing
        var nonce2 = await GetFreshNonce();
        var (jws2, _) = CreateNewAccountJws(nonce2, new NewAccountRequest
        {
            TermsOfServiceAgreed = true
        }, rsa);

        var response2 = await PostJws("/acme/WebServer/new-account", jws2);
        response2.StatusCode.Should().Be(HttpStatusCode.OK);
        var location2 = response2.Headers.GetValues("Location").First();

        location1.Should().Be(location2);
    }

    [Fact]
    public async Task NewAccount_OnlyReturnExisting_NoAccount_Returns400()
    {
        var nonce = await GetFreshNonce();
        var (jws, _) = CreateNewAccountJws(nonce, new NewAccountRequest
        {
            OnlyReturnExisting = true
        });

        var response = await PostJws("/acme/WebServer/new-account", jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await response.Content.ReadAsStringAsync();
        var error = JsonSerializer.Deserialize<AcmeError>(json);
        error!.Type.Should().Be(AcmeErrorType.AccountDoesNotExist);
    }

    [Fact]
    public async Task NewAccount_BadNonce_Returns400()
    {
        var (jws, _) = CreateNewAccountJws("invalid-nonce-value", new NewAccountRequest
        {
            TermsOfServiceAgreed = true
        });

        var response = await PostJws("/acme/WebServer/new-account", jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await response.Content.ReadAsStringAsync();
        var error = JsonSerializer.Deserialize<AcmeError>(json);
        error!.Type.Should().Be(AcmeErrorType.BadNonce);
    }

    [Fact]
    public async Task NewAccount_ReplayedNonce_Returns400()
    {
        var nonce = await GetFreshNonce();

        // First use — should succeed
        var (jws1, _) = CreateNewAccountJws(nonce, new NewAccountRequest
        {
            TermsOfServiceAgreed = true
        });
        var response1 = await PostJws("/acme/WebServer/new-account", jws1);
        response1.StatusCode.Should().Be(HttpStatusCode.Created);

        // Second use of same nonce — should fail
        var (jws2, _) = CreateNewAccountJws(nonce, new NewAccountRequest
        {
            TermsOfServiceAgreed = true
        });
        var response2 = await PostJws("/acme/WebServer/new-account", jws2);
        response2.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task NewAccount_ForgedSignature_Returns400()
    {
        // The signing key does not match the embedded JWK: the protected header
        // carries one key's public JWK, but a different key produced the signature.
        // The server must reject this rather than trust the JWK. JwsService maps the
        // failed verification to Malformed (unit covered in JwsServiceTests); this
        // pins the controller boundary.
        using var signingKey = RSA.Create(2048);
        using var advertisedKey = RSA.Create(2048);

        var nonce = await GetFreshNonce();
        var jwkJson = ExportRsaJwk(advertisedKey);
        var payloadJson = JsonSerializer.Serialize(
            new NewAccountRequest { TermsOfServiceAgreed = true });

        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{_client.BaseAddress}}acme/WebServer/new-account","jwk":{{jwkJson}}}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");

        // Sign with the wrong key.
        var signature = signingKey.SignData(
            signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var jws = new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };

        var response = await PostJws("/acme/WebServer/new-account", jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    #endregion

    #region URL Encoding (Issue #18)

    [Fact]
    public async Task Directory_TemplateDisplayNameWithSpaces_EncodesUrls()
    {
        // "Web Server" is the display name of the seeded template whose programmatic
        // name is "WebServer". TemplateService accepts either; the directory must echo
        // the form the client requested, percent-encoded for URL safety.
        var response = await _client.GetAsync("/acme/Web%20Server/directory");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        var directory = JsonSerializer.Deserialize<AcmeDirectory>(json);

        directory.Should().NotBeNull();
        directory!.NewOrder.Should().Contain("/acme/Web%20Server/new-order");
        directory.NewOrder.Should().NotContain("/acme/Web Server/");
        directory.NewAccount.Should().Contain("/acme/Web%20Server/new-account");
        directory.NewNonce.Should().Contain("/acme/Web%20Server/new-nonce");
    }

    [Fact]
    public async Task NewAccount_TemplateWithSpaces_EncodedJwsUrl_Succeeds()
    {
        // Round-trip: directory emits encoded URLs, client embeds the encoded URL
        // in JWS protected header, server validates against its own encoded form.
        var nonce = await GetFreshNonce("/acme/Web%20Server/new-nonce");
        var (jws, _) = CreateNewAccountJws(
            nonce,
            new NewAccountRequest { TermsOfServiceAgreed = true },
            jwsUrlSuffix: "acme/Web%20Server/new-account");

        var response = await PostJws("/acme/Web%20Server/new-account", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task NewAccount_TemplateWithSpaces_DecodedJwsUrl_Succeeds()
    {
        // Resource equivalence: a client that decodes the URL from the directory
        // response before signing (e.g. win-acme) sends a literal space in the
        // JWS url header. RFC 8555 6.4 prescribes percent encoded form, but the
        // server treats the URL as a resource identifier and accepts both forms
        // via NormalizeAcmeUrl on AcmeControllerBase. Issue #21.
        var nonce = await GetFreshNonce("/acme/Web%20Server/new-nonce");
        var (jws, _) = CreateNewAccountJws(
            nonce,
            new NewAccountRequest { TermsOfServiceAgreed = true },
            jwsUrlSuffix: "acme/Web Server/new-account");

        var response = await PostJws("/acme/Web%20Server/new-account", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    #endregion

    #region ACME URL Origin (host header injection remediation)

    [Fact]
    public async Task Directory_SpoofedForwardedHost_IsIgnored()
    {
        // No trusted proxies are configured in the test host, so an X-Forwarded-Host
        // supplied by the client must not influence the ACME URLs. Before the fix AcmeUrl
        // read the raw header and would have emitted the attacker host.
        var request = new HttpRequestMessage(HttpMethod.Get, "/acme/WebServer/directory");
        request.Headers.Add("X-Forwarded-Host", "evil.example.com");
        request.Headers.Add("X-Forwarded-Proto", "https");

        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var directory = JsonSerializer.Deserialize<AcmeDirectory>(
            await response.Content.ReadAsStringAsync());

        directory!.NewOrder.Should().NotContain("evil.example.com");
        directory.NewOrder.Should().Contain("/acme/WebServer/new-order");
    }

    [Fact]
    public async Task Directory_ExternalUrlConfigured_UsesConfiguredOrigin()
    {
        // When Certus:ExternalUrl is set it is the authoritative origin for ACME URLs,
        // independent of the request host.
        using var customFactory = _factory.WithWebHostBuilder(b =>
            b.UseSetting("Certus:ExternalUrl", "https://acme.example.test"));
        var client = customFactory.CreateClient();

        var response = await client.GetAsync("/acme/WebServer/directory");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var directory = JsonSerializer.Deserialize<AcmeDirectory>(
            await response.Content.ReadAsStringAsync());

        directory!.NewOrder.Should().Be("https://acme.example.test/acme/WebServer/new-order");
        directory.NewAccount.Should().Be("https://acme.example.test/acme/WebServer/new-account");
    }

    #endregion

    #region Helpers

    private async Task<string> GetFreshNonce(string path = "/acme/WebServer/new-nonce")
    {
        var response = await _client.GetAsync(path);
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    private async Task<HttpResponseMessage> PostJws(string url, JwsFlattenedRequest jws)
    {
        var json = JsonSerializer.Serialize(jws);
        var content = new StringContent(json, Encoding.UTF8, "application/jose+json");
        return await _client.PostAsync(url, content);
    }

    private (JwsFlattenedRequest Jws, string JwkJson) CreateNewAccountJws(
        string nonce,
        NewAccountRequest payload,
        RSA? rsa = null,
        string jwsUrlSuffix = "acme/WebServer/new-account")
    {
        var disposeRsa = rsa == null;
        rsa ??= RSA.Create(2048);

        try
        {
            var jwkJson = ExportRsaJwk(rsa);
            var payloadJson = JsonSerializer.Serialize(payload);

            var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{_client.BaseAddress}}{{jwsUrlSuffix}}","jwk":{{jwkJson}}}""";

            var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
            var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return (new JwsFlattenedRequest
            {
                Protected = protectedB64,
                Payload = payloadB64,
                Signature = JwsService.Base64UrlEncode(signature)
            }, jwkJson);
        }
        finally
        {
            if (disposeRsa) rsa.Dispose();
        }
    }

    private static string ExportRsaJwk(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var n = JwsService.Base64UrlEncode(p.Modulus!);
        var e = JwsService.Base64UrlEncode(p.Exponent!);
        return $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
    }

    #endregion
}
