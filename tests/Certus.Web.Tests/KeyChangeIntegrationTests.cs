using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for POST /acme/{template}/key-change (RFC 8555 §7.3.5).
/// The request is a nested JWS: the outer JWS is signed by the old account key (kid) and its
/// payload is an inner JWS signed by the new key (jwk). Each test creates real accounts through
/// new-account so it controls both key pairs and can sign both layers.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class KeyChangeIntegrationTests : IDisposable
{
    private const string KeyChangePath = "/acme/WebServer/key-change";

    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public KeyChangeIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
    }

    [Fact]
    public async Task KeyChange_HappyPath_SwapsKeyAndOldKeyStopsWorking()
    {
        var (account, oldKey) = await CreateAccountAsync();
        var newKey = NewKey();

        var jws = await BuildKeyChangeJws(oldKey, newKey, account.Kid, account.Kid);
        var response = await PostJws(KeyChangePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // The stored account key is now the new key.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var stored = await db.AcmeAccounts.FirstAsync(a => a.AccountId == account.AccountId);
            stored.JwkThumbprint.Should().Be(
                JwsService.ComputeThumbprint(ExportRsaJwk(newKey)),
                "a successful rollover replaces the account key");
        }

        // The new key now authenticates the account; the old key no longer does.
        var accountPath = AccountPath(account.AccountId);
        var withNew = await PostJws(accountPath, await BuildKidPostAsGet(newKey, account.Kid, accountPath));
        withNew.StatusCode.Should().Be(HttpStatusCode.OK, "the new key is now the account key");

        var withOld = await PostJws(accountPath, await BuildKidPostAsGet(oldKey, account.Kid, accountPath));
        withOld.StatusCode.Should().Be(HttpStatusCode.Forbidden, "the old key was replaced");
    }

    [Fact]
    public async Task KeyChange_WrongOldKey_Returns400Malformed()
    {
        var (account, oldKey) = await CreateAccountAsync();
        var newKey = NewKey();
        // The inner payload claims an oldKey that is not the account's current key.
        using var wrongOldKey = RSA.Create(2048);

        var jws = await BuildKeyChangeJws(
            oldKey, newKey, account.Kid, account.Kid, oldKeyOverride: wrongOldKey);
        var response = await PostJws(KeyChangePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task KeyChange_NewKeyAlreadyRegistered_Returns409WithLocation()
    {
        var (accountA, oldKeyA) = await CreateAccountAsync();
        var (accountB, keyB) = await CreateAccountAsync();

        // Roll account A onto account B's key, which is already in use.
        var jws = await BuildKeyChangeJws(oldKeyA, keyB, accountA.Kid, accountA.Kid);
        var response = await PostJws(KeyChangePath, jws);

        // Read the body before asserting. This test failed twice under the full Release suite
        // (issue #127) and the status code alone did not say why; the ACME problem document
        // names the refusal, so carry it into the failure message.
        var body = await response.Content.ReadAsStringAsync();

        response.StatusCode.Should().Be(HttpStatusCode.Conflict, "the response body was {0}", body);
        response.Headers.Location.Should().NotBeNull(
            "a 409 must name the account that already holds the key; the response body was {0}", body);
        response.Headers.Location!.ToString().Should().Be(accountB.Kid,
            "the 409 points at the account that already holds the key (RFC 8555 §7.3.5)");
    }

    #region Helpers

    private record AccountInfo(string Kid, string AccountId);

    private RSA NewKey()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        return rsa;
    }

    private async Task<(AccountInfo Account, RSA Rsa)> CreateAccountAsync()
    {
        var rsa = NewKey();
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:keychange@example.com" }
        });

        var url = ToAbsoluteUrl("/acme/WebServer/new-account");
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";
        var jws = SignJws(rsa, headerJson, payloadJson);

        var response = await PostJws("/acme/WebServer/new-account", jws);

        // Assert rather than EnsureSuccessStatusCode: every test here builds its accounts through
        // this helper, and a bare HttpRequestException names neither the status nor the problem
        // document, which is what made the issue #127 failure unreadable after the fact.
        var body = await response.Content.ReadAsStringAsync();
        response.IsSuccessStatusCode.Should().BeTrue(
            "new-account must succeed before the key-change assertions mean anything; " +
            "the status was {0} and the body was {1}", response.StatusCode, body);

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    /// <summary>
    /// Builds a key-change request: the outer JWS is signed by the old account key (kid) and its
    /// payload is an inner JWS signed by the new key (jwk) carrying { account, oldKey }. Pass
    /// oldKeyOverride to put a different key in the inner oldKey field than the account's current one.
    /// </summary>
    private async Task<JwsFlattenedRequest> BuildKeyChangeJws(
        RSA oldKey, RSA newKey, string kid, string accountUrl, RSA? oldKeyOverride = null)
    {
        var url = ToAbsoluteUrl(KeyChangePath);

        // Inner JWS — signed by the new key, no nonce (RFC 8555 §7.3.5).
        var newJwk = ExportRsaJwk(newKey);
        var oldJwk = ExportRsaJwk(oldKeyOverride ?? oldKey);
        var innerHeaderJson = $$"""{"alg":"RS256","url":"{{url}}","jwk":{{newJwk}}}""";
        var innerPayloadJson = $$"""{"account":"{{accountUrl}}","oldKey":{{oldJwk}}}""";
        var innerJws = SignJws(newKey, innerHeaderJson, innerPayloadJson);

        // Outer JWS — signed by the old account key, its payload is the inner JWS.
        var nonce = await GetFreshNonce();
        var outerHeaderJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        var outerPayloadJson = JsonSerializer.Serialize(innerJws);
        return SignJws(oldKey, outerHeaderJson, outerPayloadJson);
    }

    /// <summary>Builds a kid-authenticated POST-as-GET (empty payload) signed by the given key.</summary>
    private async Task<JwsFlattenedRequest> BuildKidPostAsGet(RSA rsa, string kid, string path)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(path);
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        return SignJws(rsa, headerJson, string.Empty);
    }

    private static string AccountPath(string accountId) => $"/acme/WebServer/acct/{accountId}";

    private string ToAbsoluteUrl(string path)
    {
        var encodedPath = new Microsoft.AspNetCore.Http.PathString(path).ToUriComponent();
        return $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";
    }

    private static JwsFlattenedRequest SignJws(RSA rsa, string headerJson, string payloadJson)
    {
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = string.IsNullOrEmpty(payloadJson)
            ? string.Empty
            : JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };
    }

    private async Task<string> GetFreshNonce()
    {
        var response = await _client.GetAsync("/acme/WebServer/new-nonce");
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    private async Task<HttpResponseMessage> PostJws(string url, JwsFlattenedRequest jws)
    {
        var json = JsonSerializer.Serialize(jws);
        var content = new StringContent(json, Encoding.UTF8, "application/jose+json");
        return await _client.PostAsync(url, content);
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
