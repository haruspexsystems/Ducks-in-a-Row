using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for /acme/{template}/issuer-cert, the "up" link target
/// RFC 8555 §7.4.2 requires on a certificate download. It answers on two methods
/// with deliberately opposite caching: GET and HEAD are anonymous and publicly
/// cacheable, POST is an authenticated POST-as-GET that carries a nonce and
/// no-store (issue #373). Both are template scoped, so each inherits the fail
/// closed template policy and refuses an unknown template like every other ACME
/// route. Issues #318 and #373.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class IssuerCertificateIntegrationTests : IDisposable
{
    private const string IssuerCertPath = "/acme/WebServer/issuer-cert";

    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public IssuerCertificateIntegrationTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
    }

    [Fact]
    public async Task IssuerCert_ReturnsThePemChain()
    {
        var response = await _client.GetAsync(IssuerCertPath);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType
            .Should().Be("application/pem-certificate-chain");

        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("-----BEGIN CERTIFICATE-----");
        body.Should().Contain("-----END CERTIFICATE-----");
    }

    [Fact]
    public async Task IssuerCert_IsPubliclyCacheable()
    {
        // RFC 8555 §7.4.2 describes the up target as an indefinitely cacheable
        // resource, and the max-age is what keeps an anonymous GET from becoming
        // one CA round trip per request.
        var response = await _client.GetAsync(IssuerCertPath);

        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.Public.Should().BeTrue();
        response.Headers.CacheControl.NoStore.Should().BeFalse();
        response.Headers.CacheControl.MaxAge
            .Should().Be(AcmeIssuerChainCache.Ttl);

        // Both middlewares that blanket the ACME surface with no-store skip this
        // path, so nothing is left behind to contradict the header above.
        response.Headers.Pragma.Should().BeEmpty();
        response.Headers.Contains("Replay-Nonce").Should().BeFalse(
            "this endpoint carries no nonce, which is why RFC 8555 6.1 no-store does not apply");
    }

    [Fact]
    public async Task OrdinaryAcmeResponse_StillCarriesNoStoreAndANonce()
    {
        // The guard on the exclusion above: the issuer endpoint is the only ACME
        // path exempt from RFC 8555 6.1, and widening it would silently make the
        // rest of the protocol surface cacheable. (The renewalInfo path skips
        // only the nonce and deliberately keeps no-store;
        // RenewalInfoIntegrationTests pins that side.)
        var response = await _client.GetAsync("/acme/WebServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
        response.Headers.Contains("Replay-Nonce").Should().BeTrue();
    }

    [Fact]
    public async Task IssuerCert_AnsweredForHead()
    {
        // Declared explicitly on the action, because the ACME protocol fallback is
        // an unconstrained catch all that would otherwise claim the HEAD and report
        // a live resource as missing (issue #147).
        using var request = new HttpRequestMessage(HttpMethod.Head, IssuerCertPath);

        var response = await _client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task IssuerCert_UnknownTemplate_Returns404()
    {
        var response = await _client.GetAsync("/acme/NoSuchTemplate/issuer-cert");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task IssuerCert_PostAsGet_ReturnsThePemChain()
    {
        // The regression test for issue #373. A client that follows the "up" link the
        // way RFC 8555 §7.1 describes, with POST-as-GET, used to get 405 and could not
        // assemble the chain, so issuance failed after validation had already
        // succeeded. Caddy (acmez) and Apache mod_md both died here.
        var (account, key) = await CreateAccountAsync();

        var response = await PostJws(
            IssuerCertPath, await BuildKidPostAsGet(key, account.Kid, IssuerCertPath));

        var body = await response.Content.ReadAsStringAsync();
        response.StatusCode.Should().Be(HttpStatusCode.OK, "the body was {0}", body);
        response.Content.Headers.ContentType?.MediaType
            .Should().Be("application/pem-certificate-chain");
        body.Should().Contain("-----BEGIN CERTIFICATE-----");
    }

    [Fact]
    public async Task IssuerCert_PostAsGet_ServesTheSameChainAsTheAnonymousGet()
    {
        // One resource, two methods. If these ever diverge a client would assemble a
        // different path depending on how it fetched the issuer.
        var (account, key) = await CreateAccountAsync();

        var viaGet = await (await _client.GetAsync(IssuerCertPath)).Content.ReadAsStringAsync();
        var viaPost = await (await PostJws(
            IssuerCertPath, await BuildKidPostAsGet(key, account.Kid, IssuerCertPath)))
            .Content.ReadAsStringAsync();

        viaPost.Should().Be(viaGet);
    }

    [Fact]
    public async Task IssuerCert_PostAsGet_CarriesANonceAndIsNotCacheable()
    {
        // The other half of issue #373, and the reason both middleware exemptions are
        // gated on the method rather than on the path alone. An authenticated response
        // is an ordinary ACME response: RFC 8555 §6.5 requires a Replay-Nonce on every
        // successful response to a POST, and §6.1 no-store then applies to it.
        var (account, key) = await CreateAccountAsync();

        var response = await PostJws(
            IssuerCertPath, await BuildKidPostAsGet(key, account.Kid, IssuerCertPath));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "RFC 8555 6.5 requires a fresh nonce on every successful response to a POST");
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
        response.Headers.CacheControl.Public.Should().BeFalse(
            "an authenticated response is not the cacheable up target of 7.4.2");

        // Pragma is what separates the two middlewares here, and it is the only
        // observable difference the security headers gate makes: AcmeNonceMiddleware
        // already stamps Cache-Control on this arm, so without this assertion that
        // gate is untested and a later tidy up would drop it. The GET arm asserts
        // Pragma is empty for the mirror reason.
        response.Headers.Pragma.Should().NotBeEmpty(
            "the security headers middleware exempts only the cacheable fetch, so an " +
            "authenticated POST is stamped like every other ACME response");
    }

    [Fact]
    public async Task IssuerCert_PostAsGet_UnknownTemplate_Returns404()
    {
        // The template gate runs on the POST arm too. AuthenticateKidJwsAsync takes a
        // template but never reads it, so leaning on authentication alone would have
        // made POST a way round the fail closed template policy of issue #101.
        var (account, key) = await CreateAccountAsync();
        const string unknown = "/acme/NoSuchTemplate/issuer-cert";

        var response = await PostJws(unknown, await BuildKidPostAsGet(key, account.Kid, unknown));

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task IssuerCert_PostWithoutAValidJws_IsRefused()
    {
        // The POST arm is authenticated, so an unsigned POST is refused rather than
        // served. It is still a better answer than the 405 this used to give, because
        // it names the real problem in an ACME problem document.
        using var content = new StringContent("{}", Encoding.UTF8, "application/jose+json");

        var response = await _client.PostAsync(IssuerCertPath, content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
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
            Contact = new[] { "mailto:issuer-cert@example.com" }
        });

        var url = ToAbsoluteUrl("/acme/WebServer/new-account");
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";
        var jws = SignJws(rsa, headerJson, payloadJson);

        var response = await PostJws("/acme/WebServer/new-account", jws);

        var body = await response.Content.ReadAsStringAsync();
        response.IsSuccessStatusCode.Should().BeTrue(
            "new-account must succeed before the issuer-cert assertions mean anything; " +
            "the status was {0} and the body was {1}", response.StatusCode, body);

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    /// <summary>Builds a kid-authenticated POST-as-GET (empty payload) signed by the given key.</summary>
    private async Task<JwsFlattenedRequest> BuildKidPostAsGet(RSA rsa, string kid, string path)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(path);
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        return SignJws(rsa, headerJson, string.Empty);
    }

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
