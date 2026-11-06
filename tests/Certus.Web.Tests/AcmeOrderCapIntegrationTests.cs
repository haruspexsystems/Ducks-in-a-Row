using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// The two resource caps on new-order from issue #632 (CRA R04), as a client
/// sees them: more identifiers than the cap is malformed, and an account at its
/// open order cap is rateLimited. Each test owns a host, because the caps are
/// settings and the shared factory runs at the defaults.
/// </summary>
[Trait("Category", "Integration")]
public class AcmeOrderCapIntegrationTests : IDisposable
{
    private readonly List<RSA> _keys = new();
    private readonly List<CappedFactory> _factories = new();

    public void Dispose()
    {
        foreach (var factory in _factories)
            factory.Dispose();
        foreach (var key in _keys)
            key.Dispose();
    }

    [Fact]
    public async Task NewOrder_OverTheIdentifierCap_IsMalformed_BeforeAnyIdentifierIsRead()
    {
        var client = Host(("Certus:RateLimiting:MaxIdentifiersPerOrder", "2"));
        var (kid, rsa) = await CreateAccountAsync(client);

        // The second identifier is not a valid name. If the loop ran first the
        // refusal would be the grammar's; the cap refusal names the count.
        var response = await PostNewOrderAsync(client, rsa, kid,
            "a.example.com", "not a domain", "c.example.com");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadProblemAsync(response);
        error.Type.Should().Be(AcmeErrorType.Malformed);
        error.Detail.Should().Contain("at most 2 identifiers");
    }

    [Fact]
    public async Task NewOrder_AtTheIdentifierCap_IsAccepted()
    {
        var client = Host(("Certus:RateLimiting:MaxIdentifiersPerOrder", "2"));
        var (kid, rsa) = await CreateAccountAsync(client);

        var response = await PostNewOrderAsync(client, rsa, kid, "a.example.com", "b.example.com");

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task NewOrder_AtTheOpenOrderCap_IsRateLimited_UntilAnOrderCloses()
    {
        var client = Host(("Certus:RateLimiting:MaxPendingOrdersPerAccount", "1"));
        var (kid, rsa) = await CreateAccountAsync(client);

        var first = await PostNewOrderAsync(client, rsa, kid, "first.example.com");
        first.StatusCode.Should().Be(HttpStatusCode.Created);

        var refused = await PostNewOrderAsync(client, rsa, kid, "second.example.com");
        refused.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        var error = await ReadProblemAsync(refused);
        error.Type.Should().Be(AcmeErrorType.RateLimited);
        error.Detail.Should().ContainEquivalentOf("too many");
        error.Detail.Should().Contain("limit of 1 orders");

        // Deactivating the open order's authorization invalidates the order,
        // which is one of the three ways the cap clears.
        var order = JsonSerializer.Deserialize<OrderResponse>(await first.Content.ReadAsStringAsync())!;
        var authzPath = new Uri(order.Authorizations[0]).AbsolutePath;
        var deactivate = await PostJwsAsync(client, rsa, kid, authzPath, new { status = "deactivated" });
        deactivate.StatusCode.Should().Be(HttpStatusCode.OK);

        var afterwards = await PostNewOrderAsync(client, rsa, kid, "third.example.com");
        afterwards.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task NewOrder_OpenOrderCap_IsPerAccount()
    {
        var client = Host(("Certus:RateLimiting:MaxPendingOrdersPerAccount", "1"));
        var (kid, rsa) = await CreateAccountAsync(client);
        (await PostNewOrderAsync(client, rsa, kid, "first.example.com"))
            .StatusCode.Should().Be(HttpStatusCode.Created);

        var (otherKid, otherRsa) = await CreateAccountAsync(client);
        var response = await PostNewOrderAsync(client, otherRsa, otherKid, "other.example.com");

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    private HttpClient Host(params (string Key, string Value)[] settings)
    {
        var factory = new CappedFactory(settings);
        _factories.Add(factory);
        return factory.CreateClient();
    }

    private static async Task<AcmeError> ReadProblemAsync(HttpResponseMessage response)
    {
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
        var error = JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync());
        error.Should().NotBeNull();
        return error!;
    }

    private async Task<(string Kid, RSA Rsa)> CreateAccountAsync(HttpClient client)
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        var p = rsa.ExportParameters(false);
        var jwkJson = $$"""{"kty":"RSA","n":"{{JwsService.Base64UrlEncode(p.Modulus!)}}","e":"{{JwsService.Base64UrlEncode(p.Exponent!)}}"}""";
        var nonce = await GetFreshNonceAsync(client);
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:test@example.com" }
        });
        var url = $"{client.BaseAddress}acme/WebServer/new-account";
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";

        var response = await client.PostAsync("/acme/WebServer/new-account", Sign(rsa, headerJson, payloadJson));
        response.EnsureSuccessStatusCode();
        return (response.Headers.GetValues("Location").First(), rsa);
    }

    private static Task<HttpResponseMessage> PostNewOrderAsync(
        HttpClient client, RSA rsa, string kid, params string[] domains)
    {
        var payload = new NewOrderRequest
        {
            Identifiers = domains.Select(d => new AcmeIdentifier { Type = "dns", Value = d }).ToArray()
        };
        return PostJwsAsync(client, rsa, kid, "/acme/WebServer/new-order", payload);
    }

    private static async Task<HttpResponseMessage> PostJwsAsync(
        HttpClient client, RSA rsa, string kid, string path, object payload)
    {
        var nonce = await GetFreshNonceAsync(client);
        var url = $"{client.BaseAddress!.Scheme}://{client.BaseAddress.Authority}{path}";
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        return await client.PostAsync(path, Sign(rsa, headerJson, JsonSerializer.Serialize(payload)));
    }

    private static StringContent Sign(RSA rsa, string headerJson, string payloadJson)
    {
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var jws = new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };
        return new StringContent(JsonSerializer.Serialize(jws), Encoding.UTF8, "application/jose+json");
    }

    private static async Task<string> GetFreshNonceAsync(HttpClient client)
    {
        var response = await client.GetAsync("/acme/WebServer/new-nonce");
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    /// <summary>
    /// The shared factory's settings plus the caps a test names. Rate limiting
    /// stays off, as in the shared factory: the caps apply either way.
    /// </summary>
    private sealed class CappedFactory : CertusWebApplicationFactory
    {
        private readonly (string Key, string Value)[] _settings;

        public CappedFactory((string Key, string Value)[] settings)
        {
            _settings = settings;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            foreach (var (key, value) in _settings)
                builder.UseSetting(key, value);
        }
    }
}
