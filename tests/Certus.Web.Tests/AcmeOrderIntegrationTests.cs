using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the ACME order lifecycle: new-order, authz, challenge, finalize, cert download.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class AcmeOrderIntegrationTests : IDisposable
{
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AcmeOrderIntegrationTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
    }

    #region New Order Tests

    [Fact]
    public async Task NewOrder_ValidRequest_Returns201WithOrder()
    {
        var (account, rsa) = await CreateAccountAsync();

        var nonce = await GetFreshNonce();
        var orderPayload = new NewOrderRequest
        {
            Identifiers = new[]
            {
                new AcmeIdentifier { Type = "dns", Value = "test.example.com" }
            }
        };

        var jws = CreateKidJws(
            rsa, account.Kid,
            "/acme/WebServer/new-order",
            nonce, orderPayload);

        var response = await PostJws("/acme/WebServer/new-order", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        response.Headers.Should().ContainKey("Location");

        var json = await response.Content.ReadAsStringAsync();
        var order = JsonSerializer.Deserialize<OrderResponse>(json);

        order.Should().NotBeNull();
        order!.Status.Should().Be("pending");
        order.Identifiers.Should().HaveCount(1);
        order.Identifiers[0].Value.Should().Be("test.example.com");
        order.Authorizations.Should().HaveCount(1);
        order.Finalize.Should().Contain("/finalize");
        order.Certificate.Should().BeNull();
    }

    [Fact]
    public async Task NewOrder_MultipleIdentifiers_CreatesMultipleAuthz()
    {
        var (account, rsa) = await CreateAccountAsync();

        var nonce = await GetFreshNonce();
        var orderPayload = new NewOrderRequest
        {
            Identifiers = new[]
            {
                new AcmeIdentifier { Type = "dns", Value = "a.example.com" },
                new AcmeIdentifier { Type = "dns", Value = "b.example.com" }
            }
        };

        var jws = CreateKidJws(rsa, account.Kid, "/acme/WebServer/new-order", nonce, orderPayload);
        var response = await PostJws("/acme/WebServer/new-order", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var order = JsonSerializer.Deserialize<OrderResponse>(
            await response.Content.ReadAsStringAsync());
        order!.Authorizations.Should().HaveCount(2);
    }

    [Fact]
    public async Task NewOrder_NoIdentifiers_Returns400()
    {
        var (account, rsa) = await CreateAccountAsync();

        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, account.Kid, "/acme/WebServer/new-order", nonce,
            new NewOrderRequest { Identifiers = Array.Empty<AcmeIdentifier>() });

        var response = await PostJws("/acme/WebServer/new-order", jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task NewOrder_WildcardDomain_OnlyGetsDns01Challenge()
    {
        var (account, rsa) = await CreateAccountAsync();

        var nonce = await GetFreshNonce();
        var orderPayload = new NewOrderRequest
        {
            Identifiers = new[]
            {
                new AcmeIdentifier { Type = "dns", Value = "*.wildcard-test.example.com" }
            }
        };

        var jws = CreateKidJws(rsa, account.Kid, "/acme/WebServer/new-order", nonce, orderPayload);
        var response = await PostJws("/acme/WebServer/new-order", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var order = JsonSerializer.Deserialize<OrderResponse>(
            await response.Content.ReadAsStringAsync());

        // Get the authorization
        var authzPath = new Uri(order!.Authorizations[0]).AbsolutePath;
        var nonce2 = await GetFreshNonce();
        var authzJws = CreateKidJws(rsa, account.Kid, authzPath, nonce2, (object?)null);
        var authzResponse = await PostJws(authzPath, authzJws);
        var authz = JsonSerializer.Deserialize<AuthorizationResponse>(
            await authzResponse.Content.ReadAsStringAsync());

        authz!.Wildcard.Should().BeTrue();
        // RFC 8555 §7.1.4: the wildcard authorization identifier is the base domain,
        // without the "*." prefix
        authz.Identifier.Value.Should().Be("wildcard-test.example.com");
        authz.Challenges.Should().HaveCount(1);
        authz.Challenges[0].Type.Should().Be("dns-01");
    }

    [Fact]
    public async Task NewOrder_UnknownKid_Returns401AccountDoesNotExist()
    {
        using var rsa = RSA.Create(2048);
        var fakeKid = $"{_client.BaseAddress}acme/WebServer/acct/does-not-exist";
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, fakeKid, "/acme/WebServer/new-order", nonce,
            new NewOrderRequest
            {
                Identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "test.example.com" } }
            });

        var response = await PostJws("/acme/WebServer/new-order", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.AccountDoesNotExist);
    }

    [Fact]
    public async Task NewOrder_TemplateWithSpaces_DecodedJwsUrl_Succeeds()
    {
        // Issue #21: a client authenticated by kid (e.g. win-acme) decodes the URL
        // from the new-order response before signing the next request and sends
        // the literal "Web Server" form in the JWS url header. AcmeUrl produces
        // the percent encoded form. NormalizeAcmeUrl on AcmeControllerBase makes
        // both forms equivalent so the order endpoint accepts the request.
        var (account, rsa) = await CreateAccountForTemplateAsync("Web%20Server");

        var nonce = await GetFreshNonce("/acme/Web%20Server/new-nonce");
        var orderPayload = new NewOrderRequest
        {
            Identifiers = new[]
            {
                new AcmeIdentifier { Type = "dns", Value = "winacme.example.com" }
            }
        };

        // JWS url uses the literal-space (decoded) form, matching win-acme.
        var jws = CreateKidJwsWithRawUrl(
            rsa, account.Kid,
            jwsUrl: $"{_client.BaseAddress}acme/Web Server/new-order",
            nonce, orderPayload);

        var response = await PostJws("/acme/Web%20Server/new-order", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task NewOrder_UnsupportedIdentifierType_Returns400()
    {
        var (account, rsa) = await CreateAccountAsync();

        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, account.Kid, "/acme/WebServer/new-order", nonce,
            new NewOrderRequest
            {
                Identifiers = new[] { new AcmeIdentifier { Type = "ip", Value = "1.2.3.4" } }
            });

        var response = await PostJws("/acme/WebServer/new-order", jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.UnsupportedIdentifier);
    }

    #endregion

    #region Order Query Tests

    [Fact]
    public async Task GetOrder_PostAsGet_ReturnsOrder()
    {
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "query.example.com");

        // Extract order URL from Location header
        var orderUrl = order.Location;
        var orderPath = new Uri(orderUrl).AbsolutePath;

        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, account.Kid, orderPath, nonce, (object?)null);

        var response = await PostJws(orderPath, jws);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var orderResponse = JsonSerializer.Deserialize<OrderResponse>(
            await response.Content.ReadAsStringAsync());
        orderResponse!.Status.Should().Be("pending");
    }

    #endregion

    #region Authorization Query Tests

    [Fact]
    public async Task GetAuthorization_ReturnsAuthzWithChallenges()
    {
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "authz-test.example.com");

        // Get the authorization URL from the order
        var authzUrl = order.OrderResponse!.Authorizations[0];
        var authzPath = new Uri(authzUrl).AbsolutePath;

        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, account.Kid, authzPath, nonce, (object?)null);
        var response = await PostJws(authzPath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var authz = JsonSerializer.Deserialize<AuthorizationResponse>(
            await response.Content.ReadAsStringAsync());
        authz!.Identifier.Type.Should().Be("dns");
        authz.Identifier.Value.Should().Be("authz-test.example.com");
        authz.Status.Should().Be("pending");
        authz.Challenges.Should().HaveCount(3);
        authz.Challenges.Select(c => c.Type).Should()
            .Contain("http-01")
            .And.Contain("dns-01")
            .And.Contain("tls-alpn-01");
        authz.Challenges.Should().OnlyContain(c => !string.IsNullOrEmpty(c.Token));
        authz.Challenges.Should().OnlyContain(c => c.Status == "pending");
    }

    #endregion

    #region Challenge Response Tests

    [Fact]
    public async Task RespondToChallenge_Pending_TransitionsToProcessing()
    {
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "chall-test.example.com");

        // Get the challenge URL from the authorization
        var authzUrl = order.OrderResponse!.Authorizations[0];
        var authzPath = new Uri(authzUrl).AbsolutePath;

        var nonce1 = await GetFreshNonce();
        var authzJws = CreateKidJws(rsa, account.Kid, authzPath, nonce1, (object?)null);
        var authzResponse = await PostJws(authzPath, authzJws);
        var authz = JsonSerializer.Deserialize<AuthorizationResponse>(
            await authzResponse.Content.ReadAsStringAsync());

        var challengeUrl = authz!.Challenges[0].Url;
        var challengePath = new Uri(challengeUrl).AbsolutePath;

        // Respond to challenge (POST empty JSON object)
        var nonce2 = await GetFreshNonce();
        var challJws = CreateKidJws(rsa, account.Kid, challengePath, nonce2,
            new { }); // empty object per RFC 8555 §7.5.1
        var challResponse = await PostJws(challengePath, challJws);

        challResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var challenge = JsonSerializer.Deserialize<ChallengeResponse>(
            await challResponse.Content.ReadAsStringAsync());
        challenge!.Status.Should().Be("processing");
        challenge.Type.Should().Be("http-01");
    }

    #endregion

    #region Finalize Tests

    [Fact]
    public async Task FinalizeOrder_NotReady_Returns403()
    {
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "finalize-test.example.com");

        // Try to finalize a pending order (not ready)
        var finalizePath = new Uri(order.OrderResponse!.Finalize).AbsolutePath;
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, account.Kid, finalizePath, nonce,
            new FinalizeRequest { Csr = JwsService.Base64UrlEncode(new byte[] { 1, 2, 3 }) });

        var response = await PostJws(finalizePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.OrderNotReady);
    }

    #endregion

    #region Account Query Tests

    [Fact]
    public async Task GetAccount_PostAsGet_ReturnsAccount()
    {
        var (account, rsa) = await CreateAccountAsync();
        var acctPath = new Uri(account.Kid).AbsolutePath;

        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, account.Kid, acctPath, nonce, (object?)null);

        var response = await PostJws(acctPath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var acct = JsonSerializer.Deserialize<AcmeAccountResponse>(
            await response.Content.ReadAsStringAsync());
        acct!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task GetAccount_JwsUrlDoesNotMatch_Returns400()
    {
        // RFC 8555 §6.4: the server must verify the JWS url header matches the request URL.
        // The account endpoint now enforces this through the shared helper.
        var (account, rsa) = await CreateAccountAsync();
        var acctPath = new Uri(account.Kid).AbsolutePath;

        var nonce = await GetFreshNonce();
        var jws = CreateKidJwsWithRawUrl(
            rsa, account.Kid,
            jwsUrl: $"{_client.BaseAddress}acme/WebServer/new-order",
            nonce, (object?)null);

        var response = await PostJws(acctPath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    #endregion

    #region Test Helpers

    private record AccountInfo(string Kid, string AccountId);

    private record OrderInfo(
        string Location,
        OrderResponse? OrderResponse);

    private async Task<(AccountInfo Account, RSA Rsa)> CreateAccountAsync()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:test@example.com" }
        });

        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{_client.BaseAddress}}acme/WebServer/new-account","jwk":{{jwkJson}}}""";
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

        var response = await PostJws("/acme/WebServer/new-account", jws);
        response.EnsureSuccessStatusCode();

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    private async Task<OrderInfo> CreateOrderAsync(RSA rsa, string kid, string domain)
    {
        var nonce = await GetFreshNonce();
        var payload = new NewOrderRequest
        {
            Identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = domain } }
        };
        var jws = CreateKidJws(rsa, kid, "/acme/WebServer/new-order", nonce, payload);
        var response = await PostJws("/acme/WebServer/new-order", jws);
        response.StatusCode.Should().Be(HttpStatusCode.Created);

        var location = response.Headers.GetValues("Location").First();
        var orderResponse = JsonSerializer.Deserialize<OrderResponse>(
            await response.Content.ReadAsStringAsync());

        return new OrderInfo(location, orderResponse);
    }

    private JwsFlattenedRequest CreateKidJws(
        RSA rsa, string kid, string path, string nonce, object? payload)
    {
        var encodedPath = new Microsoft.AspNetCore.Http.PathString(path).ToUriComponent();
        var url = $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";
        var payloadJson = payload != null
            ? JsonSerializer.Serialize(payload)
            : ""; // POST-as-GET has empty payload

        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };
    }

    private async Task<string> GetFreshNonce(string path = "/acme/WebServer/new-nonce")
    {
        var response = await _client.GetAsync(path);
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    /// <summary>
    /// Creates an account against an arbitrary template path (encoded form).
    /// Used by the win-acme regression test that exercises the "Web Server"
    /// template (display name with spaces).
    /// </summary>
    private async Task<(AccountInfo Account, RSA Rsa)> CreateAccountForTemplateAsync(
        string encodedTemplate)
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce($"/acme/{encodedTemplate}/new-nonce");
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:test@example.com" }
        });

        var url = $"{_client.BaseAddress}acme/{encodedTemplate}/new-account";
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";
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

        var response = await PostJws($"/acme/{encodedTemplate}/new-account", jws);
        response.EnsureSuccessStatusCode();

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    /// <summary>
    /// Builds a kid-authenticated JWS where the protected header url is taken
    /// verbatim from the caller. Used to emulate clients (e.g. win-acme) that
    /// decode percent-encoded characters before signing.
    /// </summary>
    private JwsFlattenedRequest CreateKidJwsWithRawUrl(
        RSA rsa, string kid, string jwsUrl, string nonce, object? payload)
    {
        var payloadJson = payload != null
            ? JsonSerializer.Serialize(payload)
            : "";

        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{jwsUrl}}","kid":"{{kid}}"}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };
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
