using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Issue #330 at the wire. RFC 8555 section 7.1.3 gives an order an error member
/// and section 7.1.6 tells a client to read it once the order goes invalid.
/// <c>OrderService.ToResponse</c> built the order object without it, so nine
/// writers of <c>AcmeOrder.ErrorJson</c> were filling a column no client could
/// reach and a failed order answered with a status and nothing else.
///
/// These run over the real ACME conversation because that is the only place the
/// claim can be settled: the assertions are on the bytes a client receives, and
/// they read the raw JSON rather than only a deserialized
/// <see cref="OrderResponse"/>, which would pass just as happily on a member
/// serialized under the wrong name.
/// </summary>
[Trait("Category", "Integration")]
public class AcmeOrderErrorIntegrationTests
    : IClassFixture<CertusWebApplicationFactory>, IDisposable
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AcmeOrderErrorIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task PollingAnOrderKilledByADeactivation_ReadsWhyItDied()
    {
        // Driven entirely through the protocol, with no reach into the database:
        // an account, an order, a section 7.5.2 deactivation of its authorization,
        // and then the POST-as-GET a real client makes next. Before this change the
        // last response was a bare {"status":"invalid"} and the client had nowhere
        // left to look.
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "deactivated.example.com");

        var authzPath = new Uri(order.OrderResponse!.Authorizations[0]).AbsolutePath;
        var deactivate = await PostJws(authzPath, CreateKidJws(
            rsa, account.Kid, authzPath, await GetFreshNonce(),
            new AuthorizationUpdateRequest { Status = "deactivated" }));
        deactivate.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ReadOrderJsonAsync(rsa, account.Kid, order);

        body.Should().Contain("\"error\"",
            "the member RFC 8555 section 7.1.3 names has to be on the wire under " +
            "that name, not merely populated on a DTO");

        var polled = JsonSerializer.Deserialize<OrderResponse>(body)!;
        polled.Status.Should().Be("invalid");
        polled.Error.Should().NotBeNull();
        polled.Error!.Type.Should().Be(AcmeErrorType.Unauthorized,
            "section 6.7 gives unauthorized to a client whose authorization is gone, " +
            "and the client retired this one itself");
        polled.Error.Detail.Should().NotBeNullOrEmpty(
            "a problem document with no detail leaves the client exactly where it was");
    }

    [Fact]
    public async Task ACaRefusal_ReadsTheSameOnTheFinalizeAndOnTheOrder()
    {
        // The property issue #324 established, now that there are two wires to hold
        // it on. The finalize's problem document has always carried the CA's own
        // disposition message, so projecting the column discloses nothing new; what
        // it must not do is paraphrase, because then one refusal would read two ways
        // depending on which response the client happened to keep.
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "ca-refuses.example.com");
        await PointAtATemplateTheCaDoesNotPublishAsync(order.Location.Split('/').Last());

        var finalize = await FinalizeAsync(rsa, account.Kid, order, "ca-refuses.example.com");
        finalize.StatusCode.Should().Be(HttpStatusCode.InternalServerError);

        var refusal = JsonSerializer.Deserialize<AcmeError>(
            await finalize.Content.ReadAsStringAsync())!;
        refusal.Type.Should().Be(AcmeErrorType.ServerInternal);

        var polled = JsonSerializer.Deserialize<OrderResponse>(
            await ReadOrderJsonAsync(rsa, account.Kid, order))!;

        polled.Status.Should().Be("invalid");
        polled.Error.Should().NotBeNull(
            "the client that polls instead of reading the finalize response gets the " +
            "same answer");
        polled.Error!.Type.Should().Be(refusal.Type);
        refusal.Detail.Should().NotBeNullOrEmpty(
            "asserted before the comparison below, which two empty strings would " +
            "satisfy without either wire carrying anything");
        polled.Error.Detail.Should().Be(refusal.Detail,
            "string for string: one refusal, one description");
    }

    [Fact]
    public async Task ALiveOrder_SaysNothingAboutFailure()
    {
        // JsonIgnore WhenWritingNull is what keeps the member off an order that has
        // not failed, and the projection is unconditional, so this is where the two
        // meet. An "error": null on every pending order would be a wire change in
        // its own right, and clients do read the presence of the member.
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "healthy.example.com");

        var body = await ReadOrderJsonAsync(rsa, account.Kid, order);

        body.Should().NotContain("\"error\"");
        JsonSerializer.Deserialize<OrderResponse>(body)!.Status.Should().Be("pending");
    }

    #region Test Helpers

    private record AccountInfo(string Kid, string AccountId);

    private record OrderInfo(string Location, OrderResponse? OrderResponse);

    private async Task<string> ReadOrderJsonAsync(RSA rsa, string kid, OrderInfo order)
    {
        var path = new Uri(order.Location).AbsolutePath;
        var response = await PostJws(path, CreateKidJws(
            rsa, kid, path, await GetFreshNonce(), payload: null));
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Puts the order into the state a CA refusal needs: ready, and naming a
    /// template <see cref="Certus.Core.Adcs.MockAdcsClient"/> does not publish, so
    /// its submit answers Denied. Challenge validation cannot run under TestServer,
    /// so the ready half is written directly the way every other finalize test in
    /// this assembly does.
    /// </summary>
    private async Task PointAtATemplateTheCaDoesNotPublishAsync(string orderId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var entity = await db.AcmeOrders.SingleAsync(o => o.OrderId == orderId);
        entity.Status = "ready";
        entity.TemplateId = "NoSuchTemplate";
        await db.SaveChangesAsync();
    }

    private async Task<HttpResponseMessage> FinalizeAsync(
        RSA rsa, string kid, OrderInfo order, string domain)
    {
        var finalizePath = new Uri(order.OrderResponse!.Finalize).AbsolutePath;
        var jws = CreateKidJws(rsa, kid, finalizePath, await GetFreshNonce(),
            new FinalizeRequest { Csr = JwsService.Base64UrlEncode(BuildCsr(domain)) });
        return await PostJws(finalizePath, jws);
    }

    private static byte[] BuildCsr(string domain)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={domain}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(domain);
        request.CertificateExtensions.Add(sanBuilder.Build());
        return request.CreateSigningRequest();
    }

    private async Task<OrderInfo> CreateOrderAsync(RSA rsa, string kid, string domain)
    {
        var payload = new NewOrderRequest
        {
            Identifiers = [new AcmeIdentifier { Type = "dns", Value = domain }],
        };
        var jws = CreateKidJws(
            rsa, kid, "/acme/WebServer/new-order", await GetFreshNonce(), payload);
        var response = await PostJws("/acme/WebServer/new-order", jws);
        response.StatusCode.Should().Be(HttpStatusCode.Created);

        var location = response.Headers.GetValues("Location").First();
        var orderResponse = JsonSerializer.Deserialize<OrderResponse>(
            await response.Content.ReadAsStringAsync());
        return new OrderInfo(location, orderResponse);
    }

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

    private JwsFlattenedRequest CreateKidJws(
        RSA rsa, string kid, string path, string nonce, object? payload)
    {
        var encodedPath = new Microsoft.AspNetCore.Http.PathString(path).ToUriComponent();
        var url = $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";
        var payloadJson = payload != null ? JsonSerializer.Serialize(payload) : "";

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

    private async Task<string> GetFreshNonce()
    {
        var response = await _client.GetAsync("/acme/WebServer/new-nonce");
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    private async Task<HttpResponseMessage> PostJws(string url, JwsFlattenedRequest jws)
    {
        var content = new StringContent(
            JsonSerializer.Serialize(jws), Encoding.UTF8, "application/jose+json");
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
