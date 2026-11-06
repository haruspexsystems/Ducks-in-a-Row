using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;

namespace Certus.Service.Tests;

/// <summary>
/// An ACME client for one account against one template, signing every request with an
/// RS256 JWS the way Certus.Web.Tests' DeviceAttestIntegrationTests does, from which these
/// helpers come.
/// </summary>
public sealed class AcmeTestClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _template;
    private readonly RSA _key = RSA.Create(2048);

    public AcmeTestClient(HttpClient http, string template)
    {
        _http = http;
        _template = template;
    }

    /// <summary>The account URL, set by <see cref="CreateAccountAsync"/>.</summary>
    public string Kid { get; private set; } = "";

    public void Dispose() => _key.Dispose();

    public async Task CreateAccountAsync()
    {
        var nonce = await GetFreshNonceAsync();
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = ["mailto:service-tests@example.com"],
        });
        var headerJson =
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{_http.BaseAddress}}acme/{{_template}}/new-account","jwk":{{ExportJwk()}}}""";

        var response = await PostJwsAsync($"/acme/{_template}/new-account", Sign(headerJson, payloadJson));
        response.EnsureSuccessStatusCode();
        Kid = response.Headers.GetValues("Location").First();
    }

    /// <summary>
    /// A new order for one permanent-identifier, answered with its order path. A renewal names the
    /// certificate it replaces with its ARI identifier (RFC 9773 section 5).
    /// </summary>
    public async Task<(string OrderPath, OrderResponse Order)> NewDeviceOrderAsync(string identifierValue, string? replaces = null)
    {
        var response = await PostAsync($"/acme/{_template}/new-order", new NewOrderRequest
        {
            Identifiers = [new AcmeIdentifier { Type = "permanent-identifier", Value = identifierValue }],
            Replaces = replaces,
        });
        response.StatusCode.Should().Be(HttpStatusCode.Created, await response.Content.ReadAsStringAsync());

        var orderPath = new Uri(response.Headers.GetValues("Location").First()).AbsolutePath;
        return (orderPath, await ReadAsync<OrderResponse>(response));
    }

    public async Task<AuthorizationResponse> GetAuthorizationAsync(string path) =>
        await ReadAsync<AuthorizationResponse>(await PostAsGetAsync(path));

    public async Task<OrderResponse> GetOrderAsync(string path) =>
        await ReadAsync<OrderResponse>(await PostAsGetAsync(path));

    public Task<HttpResponseMessage> PostAsync(string path, object payload) => SendKidAsync(path, payload);

    public Task<HttpResponseMessage> FinalizeAsync(string path, byte[] csrDer) =>
        SendKidAsync(path, new FinalizeRequest { Csr = JwsService.Base64UrlEncode(csrDer) });

    /// <summary>The leaf of the chain at an order's certificate URL, fetched with POST-as-GET.</summary>
    public async Task<X509Certificate2> DownloadCertificateAsync(string path)
    {
        var pem = await (await PostAsGetAsync(path)).Content.ReadAsStringAsync();
        return X509Certificate2.CreateFromPem(pem);
    }

    /// <summary>revoke-cert (RFC 8555 section 7.6), signed by this account.</summary>
    public Task<HttpResponseMessage> RevokeAsync(byte[] certificateDer) =>
        SendKidAsync($"/acme/{_template}/revoke-cert", new RevokeCertRequest { Certificate = JwsService.Base64UrlEncode(certificateDer) });

    /// <summary>
    /// Polls <paramref name="read"/> until <paramref name="done"/> holds or the timeout
    /// passes, and answers the last value read either way, so the caller's assertion names
    /// the state it actually saw.
    /// </summary>
    public static async Task<T> PollAsync<T>(Func<Task<T>> read, Func<T, bool> done, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            var value = await read();
            if (done(value) || DateTime.UtcNow > deadline)
                return value;
            await Task.Delay(150);
        }
    }

    private async Task<HttpResponseMessage> PostAsGetAsync(string path)
    {
        var response = await SendKidAsync(path, payload: null);
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        return response;
    }

    private async Task<HttpResponseMessage> SendKidAsync(string path, object? payload)
    {
        var nonce = await GetFreshNonceAsync();
        var url = $"{_http.BaseAddress!.Scheme}://{_http.BaseAddress.Authority}{path}";
        // POST-as-GET carries an empty payload.
        var payloadJson = payload is null ? "" : JsonSerializer.Serialize(payload);
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{Kid}}"}""";
        return await PostJwsAsync(path, Sign(headerJson, payloadJson));
    }

    private JwsFlattenedRequest Sign(string headerJson, string payloadJson)
    {
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signature = _key.SignData(
            Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}"),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        };
    }

    private async Task<string> GetFreshNonceAsync()
    {
        var response = await _http.GetAsync($"/acme/{_template}/new-nonce");
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    private Task<HttpResponseMessage> PostJwsAsync(string path, JwsFlattenedRequest jws) =>
        _http.PostAsync(path, new StringContent(JsonSerializer.Serialize(jws), Encoding.UTF8, "application/jose+json"));

    private string ExportJwk()
    {
        var p = _key.ExportParameters(false);
        return $$"""{"kty":"RSA","n":"{{JwsService.Base64UrlEncode(p.Modulus!)}}","e":"{{JwsService.Base64UrlEncode(p.Exponent!)}}"}""";
    }

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<T>(await response.Content.ReadAsStringAsync())!;
}
