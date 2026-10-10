using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Issue #336 at the wire. The CA is reached and refuses this service's own
/// credentials on the submit, which used to land on the finalize's general catch:
/// the order was burned to invalid and the client was told 500 serverInternal,
/// "Failed to submit certificate request to the CA."
///
/// Two things are proved here that neither the mapping test nor the service tests
/// can prove on their own. That the outcome, the status code and the problem type
/// compose into one response, and that the operator remediation this condition
/// generates does not travel on this wire. The second is the reason this file is an
/// integration test at all: the guidance names the service's own computer account,
/// and the assertion has to run against the bytes the client actually receives.
/// </summary>
[Trait("Category", "Integration")]
public class CaAccessDeniedFinalizeIntegrationTests
    : IClassFixture<CaAccessDeniedFinalizeIntegrationTests.DeniedSubmitFactory>, IDisposable
{
    private readonly DeniedSubmitFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public CaAccessDeniedFinalizeIntegrationTests(DeniedSubmitFactory factory)
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
    public async Task Finalize_CaDeniesAccess_Answers503ServiceUnavailableAndTheOrderSurvives()
    {
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "denied.example.com");
        var orderId = order.Location.Split('/').Last();
        await DriveOrderToReadyAsync(orderId);

        var response = await FinalizeAsync(rsa, account.Kid, order, "denied.example.com");

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable,
            "a refused credential is our problem to fix and the client's to wait out");
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());

        error.Should().NotBeNull();
        error!.Type.Should().Be(AcmeErrorType.ServiceUnavailable);
        error.Status.Should().Be(503);
        error.Type.Should().NotBe(AcmeErrorType.Unauthorized,
            "RFC 8555 section 6.7 gives unauthorized to a client lacking authorization, " +
            "and this client is authorized; the missing permission is ours");

        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "an ACME protocol response carries a nonce even when the CA refuses us");

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var stored = await db.AcmeOrders.SingleAsync(o => o.OrderId == orderId);
        stored.Status.Should().Be("ready",
            "nothing reached the CA, so the claim is given back and the client can retry " +
            "this same order once an administrator grants the permission");
        stored.CsrDer.Should().BeNull();
        stored.ErrorJson.Should().BeNull();
    }

    [Fact]
    public async Task Finalize_CaDeniesAccess_TellsTheClientNothingAboutOurCa()
    {
        // The disclosure decision, pinned where the bytes leave. The remediation for
        // this condition names the computer account the service enrols as and points
        // at the CA console; it goes to the log and to the administrator
        // authenticated surfaces, both of which are audiences this one is not.
        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateOrderAsync(rsa, account.Kid, "quiet.example.com");
        await DriveOrderToReadyAsync(order.Location.Split('/').Last());

        var response = await FinalizeAsync(rsa, account.Kid, order, "quiet.example.com");
        var body = await response.Content.ReadAsStringAsync();

        body.Should().NotContain(Environment.MachineName,
            "the service account is exactly what must not travel on this wire");
        body.Should().NotContain("Security",
            "the CA console's Security tab is operator guidance, not client guidance");
        body.Should().NotContain("permission",
            "naming the missing permission describes our CA's access control to a client");
        body.Should().NotContain("Certificate Authority console");

        var error = JsonSerializer.Deserialize<AcmeError>(body);
        error!.Detail.Should().NotBeNullOrEmpty(
            "saying nothing useful is not the same as saying nothing at all");
    }

    #region Test Helpers

    private record AccountInfo(string Kid, string AccountId);

    private record OrderInfo(string Location, OrderResponse? OrderResponse);

    /// <summary>
    /// Challenge validation cannot run under TestServer, so the order is put into
    /// the state finalize requires directly, the way every other finalize test in
    /// this assembly does.
    /// </summary>
    private async Task DriveOrderToReadyAsync(string orderId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var entity = await db.AcmeOrders.SingleAsync(o => o.OrderId == orderId);
        entity.Status = "ready";
        await db.SaveChangesAsync();
    }

    private async Task<HttpResponseMessage> FinalizeAsync(
        RSA rsa, string kid, OrderInfo order, string domain)
    {
        var finalizePath = new Uri(order.OrderResponse!.Finalize).AbsolutePath;
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, kid, finalizePath, nonce,
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
        var nonce = await GetFreshNonce();
        var payload = new NewOrderRequest
        {
            Identifiers = [new AcmeIdentifier { Type = "dns", Value = domain }],
        };
        var jws = CreateKidJws(rsa, kid, "/acme/WebServer/new-order", nonce, payload);
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

    /// <summary>
    /// A CA that behaves normally everywhere except the submit, which is what makes
    /// this test possible at all: the order has to be created and the template
    /// resolved before a finalize can be refused, so a stub that throws on every
    /// call would fail long before the arm under test.
    /// </summary>
    public sealed class DeniedSubmitFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existing = services.SingleOrDefault(d => d.ServiceType == typeof(IAdcsClient));
                if (existing != null)
                    services.Remove(existing);

                services.AddSingleton<IAdcsClient>(new DeniedSubmitAdcsClient());
            });
        }
    }

    /// <summary>
    /// Delegates everything to a real <see cref="MockAdcsClient"/> except the
    /// submit, which raises what AdcsClient raises when the CA refuses this
    /// service's credentials.
    /// </summary>
    private sealed class DeniedSubmitAdcsClient : IAdcsClient
    {
        private readonly MockAdcsClient _inner = new();

        public Task<SubmitResult> SubmitCertificateRequestAsync(
            string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
            => throw new CaAccessDeniedException(
                CaAccessDeniedException.EnrollPermissionMessage,
                new UnauthorizedAccessException("simulated E_ACCESSDENIED"));

        public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
            => _inner.GetCaInfoAsync(cancellationToken);

        public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(
            CancellationToken cancellationToken = default)
            => _inner.GetTemplatesAsync(cancellationToken);

        public Task<CertificateResult> GetCertificateAsync(
            int requestId, CancellationToken cancellationToken = default)
            => _inner.GetCertificateAsync(requestId, cancellationToken);

        public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
            CertificateQuery query, CancellationToken cancellationToken = default)
            => _inner.QueryCertificatesAsync(query, cancellationToken);

        public Task<CaRequestStatus?> GetRequestStatusAsync(
            int requestId, CancellationToken cancellationToken = default)
            => _inner.GetRequestStatusAsync(requestId, cancellationToken);

        public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(
            CancellationToken cancellationToken = default)
            => _inner.GetCaCertificateChainAsync(cancellationToken);

        public Task RevokeCertificateAsync(
            string serialNumber, int reason, CancellationToken cancellationToken = default)
            => _inner.RevokeCertificateAsync(serialNumber, reason, cancellationToken);
    }
}
