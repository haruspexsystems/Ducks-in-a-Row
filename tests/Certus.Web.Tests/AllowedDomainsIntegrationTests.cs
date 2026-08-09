using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Verifies the allowed domain policy at the ACME surface. The factory seeds
/// a wizard status file restricting issuance to home.local; orders inside
/// that namespace issue, everything else is refused with a compound
/// rejectedIdentifier problem naming each refused identifier (RFC 8555
/// 6.7.1), refusals land in the audit table, edits to the file apply with no
/// restart, and finalize re-checks the policy against the stored order. The
/// shared factory (no status file) covers the unrestricted path in the
/// existing ACME tests.
/// </summary>
[Trait("Category", "Integration")]
public class AllowedDomainsIntegrationTests
    : IClassFixture<AllowedDomainsIntegrationTests.AllowedDomainsFactory>, IDisposable
{
    private readonly AllowedDomainsFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AllowedDomainsIntegrationTests(AllowedDomainsFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
    }

    [Theory]
    [InlineData("web.home.local")]
    [InlineData("a.b.home.local")]
    [InlineData("HOME.LOCAL")]
    public async Task NewOrder_AllowedDomain_Returns201(string domain)
    {
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid, domain);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task NewOrder_SuffixLookalike_Returns400RejectedIdentifier()
    {
        // myhome.local ends with home.local as a string but is a different
        // domain; the policy matches on label boundaries.
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid, "myhome.local");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Detail.Should().Contain("myhome.local");
        error.Detail.Should().Contain("Settings");
        error.Subproblems.Should().ContainSingle();
        error.Subproblems![0].Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Subproblems[0].Identifier!.Value.Should().Be("myhome.local");
    }

    [Fact]
    public async Task NewOrder_MixedIdentifiers_ListsEveryRefusedNameAsASubproblem()
    {
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid,
            "ok.home.local", "bad.other.local", "worse.example");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Subproblems.Should().HaveCount(2);
        error.Subproblems!.Select(s => s.Identifier!.Value)
            .Should().ContainInOrder("bad.other.local", "worse.example");
    }

    [Fact]
    public async Task NewOrder_WildcardWithAllowedBase_Returns201()
    {
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid, "*.home.local");

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task NewOrder_WildcardWithRefusedBase_Returns400()
    {
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid, "*.other.local");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Subproblems![0].Identifier!.Value.Should().Be("*.other.local");
    }

    [Fact]
    public async Task NewOrder_PolicyEditApplies_WithoutRestart()
    {
        var (account, rsa) = await CreateAccountAsync();
        try
        {
            var refused = await PostNewOrderAsync(rsa, account.Kid, "web.hotreload.example");
            refused.StatusCode.Should().Be(HttpStatusCode.BadRequest);

            // A settings page save rewrites the file; the same host must honor
            // the wider list on the very next order, no restart involved.
            _factory.WritePolicy(enabled: true, "home.local", "hotreload.example");

            var allowed = await PostNewOrderAsync(rsa, account.Kid, "web.hotreload.example");
            allowed.StatusCode.Should().Be(HttpStatusCode.Created);
        }
        finally
        {
            _factory.WritePolicy(enabled: true, "home.local");
        }
    }

    [Fact]
    public async Task NewOrder_Rejection_WritesAnAuditRow()
    {
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid,
            "ok.home.local", "auditcheck.other.local");
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.DomainPolicyRejections
            .SingleAsync(r => r.RejectedIdentifiers.Contains("auditcheck.other.local"));

        row.AccountId.Should().Be(account.AccountId);
        row.TemplateId.Should().Be("WebServer");
        row.RequestedIdentifiers.Should().Be("ok.home.local, auditcheck.other.local");
        row.RejectedIdentifiers.Should().Be("auditcheck.other.local");
        row.Stage.Should().Be("newOrder");
        row.OccurredAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task Finalize_PolicyTightenedAfterCreation_Returns400AndOrderStaysReady()
    {
        var (account, rsa) = await CreateAccountAsync();
        try
        {
            // Order created while the domain is allowed.
            var order = await CreateOrderAsync(rsa, account.Kid, "finalizecheck.home.local");
            var orderId = order.Location.Split('/').Last();

            // Challenge validation cannot run under TestServer, so drive the
            // order to ready directly, the state finalize requires.
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
                var entity = await db.AcmeOrders.SingleAsync(o => o.OrderId == orderId);
                entity.Status = "ready";
                await db.SaveChangesAsync();
            }

            // The admin tightens the policy between creation and finalize.
            _factory.WritePolicy(enabled: true, "elsewhere.example");

            var finalizePath = new Uri(order.OrderResponse!.Finalize).AbsolutePath;
            var nonce = await GetFreshNonce();
            var jws = CreateKidJws(rsa, account.Kid, finalizePath, nonce,
                new FinalizeRequest { Csr = JwsService.Base64UrlEncode(BuildCsr("finalizecheck.home.local")) });
            var response = await PostJws(finalizePath, jws);

            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            var error = JsonSerializer.Deserialize<AcmeError>(
                await response.Content.ReadAsStringAsync());
            error!.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
            error.Subproblems![0].Identifier!.Value.Should().Be("finalizecheck.home.local");

            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

                // The order stays ready: re-allowing the domain lets the
                // client retry this same order.
                (await db.AcmeOrders.SingleAsync(o => o.OrderId == orderId))
                    .Status.Should().Be("ready");

                var row = await db.DomainPolicyRejections
                    .SingleAsync(r => r.RejectedIdentifiers.Contains("finalizecheck.home.local"));
                row.Stage.Should().Be("finalize");
                row.AccountId.Should().Be(account.AccountId);
            }
        }
        finally
        {
            _factory.WritePolicy(enabled: true, "home.local");
        }
    }

    #region Test Helpers

    private record AccountInfo(string Kid, string AccountId);

    private record OrderInfo(string Location, OrderResponse? OrderResponse);

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

    private async Task<HttpResponseMessage> PostNewOrderAsync(
        RSA rsa, string kid, params string[] domains)
    {
        var nonce = await GetFreshNonce();
        var payload = new NewOrderRequest
        {
            Identifiers = domains
                .Select(d => new AcmeIdentifier { Type = "dns", Value = d })
                .ToArray(),
        };
        var jws = CreateKidJws(rsa, kid, "/acme/WebServer/new-order", nonce, payload);
        return await PostJws("/acme/WebServer/new-order", jws);
    }

    private async Task<OrderInfo> CreateOrderAsync(RSA rsa, string kid, string domain)
    {
        var response = await PostNewOrderAsync(rsa, kid, domain);
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
        var payloadJson = payload != null
            ? JsonSerializer.Serialize(payload)
            : "";

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

    /// <summary>
    /// Test factory that seeds a wizard status file restricting issuance to
    /// home.local, following the EnabledTemplatesFactory pattern.
    /// </summary>
    public sealed class AllowedDomainsFactory : CertusWebApplicationFactory
    {
        private static long _writeCounter;

        public string StatusFilePath => Path.Combine(TempDataDir, SetupStatus.FileName);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            // Written before the host starts; the policy reads it lazily on
            // the first order.
            WritePolicy(enabled: true, "home.local");
        }

        /// <summary>
        /// Rewrite the policy and bump the file's write time monotonically,
        /// so the policy's write time cache always sees a change even when
        /// two writes land within the file system timestamp resolution.
        /// </summary>
        public void WritePolicy(bool enabled, params string[] domains)
        {
            new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = ["WebServer"],
                AllowedDomainsEnabled = enabled,
                AllowedDomains = domains.ToList(),
            }.Save(StatusFilePath);

            var bump = Interlocked.Increment(ref _writeCounter);
            File.SetLastWriteTimeUtc(StatusFilePath, DateTime.UtcNow.AddSeconds(bump));
        }
    }
}
