using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for POST /acme/{template}/cert/{certId}.
/// Pins the RFC 8555 7.4.2 contract that the response body carries the full
/// PEM certificate chain (leaf + issuer) when the stored AcmeCertificate has
/// one, regardless of how the chain was built upstream. Issue #21.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class CertificateDownloadIntegrationTests : IDisposable
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public CertificateDownloadIntegrationTests(CertusWebApplicationFactory factory)
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
    public async Task DownloadCertificate_StoredChain_ReturnsBothCerts()
    {
        var (account, rsa) = await CreateAccountAsync();

        // Stage an order plus a certificate row whose CertificatePem holds two
        // PEM blocks: a leaf and an issuer. The controller must pass them both
        // through verbatim so certbot can parse fullchain into 2 certificates.
        var certId = await SeedCertificateAsync(account.AccountId);

        var response = await DownloadAsync(rsa, account.Kid, certId);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType
            .Should().Be("application/pem-certificate-chain");

        var body = await response.Content.ReadAsStringAsync();
        CountOccurrences(body, "-----BEGIN CERTIFICATE-----")
            .Should().Be(2, "RFC 8555 7.4.2 requires the full chain in the response");
        CountOccurrences(body, "-----END CERTIFICATE-----")
            .Should().Be(2);
    }

    [Fact]
    public async Task DownloadCertificate_Valid_CarriesUpLinkToTheIssuerEndpoint()
    {
        var (account, rsa) = await CreateAccountAsync();
        var certId = await SeedCertificateAsync(account.AccountId);

        var response = await DownloadAsync(rsa, account.Kid, certId);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.TryGetValues("Link", out var links).Should().BeTrue(
            "RFC 8555 7.4.2 requires at least one up link on the certificate response");
        links!.Should().Contain(link =>
            link.Contains("/acme/WebServer/issuer-cert", StringComparison.Ordinal)
            && link.Contains("rel=\"up\"", StringComparison.Ordinal));
    }

    // The gate itself (issue #318). Each of these is a shape no path in the product
    // can currently produce, which is the point: the check is what keeps it that way
    // if a future writer lets an order and its certificate drift apart.
    [Theory]
    [InlineData("pending")]
    [InlineData("ready")]
    [InlineData("processing")]
    [InlineData("invalid")]
    public async Task DownloadCertificate_OrderNotValid_Returns403(string orderStatus)
    {
        var (account, rsa) = await CreateAccountAsync();
        var certId = await SeedCertificateAsync(account.AccountId, orderStatus: orderStatus);

        var response = await DownloadAsync(rsa, account.Kid, certId);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task DownloadCertificate_OrderNamesADifferentCertificate_Returns403()
    {
        // A valid order that points somewhere else. RFC 8555 7.4.2 describes fetching
        // the certificate URL provided in the order, so a row the order does not name
        // is not that certificate even though the order reads valid.
        var (account, rsa) = await CreateAccountAsync();
        var certId = await SeedCertificateAsync(
            account.AccountId, orderCertificateId: "some-other-certificate");

        var response = await DownloadAsync(rsa, account.Kid, certId);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task DownloadCertificate_OtherAccount_Returns403()
    {
        var (owner, _) = await CreateAccountAsync();
        var (attacker, attackerRsa) = await CreateAccountAsync();
        var certId = await SeedCertificateAsync(owner.AccountId);

        var response = await DownloadAsync(attackerRsa, attacker.Kid, certId);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task DownloadCertificate_RevokedCertificate_StillReturns200()
    {
        // The control for the "valid alone is the whole set" decision. Revocation
        // stamps the certificate row and the inventory and never touches the order,
        // so a revoked certificate stays downloadable, which RFC 8555 permits and
        // which a status gate must not accidentally break.
        var (account, rsa) = await CreateAccountAsync();
        var certId = await SeedCertificateAsync(account.AccountId);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var stored = await db.AcmeCertificates.FirstAsync(c => c.CertificateId == certId);
            stored.RevokedAt = DateTime.UtcNow;
            stored.RevokedReason = 1;
            await db.SaveChangesAsync();
        }

        var response = await DownloadAsync(rsa, account.Kid, certId);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    /// <summary>
    /// Seeds an order and its certificate for the given account and returns the public
    /// certificate ID. Defaults to the only shape production can produce: a valid order
    /// naming this certificate. Pass orderStatus or orderCertificateId to stage a row
    /// the download gate must refuse.
    /// </summary>
    private async Task<string> SeedCertificateAsync(
        string accountId,
        string orderStatus = "valid",
        string? orderCertificateId = null)
    {
        var leafPem = GenerateSelfSignedCertPem("CN=leaf.example.com");
        var issuerPem = GenerateSelfSignedCertPem("CN=issuer.example.com");
        var chainPem = leafPem + "\n" + issuerPem;
        var certId = "test-cert-" + Guid.NewGuid().ToString("N").Substring(0, 8);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var dbAccount = await db.AcmeAccounts.FirstAsync(a => a.AccountId == accountId);
        var order = new AcmeOrder
        {
            OrderId = "order-" + Guid.NewGuid().ToString("N").Substring(0, 8),
            AccountId = dbAccount.Id,
            Status = orderStatus,
            TemplateId = "WebServer",
            IdentifiersJson = "[]",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CertificateId = orderCertificateId ?? certId
        };
        db.AcmeOrders.Add(order);
        await db.SaveChangesAsync();

        db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = certId,
            OrderId = order.Id,
            CertificatePem = chainPem,
            AdcsRequestId = 9999,
            IssuedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        return certId;
    }

    private async Task<HttpResponseMessage> DownloadAsync(RSA rsa, string kid, string certId)
    {
        var nonce = await GetFreshNonce();
        var path = $"/acme/WebServer/cert/{certId}";
        var jws = CreateKidJws(rsa, kid, path, nonce, payload: null);
        return await PostJws(path, jws);
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) != -1)
        {
            count++;
            index += needle.Length;
        }
        return count;
    }

    private static string GenerateSelfSignedCertPem(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return cert.ExportCertificatePem();
    }

    #region Account & JWS helpers (mirrors AcmeOrderIntegrationTests)

    private record AccountInfo(string Kid, string AccountId);

    private async Task<(AccountInfo Account, RSA Rsa)> CreateAccountAsync()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:certdl@example.com" }
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
