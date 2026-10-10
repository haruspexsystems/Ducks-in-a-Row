using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The RFC 9773 §5 "replaces" member on the wire: a verified identifier is
/// echoed on the 201 and on every later fetch of the order (the section's
/// MUST), a second live order naming the same certificate answers 409
/// alreadyReplaced, and an invalid identifier refuses the whole new-order
/// rather than being silently dropped. The outcome matrix lives in
/// Certus.Core.Tests (ReplacesResolutionTests); this file proves the wiring.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class ReplacesIntegrationTests : IDisposable
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public ReplacesIntegrationTests(CertusWebApplicationFactory factory)
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
    public async Task NewOrder_WithAVerifiedReplaces_EchoesItOnCreateAndOnFetch()
    {
        var (account, rsa) = await CreateAccountAsync();
        var ariId = await SeedIssuedCertificateAsync(account.AccountId, "echo.replaces.example.com");

        var payload = new NewOrderRequest
        {
            Identifiers = new[]
            {
                new AcmeIdentifier { Type = "dns", Value = "echo.replaces.example.com" }
            },
            Replaces = ariId
        };
        var jws = CreateKidJws(rsa, account.Kid, "/acme/WebServer/new-order",
            await GetFreshNonce(), payload);
        var response = await PostJws("/acme/WebServer/new-order", jws);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var order = JsonSerializer.Deserialize<OrderResponse>(
            await response.Content.ReadAsStringAsync());
        order!.Replaces.Should().Be(ariId, "RFC 9773 §5: an accepted replaces is reflected");

        // And on the POST-as-GET fetch of the same order.
        var location = response.Headers.GetValues("Location").First();
        var orderPath = new Uri(location).AbsolutePath;
        var fetchJws = CreateKidJws(rsa, account.Kid, orderPath, await GetFreshNonce(), null);
        var fetch = await PostJws(orderPath, fetchJws);

        fetch.StatusCode.Should().Be(HttpStatusCode.OK);
        var fetched = JsonSerializer.Deserialize<OrderResponse>(
            await fetch.Content.ReadAsStringAsync());
        fetched!.Replaces.Should().Be(ariId);
    }

    [Fact]
    public async Task NewOrder_NamingAnAlreadyReplacedCertificate_Returns409()
    {
        var (account, rsa) = await CreateAccountAsync();
        var ariId = await SeedIssuedCertificateAsync(account.AccountId, "dup.replaces.example.com");

        var payload = new NewOrderRequest
        {
            Identifiers = new[]
            {
                new AcmeIdentifier { Type = "dns", Value = "dup.replaces.example.com" }
            },
            Replaces = ariId
        };

        var first = await PostJws("/acme/WebServer/new-order",
            CreateKidJws(rsa, account.Kid, "/acme/WebServer/new-order", await GetFreshNonce(), payload));
        first.StatusCode.Should().Be(HttpStatusCode.Created);

        var second = await PostJws("/acme/WebServer/new-order",
            CreateKidJws(rsa, account.Kid, "/acme/WebServer/new-order", await GetFreshNonce(), payload));

        second.StatusCode.Should().Be(HttpStatusCode.Conflict);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await second.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.AlreadyReplaced);
    }

    [Fact]
    public async Task NewOrder_WithAMalformedReplaces_Returns400InsteadOfDroppingIt()
    {
        var (account, rsa) = await CreateAccountAsync();

        var payload = new NewOrderRequest
        {
            Identifiers = new[]
            {
                new AcmeIdentifier { Type = "dns", Value = "bad.replaces.example.com" }
            },
            Replaces = "not-an-ari-identifier"
        };
        var response = await PostJws("/acme/WebServer/new-order",
            CreateKidJws(rsa, account.Kid, "/acme/WebServer/new-order", await GetFreshNonce(), payload));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    /// <summary>
    /// Seeds an issued certificate for the account: a valid order carrying the
    /// given dns identifier and the certificate row, whose leaf carries the
    /// AKI the ARI identifier is built from. Returns the identifier.
    /// </summary>
    private async Task<string> SeedIssuedCertificateAsync(string accountId, string dnsName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=" + dnsName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(
                RandomNumberGenerator.GetBytes(20)));
        using var leaf = request.Create(
            new X500DistinguishedName("CN=" + dnsName),
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(335),
            RandomNumberGenerator.GetBytes(12));

        var suffix = Guid.NewGuid().ToString("N")[..8];
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var dbAccount = await db.AcmeAccounts.FirstAsync(a => a.AccountId == accountId);

        var order = new AcmeOrder
        {
            OrderId = "repl-order-" + suffix,
            AccountId = dbAccount.Id,
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = JsonSerializer.Serialize(
                new[] { new AcmeIdentifier { Type = "dns", Value = dnsName } }),
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CertificateId = "repl-cert-" + suffix
        };
        db.AcmeOrders.Add(order);
        await db.SaveChangesAsync();

        db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = "repl-cert-" + suffix,
            OrderId = order.Id,
            CertificatePem = leaf.ExportCertificatePem(),
            AdcsRequestId = Random.Shared.Next(500000, 900000),
            SerialNumber = leaf.SerialNumber,
            IssuedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        return AriCertificateId.FromCertificate(leaf)!;
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
            Contact = new[] { "mailto:replaces@example.com" }
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
