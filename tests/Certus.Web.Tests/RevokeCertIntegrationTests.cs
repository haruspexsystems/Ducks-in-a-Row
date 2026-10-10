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
/// Integration tests for POST /acme/{template}/revoke-cert (RFC 8555 §7.6).
/// Certificates are seeded directly (mirroring CertificateDownloadIntegrationTests)
/// because driving the full order lifecycle to an issued certificate needs the
/// background challenge validator. Each test controls the certificate's key pair so it
/// can sign with either the owning account key (kid) or the certificate key (jwk).
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class RevokeCertIntegrationTests : IDisposable
{
    private const string RevokePath = "/acme/WebServer/revoke-cert";

    /// <summary>
    /// CA request ids for the seeded rows, one per row, from a range no mock
    /// issuance in this host reaches. See the comment at the seed itself.
    /// Static because xunit builds a fresh instance of this class per test.
    /// </summary>
    private static int _nextAdcsRequestId = 7100;

    private static int NextRequestId() => Interlocked.Increment(ref _nextAdcsRequestId);

    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public RevokeCertIntegrationTests(CertusWebApplicationFactory factory)
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
    public async Task Revoke_WithAccountKey_Returns200AndMarksRevoked()
    {
        var (account, rsa) = await CreateAccountAsync();
        using var certKey = RSA.Create(2048);
        using var cert = CreateSelfSignedCert(certKey, "CN=revoke-account-key.example.com");
        var certId = await SeedCertificateAsync(account.AccountId, cert);

        var jws = await BuildKidRevokeJws(rsa, account.Kid, cert, reason: null);
        var response = await PostJws(RevokePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var stored = await db.AcmeCertificates.FirstAsync(c => c.CertificateId == certId);
        stored.RevokedAt.Should().NotBeNull("a successful revocation records the timestamp");
        stored.RevokedReason.Should().Be(0, "an absent reason defaults to unspecified (0)");
    }

    [Fact]
    public async Task Revoke_WithCertificateKey_Returns200()
    {
        // RFC 8555 §7.6 also accepts a JWS signed by the certificate's own key pair (jwk),
        // proving possession without the account key.
        var (account, _) = await CreateAccountAsync();
        using var certKey = RSA.Create(2048);
        using var cert = CreateSelfSignedCert(certKey, "CN=revoke-cert-key.example.com");
        await SeedCertificateAsync(account.AccountId, cert);

        var jws = await BuildJwkRevokeJws(certKey, cert, reason: 1);
        var response = await PostJws(RevokePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Revoke_SignedByOtherAccount_Returns403Unauthorized()
    {
        var (owner, _) = await CreateAccountAsync();
        var (attacker, attackerRsa) = await CreateAccountAsync();
        using var certKey = RSA.Create(2048);
        using var cert = CreateSelfSignedCert(certKey, "CN=revoke-unauthorized.example.com");
        await SeedCertificateAsync(owner.AccountId, cert);

        // Signed with a valid account key that does not own the certificate.
        var jws = await BuildKidRevokeJws(attackerRsa, attacker.Kid, cert, reason: null);
        var response = await PostJws(RevokePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var error = JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task Revoke_AlreadyRevoked_Returns400AlreadyRevoked()
    {
        var (account, rsa) = await CreateAccountAsync();
        using var certKey = RSA.Create(2048);
        using var cert = CreateSelfSignedCert(certKey, "CN=revoke-twice.example.com");
        await SeedCertificateAsync(account.AccountId, cert);

        var first = await PostJws(RevokePath, await BuildKidRevokeJws(rsa, account.Kid, cert, reason: null));
        first.StatusCode.Should().Be(HttpStatusCode.OK);

        var second = await PostJws(RevokePath, await BuildKidRevokeJws(rsa, account.Kid, cert, reason: null));
        second.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(await second.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.AlreadyRevoked);
    }

    [Fact]
    public async Task Revoke_UnsupportedReason_Returns400BadRevocationReason()
    {
        // Reason 7 is unused in RFC 5280 §5.3.1. The reason is validated before the
        // certificate is located, so no seeded certificate is needed here.
        var (account, rsa) = await CreateAccountAsync();
        using var certKey = RSA.Create(2048);
        using var cert = CreateSelfSignedCert(certKey, "CN=revoke-bad-reason.example.com");

        var jws = await BuildKidRevokeJws(rsa, account.Kid, cert, reason: 7);
        var response = await PostJws(RevokePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.BadRevocationReason);
    }

    [Fact]
    public async Task Revoke_SubmittedCertificateIsNotTheIssuedOne_Returns404()
    {
        // Regression for the jwk possession bypass. An attacker crafts a certificate with their
        // own key whose serial collides with a victim's issued certificate, then signs with that
        // key (jwk). The serial lookup hits the victim row, but the submitted bytes are not the
        // issued certificate, so the request must be rejected rather than authorized by the
        // attacker's own key. The stored row is seeded under the attacker serial to force the
        // collision while keeping the victim certificate as the stored bytes.
        var (account, _) = await CreateAccountAsync();

        using var attackerKey = RSA.Create(2048);
        using var attackerCert = CreateSelfSignedCert(attackerKey, "CN=attacker.example.com");
        using var victimKey = RSA.Create(2048);
        using var victimCert = CreateSelfSignedCert(victimKey, "CN=victim.example.com");

        await SeedCertificateAsync(account.AccountId, victimCert, serialOverride: attackerCert.SerialNumber);

        var jws = await BuildJwkRevokeJws(attackerKey, attackerCert, reason: null);
        var response = await PostJws(RevokePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var error = JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    #region Helpers

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
            Contact = new[] { "mailto:revoke@example.com" }
        });

        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{_client.BaseAddress}}acme/WebServer/new-account","jwk":{{jwkJson}}}""";
        var jws = SignJws(rsa, headerJson, payloadJson);

        var response = await PostJws("/acme/WebServer/new-account", jws);
        response.EnsureSuccessStatusCode();

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    /// <summary>
    /// Seeds a valid order and certificate owned by the given account, recording the leaf
    /// serial the revoke path matches on. Pass serialOverride to store a serial that differs
    /// from the certificate's own (used to simulate a serial collision). Returns the public
    /// certificate ID.
    /// </summary>
    private async Task<string> SeedCertificateAsync(
        string accountId, X509Certificate2 cert, string? serialOverride = null)
    {
        var certId = "revoke-cert-" + Guid.NewGuid().ToString("N")[..8];

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var dbAccount = await db.AcmeAccounts.FirstAsync(a => a.AccountId == accountId);

        var order = new AcmeOrder
        {
            OrderId = "revoke-order-" + Guid.NewGuid().ToString("N")[..8],
            AccountId = dbAccount.Id,
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = "[]",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CertificateId = certId
        };
        db.AcmeOrders.Add(order);
        await db.SaveChangesAsync();

        db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = certId,
            OrderId = order.Id,
            CertificatePem = cert.ExportCertificatePem(),
            SerialNumber = serialOverride ?? cert.SerialNumber,
            // Distinctive, and one of its own per seeded row. MockAdcsClient
            // numbers its own requests from 1, so a seeded row claiming request 1
            // shares that bridge with the first certificate any other test in
            // this host issues, and
            // CertificateSyncService.ClearReleasedRevocationStampsAsync reads
            // exactly that bridge (issue #375): a revoked ACME row whose request
            // id the inventory reports as issued, in a pass that started after
            // the stamp, has that stamp cleared. That un-revoked the certificate
            // under Revoke_AlreadyRevoked_Returns400AlreadyRevoked between its
            // two calls and answered the second with 200 (issue #432). One id
            // per row rather than one for the class, because the bridge is
            // read both ways: OrderService.StampInventoryRowAsync writes the
            // inventory by the same key.
            AdcsRequestId = NextRequestId(),
            IssuedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        return certId;
    }

    private async Task<JwsFlattenedRequest> BuildKidRevokeJws(
        RSA rsa, string kid, X509Certificate2 cert, int? reason)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(RevokePath);
        var payloadJson = JsonSerializer.Serialize(BuildRevokePayload(cert, reason));
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        return SignJws(rsa, headerJson, payloadJson);
    }

    private async Task<JwsFlattenedRequest> BuildJwkRevokeJws(
        RSA rsa, X509Certificate2 cert, int? reason)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(RevokePath);
        var jwkJson = ExportRsaJwk(rsa);
        var payloadJson = JsonSerializer.Serialize(BuildRevokePayload(cert, reason));
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";
        return SignJws(rsa, headerJson, payloadJson);
    }

    private static RevokeCertRequest BuildRevokePayload(X509Certificate2 cert, int? reason)
        => new()
        {
            Certificate = JwsService.Base64UrlEncode(cert.RawData),
            Reason = reason
        };

    private string ToAbsoluteUrl(string path)
    {
        var encodedPath = new Microsoft.AspNetCore.Http.PathString(path).ToUriComponent();
        return $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";
    }

    private static JwsFlattenedRequest SignJws(RSA rsa, string headerJson, string payloadJson)
    {
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

    private static X509Certificate2 CreateSelfSignedCert(RSA key, string subject)
    {
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
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

/// <summary>
/// The CA down path for revoke-cert: when the ADCS revoke call fails with the RPC unavailable
/// HRESULT the endpoint returns 503 serviceUnavailable, mirroring the other endpoints that
/// depend on the CA. Uses the shared unavailable CA factory whose IAdcsClient throws on every
/// call, so the certificate is seeded directly and signed with its own key (no account lookup).
/// </summary>
[Trait("Category", "Integration")]
public class RevokeCertCaUnavailableTests
    : IClassFixture<CaUnavailableIntegrationTests.UnavailableCaFactory>
{
    private const string RevokePath = "/acme/WebServer/revoke-cert";

    private readonly CaUnavailableIntegrationTests.UnavailableCaFactory _factory;
    private readonly HttpClient _client;

    public RevokeCertCaUnavailableTests(CaUnavailableIntegrationTests.UnavailableCaFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Revoke_CaUnavailable_Returns503ServiceUnavailable()
    {
        using var certKey = RSA.Create(2048);
        var req = new CertificateRequest("CN=revoke-ca-down.example.com", certKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        await SeedAccountOrderAndCertAsync(cert);

        var nonce = (await _client.GetAsync("/acme/WebServer/new-nonce"))
            .Headers.GetValues("Replay-Nonce").First();
        var url = $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{RevokePath}";
        var jwkJson = ExportRsaJwk(certKey);
        var payloadJson = JsonSerializer.Serialize(new RevokeCertRequest
        {
            Certificate = JwsService.Base64UrlEncode(cert.RawData)
        });
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = certKey.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var jws = new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };

        var content = new StringContent(JsonSerializer.Serialize(jws), Encoding.UTF8, "application/jose+json");
        var response = await _client.PostAsync(RevokePath, content);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        var error = JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.ServiceUnavailable);
    }

    private async Task SeedAccountOrderAndCertAsync(X509Certificate2 cert)
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var account = new AcmeAccount
        {
            AccountId = "seed-acct-" + suffix,
            JwkJson = "{}",
            JwkThumbprint = "seed-thumb-" + suffix,
            Status = "valid"
        };
        db.AcmeAccounts.Add(account);
        await db.SaveChangesAsync();

        var certId = "seed-cert-" + suffix;
        var order = new AcmeOrder
        {
            OrderId = "seed-order-" + suffix,
            AccountId = account.Id,
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = "[]",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CertificateId = certId
        };
        db.AcmeOrders.Add(order);
        await db.SaveChangesAsync();

        db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = certId,
            OrderId = order.Id,
            CertificatePem = cert.ExportCertificatePem(),
            SerialNumber = cert.SerialNumber,
            // Distinctive for the same reason as the helper above, and out of
            // that helper's range. This factory's CA is unavailable, so no
            // inventory row can collide today, but the value is not worth leaving
            // as the one number that would.
            AdcsRequestId = 7201,
            IssuedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
    }

    private static string ExportRsaJwk(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var n = JwsService.Base64UrlEncode(p.Modulus!);
        var e = JwsService.Base64UrlEncode(p.Exponent!);
        return $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
    }
}
