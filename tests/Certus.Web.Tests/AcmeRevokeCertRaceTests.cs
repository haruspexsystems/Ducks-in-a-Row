using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The race issue #226 closes, on the ACME surface: two revoke-cert requests for one
/// certificate in flight at once. The dashboard got its per serial gate in issue #203;
/// <c>OrderService.RevokeCertificateAsync</c> kept the same check then act shape, so
/// two concurrent ACME clients (or one client retrying its own request) could both read
/// <c>RevokedAt</c> as null and both send the CA a revocation.
///
/// <para>
/// The factory's CA parks the first revoke call until the test releases it, which holds
/// the winner inside the CA call while the second request arrives. The same test also
/// pins the gate as per serial rather than global, by revoking an unrelated certificate
/// while the winner is parked: that one must reach the CA, or the gate is a global lock
/// that would serialize every unrelated revocation in the installation.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public class AcmeRevokeCertRaceTests
    : IClassFixture<AcmeRevokeCertRaceTests.AcmeRevokeRaceCaFactory>, IDisposable
{
    private const string RevokePath = "/acme/WebServer/revoke-cert";

    private readonly AcmeRevokeRaceCaFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AcmeRevokeCertRaceTests(AcmeRevokeRaceCaFactory factory)
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
    public async Task Revoke_TwoSimultaneousAcmeRequests_OnlyOneReachesTheCa()
    {
        var stub = _factory.Client;
        var accountId = await SeedAccountAsync();

        using var targetKey = RSA.Create(2048);
        using var target = CreateSelfSignedCert(targetKey, "CN=acme-revoke-race.example.com");
        await SeedCertificateAsync(accountId, target, adcsRequestId: 8101);

        // An unrelated certificate, to prove the gate is keyed per serial.
        using var otherKey = RSA.Create(2048);
        using var other = CreateSelfSignedCert(otherKey, "CN=acme-revoke-race-other.example.com");
        await SeedCertificateAsync(accountId, other, adcsRequestId: 8102);

        // Every JWS is built up front, before any request is in flight. Each build
        // takes its own nonce and an ACME nonce is single use, so a JWS built after
        // the race started would be the losing request's second chance at a fresh
        // nonce rather than the replay of an in flight one. Building here also keeps
        // the loser from failing badNonce, which would turn a real regression into a
        // green test for the wrong reason.
        var winnerJws = await BuildJwkRevokeJws(targetKey, target, reason: 4);
        var loserJws = await BuildJwkRevokeJws(targetKey, target, reason: 4);
        var unrelatedJws = await BuildJwkRevokeJws(otherKey, other, reason: 4);

        try
        {
            // The winner: enters the CA call and parks there, holding the per serial
            // gate for the duration.
            var winner = PostJws(RevokePath, winnerJws);
            await stub.FirstRevokeEntered.WaitAsync(TimeSpan.FromSeconds(10));

            // The loser: must wait at the gate, short of the CA. The delay only gives
            // a regression time to show; with the gate in place the second request
            // cannot reach the stub while the winner is parked, so this cannot flake.
            var loser = PostJws(RevokePath, loserJws);
            await Task.Delay(250);
            stub.RevokeCalls.Should().Be(1,
                "the gate must hold the second request for the same serial short of the CA");

            // The unrelated certificate: must NOT be held. Asserted on the recorded
            // serials rather than the raw count, so a count of two cannot be read as
            // a pass when it was really the gated request leaking through.
            var unrelated = PostJws(RevokePath, unrelatedJws);
            await WaitForRevokeCallsAsync(stub, 2, TimeSpan.FromSeconds(10));
            stub.EnteredSerials.Should().BeEquivalentTo(
                new[] { target.SerialNumber, other.SerialNumber },
                "the gate is per serial, so an unrelated revocation runs while one is parked");

            stub.ReleaseRevokes();

            var responses = await Task.WhenAll(winner, loser, unrelated)
                .WaitAsync(TimeSpan.FromSeconds(30));

            // Deterministic roles: the winner held the gate before the loser was posted.
            responses[0].StatusCode.Should().Be(HttpStatusCode.OK);

            responses[1].StatusCode.Should().Be(HttpStatusCode.BadRequest);
            var error = JsonSerializer.Deserialize<AcmeError>(
                await responses[1].Content.ReadAsStringAsync());
            error!.Type.Should().Be(AcmeErrorType.AlreadyRevoked,
                "the loser re-reads the row inside the gate and finds it already revoked");

            responses[2].StatusCode.Should().Be(HttpStatusCode.OK);

            stub.RevokeCalls.Should().Be(2, "one CA call per certificate, never two for one");
        }
        finally
        {
            // A failing assert must not leave a server request parked on the release source.
            stub.ReleaseRevokes();
        }
    }

    private static async Task WaitForRevokeCallsAsync(
        BlockingRevokeAdcsClient stub, int expected, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (stub.RevokeCalls < expected && DateTime.UtcNow < deadline)
            await Task.Delay(25);
    }

    #region Helpers

    /// <summary>
    /// Seeds an ACME account row directly. The revocations here are signed with each
    /// certificate's own key pair (RFC 8555 §7.6 jwk form), so the account is only
    /// needed to satisfy the order's foreign key, never to authorize the request.
    /// </summary>
    private async Task<int> SeedAccountAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var account = new AcmeAccount
        {
            AccountId = "acme-race-account-" + Guid.NewGuid().ToString("N")[..8],
            JwkJson = """{"kty":"RSA","n":"race","e":"AQAB"}""",
            JwkThumbprint = "acme-race-thumb-" + Guid.NewGuid().ToString("N")[..8],
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        db.AcmeAccounts.Add(account);
        await db.SaveChangesAsync();

        return account.Id;
    }

    private async Task<string> SeedCertificateAsync(
        int accountId, X509Certificate2 cert, int adcsRequestId)
    {
        var certId = "acme-race-cert-" + Guid.NewGuid().ToString("N")[..8];

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var order = new AcmeOrder
        {
            OrderId = "acme-race-order-" + Guid.NewGuid().ToString("N")[..8],
            AccountId = accountId,
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
            AdcsRequestId = adcsRequestId,
            IssuedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        return certId;
    }

    private async Task<JwsFlattenedRequest> BuildJwkRevokeJws(
        RSA rsa, X509Certificate2 cert, int? reason)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(RevokePath);
        var jwkJson = ExportRsaJwk(rsa);
        var payloadJson = JsonSerializer.Serialize(new RevokeCertRequest
        {
            Certificate = JwsService.Base64UrlEncode(cert.RawData),
            Reason = reason
        });
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";
        return SignJws(rsa, headerJson, payloadJson);
    }

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

    private Task<HttpResponseMessage> PostJws(string url, JwsFlattenedRequest jws)
    {
        var json = JsonSerializer.Serialize(jws);
        var content = new StringContent(json, Encoding.UTF8, "application/jose+json");
        return _client.PostAsync(url, content);
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
    /// Factory whose IAdcsClient is the shared parking stub, so one revoke can be held
    /// inside the CA call while others arrive.
    /// </summary>
    public sealed class AcmeRevokeRaceCaFactory : CertusWebApplicationFactory
    {
        public BlockingRevokeAdcsClient Client { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existing = services.SingleOrDefault(d => d.ServiceType == typeof(IAdcsClient));
                if (existing != null)
                    services.Remove(existing);

                services.AddSingleton<IAdcsClient>(Client);
            });
        }
    }
}
