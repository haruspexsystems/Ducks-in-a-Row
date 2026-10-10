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
/// The cross surface half of issue #226, dashboard first: an admin revokes from the
/// dashboard while an ACME client revokes the same certificate. Both surfaces share one
/// <c>CertificateRevocationGate</c> singleton because both run in one process (the
/// production host is Certus.Service, which serves the ACME controllers out of the
/// referenced Certus.Web assembly), so the ACME request must park at the gate.
///
/// <para>
/// This is also the test that pins the stale read. The ACME request loads its certificate
/// row through <c>FindCertificateBySerialAsync</c> <em>before</em> it reaches the gate, and
/// EF tracks that entity. Without the <c>ReloadAsync</c> inside the gate, the request would
/// wake holding its own pre revocation copy, read <c>RevokedAt</c> as null, and send the CA
/// a second revocation. A repeat query would not save it either: EF answers from the
/// scope's identity map without overwriting the tracked values, so the stale row would
/// survive the re-read and the gate would buy nothing.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public class AcmeRevokeAfterDashboardRaceTests
    : IClassFixture<AcmeRevokeAfterDashboardRaceTests.CrossSurfaceRaceCaFactory>, IDisposable
{
    private const string RevokePath = "/acme/WebServer/revoke-cert";

    private readonly CrossSurfaceRaceCaFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AcmeRevokeAfterDashboardRaceTests(CrossSurfaceRaceCaFactory factory)
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
    public async Task DashboardRevokeInFlight_AcmeRevokeIsGatedAndRefused()
    {
        var stub = _factory.Client;
        var (inventoryId, leaf, leafKey) = await IssueSyncAndBridgeAsync("cross-surface-race.example.com");
        _keys.Add(leafKey);

        using (leaf)
        {
            // Built before the race starts: an ACME nonce is single use, and a JWS
            // built mid race would silently be testing nonce handling instead.
            var acmeJws = await BuildJwkRevokeJws(leafKey, leaf, reason: 4);

            try
            {
                // The dashboard admin wins the gate and parks inside the CA call.
                var dashboard = PostDashboardRevokeAsync(inventoryId, reason: 4, leaf.SerialNumber);
                await stub.FirstRevokeEntered.WaitAsync(TimeSpan.FromSeconds(10));

                // The ACME client must wait at the gate, short of the CA.
                var acme = PostJws(RevokePath, acmeJws);
                await Task.Delay(250);
                stub.RevokeCalls.Should().Be(1,
                    "the shared gate must hold the ACME request while the dashboard holds it");

                stub.ReleaseRevokes();

                var dashboardResponse = await dashboard.WaitAsync(TimeSpan.FromSeconds(30));
                var acmeResponse = await acme.WaitAsync(TimeSpan.FromSeconds(30));

                dashboardResponse.StatusCode.Should().Be(HttpStatusCode.OK);
                var body = JsonSerializer.Deserialize<JsonElement>(
                    await dashboardResponse.Content.ReadAsStringAsync());
                body.GetProperty("outcome").GetString().Should().Be("revoked");

                acmeResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                var error = JsonSerializer.Deserialize<AcmeError>(
                    await acmeResponse.Content.ReadAsStringAsync());
                error!.Type.Should().Be(AcmeErrorType.AlreadyRevoked,
                    "the ACME request must re-read its row inside the gate, not trust the " +
                    "copy it loaded before waiting");

                stub.RevokeCalls.Should().Be(1, "the CA must see exactly one revocation");
            }
            finally
            {
                stub.ReleaseRevokes();
            }
        }
    }

    /// <summary>
    /// Issues a certificate through the mock CA, syncs it into the dashboard inventory,
    /// and bridges it to an ACME certificate row on the CA request id, so one leaf is
    /// addressable from both surfaces. Returns the inventory row id, the leaf, and the
    /// key it was issued from (the revocation is signed with it, RFC 8555 §7.6 jwk form).
    /// </summary>
    private async Task<(int InventoryId, X509Certificate2 Leaf, RSA Key)> IssueSyncAndBridgeAsync(string cn)
    {
        var inner = _factory.Client.Inner;

        var key = RSA.Create(2048);
        var csr = new CertificateRequest(
                new X500DistinguishedName($"CN={cn}"), key,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSigningRequest();

        var submit = await inner.SubmitCertificateRequestAsync("WebServer", csr);
        var issued = await inner.GetCertificateAsync(submit.RequestId);
        var leaf = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);

        // The dashboard side: pull the CA so the inventory carries the row the
        // revocation endpoint addresses by id.
        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        var list = await _client.GetAsync($"/api/certificates?search={cn}");
        var listBody = JsonSerializer.Deserialize<JsonElement>(
            await list.Content.ReadAsStringAsync());
        var row = listBody.GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("subject").GetString()!.Contains(cn));

        // The ACME side: the same leaf, bridged on the CA request id, which is the key
        // both surfaces' cross stamps use.
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var account = new AcmeAccount
        {
            AccountId = "cross-account-" + Guid.NewGuid().ToString("N")[..8],
            JwkJson = """{"kty":"RSA","n":"cross","e":"AQAB"}""",
            JwkThumbprint = "cross-thumb-" + Guid.NewGuid().ToString("N")[..8],
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        db.AcmeAccounts.Add(account);
        await db.SaveChangesAsync();

        var certId = "cross-cert-" + Guid.NewGuid().ToString("N")[..8];
        var order = new AcmeOrder
        {
            OrderId = "cross-order-" + Guid.NewGuid().ToString("N")[..8],
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
            CertificatePem = leaf.ExportCertificatePem(),
            SerialNumber = leaf.SerialNumber,
            AdcsRequestId = submit.RequestId,
            IssuedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        return (row.GetProperty("id").GetInt32(), leaf, key);
    }

    private Task<HttpResponseMessage> PostDashboardRevokeAsync(int id, int reason, string serialNumber)
        => _client.PostAsync(
            $"/api/certificates/{id}/revoke",
            new StringContent(
                JsonSerializer.Serialize(new { reason, serialNumber }),
                Encoding.UTF8, "application/json"));

    private async Task<JwsFlattenedRequest> BuildJwkRevokeJws(
        RSA rsa, X509Certificate2 cert, int? reason)
    {
        var nonceResponse = await _client.GetAsync("/acme/WebServer/new-nonce");
        var nonce = nonceResponse.Headers.GetValues("Replay-Nonce").First();

        var encodedPath = new Microsoft.AspNetCore.Http.PathString(RevokePath).ToUriComponent();
        var url = $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";

        var p = rsa.ExportParameters(false);
        var jwkJson = $$"""{"kty":"RSA","n":"{{JwsService.Base64UrlEncode(p.Modulus!)}}","e":"{{JwsService.Base64UrlEncode(p.Exponent!)}}"}""";

        var payloadJson = JsonSerializer.Serialize(new RevokeCertRequest
        {
            Certificate = JwsService.Base64UrlEncode(cert.RawData),
            Reason = reason
        });
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";

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

    private Task<HttpResponseMessage> PostJws(string url, JwsFlattenedRequest jws)
        => _client.PostAsync(
            url,
            new StringContent(JsonSerializer.Serialize(jws), Encoding.UTF8, "application/jose+json"));

    /// <summary>
    /// Factory whose IAdcsClient is the shared parking stub, so the dashboard revocation
    /// can be held inside the CA call while the ACME request arrives.
    /// </summary>
    public sealed class CrossSurfaceRaceCaFactory : CertusWebApplicationFactory
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

/// <summary>
/// The cross surface half of issue #226 the filed analysis did not carry, ACME first.
/// Issue #202's stamp runs one way only: a dashboard revocation stamps the ACME row
/// synchronously, but the ACME path used to stamp nothing but its own row and fire an
/// asynchronous inventory sync. So for as long as that sync took, which is a full CA
/// pull, a dashboard revocation for the same certificate would re-read an inventory row
/// still saying Issued, pass every guard, and send the CA a second revocation. The gate
/// cannot close that on its own, because the two requests never overlap.
///
/// <para>
/// The inventory row here is bridged to a CA request id the mock CA never issued, so no
/// sync can reach it. Any Revoked status on it therefore came from the mirror stamp and
/// nothing else, which is what makes the assertion deterministic even though the sync
/// worker is live in this host.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class AcmeRevokeInventoryStampTests : IDisposable
{
    private const string RevokePath = "/acme/WebServer/revoke-cert";

    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AcmeRevokeInventoryStampTests(CertusWebApplicationFactory factory)
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
    public async Task AcmeRevoke_StampsTheDashboardInventoryRow()
    {
        // A request id the mock CA has never issued, so the background sync can neither
        // update this row nor delete it (the sync only ever writes what the CA reports).
        var requestId = 970_226;

        var key = RSA.Create(2048);
        _keys.Add(key);
        using var cert = CreateSelfSignedCert(key, "CN=acme-inventory-stamp.example.com");

        await SeedBridgedRowsAsync(cert, requestId);

        var response = await PostJws(RevokePath, await BuildJwkRevokeJws(key, cert, reason: 4));
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var inventory = await db.SyncedCertificates.AsNoTracking()
            .FirstAsync(c => c.RequestId == requestId);

        inventory.Status.Should().Be(nameof(CertificateStatus.Revoked),
            "an ACME revocation must stamp the inventory row, or a dashboard revocation " +
            "inside the sync window would send the CA a second revocation");
        inventory.RevokedAt.Should().NotBeNull();
        inventory.RevokedReason.Should().Be(4);
    }

    private async Task SeedBridgedRowsAsync(X509Certificate2 cert, int requestId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var account = new AcmeAccount
        {
            AccountId = "stamp-account-" + Guid.NewGuid().ToString("N")[..8],
            JwkJson = """{"kty":"RSA","n":"stamp","e":"AQAB"}""",
            JwkThumbprint = "stamp-thumb-" + Guid.NewGuid().ToString("N")[..8],
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        db.AcmeAccounts.Add(account);
        await db.SaveChangesAsync();

        var certId = "stamp-cert-" + Guid.NewGuid().ToString("N")[..8];
        var order = new AcmeOrder
        {
            OrderId = "stamp-order-" + Guid.NewGuid().ToString("N")[..8],
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
            AdcsRequestId = requestId,
            IssuedAt = DateTime.UtcNow
        });

        // The dashboard's view of the same certificate, bridged on the CA request id.
        db.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = requestId,
            SerialNumber = cert.SerialNumber,
            Subject = cert.Subject,
            TemplateName = "WebServer",
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Status = nameof(CertificateStatus.Issued),
            RequestDate = DateTime.UtcNow
        });

        await db.SaveChangesAsync();
    }

    private static X509Certificate2 CreateSelfSignedCert(RSA key, string subject)
    {
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private async Task<JwsFlattenedRequest> BuildJwkRevokeJws(
        RSA rsa, X509Certificate2 cert, int? reason)
    {
        var nonceResponse = await _client.GetAsync("/acme/WebServer/new-nonce");
        var nonce = nonceResponse.Headers.GetValues("Replay-Nonce").First();

        var encodedPath = new Microsoft.AspNetCore.Http.PathString(RevokePath).ToUriComponent();
        var url = $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";

        var p = rsa.ExportParameters(false);
        var jwkJson = $$"""{"kty":"RSA","n":"{{JwsService.Base64UrlEncode(p.Modulus!)}}","e":"{{JwsService.Base64UrlEncode(p.Exponent!)}}"}""";

        var payloadJson = JsonSerializer.Serialize(new RevokeCertRequest
        {
            Certificate = JwsService.Base64UrlEncode(cert.RawData),
            Reason = reason
        });
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";

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

    private Task<HttpResponseMessage> PostJws(string url, JwsFlattenedRequest jws)
        => _client.PostAsync(
            url,
            new StringContent(JsonSerializer.Serialize(jws), Encoding.UTF8, "application/jose+json"));
}
