using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for GET /acme/{template}/renewalInfo/{certID}, the ARI
/// resource (RFC 9773). Unauthenticated plain GET like the issuer certificate,
/// but with the opposite cache stance: it skips the Replay-Nonce (a stored
/// nonce per anonymous poll that no client consumes) while deliberately
/// keeping no-store, so a revocation driven window change is never served
/// stale. Only certificates issued through ACME answer; everything else is an
/// indistinguishable 404.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class RenewalInfoIntegrationTests
{
    // The RFC 9773 Appendix A example identifier: well formed, and no seeded
    // row carries its serial.
    private const string UnknownButWellFormed = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public RenewalInfoIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task RenewalInfo_ReturnsASuggestedWindowInsideTheValidity()
    {
        var seeded = await SeedCertificateAsync();

        var response = await _client.GetAsync($"/acme/WebServer/renewalInfo/{seeded.AriId}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/json");

        var body = JsonSerializer.Deserialize<RenewalInfoResponse>(
            await response.Content.ReadAsStringAsync());
        var start = ParseRfc3339(body!.SuggestedWindow.Start);
        var end = ParseRfc3339(body.SuggestedWindow.End);

        end.Should().BeAfter(start, "RFC 9773 §4.2 forbids serving end <= start");
        start.Should().BeOnOrAfter(seeded.NotBefore.AddSeconds(-1));
        end.Should().BeOnOrBefore(seeded.NotAfter.AddSeconds(1));
    }

    [Fact]
    public async Task RenewalInfo_CarriesRetryAfter_NoNonce_AndStaysNoStore()
    {
        var seeded = await SeedCertificateAsync();

        var response = await _client.GetAsync($"/acme/WebServer/renewalInfo/{seeded.AriId}");

        // RFC 9773 §4.3: the polling interval rides the Retry-After header,
        // never the body.
        response.Headers.RetryAfter.Should().NotBeNull();
        response.Headers.RetryAfter!.Delta.Should().Be(RenewalWindowPolicy.RetryAfter);

        // The nonce middleware skips this path: a stamp would store a nonce per
        // anonymous poll that no client ever consumes.
        response.Headers.Contains("Replay-Nonce").Should().BeFalse();

        // Unlike issuer-cert the response stays under no-store, so a revoked
        // certificate's "renew now" window is never served from a cache.
        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
        response.Headers.Pragma.ToString().Should().Contain("no-cache");
    }

    [Fact]
    public async Task RenewalInfo_AnsweredForHead()
    {
        // Declared explicitly on the action, because the ACME protocol fallback
        // is an unconstrained catch all that would otherwise claim the HEAD and
        // report a live resource as missing (issue #147).
        var seeded = await SeedCertificateAsync();
        using var request = new HttpRequestMessage(
            HttpMethod.Head, $"/acme/WebServer/renewalInfo/{seeded.AriId}");

        var response = await _client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("not-an-identifier")]
    [InlineData("trailing.")]
    [InlineData(".leading")]
    [InlineData("pad=.AAAA")]
    [InlineData("a.b.c")]
    public async Task RenewalInfo_MalformedIdentifier_Returns400(string certId)
    {
        var response = await _client.GetAsync($"/acme/WebServer/renewalInfo/{certId}");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task RenewalInfo_UnknownCertificate_Returns404()
    {
        var response = await _client.GetAsync(
            $"/acme/WebServer/renewalInfo/{UnknownButWellFormed}");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task RenewalInfo_MatchingSerialWithTheWrongKeyIdentifier_Returns404()
    {
        // The serial finds the row; the identifier still is not this
        // certificate's, so the answer is the same 404 as for no row at all.
        var seeded = await SeedCertificateAsync();
        AriCertificateId.TryParse(seeded.AriId, out _, out var serial).Should().BeTrue();
        var wrongIssuer = AriCertificateId.Format(new byte[] { 1, 2, 3, 4, 5 }, serial);

        var response = await _client.GetAsync($"/acme/WebServer/renewalInfo/{wrongIssuer}");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task RenewalInfo_UnknownTemplate_Returns404()
    {
        var response = await _client.GetAsync(
            $"/acme/NoSuchTemplate/renewalInfo/{UnknownButWellFormed}");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task RenewalInfo_RevokedCertificate_WindowIsEntirelyInThePast()
    {
        // The "renew immediately" signal: whatever instant the client picks
        // inside a past window has already gone by.
        var seeded = await SeedCertificateAsync(revoked: true);

        var response = await _client.GetAsync($"/acme/WebServer/renewalInfo/{seeded.AriId}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonSerializer.Deserialize<RenewalInfoResponse>(
            await response.Content.ReadAsStringAsync());
        var end = ParseRfc3339(body!.SuggestedWindow.End);
        end.Should().BeBefore(DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task RenewalInfo_RevokedOnlyInTheSyncedInventory_WindowIsEntirelyInThePast()
    {
        // A revocation done at the CA itself (certutil, certsrv.msc) reaches
        // the synced inventory and never the ACME row, and the renew now
        // window exists precisely for that case, so the endpoint reads the
        // synced twin belt and braces.
        var seeded = await SeedCertificateAsync();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            db.SyncedCertificates.Add(new SyncedCertificate
            {
                RequestId = seeded.AdcsRequestId,
                SerialNumber = "SYNCED" + seeded.AdcsRequestId,
                Subject = "CN=ari.example.com",
                Status = "Revoked",
                RevokedAt = DateTime.UtcNow.AddMinutes(-10)
            });
            await db.SaveChangesAsync();
        }

        var response = await _client.GetAsync($"/acme/WebServer/renewalInfo/{seeded.AriId}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonSerializer.Deserialize<RenewalInfoResponse>(
            await response.Content.ReadAsStringAsync());
        var end = ParseRfc3339(body!.SuggestedWindow.End);
        end.Should().BeBefore(DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task PostAtTheRenewalInfoShape_StillCarriesANonce()
    {
        // The nonce exemption is gated on GET and HEAD, the only methods the
        // resource defines. An errant POST at the same shape is an error a
        // client may harvest its next nonce from (RFC 8555 §7.2).
        var response = await _client.PostAsync(
            $"/acme/WebServer/renewalInfo/{UnknownButWellFormed}",
            new StringContent("{}", System.Text.Encoding.UTF8, "application/jose+json"));

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
        response.Headers.Contains("Replay-Nonce").Should().BeTrue();
    }

    private static DateTimeOffset ParseRfc3339(string value)
    {
        return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind);
    }

    private sealed record SeededCertificate(
        string AriId, int AdcsRequestId, DateTimeOffset NotBefore, DateTimeOffset NotAfter);

    /// <summary>
    /// Seeds the shape production leaves behind after an ACME issuance: an
    /// account, a valid order naming the certificate, and the certificate row
    /// whose leaf carries the Authority Key Identifier the identifier is built
    /// from. Self contained rather than shared with the download tests, whose
    /// seeder deliberately mints AKI-less leaves this endpoint cannot address.
    /// </summary>
    private async Task<SeededCertificate> SeedCertificateAsync(bool revoked = false)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=ari.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(
                RandomNumberGenerator.GetBytes(20)));
        var notBefore = DateTimeOffset.UtcNow.AddDays(-30);
        var notAfter = DateTimeOffset.UtcNow.AddDays(335);
        using var leaf = request.Create(
            new X500DistinguishedName("CN=ari.example.com"),
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            notBefore, notAfter,
            RandomNumberGenerator.GetBytes(12));

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var certId = "ari-cert-" + suffix;
        var adcsRequestId = Random.Shared.Next(500000, 900000);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var account = new AcmeAccount
        {
            AccountId = "ari-acct-" + suffix,
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = "ari-thumb-" + suffix,
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        db.AcmeAccounts.Add(account);
        await db.SaveChangesAsync();

        var order = new AcmeOrder
        {
            OrderId = "ari-order-" + suffix,
            AccountId = account.Id,
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = """[{"type":"dns","value":"ari.example.com"}]""",
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
            AdcsRequestId = adcsRequestId,
            SerialNumber = leaf.SerialNumber,
            IssuedAt = DateTime.UtcNow,
            RevokedAt = revoked ? DateTime.UtcNow.AddMinutes(-5) : null,
            RevokedReason = revoked ? 1 : null
        });
        await db.SaveChangesAsync();

        return new SeededCertificate(
            AriCertificateId.FromCertificate(leaf)!, adcsRequestId, notBefore, notAfter);
    }
}
