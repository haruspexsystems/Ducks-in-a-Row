using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Adcs;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// End to end cover for the revoke visibility chain: a certificate issued
/// and revoked through the mock CA must appear in the inventory and the
/// activity feed as revoked with its real name after a sync. Exercises the
/// mock revoke flip, the sync upsert, and the dashboard feed together. The
/// mock always returns a populated subject, so the empty subject fallbacks
/// (first SAN, update guard, ACME store backfill) are covered by the unit
/// tests in AdcsColumnMappingTests and CertificateSyncServiceTests instead.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class MockRevokeSyncIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public MockRevokeSyncIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task RevokedMockCertificate_ShowsNameInInventoryAndActivity()
    {
        // Issue a certificate straight through the mock CA.
        var adcs = (MockAdcsClient)_factory.Services.GetRequiredService<IAdcsClient>();
        var submit = await adcs.SubmitCertificateRequestAsync(
            "WebServer", CreateCsr("CN=mock-revoke.example.com"));
        submit.Status.Should().Be(SubmitStatus.Issued);

        // Revoke it by the X509 serial form (uppercase, possibly 00 padded),
        // the way the ACME revoke endpoint supplies it.
        var issued = await adcs.GetCertificateAsync(submit.RequestId);
        using var x509 = X509CertificateLoader.LoadCertificate(issued.CertificateDer!);
        await adcs.RevokeCertificateAsync(x509.SerialNumber, reason: 0);

        // Pull the inventory from the CA into the local database.
        var sync = await _client.PostAsync("/api/certificates/sync", content: null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        // Inventory: the row is revoked and keeps its name.
        var list = await _client.GetAsync("/api/certificates?search=mock-revoke");
        list.StatusCode.Should().Be(HttpStatusCode.OK);
        var listBody = JsonSerializer.Deserialize<JsonElement>(
            await list.Content.ReadAsStringAsync());
        var items = listBody.GetProperty("items").EnumerateArray().ToList();
        items.Should().Contain(i =>
            i.GetProperty("subject").GetString()!.Contains("mock-revoke.example.com") &&
            i.GetProperty("status").GetString() == "Revoked");

        // Activity feed: a revoked entry with the real name, not "Unknown".
        var activity = await _client.GetAsync("/api/dashboard/activity?take=100");
        activity.StatusCode.Should().Be(HttpStatusCode.OK);
        var activityBody = JsonSerializer.Deserialize<JsonElement>(
            await activity.Content.ReadAsStringAsync());
        activityBody.EnumerateArray().Should().Contain(i =>
            i.GetProperty("type").GetString() == "revoked" &&
            i.GetProperty("cn").GetString() == "mock-revoke.example.com");
    }

    private static byte[] CreateCsr(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSigningRequest();
    }
}
