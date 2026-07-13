using System.Net;
using System.Text.Json;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the Dashboard API endpoints:
///   GET /api/certificates
///   GET /api/certificates/{id}
///   GET /api/certificates/stats
///   GET /api/templates
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class DashboardIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public DashboardIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    /// <summary>Seed test certificates and return the scope so the DB is committed.</summary>
    private async Task SeedCertificatesAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        // Only seed if our specific data doesn't exist yet (tests share factory)
        if (await db.SyncedCertificates.AnyAsync(c => c.RequestId == 1001))
            return;

        var now = DateTime.UtcNow;
        db.SyncedCertificates.AddRange(
            new SyncedCertificate
            {
                RequestId = 1001,
                SerialNumber = "DASHSERIAL001",
                Subject = "CN=dash-web.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-30),
                NotAfter = now.AddDays(335),
                Status = "Issued",
                Requestor = "admin",
                RequestDate = now.AddDays(-30)
            },
            new SyncedCertificate
            {
                RequestId = 1002,
                SerialNumber = "DASHSERIAL002",
                Subject = "CN=dash-api.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-60),
                NotAfter = now.AddDays(10), // Expiring soon
                Status = "Issued",
                Requestor = "admin",
                RequestDate = now.AddDays(-60)
            },
            new SyncedCertificate
            {
                RequestId = 1003,
                SerialNumber = "DASHSERIAL003",
                Subject = "CN=dash-db.internal",
                TemplateName = "InternalServer",
                NotBefore = now.AddDays(-90),
                NotAfter = now.AddDays(275),
                Status = "Revoked",
                Requestor = "dba-team",
                RequestDate = now.AddDays(-90)
            });

        await db.SaveChangesAsync();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    #region POST /api/certificates/sync

    [Fact]
    public async Task TriggerSync_Returns200WithSyncCounts()
    {
        // The test host runs the mock ADCS client, so the sync completes
        // against the mock inventory (possibly empty, depending on sibling
        // tests in the shared collection).
        var response = await _client.PostAsync("/api/certificates/sync", null);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var processed = body.GetProperty("processed").GetInt32();
        var created = body.GetProperty("created").GetInt32();
        var updated = body.GetProperty("updated").GetInt32();

        processed.Should().BeGreaterThanOrEqualTo(0);
        (created + updated).Should().Be(processed);
        body.GetProperty("completedAtUtc").GetDateTime()
            .Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(2));
    }

    #endregion

    #region GET /api/certificates

    [Fact]
    public async Task ListCertificates_Returns200WithPagedResult()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("items").GetArrayLength().Should().BeGreaterThan(0);
        body.GetProperty("totalCount").GetInt32().Should().BeGreaterThan(0);
        body.TryGetProperty("hasMore", out _).Should().BeTrue();
        body.TryGetProperty("skip", out _).Should().BeTrue();
        body.TryGetProperty("take", out _).Should().BeTrue();
    }

    [Fact]
    public async Task ListCertificates_SearchBySubject_FiltersResults()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates?search=dash-web");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var items = body.GetProperty("items");
        items.GetArrayLength().Should().Be(1);
        items[0].GetProperty("subject").GetString().Should().Contain("dash-web");
    }

    [Fact]
    public async Task ListCertificates_FilterByTemplate_ReturnsOnlyMatching()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates?template=InternalServer");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var items = body.GetProperty("items");
        items.GetArrayLength().Should().BeGreaterThan(0);

        // All returned items should have the InternalServer template
        foreach (var item in items.EnumerateArray())
        {
            item.GetProperty("templateName").GetString().Should().Be("InternalServer");
        }
    }

    [Fact]
    public async Task ListCertificates_FilterByStatus_ReturnsOnlyMatching()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates?status=Revoked");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var items = body.GetProperty("items");
        items.GetArrayLength().Should().BeGreaterThan(0);

        foreach (var item in items.EnumerateArray())
        {
            item.GetProperty("status").GetString().Should().Be("Revoked");
        }
    }

    [Fact]
    public async Task ListCertificates_Pagination_RespectsSkipAndTake()
    {
        await SeedCertificatesAsync();

        // Use search filter to isolate our seeded data
        var page1 = await _client.GetAsync("/api/certificates?search=dash-&skip=0&take=1");
        var page2 = await _client.GetAsync("/api/certificates?search=dash-&skip=1&take=1");

        page1.StatusCode.Should().Be(HttpStatusCode.OK);
        page2.StatusCode.Should().Be(HttpStatusCode.OK);

        var body1 = await ParseJsonAsync(page1);
        var body2 = await ParseJsonAsync(page2);

        body1.GetProperty("items").GetArrayLength().Should().Be(1);
        body2.GetProperty("items").GetArrayLength().Should().BeGreaterThan(0);

        // Different items
        var id1 = body1.GetProperty("items")[0].GetProperty("id").GetInt32();
        var id2 = body2.GetProperty("items")[0].GetProperty("id").GetInt32();
        id1.Should().NotBe(id2);
    }

    [Fact]
    public async Task ListCertificates_TakeExceedsMax_ClampedTo200()
    {
        await SeedCertificatesAsync();

        // Request take=999, should be clamped to 200 (controller logic)
        var response = await _client.GetAsync("/api/certificates?take=999");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("take").GetInt32().Should().BeLessThanOrEqualTo(200);
    }

    #endregion

    #region GET /api/certificates/{id}

    [Fact]
    public async Task GetCertificate_Existing_Returns200()
    {
        await SeedCertificatesAsync();

        // First, list to get an actual ID
        var listResponse = await _client.GetAsync("/api/certificates?take=1");
        var listBody = await ParseJsonAsync(listResponse);
        var id = listBody.GetProperty("items")[0].GetProperty("id").GetInt32();

        var response = await _client.GetAsync($"/api/certificates/{id}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("id").GetInt32().Should().Be(id);
        body.TryGetProperty("subject", out _).Should().BeTrue();
        body.TryGetProperty("serialNumber", out _).Should().BeTrue();
    }

    [Fact]
    public async Task GetCertificate_NonExistent_Returns404()
    {
        var response = await _client.GetAsync("/api/certificates/999999");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    #endregion

    #region GET /api/certificates/stats

    [Fact]
    public async Task GetStats_Returns200WithStatistics()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates/stats");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("totalCertificates").GetInt32().Should().BeGreaterThan(0);
        body.TryGetProperty("issuedCertificates", out _).Should().BeTrue();
        body.TryGetProperty("expiringSoon", out _).Should().BeTrue();
        body.TryGetProperty("expired", out _).Should().BeTrue();
        // Seed 1003 is Revoked; the factory is shared across tests, so assert
        // presence and a lower bound rather than an exact count.
        body.GetProperty("revokedCertificates").GetInt32().Should().BeGreaterThan(0);
    }

    #endregion

    #region GET /api/templates

    [Fact]
    public async Task ListTemplates_Returns200()
    {
        var response = await _client.GetAsync("/api/templates");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.ValueKind.Should().Be(JsonValueKind.Array);
        // MockAdcsClient returns default templates: WebServer, CodeSigning, User
        body.GetArrayLength().Should().BeGreaterThan(0);
    }

    #endregion
}
