using System.Net;
using System.Text.Json;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the dashboard metrics API:
///   GET /api/dashboard/health
///   GET /api/dashboard/validation
///   GET /api/dashboard/activity
///   GET /api/dashboard/registrations
///
/// These share the collection's in-memory SQLite database, so assertions are
/// tolerant of data seeded by sibling tests (counts use lower bounds, not
/// exact totals).
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class DashboardMetricsIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public DashboardMetricsIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    /// <summary>Seed a known mix of certificates exactly once across the shared factory.</summary>
    private async Task SeedAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        if (await db.SyncedCertificates.AnyAsync(c => c.RequestId == 2001))
            return;

        var now = DateTime.UtcNow;
        db.SyncedCertificates.AddRange(
            new SyncedCertificate
            {
                RequestId = 2001, SerialNumber = "MDVALID01", Subject = "CN=md-valid.example.com",
                TemplateName = "WebServer", NotBefore = now.AddDays(-5), NotAfter = now.AddDays(335),
                Status = "Issued", Requestor = "admin", RequestDate = now.AddDays(-5)
            },
            new SyncedCertificate
            {
                RequestId = 2002, SerialNumber = "MDEXPIRING01", Subject = "CN=md-expiring.example.com",
                TemplateName = "WebServer", NotBefore = now.AddDays(-60), NotAfter = now.AddDays(10),
                Status = "Issued", Requestor = "admin", RequestDate = now.AddDays(-3)
            },
            new SyncedCertificate
            {
                RequestId = 2003, SerialNumber = "MDEXPIRED01", Subject = "CN=md-expired.example.com",
                TemplateName = "InternalServer", NotBefore = now.AddDays(-400), NotAfter = now.AddDays(-2),
                Status = "Issued", Requestor = "admin", RequestDate = now.AddDays(-2)
            },
            new SyncedCertificate
            {
                RequestId = 2004, SerialNumber = "MDPENDING01", Subject = "CN=md-pending.example.com",
                TemplateName = "WebServer", NotBefore = now.AddDays(-1), NotAfter = now.AddDays(100),
                Status = "Pending", Requestor = "admin", RequestDate = now.AddDays(-1)
            });

        await db.SaveChangesAsync();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task Health_Returns200WithScoreAndSegments()
    {
        await SeedAsync();

        var response = await _client.GetAsync("/api/dashboard/health");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var score = body.GetProperty("score").GetInt32();
        score.Should().BeInRange(0, 100);

        var segments = body.GetProperty("segments");
        segments.ValueKind.Should().Be(JsonValueKind.Array);

        var keys = segments.EnumerateArray()
            .Select(s => s.GetProperty("key").GetString())
            .ToList();
        keys.Should().Contain(new[] { "valid", "expiring", "expired", "pending" });

        // Each segment exposes an integer count and a tone.
        foreach (var seg in segments.EnumerateArray())
        {
            seg.GetProperty("count").GetInt32().Should().BeGreaterThanOrEqualTo(0);
            seg.GetProperty("tone").GetString().Should().NotBeNullOrEmpty();
        }
    }

    [Fact]
    public async Task Validation_ReturnsAllThreeCanonicalMethods()
    {
        var response = await _client.GetAsync("/api/dashboard/validation");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.ValueKind.Should().Be(JsonValueKind.Array);
        body.GetArrayLength().Should().Be(3);

        var types = body.EnumerateArray().Select(m => m.GetProperty("type").GetString()).ToList();
        types.Should().BeEquivalentTo(new[] { "http-01", "dns-01", "tls-alpn-01" });

        foreach (var method in body.EnumerateArray())
        {
            method.GetProperty("count").GetInt32().Should().BeGreaterThanOrEqualTo(0);
        }
    }

    [Fact]
    public async Task Activity_IncludesSyntheticExpiredEntry()
    {
        await SeedAsync();

        var response = await _client.GetAsync("/api/dashboard/activity?take=50");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.ValueKind.Should().Be(JsonValueKind.Array);

        var items = body.EnumerateArray().ToList();
        items.Should().Contain(i =>
            i.GetProperty("type").GetString() == "expired" &&
            i.GetProperty("cn").GetString() == "md-expired.example.com");

        // Newest first.
        var timestamps = items
            .Select(i => i.GetProperty("timestamp").GetDateTime())
            .ToList();
        timestamps.Should().BeInDescendingOrder();
    }

    [Fact]
    public async Task Registrations_ReturnsDailyBucketsWithZeroRenewals()
    {
        await SeedAsync();

        var response = await _client.GetAsync("/api/dashboard/registrations?days=30");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var registrations = body.GetProperty("registrations");
        var renewals = body.GetProperty("renewals");

        registrations.GetArrayLength().Should().Be(30);
        renewals.GetArrayLength().Should().Be(30);

        // The four seeded certs were all requested within the last 30 days.
        registrations.EnumerateArray().Sum(d => d.GetInt32()).Should().BeGreaterThanOrEqualTo(4);

        // Renewals are not yet distinguishable — the series is all zero.
        renewals.EnumerateArray().Should().OnlyContain(d => d.GetInt32() == 0);
    }

    [Fact]
    public async Task Registrations_ClampsDaysToMax90()
    {
        var response = await _client.GetAsync("/api/dashboard/registrations?days=999");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("registrations").GetArrayLength().Should().Be(90);
    }
}
