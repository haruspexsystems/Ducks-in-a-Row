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
    public async Task Validation_ReturnsAllFourCanonicalMethods()
    {
        var response = await _client.GetAsync("/api/dashboard/validation");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.ValueKind.Should().Be(JsonValueKind.Array);
        body.GetArrayLength().Should().Be(4);

        var types = body.EnumerateArray().Select(m => m.GetProperty("type").GetString()).ToList();
        types.Should().BeEquivalentTo(new[] { "http-01", "dns-01", "tls-alpn-01", "device-attest-01" });

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

        // One constant drives the request, the array lengths, and the window
        // arithmetic below. Before issue #260 the query string said 30 and the
        // expectation said 29 with nothing but matching literals holding them
        // together, so editing one silently broke the other.
        const int Days = 30;

        var response = await _client.GetAsync($"/api/dashboard/registrations?days={Days}");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var registrations = body.GetProperty("registrations");
        var renewals = body.GetProperty("renewals");

        registrations.GetArrayLength().Should().Be(Days);
        renewals.GetArrayLength().Should().Be(Days);

        // The expectation is computed from the shared database rather than
        // hardcoded, honouring this file's tolerance rule: sibling tests in
        // the collection legitimately add certificates (the revocation tests
        // do), and class ordering decides who runs first. The regression from
        // issue #151 keeps its teeth because the expectation counts only
        // Issued and Revoked rows: SeedAsync guarantees a Pending row inside
        // the window, so an endpoint that counted requests again would sum
        // higher than this expectation.
        //
        // Both bounds are load bearing, and the upper one is issue #260.
        // GetRegistrationsAsync fetches with the same lower bound and then
        // buckets into a fixed length array, dropping every date past the end
        // of it, so a row dated in the future is counted here and missing from
        // the series. The assertion then fails by exactly one and names the
        // metrics endpoint, when the real cause is a sibling test's seed date.
        // That is what happened on PR #259.
        //
        // Residual, knowingly unguarded: the endpoint reads UtcNow inside the
        // request and this block reads it again afterwards, so a UTC midnight
        // landing between the two shifts the windows a day apart. It is a
        // millisecond wide gap once a day. If this ever fails by one bucket
        // at midnight UTC, that is why.
        int expected;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var since = DateTime.UtcNow.Date.AddDays(-(Days - 1));
            var until = since.AddDays(Days);
            expected = await db.SyncedCertificates.CountAsync(c =>
                (c.Status == "Issued" || c.Status == "Revoked")
                && c.RequestDate >= since
                && c.RequestDate < until);
        }

        expected.Should().BeGreaterThanOrEqualTo(3, "the seed adds three certificates in window");
        registrations.EnumerateArray().Sum(d => d.GetInt32()).Should().Be(expected);

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
