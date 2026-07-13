using System.Net;
using System.Text.Json;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the Alerts Dashboard API endpoints:
///   GET /api/alerts/history
///   GET /api/alerts/summary
///   GET /api/alerts/config
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class AlertsIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public AlertsIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    private async Task SeedAlertsAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        if (await db.AlertsSent.AnyAsync())
            return;

        // Ensure we have certificates first
        if (!await db.SyncedCertificates.AnyAsync())
        {
            var now = DateTime.UtcNow;
            db.SyncedCertificates.Add(new SyncedCertificate
            {
                RequestId = 5001,
                SerialNumber = "ALERTTEST001",
                Subject = "CN=alert-test.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-30),
                NotAfter = now.AddDays(25),
                Status = "Issued",
                RequestDate = now.AddDays(-30),
            });
            await db.SaveChangesAsync();
        }

        var cert = await db.SyncedCertificates.FirstAsync();
        db.AlertsSent.Add(new AlertSent
        {
            CertificateId = cert.Id,
            ThresholdDays = 30,
            SentAt = DateTime.UtcNow.AddHours(-1),
            Channels = "email",
            Success = true,
        });
        await db.SaveChangesAsync();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    [Fact]
    public async Task GetHistory_Returns200()
    {
        await SeedAlertsAsync();

        var response = await _client.GetAsync("/api/alerts/history");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.TryGetProperty("items", out _).Should().BeTrue();
        body.TryGetProperty("totalCount", out _).Should().BeTrue();
        body.TryGetProperty("hasMore", out _).Should().BeTrue();
    }

    [Fact]
    public async Task GetSummary_Returns200()
    {
        await SeedAlertsAsync();

        var response = await _client.GetAsync("/api/alerts/summary");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.TryGetProperty("totalAlertsSent", out _).Should().BeTrue();
        body.TryGetProperty("failedAlerts", out _).Should().BeTrue();
        body.TryGetProperty("uniqueCertificatesAlerted", out _).Should().BeTrue();
    }

    [Fact]
    public async Task GetConfig_Returns200WithSanitizedConfig()
    {
        var response = await _client.GetAsync("/api/alerts/config");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.TryGetProperty("enabled", out _).Should().BeTrue();
        body.TryGetProperty("thresholdDays", out _).Should().BeTrue();
        body.TryGetProperty("checkIntervalMinutes", out _).Should().BeTrue();
    }
}
