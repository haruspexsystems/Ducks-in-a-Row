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

    /// <summary>
    /// The per certificate ladder behind the detail page block (issue #160).
    /// The ladder's own decisions are covered by CertificateAlertLadderTests;
    /// what matters here is that the route exists, is admin gated like the rest
    /// of this controller, and returns the shape the dashboard reads.
    /// </summary>
    [Fact]
    public async Task GetForCertificate_Returns200WithTheLadder()
    {
        await SeedAlertsAsync();

        int certificateId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            certificateId = (await db.SyncedCertificates.FirstAsync()).Id;
        }

        var response = await _client.GetAsync($"/api/alerts/certificate/{certificateId}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("certificateId").GetInt32().Should().Be(certificateId);
        body.TryGetProperty("coverage", out _).Should().BeTrue();
        body.TryGetProperty("enabledChannels", out _).Should().BeTrue();
        body.TryGetProperty("checkIntervalMinutes", out _).Should().BeTrue();

        // Every rung carries the two fields the page cannot render without.
        var thresholds = body.GetProperty("thresholds").EnumerateArray().ToList();
        thresholds.Should().NotBeEmpty();
        foreach (var threshold in thresholds)
        {
            threshold.TryGetProperty("thresholdDays", out _).Should().BeTrue();
            threshold.TryGetProperty("state", out _).Should().BeTrue();
        }
    }

    [Fact]
    public async Task GetForCertificate_UnknownCertificate_Returns404()
    {
        // Not an empty ladder: that is the answer for a real certificate nobody
        // has been warned about, and the two must not look alike.
        var response = await _client.GetAsync("/api/alerts/certificate/999999");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task GetConfig_CarriesTheDerivedExpiryWindow()
    {
        // The dashboard reads this rather than recomputing a maximum from
        // thresholdDays, so the backend stays the single source of the rule
        // (issue #152). It is the widest threshold, 30 on a default install.
        var response = await _client.GetAsync("/api/alerts/config");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.TryGetProperty("expiryWarningDays", out var window).Should().BeTrue();

        var thresholds = body.GetProperty("thresholdDays")
            .EnumerateArray().Select(t => t.GetInt32()).ToArray();
        window.GetInt32().Should().Be(thresholds.Max());
    }

    /// <summary>
    /// The config endpoint used to return the webhook URL, its custom header
    /// names, and the SMTP host, port, TLS flag, and from address. None of it was
    /// ever read by the dashboard, and the webhook URL routinely embeds a bearer
    /// token, which is how most webhook relays authenticate (issue #161).
    ///
    /// Asserted against the raw JSON rather than the deserialized shape, so a
    /// field reintroduced later under any name is still caught.
    /// </summary>
    [Fact]
    public async Task GetConfig_DoesNotCarryTheWebhookUrlOrItsHeaderNames()
    {
        var response = await _client.GetAsync("/api/alerts/config");
        var json = await response.Content.ReadAsStringAsync();

        json.Should().NotContain("\"url\"");
        json.Should().NotContain("\"headers\"");
    }

    [Fact]
    public async Task GetConfig_DoesNotCarryTheSmtpTransportSettings()
    {
        var response = await _client.GetAsync("/api/alerts/config");
        var json = await response.Content.ReadAsStringAsync();

        json.Should().NotContain("\"host\"");
        json.Should().NotContain("\"port\"");
        json.Should().NotContain("\"useSsl\"");
        json.Should().NotContain("\"fromAddress\"");
        json.Should().NotContain("\"fromName\"");
        json.Should().NotContain("\"username\"");
        json.Should().NotContain("\"password\"");
        json.Should().NotContain("\"secret\"");
    }

    /// <summary>
    /// The test send (issue #161). This factory ships no Certus:Alerts section at
    /// all, so no notifier is enabled and refusal is the natural answer here.
    /// The delivering path lives in AlertTestSendIntegrationTests, which needs
    /// its own host because the cooldown is a singleton.
    /// </summary>
    [Fact]
    public async Task SendTest_WithNoChannelConfigured_Returns409()
    {
        var response = await _client.PostAsync("/api/alerts/test", null);

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);

        var body = await ParseJsonAsync(response);
        body.GetProperty("error").GetString().Should().Contain("No alert channel is configured");
    }

    [Fact]
    public async Task SendTest_WithNoChannelConfigured_CanBeCalledRepeatedly()
    {
        // A refusal must not arm the cooldown. An operator who is told nothing is
        // configured, fixes the configuration, and tries again must not be locked
        // out for a minute by a send that never happened.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var response = await _client.PostAsync("/api/alerts/test", null);
            response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }

    [Fact]
    public async Task SendTest_WritesNoAlertHistoryRow()
    {
        // AlertsSent has no column that could mark a row as a test, and its
        // unique index on (CertificateId, ThresholdDays) means a test row would
        // consume a real certificate's slot and permanently suppress its real
        // warning. Nothing may be written.
        await SeedAlertsAsync();

        int before, after;
        using (var scope = _factory.Services.CreateScope())
        {
            before = await scope.ServiceProvider
                .GetRequiredService<CertusDbContext>().AlertsSent.CountAsync();
        }

        await _client.PostAsync("/api/alerts/test", null);

        using (var scope = _factory.Services.CreateScope())
        {
            after = await scope.ServiceProvider
                .GetRequiredService<CertusDbContext>().AlertsSent.CountAsync();
        }

        after.Should().Be(before);
    }
}
