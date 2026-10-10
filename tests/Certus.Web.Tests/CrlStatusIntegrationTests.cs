using System.Net;
using System.Text.Json;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The settings page's revocation list surface (issue #447).
///
/// It reads what the monitor stored and fetches nothing itself, which is the
/// property worth pinning: an endpoint that read distribution points per page
/// view would turn a browser refresh into load on the CA and on whatever serves
/// its CRLs.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class CrlStatusIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public CrlStatusIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task It_reports_every_copy_of_every_crl_grouped_by_the_ca_that_signs_it()
    {
        var issuerKeyId = SeedRootCrl();

        var response = await _client.GetAsync("/api/settings/crl-status");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());

        var group = body.GetProperty("crls").EnumerateArray()
            .Single(g => g.GetProperty("issuerName").GetString() == $"CN=Test Root {issuerKeyId}");

        group.GetProperty("scope").GetString().Should().Be("parent");
        group.GetProperty("kind").GetString().Should().Be("base");
        group.GetProperty("autoPublished").GetBoolean().Should().BeFalse();

        // Two copies of one CRL, and they disagree: the directory has the
        // renewed one and the web server was never updated. That is the failure
        // the card exists to show.
        var sources = group.GetProperty("sources").EnumerateArray().ToList();
        sources.Should().HaveCount(2);
        sources.Select(s => s.GetProperty("crlNumber").GetString())
            .Should().BeEquivalentTo(["0C", "0D"]);
        sources.Should().Contain(s => s.GetProperty("lastError").GetString() != null);
        body.GetProperty("lastCheckedAt").GetString().Should().NotBeNull();
    }

    [Fact]
    public async Task An_install_that_has_watched_nothing_yet_answers_empty_rather_than_failing()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        db.MonitoredCrls.RemoveRange(db.MonitoredCrls);
        await db.SaveChangesAsync();

        var response = await _client.GetAsync("/api/settings/crl-status");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());
        body.GetProperty("crls").GetArrayLength().Should().Be(0);
        body.GetProperty("lastCheckedAt").ValueKind.Should().Be(JsonValueKind.Null);
    }

    /// <summary>
    /// Seeds one root CRL published in two places, the second of them stale and
    /// currently unreadable. Returns the key identifier used, which is unique
    /// per run because this collection shares one database.
    /// </summary>
    private string SeedRootCrl()
    {
        var issuerKeyId = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var now = DateTime.UtcNow;

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        db.MonitoredCrls.AddRange(
            new MonitoredCrl
            {
                Scope = "parent",
                IssuerKeyId = issuerKeyId,
                IssuerName = $"CN=Test Root {issuerKeyId}",
                Kind = "base",
                Source = "ldap:///CN=Test%20Root,CN=CDP,DC=corp,DC=example,DC=com",
                CrlNumber = "0D",
                InstanceKey = "0D",
                ThisUpdate = now.AddDays(-2),
                NextUpdate = now.AddDays(363),
                NextPublish = now.AddDays(362),
                AutoPublished = false,
                SignatureStatus = "verified",
                LastCheckedAt = now,
                LastReadAt = now,
            },
            new MonitoredCrl
            {
                Scope = "parent",
                IssuerKeyId = issuerKeyId,
                IssuerName = $"CN=Test Root {issuerKeyId}",
                Kind = "base",
                Source = "http://pki.corp.example.com/TestRoot.crl",
                CrlNumber = "0C",
                InstanceKey = "0C",
                ThisUpdate = now.AddDays(-360),
                NextUpdate = now.AddDays(5),
                NextPublish = now.AddDays(4),
                AutoPublished = false,
                SignatureStatus = "verified",
                LastCheckedAt = now,
                LastReadAt = now.AddHours(-3),
                LastError = "The distribution point answered 404.",
            });

        db.SaveChanges();
        return issuerKeyId;
    }
}
