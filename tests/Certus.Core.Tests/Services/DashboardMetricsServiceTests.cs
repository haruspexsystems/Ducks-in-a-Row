using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Services;

/// <summary>
/// Tests for the fleet health computation: score semantics, the null score
/// empty state (a fresh install must not read "100% Healthy"), and the
/// mutually exclusive segment buckets.
/// </summary>
public class DashboardMetricsServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly DashboardMetricsService _sut;

    public DashboardMetricsServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _sut = new DashboardMetricsService(_db, NullLogger<DashboardMetricsService>.Instance);
    }

    private void Seed(int requestId, string status, DateTime notAfter, DateTime? revokedAt = null)
    {
        _db.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = requestId,
            SerialNumber = $"SERIAL{requestId:D4}",
            Subject = $"CN=cert{requestId}.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-30),
            NotAfter = notAfter,
            Status = status,
            RequestDate = DateTime.UtcNow.AddDays(-30),
            RevokedAt = revokedAt,
        });
    }

    [Fact]
    public async Task FleetHealth_EmptyInventory_HasNullScoreAndZeroSegments()
    {
        var health = await _sut.GetFleetHealthAsync();

        health.Score.Should().BeNull();
        health.Segments.Should().OnlyContain(s => s.Count == 0);
    }

    [Fact]
    public async Task FleetHealth_OnlyNonIssuedRows_StillHasNullScore()
    {
        // Failed or denied rows are not part of the lifecycle score; a fleet
        // of them alone must not manufacture a 100.
        Seed(1, "Failed", DateTime.UtcNow.AddDays(300));
        Seed(2, "Denied", DateTime.UtcNow.AddDays(300));
        await _db.SaveChangesAsync();

        var health = await _sut.GetFleetHealthAsync();

        health.Score.Should().BeNull();
    }

    [Fact]
    public async Task FleetHealth_ComputesScoreAndSegmentsFromIssuedRows()
    {
        var now = DateTime.UtcNow;
        Seed(1, "Issued", now.AddDays(300)); // valid
        Seed(2, "Issued", now.AddDays(200)); // valid
        Seed(3, "Issued", now.AddDays(400)); // valid
        Seed(4, "Issued", now.AddDays(10));  // expiring
        Seed(5, "Pending", now.AddDays(90)); // pending (excluded from score)
        await _db.SaveChangesAsync();

        var health = await _sut.GetFleetHealthAsync();

        // 3 valid out of 4 scored (valid + expiring + expired) = 75.
        health.Score.Should().Be(75);

        var byKey = health.Segments.ToDictionary(s => s.Key, s => s.Count);
        byKey["valid"].Should().Be(3);
        byKey["expiring"].Should().Be(1);
        byKey["expired"].Should().Be(0);
        byKey["pending"].Should().Be(1);
    }

    [Fact]
    public async Task Activity_IncludesRevokedEntry()
    {
        var revokedAt = DateTime.UtcNow.AddHours(-2);
        Seed(1, "Revoked", DateTime.UtcNow.AddDays(300), revokedAt);
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        var item = activity.Should().ContainSingle(i => i.Type == "revoked").Subject;
        item.Id.Should().Be("revoked-1");
        item.Cn.Should().Be("cert1.example.com");
        item.Tmpl.Should().Be("WebServer");
        item.Timestamp.Should().Be(revokedAt);
    }

    [Fact]
    public async Task Activity_RevokedWithoutRevokedAt_IsExcluded()
    {
        // A revoked row without a revocation time has nothing truthful to
        // timestamp the feed entry with, so it stays out.
        Seed(1, "Revoked", DateTime.UtcNow.AddDays(300));
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        activity.Should().NotContain(i => i.Type == "revoked");
    }

    [Fact]
    public async Task Activity_RevokedCertPastNotAfter_AppearsOnceAsRevoked()
    {
        // A revoked certificate whose validity has also lapsed must not show
        // up twice: the expired source only reads rows still marked Issued.
        Seed(1, "Revoked", DateTime.UtcNow.AddDays(-5), DateTime.UtcNow.AddDays(-10));
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        activity.Should().ContainSingle();
        activity[0].Type.Should().Be("revoked");
    }

    [Fact]
    public async Task Activity_OrdersNewestFirstAcrossSources_AndHonorsTake()
    {
        var now = DateTime.UtcNow;
        Seed(1, "Issued", now.AddHours(-1));                      // expired 1h ago
        Seed(2, "Issued", now.AddHours(-5));                      // expired 5h ago
        Seed(3, "Revoked", now.AddDays(300), now.AddHours(-2));   // revoked 2h ago
        Seed(4, "Revoked", now.AddDays(300), now.AddHours(-4));   // revoked 4h ago
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync(take: 3);

        activity.Should().HaveCount(3);
        activity.Select(i => i.Id).Should().ContainInOrder("expired-1", "revoked-3", "revoked-4");
        activity.Should().BeInDescendingOrder(i => i.Timestamp);
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }
}
