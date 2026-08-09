using Certus.Core.Alerts;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

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

        _sut = CreateSut();
    }

    /// <summary>
    /// Builds the service over a given set of alert thresholds, normalized the
    /// way both hosts do at startup. Passing none yields the default install
    /// (30, 14, 7, 1), so the widest window is 30. Issue #152.
    /// </summary>
    private DashboardMetricsService CreateSut(params int[] thresholdDays)
    {
        var alerts = new AlertOptions { ThresholdDays = thresholdDays };
        alerts.NormalizeThresholdDays();
        return new DashboardMetricsService(
            _db, NullLogger<DashboardMetricsService>.Instance, Options.Create(alerts));
    }

    private void Seed(
        int requestId, string status, DateTime notAfter, DateTime? revokedAt = null,
        string? subject = null)
    {
        _db.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = requestId,
            SerialNumber = $"SERIAL{requestId:D4}",
            Subject = subject ?? $"CN=cert{requestId}.example.com",
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

    // ── Expiry window comes from the operator's alert thresholds (issue #152) ──
    // The donut and the "Expiring Soon" stat card render on one screen, so the
    // donut reading a literal 30 while the card read the configured window would
    // just relocate the contradiction this issue exists to remove.

    [Fact]
    public async Task FleetHealth_WiderThreshold_MovesCertIntoExpiringSegment()
    {
        var now = DateTime.UtcNow;
        Seed(1, "Issued", now.AddDays(45));
        await _db.SaveChangesAsync();

        var sut = CreateSut(60, 30, 7);
        var health = await sut.GetFleetHealthAsync();

        var byKey = health.Segments.ToDictionary(s => s.Key, s => s.Count);
        byKey["expiring"].Should().Be(1, "45 days is inside a 60 day window");
        byKey["valid"].Should().Be(0);
    }

    [Fact]
    public async Task FleetHealth_DefaultThresholds_LeavesSameCertValid()
    {
        var now = DateTime.UtcNow;
        Seed(1, "Issued", now.AddDays(45));
        await _db.SaveChangesAsync();

        // The default install is unchanged: 45 days is outside the 30 day window.
        var health = await _sut.GetFleetHealthAsync();

        var byKey = health.Segments.ToDictionary(s => s.Key, s => s.Count);
        byKey["expiring"].Should().Be(0);
        byKey["valid"].Should().Be(1);
    }

    [Fact]
    public async Task FleetHealth_NarrowerThreshold_LeavesCertValid()
    {
        var now = DateTime.UtcNow;
        Seed(1, "Issued", now.AddDays(20));
        await _db.SaveChangesAsync();

        // Coupling runs both ways: an operator who alerts only at 7 days gets a
        // 7 day dashboard, so the screen never contradicts the emails.
        var sut = CreateSut(7);
        var health = await sut.GetFleetHealthAsync();

        var byKey = health.Segments.ToDictionary(s => s.Key, s => s.Count);
        byKey["expiring"].Should().Be(0);
        byKey["valid"].Should().Be(1);
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
    public async Task Activity_QuotedCommaBearingSubject_ReportsTheWholeCommonName()
    {
        // Issue #231. Windows renders a comma bearing common name in quotes, so
        // reading to the first comma reported the fragment "\"host.example.com"
        // and the feed named something that was never issued. On a template with
        // enrollee supplies subject the requester picks that name.
        var revokedAt = DateTime.UtcNow.AddHours(-2);
        Seed(1, "Revoked", DateTime.UtcNow.AddDays(300), revokedAt,
            subject: "CN=\"host.example.com, O=Trusted Corp\", O=Real Org");
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        activity.Should().ContainSingle(i => i.Type == "revoked")
            .Subject.Cn.Should().Be("host.example.com, O=Trusted Corp");
    }

    [Fact]
    public async Task Activity_SubjectWithNoCommonName_StillFallsBackToTheWholeSubject()
    {
        // The SAN only shape, stored as a bare name with no "CN=" prefix at all.
        // The parser returns null for it and the fallback is what names the row,
        // so this path has to keep working alongside the fix above.
        var revokedAt = DateTime.UtcNow.AddHours(-2);
        Seed(1, "Revoked", DateTime.UtcNow.AddDays(300), revokedAt,
            subject: "acme.example.com");
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        activity.Should().ContainSingle(i => i.Type == "revoked")
            .Subject.Cn.Should().Be("acme.example.com");
    }

    [Fact]
    public async Task Activity_IncludesDomainPolicyRejection()
    {
        var occurredAt = DateTime.UtcNow.AddMinutes(-30);
        _db.DomainPolicyRejections.Add(new DomainPolicyRejection
        {
            OccurredAt = occurredAt,
            AccountId = "acct-1",
            TemplateId = "WebServer",
            RequestedIdentifiers = "bad.other.local, worse.example",
            RejectedIdentifiers = "bad.other.local, worse.example",
            Stage = "newOrder",
        });
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        var item = activity.Should().ContainSingle(i => i.Type == "rejected").Subject;
        item.Id.Should().Be("rejected-1");
        item.Cn.Should().Be("bad.other.local");
        item.Tmpl.Should().Be("blocked by the domain allow list");
        item.Timestamp.Should().Be(occurredAt);
    }

    [Fact]
    public async Task Activity_NamespaceRejection_NamesTheCredentialNamespace()
    {
        // The "-eab" stages are refusals by an EAB credential's domain
        // namespace. Labeling them like allow list refusals would send the
        // admin to the Settings page when the fix lives on the ACME page.
        _db.DomainPolicyRejections.Add(new DomainPolicyRejection
        {
            OccurredAt = DateTime.UtcNow.AddMinutes(-10),
            AccountId = "acct-1",
            TemplateId = "WebServer",
            RequestedIdentifiers = "outside.example",
            RejectedIdentifiers = "outside.example",
            Stage = "newOrder-eab",
        });
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        var item = activity.Should().ContainSingle(i => i.Type == "rejected").Subject;
        item.Tmpl.Should().Be("blocked by the EAB credential's domain namespace");
    }

    [Theory]
    [InlineData("newOrder-device")]
    [InlineData("challenge-device")]
    [InlineData("finalize-device")]
    public async Task Activity_DeviceRejection_NamesTheDeviceAttestationPolicy(string stage)
    {
        // The "-device" stages are refusals by the device attestation gate at
        // newOrder, challenge validation, or finalize. They must read as the
        // device attestation policy, not the domain allow list, so the admin
        // looks at the device attestation card rather than the Settings page.
        _db.DomainPolicyRejections.Add(new DomainPolicyRejection
        {
            OccurredAt = DateTime.UtcNow.AddMinutes(-10),
            AccountId = "acct-1",
            TemplateId = "WebServer",
            RequestedIdentifiers = "PROBE-SN-0001",
            RejectedIdentifiers = "PROBE-SN-0001",
            Stage = stage,
        });
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        var item = activity.Should().ContainSingle(i => i.Type == "rejected").Subject;
        item.Tmpl.Should().Be("blocked by the device attestation policy");
    }

    [Fact]
    public async Task Activity_FinalizeGuardRejection_NamesTheTlsGuardrail()
    {
        // The "-guard" stage is the TLS capability ceiling's finalize leaf
        // check: the CA issued something outside the ceiling and it was
        // refused and revoked. The fix is the template configuration, not
        // the domain allow list, so the label must say so. The branch must
        // sit above the bare fallback in the label chain or this reads as
        // an allow list refusal.
        _db.DomainPolicyRejections.Add(new DomainPolicyRejection
        {
            OccurredAt = DateTime.UtcNow.AddMinutes(-10),
            AccountId = "acct-1",
            TemplateId = "Sneaky",
            RequestedIdentifiers = "guard.example.com",
            RejectedIdentifiers = "guard.example.com",
            Stage = "finalize-guard",
        });
        await _db.SaveChangesAsync();

        var activity = await _sut.GetActivityAsync();

        var item = activity.Should().ContainSingle(i => i.Type == "rejected").Subject;
        item.Tmpl.Should().Be("blocked by the TLS certificate guardrail");
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
