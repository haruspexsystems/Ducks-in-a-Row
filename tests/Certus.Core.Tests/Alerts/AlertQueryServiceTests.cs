using Certus.Core.Alerts;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Alerts;

public class AlertQueryServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly AlertQueryService _sut;

    public AlertQueryServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _sut = new AlertQueryService(_db, NullLogger<AlertQueryService>.Instance);

        SeedData();
    }

    private void SeedData()
    {
        var now = DateTime.UtcNow;

        // Seed certificates
        var cert1 = new SyncedCertificate
        {
            RequestId = 1,
            SerialNumber = "ALERT001",
            Subject = "CN=web.example.com",
            TemplateName = "WebServer",
            NotBefore = now.AddDays(-30),
            NotAfter = now.AddDays(25),
            Status = "Issued",
            RequestDate = now.AddDays(-30),
        };
        var cert2 = new SyncedCertificate
        {
            RequestId = 2,
            SerialNumber = "ALERT002",
            Subject = "CN=api.example.com",
            TemplateName = "WebServer",
            NotBefore = now.AddDays(-60),
            NotAfter = now.AddDays(10),
            Status = "Issued",
            RequestDate = now.AddDays(-60),
        };
        _db.SyncedCertificates.AddRange(cert1, cert2);
        _db.SaveChanges();

        // Seed alert history
        _db.AlertsSent.AddRange(
            new AlertSent
            {
                CertificateId = cert1.Id,
                ThresholdDays = 30,
                SentAt = now.AddHours(-2),
                Channels = "email,webhook",
                Success = true,
            },
            new AlertSent
            {
                CertificateId = cert2.Id,
                ThresholdDays = 30,
                SentAt = now.AddHours(-2),
                Channels = "email",
                Success = true,
            },
            new AlertSent
            {
                CertificateId = cert2.Id,
                ThresholdDays = 14,
                SentAt = now.AddHours(-1),
                Channels = "email",
                Success = false,
                ErrorMessage = "SMTP timeout",
            });
        _db.SaveChanges();
    }

    [Fact]
    public async Task GetHistory_ReturnsAllAlerts()
    {
        var result = await _sut.GetHistoryAsync();

        result.TotalCount.Should().Be(3);
        result.Items.Should().HaveCount(3);
    }

    [Fact]
    public async Task GetHistory_OrdersByMostRecent()
    {
        var result = await _sut.GetHistoryAsync();

        // Most recent first
        result.Items[0].ThresholdDays.Should().Be(14); // Sent most recently
        result.Items[0].SentAt.Should().BeAfter(result.Items[1].SentAt);
    }

    [Fact]
    public async Task GetHistory_IncludesCertificateDetails()
    {
        var result = await _sut.GetHistoryAsync();

        result.Items.Should().Contain(a => a.Subject == "CN=web.example.com");
        result.Items.Should().Contain(a => a.Subject == "CN=api.example.com");
    }

    [Fact]
    public async Task GetHistory_Pagination_RespectsSkipAndTake()
    {
        var page1 = await _sut.GetHistoryAsync(skip: 0, take: 2);
        var page2 = await _sut.GetHistoryAsync(skip: 2, take: 2);

        page1.Items.Should().HaveCount(2);
        page2.Items.Should().HaveCount(1);
        page1.TotalCount.Should().Be(3);
        page1.HasMore.Should().BeTrue();
        page2.HasMore.Should().BeFalse();
    }

    [Fact]
    public async Task GetSummary_ReturnsAccurateCounts()
    {
        var summary = await _sut.GetSummaryAsync();

        summary.TotalAlertsSent.Should().Be(3);
        summary.FailedAlerts.Should().Be(1);
        summary.UniqueCertificatesAlerted.Should().Be(2);
        summary.LastAlertSent.Should().NotBeNull();
    }

    [Fact]
    public async Task GetHistory_IncludesErrorMessages()
    {
        var result = await _sut.GetHistoryAsync();

        var failed = result.Items.FirstOrDefault(a => !a.Success);
        failed.Should().NotBeNull();
        failed!.ErrorMessage.Should().Be("SMTP timeout");
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }
}
