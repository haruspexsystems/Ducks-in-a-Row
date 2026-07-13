using Certus.Core.Alerts;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Certus.Core.Tests.Alerts;

public class ExpiryMonitorServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _serviceProvider;
    private readonly IAlertNotifier _mockNotifier;
    private readonly AlertOptions _alertOptions;
    private readonly List<IServiceScope> _scopes = new();

    public ExpiryMonitorServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        _mockNotifier = Substitute.For<IAlertNotifier>();
        _mockNotifier.Channel.Returns("test");
        _mockNotifier.IsEnabled.Returns(true);
        _mockNotifier.SendExpiryAlertAsync(Arg.Any<ExpiryAlertBatch>(), Arg.Any<CancellationToken>())
            .Returns(new AlertNotificationResult(true));

        _alertOptions = new AlertOptions
        {
            Enabled = true,
            ThresholdDays = [30, 14, 7, 1],
        };

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(options =>
            options.UseSqlite(_connection));
        services.AddScoped<IAlertNotifier>(_ => _mockNotifier);

        _serviceProvider = services.BuildServiceProvider();

        // Create the database
        using var scope = _serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        db.Database.EnsureCreated();
    }

    private ExpiryMonitorService CreateService()
    {
        return new ExpiryMonitorService(
            _serviceProvider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(_alertOptions),
            NullLogger<ExpiryMonitorService>.Instance);
    }

    private CertusDbContext GetDb()
    {
        var scope = _serviceProvider.CreateScope();
        _scopes.Add(scope);
        return scope.ServiceProvider.GetRequiredService<CertusDbContext>();
    }

    private void SeedCertificate(int requestId, string subject, int daysUntilExpiry, string status = "Issued")
    {
        var db = GetDb();
        db.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = requestId,
            SerialNumber = $"SERIAL{requestId:D4}",
            Subject = subject,
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-30),
            NotAfter = DateTime.UtcNow.AddDays(daysUntilExpiry),
            Status = status,
            Requestor = "admin",
            RequestDate = DateTime.UtcNow.AddDays(-30),
        });
        db.SaveChanges();
    }

    [Fact]
    public async Task Check_CertExpiringWithin30Days_SendsAlert()
    {
        SeedCertificate(1, "CN=expiring.example.com", 25);

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.Received(1).SendExpiryAlertAsync(
            Arg.Is<ExpiryAlertBatch>(b => b.ThresholdDays == 30 && b.Certificates.Count == 1),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Check_CertExpiringWithin7Days_SendsMultipleThresholdAlerts()
    {
        SeedCertificate(1, "CN=urgent.example.com", 5); // 5 days: triggers 30, 14, 7

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        // Should fire for 30-day, 14-day, and 7-day thresholds
        await _mockNotifier.Received(3).SendExpiryAlertAsync(
            Arg.Any<ExpiryAlertBatch>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Check_CertNotExpiringSoon_NoAlert()
    {
        SeedCertificate(1, "CN=fine.example.com", 365);

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.DidNotReceive().SendExpiryAlertAsync(
            Arg.Any<ExpiryAlertBatch>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Check_AlreadyExpired_NoAlert()
    {
        SeedCertificate(1, "CN=expired.example.com", -5); // Already expired

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        // We don't alert on already-expired certs (NotAfter <= now)
        await _mockNotifier.DidNotReceive().SendExpiryAlertAsync(
            Arg.Any<ExpiryAlertBatch>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Check_RevokedCert_NoAlert()
    {
        SeedCertificate(1, "CN=revoked.example.com", 10, status: "Revoked");

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.DidNotReceive().SendExpiryAlertAsync(
            Arg.Any<ExpiryAlertBatch>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Check_DeduplicatesAlerts()
    {
        SeedCertificate(1, "CN=expiring.example.com", 25);

        var sut = CreateService();

        // First check — should fire
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);
        await _mockNotifier.Received(1).SendExpiryAlertAsync(
            Arg.Any<ExpiryAlertBatch>(),
            Arg.Any<CancellationToken>());

        _mockNotifier.ClearReceivedCalls();

        // Second check — should NOT fire (already sent for this threshold)
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);
        await _mockNotifier.DidNotReceive().SendExpiryAlertAsync(
            Arg.Any<ExpiryAlertBatch>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Check_RecordsAlertInDatabase()
    {
        SeedCertificate(1, "CN=expiring.example.com", 25);

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var alerts = await db.AlertsSent.ToListAsync();
        alerts.Should().HaveCount(1);
        alerts[0].ThresholdDays.Should().Be(30);
        alerts[0].Channels.Should().Be("test");
        alerts[0].Success.Should().BeTrue();
    }

    [Fact]
    public async Task Check_NoEnabledNotifiers_SkipsCheck()
    {
        _mockNotifier.IsEnabled.Returns(false);
        SeedCertificate(1, "CN=expiring.example.com", 25);

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.DidNotReceive().SendExpiryAlertAsync(
            Arg.Any<ExpiryAlertBatch>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Check_MultipleCertsExpiring_BatchesTogether()
    {
        SeedCertificate(1, "CN=cert1.example.com", 25);
        SeedCertificate(2, "CN=cert2.example.com", 20);
        SeedCertificate(3, "CN=cert3.example.com", 10);

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        // 30-day threshold should batch all 3 certs
        await _mockNotifier.Received().SendExpiryAlertAsync(
            Arg.Is<ExpiryAlertBatch>(b => b.ThresholdDays == 30 && b.Certificates.Count == 3),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Check_FailedNotification_RecordsError()
    {
        _mockNotifier.SendExpiryAlertAsync(Arg.Any<ExpiryAlertBatch>(), Arg.Any<CancellationToken>())
            .Returns(new AlertNotificationResult(false, "SMTP connection refused"));

        SeedCertificate(1, "CN=expiring.example.com", 25);

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var alert = await db.AlertsSent.FirstAsync();
        alert.Success.Should().BeFalse();
        alert.ErrorMessage.Should().Be("SMTP connection refused");
    }

    public void Dispose()
    {
        foreach (var scope in _scopes)
            scope.Dispose();
        _serviceProvider.Dispose();
        _connection.Dispose();
    }
}
