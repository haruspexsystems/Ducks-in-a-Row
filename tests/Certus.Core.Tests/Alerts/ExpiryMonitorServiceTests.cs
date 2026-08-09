using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Setup;
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

    private ExpiryMonitorService CreateService(ServerCertificateIdentity? serverCertificate = null)
    {
        return new ExpiryMonitorService(
            _serviceProvider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(_alertOptions),
            NullLogger<ExpiryMonitorService>.Instance,
            serverCertificate ?? NoServerCertificate());
    }

    /// <summary>
    /// An identity that owns nothing, for the tests that are not about
    /// suppression: no thumbprint is configured, so it resolves to an empty
    /// list and every certificate alerts as it always did.
    /// </summary>
    private static ServerCertificateIdentity NoServerCertificate() =>
        new(Substitute.For<IHttpsCertificateStore>(),
            Options.Create(new CertusOptions
            {
                // Point at a path that does not exist rather than letting the
                // default resolve to the real data directory: a unit test must
                // never read the operator's ProgramData overlay.
                SettingsOverlayPath = Path.Combine(
                    Path.GetTempPath(), "certus-no-such-overlay-" + Guid.NewGuid().ToString("N") + ".json"),
            }),
            NullLogger<ServerCertificateIdentity>.Instance);

    /// <summary>
    /// A <see cref="ServerCertificateIdentity"/> whose store holds one
    /// certificate carrying <paramref name="serialHex"/>, which is what the
    /// server's own HTTPS certificate looks like to the suppression path.
    /// </summary>
    private static (ServerCertificateIdentity Identity, X509Certificate2 Certificate)
        ServerCertificateWithSerial(byte[] serialHex)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=certus.home.local", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.Create(
            request.SubjectName,
            X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(20),
            serialHex);

        var store = Substitute.For<IHttpsCertificateStore>();
        store.Find("AA11BB22").Returns(_ => X509CertificateLoader.LoadCertificate(certificate.RawData));

        var options = Options.Create(new CertusOptions
        {
            HttpsCertificateThumbprint = "AA11BB22",
            // A path that does not exist reads as an empty overlay, so the
            // in process thumbprint above is the whole answer.
            SettingsOverlayPath = Path.Combine(
                Path.GetTempPath(), "certus-no-such-overlay-" + Guid.NewGuid().ToString("N") + ".json"),
        });

        return (new ServerCertificateIdentity(
            store, options, NullLogger<ServerCertificateIdentity>.Instance), certificate);
    }

    private CertusDbContext GetDb()
    {
        var scope = _serviceProvider.CreateScope();
        _scopes.Add(scope);
        return scope.ServiceProvider.GetRequiredService<CertusDbContext>();
    }

    private void SeedCertificate(
        int requestId, string subject, int daysUntilExpiry, string status = "Issued",
        string? serialNumber = null)
    {
        var db = GetDb();
        db.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = requestId,
            SerialNumber = serialNumber ?? $"SERIAL{requestId:D4}",
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

    /// <summary>
    /// The server's own HTTPS certificate is issued by the monitored CA, so it
    /// syncs into the inventory like any other. Automatic renewal owns it
    /// (issue #105), so the threshold ladder must stay quiet about it, and no
    /// AlertsSent row may be written either: if it ever stops being ours, the
    /// normal alerts have to start firing again.
    /// </summary>
    [Fact]
    public async Task Check_ServerOwnCertificate_IsSuppressed()
    {
        // The CA database stores the serial lowercase with no pad; the X509
        // form is uppercase and carries the leading zero of a DER integer
        // whose top bit is set. Both sides must normalize before comparing.
        var (identity, certificate) = ServerCertificateWithSerial([0x00, 0xAB, 0xCD]);
        using var _ = certificate;
        SeedCertificate(1, "CN=certus.home.local", 20, serialNumber: "abcd");

        var sut = CreateService(identity);
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.DidNotReceive().SendExpiryAlertAsync(
            Arg.Any<ExpiryAlertBatch>(), Arg.Any<CancellationToken>());
        (await GetDb().AlertsSent.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task Check_ServerOwnCertificate_DoesNotSilenceItsNeighbours()
    {
        var (identity, certificate) = ServerCertificateWithSerial([0x00, 0xAB, 0xCD]);
        using var _ = certificate;
        SeedCertificate(1, "CN=certus.home.local", 20, serialNumber: "abcd");
        SeedCertificate(2, "CN=other.example.com", 20);

        var sut = CreateService(identity);
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.Received(1).SendExpiryAlertAsync(
            Arg.Is<ExpiryAlertBatch>(b =>
                b.ThresholdDays == 30 &&
                b.Certificates.Count == 1 &&
                b.Certificates[0].Subject == "CN=other.example.com"),
            Arg.Any<CancellationToken>());
    }

    public void Dispose()
    {
        foreach (var scope in _scopes)
            scope.Dispose();
        _serviceProvider.Dispose();
        _connection.Dispose();
    }
}
