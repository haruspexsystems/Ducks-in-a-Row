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
    private readonly List<ServiceProvider> _providers = new();

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
    /// An identity that owns nothing, for the tests that are not about suppression.
    /// </summary>
    private static ServerCertificateIdentity NoServerCertificate() => ServerCertificateFixtures.None();

    /// <summary>
    /// A <see cref="ServerCertificateIdentity"/> whose store holds one certificate
    /// carrying <paramref name="serialHex"/>, which is what the server's own HTTPS
    /// certificate looks like to the suppression path.
    /// </summary>
    private static (ServerCertificateIdentity Identity, X509Certificate2 Certificate)
        ServerCertificateWithSerial(
            byte[] serialHex,
            bool autoRenewalEnabled = true,
            CertusInstanceMode? instanceMode = null,
            bool installedByService = true) =>
        ServerCertificateFixtures.WithSerial(serialHex, autoRenewalEnabled, instanceMode, installedByService);

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
        alerts[0].DeliveredChannels.Should().Be("test");
        alerts[0].Success.Should().BeTrue();
    }

    /// <summary>
    /// A second provider over the same database with its own notifiers, for the
    /// tests about more than one channel. The constructor's provider registers
    /// the single mock notifier every other test uses.
    /// </summary>
    private ExpiryMonitorService CreateServiceWith(params IAlertNotifier[] notifiers)
    {
        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(options => options.UseSqlite(_connection));
        foreach (var notifier in notifiers)
            services.AddScoped(_ => notifier);

        var provider = services.BuildServiceProvider();
        _providers.Add(provider);

        return new ExpiryMonitorService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(_alertOptions),
            NullLogger<ExpiryMonitorService>.Instance,
            NoServerCertificate());
    }

    private static IAlertNotifier Notifier(string channel, AlertNotificationResult result)
    {
        var notifier = Substitute.For<IAlertNotifier>();
        notifier.Channel.Returns(channel);
        notifier.IsEnabled.Returns(true);
        notifier.SendExpiryAlertAsync(Arg.Any<ExpiryAlertBatch>(), Arg.Any<CancellationToken>())
            .Returns(result);
        return notifier;
    }

    /// <summary>
    /// Issue #206: the email arrived and the webhook did not. The row must say
    /// that, rather than read the same as both failing.
    /// </summary>
    [Fact]
    public async Task Check_MixedOutcome_RecordsEachChannelsOwnResult()
    {
        var email = Notifier("email", new AlertNotificationResult(true));
        var webhook = Notifier("webhook", new AlertNotificationResult(false, "Webhook returned 500"));
        SeedCertificate(1, "CN=expiring.example.com", 25);

        await CreateServiceWith(email, webhook).CheckForExpiringCertificatesAsync(CancellationToken.None);

        var alert = await GetDb().AlertsSent.SingleAsync();
        alert.Channels.Should().Be("email,webhook");
        alert.DeliveredChannels.Should().Be("email");
        alert.Success.Should().BeFalse("one channel failed");
        alert.ErrorMessage.Should().Be("Webhook returned 500",
            "the only failure needs no channel name; the channel columns say which it was");
    }

    /// <summary>
    /// The channel that delivered must not hear about the threshold again. The
    /// failed one is not retried either: that is issue #641, and until it lands
    /// a recorded row suppresses the threshold on every channel, as before.
    /// </summary>
    [Fact]
    public async Task Check_MixedOutcome_DoesNotSendAgainOnTheNextPass()
    {
        var email = Notifier("email", new AlertNotificationResult(true));
        var webhook = Notifier("webhook", new AlertNotificationResult(false, "Webhook returned 500"));
        SeedCertificate(1, "CN=expiring.example.com", 25);
        var sut = CreateServiceWith(email, webhook);

        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);
        email.ClearReceivedCalls();
        webhook.ClearReceivedCalls();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await email.DidNotReceive().SendExpiryAlertAsync(Arg.Any<ExpiryAlertBatch>(), Arg.Any<CancellationToken>());
        await webhook.DidNotReceive().SendExpiryAlertAsync(Arg.Any<ExpiryAlertBatch>(), Arg.Any<CancellationToken>());
        (await GetDb().AlertsSent.CountAsync()).Should().Be(1);
    }

    /// <summary>
    /// Before issue #206 the row kept only the last failing channel's error, so
    /// the email failure here was lost.
    /// </summary>
    [Fact]
    public async Task Check_EveryChannelFails_KeepsEachChannelsError()
    {
        var email = Notifier("email", new AlertNotificationResult(false, "SMTP connection refused"));
        var webhook = Notifier("webhook", new AlertNotificationResult(false, "Webhook returned 500"));
        SeedCertificate(1, "CN=expiring.example.com", 25);

        await CreateServiceWith(email, webhook).CheckForExpiringCertificatesAsync(CancellationToken.None);

        var alert = await GetDb().AlertsSent.SingleAsync();
        alert.Channels.Should().Be("email,webhook");
        alert.DeliveredChannels.Should().BeEmpty("no channel delivered");
        alert.Success.Should().BeFalse();
        alert.ErrorMessage.Should().Be("email: SMTP connection refused\nwebhook: Webhook returned 500");
    }

    [Fact]
    public void DescribeFailures_TwoLongErrors_FitTheColumn()
    {
        // Each error at the redactor's own cap, which alone is half the column.
        var error = new string('x', 501);

        var text = ExpiryMonitorService.DescribeFailures([("email", error), ("webhook", error)]);

        text!.Length.Should().BeLessThanOrEqualTo(AlertErrorRedactor.MaxStoredLength);
        var lines = text.Split('\n');
        lines.Should().HaveCount(2, "a long first error must not push the second out of the row");
        lines[0].Should().StartWith("email: ").And.EndWith("…");
        lines[1].Should().StartWith("webhook: ").And.EndWith("…");
    }

    [Fact]
    public void DescribeFailures_NeverSplitsASurrogatePair()
    {
        // An emoji straddling the cut of the email line, as a receiver's response
        // body can carry: "email: " is 7 characters, so its high half lands on
        // the last character the 499 character share keeps before the ellipsis.
        var error = new string('x', 490) + "😀" + new string('y', 20);

        var text = ExpiryMonitorService.DescribeFailures([("email", error), ("webhook", error)])!;

        text.Should().Contain("…", "the cut has to have happened for this to test anything");
        text.Where((c, i) => char.IsHighSurrogate(c) && (i + 1 >= text.Length || !char.IsLowSurrogate(text[i + 1])))
            .Should().BeEmpty("a lone high surrogate is not valid text");
    }

    [Fact]
    public void DescribeFailures_ChannelWithoutAnError_IsStillNamed()
    {
        ExpiryMonitorService.DescribeFailures([("email", null), ("webhook", "Webhook returned 500")])
            .Should().Be("email: failed\nwebhook: Webhook returned 500");
        ExpiryMonitorService.DescribeFailures([]).Should().BeNull();
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
    /// The row is the record that outlives everything else, and the database
    /// travels with every backup (issue #635). The notifiers redact their own
    /// text; this pins the second pass on the way to the table, with a notifier
    /// that did not.
    /// </summary>
    [Fact]
    public async Task Check_FailedNotification_StoresTheErrorRedacted()
    {
        _alertOptions.Webhook = new WebhookOptions
        {
            Url = "https://hooks.example.com/services/T000/xoxb-secret-token",
            Secret = "shared-secret",
        };
        _mockNotifier.SendExpiryAlertAsync(Arg.Any<ExpiryAlertBatch>(), Arg.Any<CancellationToken>())
            .Returns(new AlertNotificationResult(
                false, "POST https://hooks.example.com/services/T000/xoxb-secret-token failed: bad shared-secret"));

        SeedCertificate(1, "CN=expiring.example.com", 25);

        var sut = CreateService();
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var alert = await db.AlertsSent.FirstAsync();
        alert.Success.Should().BeFalse();
        alert.ErrorMessage.Should().NotContain("xoxb-secret-token");
        alert.ErrorMessage.Should().NotContain("shared-secret");
        alert.ErrorMessage.Should().NotContain("hooks.example.com");
        alert.ErrorMessage.Should().Contain("(redacted)");
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

    /// <summary>
    /// Issue #470. The exclusion above exists because automatic renewal owns the
    /// certificate. With renewal turned off nothing does, so it must alert like any
    /// other; before the fix it stayed silent until it expired.
    /// </summary>
    [Fact]
    public async Task Check_ServerOwnCertificate_RenewalOff_Alerts()
    {
        var (identity, certificate) = ServerCertificateWithSerial(
            [0x00, 0xAB, 0xCD], autoRenewalEnabled: false);
        using var _ = certificate;
        SeedCertificate(1, "CN=certus.home.local", 20, serialNumber: "abcd");

        var sut = CreateService(identity);
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.Received(1).SendExpiryAlertAsync(
            Arg.Is<ExpiryAlertBatch>(b =>
                b.ThresholdDays == 30 &&
                b.Certificates.Count == 1 &&
                b.Certificates[0].Subject == "CN=certus.home.local"),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// Issue #470. Monitor mode never renews, whatever the renewal setting says, so the
    /// server's own certificate alerts there too.
    /// </summary>
    [Fact]
    public async Task Check_ServerOwnCertificate_MonitorMode_Alerts()
    {
        var (identity, certificate) = ServerCertificateWithSerial(
            [0x00, 0xAB, 0xCD], autoRenewalEnabled: true, CertusInstanceMode.Monitor);
        using var _ = certificate;
        SeedCertificate(1, "CN=certus.home.local", 20, serialNumber: "abcd");

        var sut = CreateService(identity);
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.Received(1).SendExpiryAlertAsync(
            Arg.Is<ExpiryAlertBatch>(b =>
                b.ThresholdDays == 30 &&
                b.Certificates.Count == 1 &&
                b.Certificates[0].Subject == "CN=certus.home.local"),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// Issue #535. In full mode with renewal on, the automatic renewal now leaves a
    /// certificate somebody else installed to whoever issued it, typically Windows
    /// autoenrolment for one picked in monitor mode. Nothing in this product renews it
    /// then, so it alerts like any other: if its own renewal stops, this is the warning.
    /// </summary>
    [Fact]
    public async Task Check_ServerOwnCertificate_NotInstalledByTheService_Alerts()
    {
        var (identity, certificate) = ServerCertificateWithSerial(
            [0x00, 0xAB, 0xCD], autoRenewalEnabled: true, CertusInstanceMode.Full, installedByService: false);
        using var _ = certificate;
        SeedCertificate(1, "CN=certus.home.local", 20, serialNumber: "abcd");

        var sut = CreateService(identity);
        await sut.CheckForExpiringCertificatesAsync(CancellationToken.None);

        await _mockNotifier.Received(1).SendExpiryAlertAsync(
            Arg.Is<ExpiryAlertBatch>(b =>
                b.ThresholdDays == 30 &&
                b.Certificates.Count == 1 &&
                b.Certificates[0].Subject == "CN=certus.home.local"),
            Arg.Any<CancellationToken>());
    }

    public void Dispose()
    {
        foreach (var scope in _scopes)
            scope.Dispose();
        foreach (var provider in _providers)
            provider.Dispose();
        _serviceProvider.Dispose();
        _connection.Dispose();
    }
}
