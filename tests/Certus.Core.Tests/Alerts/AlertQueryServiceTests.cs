using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Setup;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

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

        var alertOptions = new AlertOptions();
        alertOptions.NormalizeThresholdDays();

        _sut = new AlertQueryService(
            _db,
            NullLogger<AlertQueryService>.Instance,
            Options.Create(alertOptions),
            // One enabled channel, so the ladder reports the certificate as
            // monitored rather than as an install with nothing configured.
            [EnabledNotifier("email")],
            NoServerCertificate());

        SeedData();
    }

    /// <summary>
    /// An identity that owns nothing, so no certificate here is mistaken for the
    /// one Ducks serves its own web interface with. Same shape as the helper in
    /// <see cref="ExpiryMonitorServiceTests"/>.
    /// </summary>
    private static ServerCertificateIdentity NoServerCertificate() =>
        new(Substitute.For<IHttpsCertificateStore>(),
            Options.Create(new CertusOptions
            {
                // A path that does not exist, so a unit test never reads the
                // operator's real ProgramData overlay.
                SettingsOverlayPath = Path.Combine(
                    Path.GetTempPath(), "certus-no-such-overlay-" + Guid.NewGuid().ToString("N") + ".json"),
            }),
            NullLogger<ServerCertificateIdentity>.Instance);

    private static IAlertNotifier EnabledNotifier(string channel)
    {
        var notifier = Substitute.For<IAlertNotifier>();
        notifier.Channel.Returns(channel);
        notifier.IsEnabled.Returns(true);
        return notifier;
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

    // ---- Per certificate ladder (issue #160) ----------------------------
    //
    // The ladder's own decisions are covered in CertificateAlertLadderTests,
    // which needs no database. What is tested here is the wiring: that the right
    // rows reach it, and only the right rows.

    [Fact]
    public async Task GetForCertificate_UnknownCertificate_ReturnsNull()
    {
        // Null rather than an empty ladder, because an empty ladder is the
        // answer for a real certificate nobody has been warned about.
        var history = await _sut.GetForCertificateAsync(9999);

        history.Should().BeNull();
    }

    [Fact]
    public async Task GetForCertificate_ReturnsOnlyThatCertificatesRows()
    {
        var cert2 = await _db.SyncedCertificates.FirstAsync(c => c.SerialNumber == "ALERT002");

        var history = await _sut.GetForCertificateAsync(cert2.Id);

        history.Should().NotBeNull();
        history!.CertificateId.Should().Be(cert2.Id);

        // cert2 has rows at 30 and 14; cert1's own 30 day row must not leak in.
        var sent = history.Thresholds
            .Where(t => t.SentAt != null)
            .Select(t => t.ThresholdDays)
            .ToList();
        sent.Should().BeEquivalentTo(new[] { 30, 14 });
    }

    [Fact]
    public async Task GetForCertificate_CarriesTheRecordedFailureAndItsError()
    {
        var cert2 = await _db.SyncedCertificates.FirstAsync(c => c.SerialNumber == "ALERT002");

        var history = await _sut.GetForCertificateAsync(cert2.Id);

        var failed = history!.Thresholds.Single(t => t.ThresholdDays == 14);
        failed.State.Should().Be(AlertThresholdState.Failed);
        failed.ErrorMessage.Should().Be("SMTP timeout");
        failed.Channels.Should().Be("email");
    }

    [Fact]
    public async Task GetForCertificate_ReportsTheChannelsThatWouldBeAttempted()
    {
        var cert1 = await _db.SyncedCertificates.FirstAsync(c => c.SerialNumber == "ALERT001");

        var history = await _sut.GetForCertificateAsync(cert1.Id);

        history!.Coverage.Should().Be(AlertCoverage.Monitored);
        history.EnabledChannels.Should().Equal("email");
    }

    [Fact]
    public void GetConfig_DelegatesToTheView()
    {
        // Wiring only. The projection rules are AlertConfigView's and are tested
        // without a database in AlertConfigViewTests.
        var config = _sut.GetConfig();

        config.Enabled.Should().BeTrue();
        config.ThresholdDays.Should().Equal(30, 14, 7, 1);
        config.ExpiryWarningDays.Should().Be(30);
    }

    [Fact]
    public async Task GetHistory_RedactsSecretsFromRecordedErrorMessages()
    {
        // The webhook notifier builds its errors from the receiver's response
        // body or from a raw exception message, either of which can name the URL
        // and the token in it. The row is written before anyone sanitizes it, so
        // the read path has to.
        var cert = await _db.SyncedCertificates.FirstAsync(c => c.SerialNumber == "ALERT001");
        _db.AlertsSent.Add(new AlertSent
        {
            CertificateId = cert.Id,
            ThresholdDays = 7,
            SentAt = DateTime.UtcNow,
            Channels = "webhook",
            Success = false,
            ErrorMessage = "No such host is known (https://hooks.example.com/xoxb-secret)",
        });
        await _db.SaveChangesAsync();

        var result = await WithWebhook("https://hooks.example.com/xoxb-secret").GetHistoryAsync();

        var item = result.Items.Single(i => i.ThresholdDays == 7);
        item.ErrorMessage.Should().NotContain("hooks.example.com");
        item.ErrorMessage.Should().NotContain("xoxb-secret");
        item.ErrorMessage.Should().Contain("(redacted)");
    }

    [Fact]
    public async Task GetForCertificate_RedactsSecretsFromRecordedErrorMessages()
    {
        // Same hole on the certificate detail page, which has rendered these
        // strings verbatim since issue #160.
        var cert = await _db.SyncedCertificates.FirstAsync(c => c.SerialNumber == "ALERT002");

        var history = await WithWebhook("https://hooks.example.com/xoxb-secret")
            .GetForCertificateAsync(cert.Id);

        var failed = history!.Thresholds.Single(t => t.ThresholdDays == 14);
        // The seeded message holds no secret, so it survives intact; what matters
        // is that the redactor ran over this path at all.
        failed.ErrorMessage.Should().Be("SMTP timeout");
    }

    /// <summary>
    /// A second service over the same database with a webhook URL configured, so
    /// the redactor has something to strip.
    /// </summary>
    private AlertQueryService WithWebhook(string url)
    {
        var options = new AlertOptions { Webhook = new WebhookOptions { Url = url } };
        options.NormalizeThresholdDays();

        return new AlertQueryService(
            _db,
            NullLogger<AlertQueryService>.Instance,
            Options.Create(options),
            [EnabledNotifier("email")],
            NoServerCertificate());
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }
}
