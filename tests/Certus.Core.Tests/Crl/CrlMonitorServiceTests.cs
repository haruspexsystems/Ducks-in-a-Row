using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Crl;
using Certus.Core.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// The monitor end to end, on a real database with a synthetic two tier
/// hierarchy: an offline root that signs an issuing CA certificate carrying two
/// distribution points, and CRLs served from both.
///
/// The two tier case is the whole point of issue #447 and cannot be built on any
/// lab, because every lab CA is a single tier Enterprise Root. So it is built
/// here instead, and the pieces that a lab can prove (that the parser reads real
/// ADCS output, that the COM properties answer) were proved on lab 2019 on
/// 2026-09-23 and recorded on the issue.
/// </summary>
public class CrlMonitorServiceTests : IDisposable
{
    private const string LdapUrl = "ldap:///CN=Example%20Root,CN=CDP,DC=corp,DC=example,DC=com"
        + "?certificateRevocationList?base?objectClass=cRLDistributionPoint";
    private const string HttpUrl = "http://pki.corp.example.com/ExampleRoot.crl";
    private const string CaOwnUrl = "http://pki.corp.example.com/ExampleIssuing.crl";

    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _services;
    private readonly FakeTimeProvider _clock;
    private readonly RecordingNotifier _notifier;
    private readonly IAdcsClient _adcs;
    private bool _chainFails;
    private byte[][] _chainCertificates = [];
    private readonly FakeCaCrlReader _caReader;
    private readonly FakeDistributionPointFetcher _fetcher;
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _issuing;
    private readonly AlertOptions _options;

    public CrlMonitorServiceTests()
    {
        _root = CrlTestPki.MintRootCa("CN=Example Root CA");
        _issuing = CrlTestPki.MintIssuingCa(_root, "CN=Example Issuing CA", LdapUrl, HttpUrl);

        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        _clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        _notifier = new RecordingNotifier();
        // NSubstitute rather than a hand written double: the monitor asks this
        // interface for one thing, and a full implementation of it here would be
        // four hundred lines of NotSupportedException that drift on every change.
        _adcs = Substitute.For<IAdcsClient>();
        _chainCertificates = [_issuing.RawData, _root.RawData];
        _adcs.GetCaCertificateChainAsync(Arg.Any<CancellationToken>()).Returns(_ =>
            _chainFails
                ? throw new CaUnavailableException("CertSvc RPC unreachable.")
                : (IReadOnlyList<byte[]>)_chainCertificates);
        _caReader = new FakeCaCrlReader();
        _fetcher = new FakeDistributionPointFetcher();

        _options = new AlertOptions { Enabled = true, ThresholdDays = [30, 14, 7, 1] };

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        services.AddScoped<IAdcsClient>(_ => _adcs);
        services.AddScoped<ICaCrlReader>(_ => _caReader);
        services.AddScoped<ICrlDistributionPointFetcher>(_ => _fetcher);
        services.AddScoped<IAlertNotifier>(_ => _notifier);
        _services = services.BuildServiceProvider();

        using var scope = _services.CreateScope();
        scope.ServiceProvider.GetRequiredService<CertusDbContext>().Database.EnsureCreated();
    }

    private CrlMonitorService CreateMonitor() => new(
        _services.GetRequiredService<IServiceScopeFactory>(),
        Options.Create(_options),
        NullLogger<CrlMonitorService>.Instance,
        _clock);

    private CertusDbContext OpenDb() =>
        _services.CreateScope().ServiceProvider.GetRequiredService<CertusDbContext>();

    #region The quiet case

    [Fact]
    public async Task A_healthy_estate_records_every_crl_and_sends_nothing()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 300);
        ServeRootCrl(HttpUrl, number: 12, expiresInDays: 300);

        await CreateMonitor().CheckAsync();

        using var db = OpenDb();
        var rows = db.MonitoredCrls.ToList();
        rows.Should().HaveCount(3, "the CA's own CRL plus one row per distribution point");
        rows.Where(r => r.Scope == "parent").Should().HaveCount(2);
        rows.Single(r => r.Source == CrlMonitorService.CaSource).AutoPublished
            .Should().BeTrue("the configured CA replaces its own CRL on a timer");
        rows.Where(r => r.Scope == "parent").Should().AllSatisfy(r =>
            r.AutoPublished.Should().BeFalse("a root CRL that lives 300 days is published by hand"));

        _notifier.Alerts.Should().BeEmpty();
        db.CrlAlertsSent.Should().BeEmpty();
    }

    [Fact]
    public async Task A_verified_signature_is_recorded_as_such()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 300);

        await CreateMonitor().CheckAsync();

        using var db = OpenDb();
        db.MonitoredCrls.Single(r => r.Source == LdapUrl).SignatureStatus.Should().Be("verified");
    }

    #endregion

    #region The case the feature exists for

    [Fact]
    public async Task A_root_crl_inside_a_threshold_alerts_once_and_names_every_place_it_is_served()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 13);
        ServeRootCrl(HttpUrl, number: 12, expiresInDays: 13);

        await CreateMonitor().CheckAsync();

        // One CRL, two copies, one alert per stage crossed.
        _notifier.Alerts.Select(a => a.Stage).Should().Equal("30", "14");
        var alert = _notifier.Alerts[0];
        alert.Sources.Should().BeEquivalentTo([LdapUrl, HttpUrl]);
        alert.Scope.Should().Be("parent");
        alert.IssuerName.Should().Contain("Example Root CA");
        alert.NewerCrlNumber.Should().BeNull();
    }

    [Fact]
    public async Task The_same_alert_is_not_sent_twice()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 13);

        var monitor = CreateMonitor();
        await monitor.CheckAsync();
        _clock.Advance(TimeSpan.FromHours(1));
        await monitor.CheckAsync();

        _notifier.Alerts.Select(a => a.Stage).Should().Equal("30", "14");
    }

    [Fact]
    public async Task A_renewed_root_crl_re_arms_every_threshold()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 13);

        var monitor = CreateMonitor();
        await monitor.CheckAsync();
        _notifier.Alerts.Should().HaveCount(2);

        // The ceremony happened: a new CRL, a new number, a year of life.
        ServeRootCrl(LdapUrl, number: 13, expiresInDays: 365);
        _clock.Advance(TimeSpan.FromHours(1));
        GiveTheCaAHealthyCrl();
        await monitor.CheckAsync();

        _notifier.Alerts.Should().HaveCount(2, "the new CRL is nowhere near expiry");

        // And when the new one ages, the ladder runs again under its own number.
        // The CA keeps publishing its own CRL through all of this, as a running
        // CA does; leaving it stale would be testing the other rule.
        _clock.Advance(TimeSpan.FromDays(352));
        GiveTheCaAHealthyCrl();
        await monitor.CheckAsync();

        // Thirteen days left on the new CRL, so it crosses both of the wide
        // thresholds in one pass, exactly as the first one did.
        _notifier.Alerts.Select(a => a.Stage).Should().Equal("30", "14", "30", "14");
        _notifier.Alerts.TakeLast(2).Should().AllSatisfy(a => a.CrlNumber.Should().Be("0D"));
    }

    [Fact]
    public async Task A_copy_left_behind_at_one_location_warns_on_its_own_and_names_the_newer_one()
    {
        // The commonest way a root CRL renewal goes wrong: published to the
        // directory, never copied to the web server.
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 13, expiresInDays: 365);
        ServeRootCrl(HttpUrl, number: 12, expiresInDays: 6);

        await CreateMonitor().CheckAsync();

        var stale = _notifier.Alerts.Where(a => a.CrlNumber == "0C").ToList();
        stale.Select(a => a.Stage).Should().Equal("30", "14", "7");
        stale.Should().AllSatisfy(a =>
        {
            a.Sources.Should().Equal(HttpUrl);
            a.NewerCrlNumber.Should().Be("0D", "a newer CRL is already published elsewhere");
        });

        _notifier.Alerts.Where(a => a.CrlNumber == "0D").Should().BeEmpty();
    }

    [Fact]
    public async Task An_expired_root_crl_says_so()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: -1);

        await CreateMonitor().CheckAsync();

        _notifier.Alerts.Select(a => a.Stage).Should().Contain(CrlAlertRules.ExpiredStage);
        _notifier.Alerts.Last().HoursRemaining.Should().BeLessThan(0);
    }

    #endregion

    #region Failures

    [Fact]
    public async Task An_unreachable_distribution_point_keeps_warning_from_the_last_copy_read()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 40);

        var monitor = CreateMonitor();
        await monitor.CheckAsync();
        _notifier.Alerts.Should().BeEmpty();

        // The directory goes away, and the CRL ages on regardless.
        _fetcher.Refuse(LdapUrl, "The directory entry was not found.");
        _clock.Advance(TimeSpan.FromDays(15));
        GiveTheCaAHealthyCrl();
        await monitor.CheckAsync();

        _notifier.Alerts.Select(a => a.Stage).Should().Equal("30");
        _notifier.Alerts[0].LastReadAt.Should().NotBeNull();
        _notifier.Alerts[0].LastReadAt!.Value.Should().BeBefore(_clock.GetUtcNow().UtcDateTime.AddDays(-14),
            "the alert says how old the reading behind it is");

        using var db = OpenDb();
        db.MonitoredCrls.Single(r => r.Source == LdapUrl).LastError
            .Should().Contain("not found");
    }

    [Fact]
    public async Task A_distribution_point_that_has_never_answered_is_recorded_as_silent()
    {
        GiveTheCaAHealthyCrl();
        _fetcher.Refuse(LdapUrl, "No such host is known.");
        _fetcher.Refuse(HttpUrl, "The distribution point answered 404.");

        await CreateMonitor().CheckAsync();

        using var db = OpenDb();
        var parents = db.MonitoredCrls.Where(r => r.Scope == "parent").ToList();
        parents.Should().HaveCount(2);
        parents.Should().AllSatisfy(r =>
        {
            r.LastReadAt.Should().BeNull();
            r.LastError.Should().NotBeNullOrEmpty();
        });
        _notifier.Alerts.Should().BeEmpty("nothing is known about that CRL yet");
    }

    [Fact]
    public async Task A_ca_that_cannot_be_reached_does_not_stop_the_distribution_point_reads()
    {
        _chainFails = false;
        _caReader.Throw = new CaUnavailableException("CertSvc is not running.");
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 13);

        await CreateMonitor().CheckAsync();

        // The root CRL is what matters most and it is nothing to do with the CA
        // being up: it is read from a distribution point.
        _notifier.Alerts.Select(a => a.Stage).Should().Equal("30", "14");
    }

    [Fact]
    public async Task A_chain_that_cannot_be_read_leaves_what_is_already_known_alone()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 40);

        var monitor = CreateMonitor();
        await monitor.CheckAsync();

        _chainFails = true;
        _clock.Advance(TimeSpan.FromDays(15));
        await monitor.CheckAsync();

        using var db = OpenDb();
        db.MonitoredCrls.Should().HaveCount(3,
            "the CA, the directory that answered, and the web server that did not");
        _notifier.Alerts.Select(a => a.Stage).Should().Contain("30",
            "the rules still run against what was read before");
    }

    [Fact]
    public async Task A_ca_that_stops_publishing_goes_overdue_and_then_expired()
    {
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 365);

        var monitor = CreateMonitor();
        await monitor.CheckAsync();
        _notifier.Alerts.Should().BeEmpty();

        // The CA keeps answering and keeps handing over the same CRL, which is
        // what a CA with a stopped publishing schedule looks like from here. It
        // said it would replace it six days from now and it has not, and there
        // are still twelve hours of overlap left when that is noticed.
        _clock.Advance(TimeSpan.FromDays(6) + TimeSpan.FromHours(3));
        await monitor.CheckAsync();
        _notifier.Alerts.Select(a => a.Stage).Should().Equal(CrlAlertRules.OverdueStage);
        _notifier.Alerts[0].Scope.Should().Be("issuing");
        _notifier.Alerts[0].HoursRemaining.Should().BeInRange(0, 12);

        _clock.Advance(TimeSpan.FromHours(12));
        await monitor.CheckAsync();
        _notifier.Alerts.Select(a => a.Stage)
            .Should().Equal(CrlAlertRules.OverdueStage, CrlAlertRules.ExpiredStage);
    }

    [Fact]
    public async Task A_crl_signed_by_the_wrong_key_is_ignored_rather_than_recorded()
    {
        using var impostor = CrlTestPki.MintRootCa("CN=Example Root CA");
        GiveTheCaAHealthyCrl();
        _fetcher.Serve(LdapUrl, CrlTestPki.BuildCrl(
            impostor, 99, _clock.GetUtcNow().AddDays(-1), _clock.GetUtcNow().AddDays(365)));

        await CreateMonitor().CheckAsync();

        using var db = OpenDb();
        var row = db.MonitoredCrls.Single(r => r.Source == LdapUrl);
        row.CrlNumber.Should().BeNull("a CRL the CA did not sign is not this CA's CRL");
        row.LastReadAt.Should().BeNull();
        row.LastError.Should().NotBeNullOrEmpty();
    }

    #endregion

    #region Wiring

    [Fact]
    public async Task With_no_alert_channel_the_state_is_recorded_and_no_history_is_written()
    {
        _notifier.Enabled = false;
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 13);

        await CreateMonitor().CheckAsync();

        using var db = OpenDb();
        db.MonitoredCrls.Should().NotBeEmpty("the card still has something to show");
        db.CrlAlertsSent.Should().BeEmpty(
            "an install that configures email next week should get the warnings it is missing");
    }

    [Fact]
    public async Task A_failed_delivery_is_recorded_and_not_retried()
    {
        _notifier.Result = new AlertNotificationResult(false, "The relay refused the message.");
        GiveTheCaAHealthyCrl();
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 13);

        var monitor = CreateMonitor();
        await monitor.CheckAsync();
        _clock.Advance(TimeSpan.FromHours(1));
        await monitor.CheckAsync();

        using var db = OpenDb();
        var history = db.CrlAlertsSent.ToList();
        history.Should().HaveCount(2);
        history.Should().AllSatisfy(h =>
        {
            h.Success.Should().BeFalse();
            h.ErrorMessage.Should().Contain("refused");
        });
        _notifier.Alerts.Should().HaveCount(2, "a failed alert is not sent again, like a leaf alert");
    }

    [Fact]
    public async Task The_cas_own_distribution_points_are_read_on_a_pass_that_does_not_ask_the_ca()
    {
        GiveTheCaAHealthyCrl(CaOwnUrl);
        _fetcher.Serve(CaOwnUrl, CrlTestPki.BuildCrl(
            _issuing, 40, _clock.GetUtcNow().AddDays(-1), _clock.GetUtcNow().AddDays(7)));

        var monitor = CreateMonitor();
        await monitor.CheckAsync();
        _caReader.Reads.Should().Be(1);

        // An hour later the CA has nothing new to say, so it is not asked: it
        // hands over whole CRLs and the one already held says it will not be
        // replaced for another six days. The copy published where clients read
        // it is still checked, because that is the one that can go stale on its
        // own.
        _fetcher.Serve(CaOwnUrl, CrlTestPki.BuildCrl(
            _issuing, 41, _clock.GetUtcNow(), _clock.GetUtcNow().AddDays(7)));
        _clock.Advance(TimeSpan.FromHours(1));
        await monitor.CheckAsync();

        _caReader.Reads.Should().Be(1, "the CA was not asked again");
        using var db = OpenDb();
        db.MonitoredCrls.Single(r => r.Source == CaOwnUrl).CrlNumber
            .Should().Be("29", "the published copy was read regardless");
    }

    [Fact]
    public async Task A_silent_source_that_starts_answering_leaves_one_row_behind_not_two()
    {
        // A CA certificate with no subject key identifier: the monitor has no
        // key id to expect, so the row it creates for a silent distribution
        // point is keyed by a hash, and the CRL that later turns up carries the
        // real one.
        using var root = CrlTestPki.MintRootCa("CN=Example Root CA", withSubjectKeyIdentifier: false);
        using var issuing = CrlTestPki.MintIssuingCa(root, "CN=Example Issuing CA", LdapUrl);
        _chainCertificates = [issuing.RawData, root.RawData];

        GiveTheCaAHealthyCrl();
        _fetcher.Refuse(LdapUrl, "The directory entry was not found.");

        var monitor = CreateMonitor();
        await monitor.CheckAsync();
        using (var first = OpenDb())
            first.MonitoredCrls.Count(r => r.Source == LdapUrl).Should().Be(1);

        _fetcher.Serve(LdapUrl, CrlTestPki.BuildCrl(
            root, 12, _clock.GetUtcNow().AddDays(-1), _clock.GetUtcNow().AddDays(300)));
        _clock.Advance(TimeSpan.FromHours(1));
        await monitor.CheckAsync();

        using var db = OpenDb();
        var rows = db.MonitoredCrls.Where(r => r.Source == LdapUrl).ToList();
        rows.Should().HaveCount(1, "the placeholder is replaced rather than left beside the answer");
        rows[0].CrlNumber.Should().Be("0C");
    }

    [Fact]
    public async Task A_distribution_point_the_ca_no_longer_names_is_forgotten()
    {
        GiveTheCaAHealthyCrl(CaOwnUrl);
        _fetcher.Serve(CaOwnUrl, CrlTestPki.BuildCrl(
            _issuing, 40, _clock.GetUtcNow().AddDays(-1), _clock.GetUtcNow().AddDays(7)));
        ServeRootCrl(LdapUrl, number: 12, expiresInDays: 365);

        var monitor = CreateMonitor();
        await monitor.CheckAsync();
        using (var first = OpenDb())
            first.MonitoredCrls.Should().Contain(r => r.Source == CaOwnUrl);

        // The administrator repoints the CA's distribution point somewhere else.
        GiveTheCaAHealthyCrl();
        _clock.Advance(TimeSpan.FromHours(13));
        await monitor.CheckAsync();

        using var db = OpenDb();
        db.MonitoredCrls.Should().NotContain(r => r.Source == CaOwnUrl,
            "a row nobody publishes to would go on ageing towards a warning about nothing");
    }

    #endregion

    #region Harness

    private void GiveTheCaAHealthyCrl(params string[] ownUrls)
    {
        var published = _clock.GetUtcNow().AddDays(-1);
        _caReader.Snapshot = new CaCrlSnapshot(
            [
                new CaCrlRecord(
                    KeyIndex: 0,
                    IsDelta: false,
                    CrlNumberHex: "25",
                    ThisUpdate: published,
                    NextUpdate: published.AddDays(7).AddHours(12),
                    NextPublish: published.AddDays(7),
                    AuthorityKeyIdentifierHex: CrlMonitorService.KeyIdentifierOf(_issuing),
                    PublishFlags: 0x5),
            ],
            ownUrls);
    }

    private void ServeRootCrl(string url, int number, double expiresInDays)
    {
        var now = _clock.GetUtcNow();
        _fetcher.Serve(url, CrlTestPki.BuildCrl(
            _root,
            number,
            thisUpdate: now.AddDays(-Math.Max(1, 365 - expiresInDays)),
            nextUpdate: now.AddDays(expiresInDays)));
    }

    private sealed class RecordingNotifier : IAlertNotifier
    {
        public string Channel => "test";
        public bool Enabled { get; set; } = true;
        public bool IsEnabled => Enabled;
        public AlertNotificationResult Result { get; set; } = new(true);
        public List<CrlAlert> Alerts { get; } = [];

        public Task<AlertNotificationResult> SendCrlAlertAsync(
            CrlAlert alert, CancellationToken cancellationToken = default)
        {
            Alerts.Add(alert);
            return Task.FromResult(Result);
        }

        public Task<AlertNotificationResult> SendExpiryAlertAsync(
            ExpiryAlertBatch batch, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AlertNotificationResult> SendServerCertificateAlertAsync(
            ServerCertificateAlert alert, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AlertNotificationResult> SendTestAlertAsync(
            TestAlert alert, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class FakeCaCrlReader : ICaCrlReader
    {
        public CaCrlSnapshot Snapshot { get; set; } = CaCrlSnapshot.Empty;
        public Exception? Throw { get; set; }
        public int Reads { get; private set; }

        public Task<CaCrlSnapshot> ReadAsync(CancellationToken cancellationToken = default)
        {
            Reads++;
            return Throw is not null ? throw Throw : Task.FromResult(Snapshot);
        }
    }

    private sealed class FakeDistributionPointFetcher : ICrlDistributionPointFetcher
    {
        private readonly Dictionary<string, byte[]> _served = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _refused = new(StringComparer.OrdinalIgnoreCase);

        public void Serve(string url, byte[] crl)
        {
            _served[url] = crl;
            _refused.Remove(url);
        }

        public void Refuse(string url, string error)
        {
            _refused[url] = error;
            _served.Remove(url);
        }

        public Task<CrlFetchResult> FetchAsync(
            string url,
            string? knownETag,
            DateTimeOffset? knownLastModified,
            CancellationToken cancellationToken = default)
        {
            if (_refused.TryGetValue(url, out var error))
                return Task.FromResult(CrlFetchResult.Failure(error));

            return Task.FromResult(_served.TryGetValue(url, out var crl)
                ? CrlFetchResult.Success([crl])
                : CrlFetchResult.Failure("No such distribution point in this test."));
        }
    }

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
        _root.Dispose();
        _issuing.Dispose();
        GC.SuppressFinalize(this);
    }

    #endregion
}
