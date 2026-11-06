using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Data.Retention;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Data;

/// <summary>
/// The daily retention pass (issue #637, CRA risk R18): what each class removes
/// at its period, what it leaves alone, that 0 turns a class off, and that the
/// pass works in bounded batches. Every test runs against a fresh in memory
/// database on a fixed clock, so the periods are exact.
/// </summary>
public class DataRetentionJobTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 23, 12, 0, 0, DateTimeKind.Utc);

    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CertusDbContext> _dbOptions;
    private readonly CertusDbContext _db;
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(Now));
    private readonly AcmeAccount _account;

    public DataRetentionJobTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _dbOptions = new DbContextOptionsBuilder<CertusDbContext>().UseSqlite(_connection).Options;
        _db = new CertusDbContext(_dbOptions);
        _db.Database.EnsureCreated();

        _account = SeedAccount("valid", createdDaysAgo: 400);
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    // ---- Finished orders ----

    [Fact]
    public async Task InvalidOrder_PastThePeriod_GoesWithItsAuthorizationsAndChallenges()
    {
        var old = SeedOrder("invalid", expiredDaysAgo: 91, authorizations: 2, challengesEach: 2);
        var recent = SeedOrder("invalid", expiredDaysAgo: 89, authorizations: 1, challengesEach: 1);

        var report = await RunAsync();

        report.InvalidOrdersRemoved.Should().Be(1);
        report.AuthorizationsRemoved.Should().Be(2);
        report.ChallengesRemoved.Should().Be(4);
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.AnyAsync(o => o.Id == old.Id)).Should().BeFalse();
        (await verify.AcmeAuthorizations.AnyAsync(a => a.OrderId == old.Id)).Should().BeFalse();
        (await verify.AcmeChallenges.CountAsync()).Should().Be(1, "the recent order keeps its challenge");
        (await verify.AcmeOrders.AnyAsync(o => o.Id == recent.Id)).Should().BeTrue();
    }

    [Fact]
    public async Task ValidOrder_PastThePeriod_LosesItsAuthorizations_ButKeepsTheOrderAndCertificateWhileTheCertificateIsLive()
    {
        // Issued 91 days ago, valid for another year: ARI, replaces and
        // revoke-cert still need the certificate record, which hangs off the
        // order, so only the authorizations and challenges go.
        var order = SeedOrder("valid", expiredDaysAgo: 84, authorizations: 1, challengesEach: 1);
        SeedCertificate(order, issuedDaysAgo: 91, notAfterDaysFromNow: 365);

        var report = await RunAsync();

        report.AuthorizationsRemoved.Should().Be(1);
        report.ChallengesRemoved.Should().Be(1);
        report.ValidOrdersRemoved.Should().Be(0);
        report.CertificateRecordsRemoved.Should().Be(0);
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id)).Status.Should().Be("valid");
        (await verify.AcmeCertificates.AnyAsync(c => c.OrderId == order.Id)).Should().BeTrue();
        (await verify.AcmeAuthorizations.AnyAsync(a => a.OrderId == order.Id)).Should().BeFalse();

        // A second pass finds nothing more to do for this order: the step's
        // due set shrinks as it works, which is what ends the loop.
        var again = await RunAsync();
        again.RemovedAnything.Should().BeFalse();
    }

    [Fact]
    public async Task ValidOrder_WhoseCertificateHasBeenExpiredForThePeriod_GoesWithItsCertificateRecord()
    {
        var longExpired = SeedOrder("valid", expiredDaysAgo: 500, authorizations: 1, challengesEach: 1);
        SeedCertificate(longExpired, issuedDaysAgo: 500, notAfterDaysFromNow: -91);
        var justExpired = SeedOrder("valid", expiredDaysAgo: 400, authorizations: 0, challengesEach: 0);
        SeedCertificate(justExpired, issuedDaysAgo: 400, notAfterDaysFromNow: -89);

        var report = await RunAsync();

        report.ValidOrdersRemoved.Should().Be(1);
        report.CertificateRecordsRemoved.Should().Be(1);
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.AnyAsync(o => o.Id == longExpired.Id)).Should().BeFalse();
        (await verify.AcmeCertificates.AnyAsync(c => c.OrderId == longExpired.Id)).Should().BeFalse();
        (await verify.AcmeOrders.AnyAsync(o => o.Id == justExpired.Id)).Should().BeTrue(
            "the certificate expired, but not yet a whole period ago");
        (await verify.AcmeCertificates.AnyAsync(c => c.OrderId == justExpired.Id)).Should().BeTrue();
    }

    [Fact]
    public async Task ValidOrder_RecentlyIssued_IsNotTouchedAtAll()
    {
        var order = SeedOrder("valid", expiredDaysAgo: 1, authorizations: 1, challengesEach: 1);
        SeedCertificate(order, issuedDaysAgo: 8, notAfterDaysFromNow: 357);

        var report = await RunAsync();

        report.RemovedAnything.Should().BeFalse();
    }

    [Fact]
    public async Task ValidOrder_WithAnUnreadableCertificate_IsKeptAndCounted()
    {
        var order = SeedOrder("valid", expiredDaysAgo: 500, authorizations: 0, challengesEach: 0);
        _db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = Guid.NewGuid().ToString("N"),
            OrderId = order.Id,
            CertificatePem = "not a certificate",
            AdcsRequestId = 4242,
            SerialNumber = "01",
            IssuedAt = Now.AddDays(-500),
        });
        _db.SaveChanges();

        var report = await RunAsync();

        report.UnreadableCertificates.Should().Be(1);
        report.ValidOrdersRemoved.Should().Be(0);
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.AnyAsync(o => o.Id == order.Id)).Should().BeTrue(
            "retention keeps what it cannot date");
    }

    [Fact]
    public async Task ValidOrder_WithNoCertificateRecord_GoesAtThePeriodFromItsExpiry()
    {
        // Nothing live hangs off an order with no certificate record, so the
        // order period alone decides, measured from the order's expiry.
        var order = SeedOrder("valid", expiredDaysAgo: 91, authorizations: 1, challengesEach: 0);

        var report = await RunAsync();

        report.ValidOrdersRemoved.Should().Be(1);
        report.AuthorizationsRemoved.Should().Be(1);
    }

    [Theory]
    [InlineData("pending")]
    [InlineData("ready")]
    [InlineData("processing")]
    public async Task AnOrderThatIsNotFinished_IsNeverTouched_HoweverOld(string status)
    {
        // "processing" in particular: the claim was the issuance decision and the
        // CSR may be at the CA. Retention takes only the two terminal statuses.
        SeedOrder(status, expiredDaysAgo: 900, authorizations: 1, challengesEach: 1);

        var report = await RunAsync();

        report.RemovedAnything.Should().BeFalse();
    }

    [Fact]
    public async Task FinishedOrderDaysZero_KeepsFinishedOrdersForEver()
    {
        SeedOrder("invalid", expiredDaysAgo: 3000, authorizations: 1, challengesEach: 1);
        var valid = SeedOrder("valid", expiredDaysAgo: 3000, authorizations: 1, challengesEach: 1);
        SeedCertificate(valid, issuedDaysAgo: 3000, notAfterDaysFromNow: -2000);

        var report = await RunAsync(o => o.FinishedOrderDays = 0);

        report.RemovedAnything.Should().BeFalse();
        (await _db.AcmeOrders.CountAsync()).Should().Be(2);
    }

    [Fact]
    public async Task ThePass_WorksInBoundedBatches_UntilNothingIsDue()
    {
        for (var i = 0; i < 5; i++)
            SeedOrder("invalid", expiredDaysAgo: 100 + i, authorizations: 1, challengesEach: 1);

        var report = await RunAsync(o => o.BatchSize = 2);

        // Five rows at two per batch is three batches for the invalid order step
        // alone, and the last batch comes back short, which ends the loop. The
        // count is a floor because the other steps run their own (empty) queries.
        report.Batches.Should().BeGreaterThanOrEqualTo(3);
        report.InvalidOrdersRemoved.Should().Be(5);
        (await _db.AcmeOrders.CountAsync()).Should().Be(0);
    }

    // ---- Deactivated accounts ----

    [Fact]
    public async Task DeactivatedAccount_PastThePeriod_LosesItsContacts_AndIsDeletedOnceNoOrderRefersToIt()
    {
        var bare = SeedAccount("deactivated", createdDaysAgo: 800, deactivatedDaysAgo: 366,
            contact: "[\"mailto:bare@example.com\"]");
        var holding = SeedAccount("deactivated", createdDaysAgo: 800, deactivatedDaysAgo: 366,
            contact: "[\"mailto:holding@example.com\"]");
        var holdingOrder = SeedOrder("valid", expiredDaysAgo: 300, authorizations: 0, challengesEach: 0, owner: holding);
        SeedCertificate(holdingOrder, issuedDaysAgo: 300, notAfterDaysFromNow: 430);
        var recent = SeedAccount("deactivated", createdDaysAgo: 800, deactivatedDaysAgo: 364,
            contact: "[\"mailto:recent@example.com\"]");

        var report = await RunAsync();

        report.AccountContactsRemoved.Should().Be(2);
        report.AccountsRemoved.Should().Be(1);
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeAccounts.AnyAsync(a => a.Id == bare.Id)).Should().BeFalse();
        var kept = await verify.AcmeAccounts.SingleAsync(a => a.Id == holding.Id);
        kept.ContactJson.Should().BeNull("the period is about the personal data");
        kept.Status.Should().Be("deactivated");
        (await verify.AcmeAccounts.SingleAsync(a => a.Id == recent.Id)).ContactJson.Should().NotBeNull();
    }

    [Fact]
    public async Task AValidAccount_IsNeverTouched_HoweverOld()
    {
        // The fixture account is valid and 400 days old with no orders.
        _account.ContactJson = "[\"mailto:live@example.com\"]";
        _db.SaveChanges();

        var report = await RunAsync();

        report.AccountContactsRemoved.Should().Be(0);
        report.AccountsRemoved.Should().Be(0);
        (await _db.AcmeAccounts.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task DeactivatedAccountDaysZero_KeepsDeactivatedAccountsForEver()
    {
        SeedAccount("deactivated", createdDaysAgo: 3000, deactivatedDaysAgo: 2900,
            contact: "[\"mailto:ancient@example.com\"]");

        var report = await RunAsync(o => o.DeactivatedAccountDays = 0);

        report.AccountContactsRemoved.Should().Be(0);
        report.AccountsRemoved.Should().Be(0);
    }

    // ---- Alert history ----

    [Fact]
    public async Task AlertHistory_PastThePeriod_GoesFromAllThreeTables()
    {
        var certificate = SeedInventoryRow(notAfterDaysFromNow: -800);
        _db.AlertsSent.Add(new AlertSent { CertificateId = certificate.Id, ThresholdDays = 30, SentAt = Now.AddDays(-731), Channels = "email" });
        _db.AlertsSent.Add(new AlertSent { CertificateId = certificate.Id, ThresholdDays = 7, SentAt = Now.AddDays(-729), Channels = "email" });
        _db.CrlAlertsSent.Add(new CrlAlertSent { IssuerKeyId = "AB", Kind = "base", InstanceKey = "1", Stage = "30", IssuerName = "CA", SentAt = Now.AddDays(-731), Channels = "email" });
        _db.CrlAlertsSent.Add(new CrlAlertSent { IssuerKeyId = "AB", Kind = "base", InstanceKey = "2", Stage = "30", IssuerName = "CA", SentAt = Now.AddDays(-1), Channels = "email" });
        _db.LicenceAlertsSent.Add(new LicenceAlertSent { LicenceId = Guid.NewGuid().ToString(), Stage = "days30", SentAt = Now.AddDays(-731), Channels = "email" });
        _db.LicenceAlertsSent.Add(new LicenceAlertSent { LicenceId = Guid.NewGuid().ToString(), Stage = "days30", SentAt = Now.AddDays(-700), Channels = "email" });
        _db.SaveChanges();

        var report = await RunAsync();

        report.AlertHistoryRemoved.Should().Be(1);
        report.CrlAlertHistoryRemoved.Should().Be(1);
        report.LicenceAlertHistoryRemoved.Should().Be(1);
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AlertsSent.CountAsync()).Should().Be(1);
        (await verify.CrlAlertsSent.CountAsync()).Should().Be(1);
        (await verify.LicenceAlertsSent.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task AlertHistoryDaysZero_KeepsAlertHistoryForEver()
    {
        var certificate = SeedInventoryRow(notAfterDaysFromNow: -800);
        _db.AlertsSent.Add(new AlertSent { CertificateId = certificate.Id, ThresholdDays = 30, SentAt = Now.AddDays(-3000), Channels = "email" });
        _db.SaveChanges();

        var report = await RunAsync(o => o.AlertHistoryDays = 0);

        report.AlertHistoryRemoved.Should().Be(0);
        (await _db.AlertsSent.CountAsync()).Should().Be(1);
    }

    // ---- The audit trail (issue #634) ----

    [Fact]
    public async Task AuditTrail_PastThePeriod_GoesFromBothTables()
    {
        _db.AdminAuditEntries.Add(new AdminAuditEntry { OccurredAt = Now.AddDays(-731), Actor = "CORP\\admin", Action = "old" });
        _db.AdminAuditEntries.Add(new AdminAuditEntry { OccurredAt = Now.AddDays(-729), Actor = "CORP\\admin", Action = "kept" });
        _db.AdminSignInFailures.Add(SignInFailureBucket(Now.AddDays(-731)));
        _db.AdminSignInFailures.Add(SignInFailureBucket(Now.AddDays(-1)));
        _db.SaveChanges();

        var report = await RunAsync();

        report.AuditEntriesRemoved.Should().Be(1);
        report.SignInFailuresRemoved.Should().Be(1);
        report.RemovedAnything.Should().BeTrue();
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AdminAuditEntries.Select(e => e.Action).ToListAsync()).Should().Equal("kept");
        (await verify.AdminSignInFailures.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task AuditTrail_BelowTheFloor_IsKeptForTheFloor_AndTheRaiseIsLogged()
    {
        _db.AdminAuditEntries.Add(new AdminAuditEntry { OccurredAt = Now.AddDays(-91), Actor = "CORP\\admin", Action = "old" });
        _db.AdminAuditEntries.Add(new AdminAuditEntry { OccurredAt = Now.AddDays(-89), Actor = "CORP\\admin", Action = "kept" });
        _db.SaveChanges();
        var logger = new RecordingLogger();

        var report = await RunAsync(o => o.AuditTrailDays = 7, logger);

        report.AuditEntriesRemoved.Should().Be(1, "7 days is raised to the 90 day floor, so only the 91 day old row goes");
        logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Warning && l.Message.Contains("AuditTrailDays is 7"));
    }

    [Fact]
    public async Task AuditTrailDaysZero_KeepsTheTrailForEver()
    {
        _db.AdminAuditEntries.Add(new AdminAuditEntry { OccurredAt = Now.AddDays(-3000), Actor = "CORP\\admin", Action = "old" });
        _db.AdminSignInFailures.Add(SignInFailureBucket(Now.AddDays(-3000)));
        _db.SaveChanges();

        var report = await RunAsync(o => o.AuditTrailDays = 0);

        report.AuditEntriesRemoved.Should().Be(0);
        report.SignInFailuresRemoved.Should().Be(0);
        (await _db.AdminAuditEntries.CountAsync()).Should().Be(1);
        (await _db.AdminSignInFailures.CountAsync()).Should().Be(1);
    }

    private static AdminSignInFailure SignInFailureBucket(DateTime at) => new()
    {
        SourceAddress = "198.51.100.7",
        StatusCode = 401,
        BucketStart = new DateTime(at.Year, at.Month, at.Day, at.Hour, 0, 0, DateTimeKind.Utc),
        Count = 1,
        FirstAt = at,
        LastAt = at,
    };

    // ---- The mirror ----

    [Fact]
    public async Task TheCaInventoryMirror_IsNeverTouched()
    {
        // Expired eight years ago and never alerted on: still the CA's record,
        // which the sync would recreate anyway.
        SeedInventoryRow(notAfterDaysFromNow: -3000);

        var report = await RunAsync();

        report.RemovedAnything.Should().BeFalse();
        (await _db.SyncedCertificates.CountAsync()).Should().Be(1);
    }

    // ---- Helpers ----

    private async Task<DataRetentionReport> RunAsync(
        Action<RetentionOptions>? configure = null, ILogger<DataRetentionJob>? logger = null)
    {
        var options = new RetentionOptions();
        configure?.Invoke(options);
        await using var db = new CertusDbContext(_dbOptions);
        var job = new DataRetentionJob(
            db, Options.Create(options), logger ?? NullLogger<DataRetentionJob>.Instance, _clock);
        return await job.RunAsync();
    }

    private sealed class RecordingLogger : ILogger<DataRetentionJob>
    {
        public List<(LogLevel Level, string Message)> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Lines)
                Lines.Add((logLevel, formatter(state, exception)));
        }
    }

    private AcmeAccount SeedAccount(
        string status, int createdDaysAgo, int? deactivatedDaysAgo = null, string? contact = null)
    {
        var account = new AcmeAccount
        {
            AccountId = Guid.NewGuid().ToString("N"),
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = Guid.NewGuid().ToString("N"),
            Status = status,
            ContactJson = contact,
            CreatedAt = Now.AddDays(-createdDaysAgo),
            UpdatedAt = deactivatedDaysAgo is int d ? Now.AddDays(-d) : null,
        };
        _db.AcmeAccounts.Add(account);
        _db.SaveChanges();
        return account;
    }

    private AcmeOrder SeedOrder(
        string status, int expiredDaysAgo, int authorizations, int challengesEach, AcmeAccount? owner = null)
    {
        var expires = Now.AddDays(-expiredDaysAgo);
        var order = new AcmeOrder
        {
            OrderId = Guid.NewGuid().ToString("N"),
            AccountId = (owner ?? _account).Id,
            Status = status,
            TemplateId = "WebServer",
            IdentifiersJson = """[{"type":"dns","value":"www.example.com"}]""",
            CreatedAt = expires.AddDays(-7),
            ExpiresAt = expires,
        };
        for (var a = 0; a < authorizations; a++)
        {
            var authorization = new AcmeAuthorization
            {
                AuthorizationId = Guid.NewGuid().ToString("N"),
                IdentifierValue = "www.example.com",
                Status = status == "invalid" ? "invalid" : "valid",
                CreatedAt = order.CreatedAt,
                ExpiresAt = expires,
            };
            for (var c = 0; c < challengesEach; c++)
            {
                authorization.Challenges.Add(new AcmeChallenge
                {
                    ChallengeId = Guid.NewGuid().ToString("N"),
                    Type = "http-01",
                    Token = Guid.NewGuid().ToString("N"),
                    Status = authorization.Status,
                });
            }
            order.Authorizations.Add(authorization);
        }
        _db.AcmeOrders.Add(order);
        _db.SaveChanges();
        return order;
    }

    private void SeedCertificate(AcmeOrder order, int issuedDaysAgo, int notAfterDaysFromNow)
    {
        var issued = new DateTimeOffset(Now.AddDays(-issuedDaysAgo));
        var notAfter = new DateTimeOffset(Now.AddDays(notAfterDaysFromNow));
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=www.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var leaf = request.CreateSelfSigned(issued, notAfter);

        _db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = Guid.NewGuid().ToString("N"),
            OrderId = order.Id,
            CertificatePem = leaf.ExportCertificatePem(),
            AdcsRequestId = Random.Shared.Next(100000, 999999),
            SerialNumber = leaf.SerialNumber,
            IssuedAt = issued.UtcDateTime,
        });
        order.CertificateId = Guid.NewGuid().ToString("N");
        _db.SaveChanges();
    }

    private SyncedCertificate SeedInventoryRow(int notAfterDaysFromNow)
    {
        var row = new SyncedCertificate
        {
            RequestId = Random.Shared.Next(1, int.MaxValue),
            SerialNumber = Guid.NewGuid().ToString("N"),
            Subject = "CN=user.example.com",
            TemplateName = "User",
            NotBefore = Now.AddDays(notAfterDaysFromNow - 365),
            NotAfter = Now.AddDays(notAfterDaysFromNow),
            Status = "Issued",
            RequestDate = Now.AddDays(notAfterDaysFromNow - 365),
            FirstSyncedAt = Now.AddDays(-3000),
            LastSyncedAt = Now.AddDays(-3000),
        };
        _db.SyncedCertificates.Add(row);
        _db.SaveChanges();
        return row;
    }
}
