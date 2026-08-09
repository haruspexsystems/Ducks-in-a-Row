using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Data;

/// <summary>
/// Verifies the startup schema flow that replaced EnsureCreated (issue #77):
/// fresh databases are created through migrations, databases created by
/// EnsureCreated before migrations existed are adopted when their schema
/// matches the current model, and older schemas fail fast with the documented
/// reset message instead of surfacing as a 500 later.
/// </summary>
public class DatabaseInitializerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dbPath;

    public DatabaseInitializerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-dbinit-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "certus.db");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort; the OS temp cleaner picks up leftovers.
        }
    }

    private CertusDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite($"Data Source={_dbPath}")
            .Options;
        return new CertusDbContext(options);
    }

    private static List<string> ReadAppliedMigrations(CertusDbContext db)
    {
        var connection = db.Database.GetDbConnection();
        connection.Open();
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT MigrationId FROM __EFMigrationsHistory ORDER BY MigrationId;";
            using var reader = command.ExecuteReader();
            var ids = new List<string>();
            while (reader.Read())
                ids.Add(reader.GetString(0));
            return ids;
        }
        finally
        {
            connection.Close();
        }
    }

    [Fact]
    public void FreshDatabase_IsCreatedThroughMigrations_WithHistory()
    {
        using var db = CreateContext();

        DatabaseInitializer.Initialize(db, enableWalMode: false, NullLogger.Instance);

        db.AcmeChallenges.Any().Should().BeFalse("the schema should exist and be queryable");
        var applied = ReadAppliedMigrations(db);
        applied.Should().Equal(db.Database.GetMigrations());
    }

    [Fact]
    public void SecondRun_IsIdempotent()
    {
        using (var first = CreateContext())
        {
            DatabaseInitializer.Initialize(first, enableWalMode: false, NullLogger.Instance);
        }

        using var second = CreateContext();
        var act = () => DatabaseInitializer.Initialize(second, enableWalMode: false, NullLogger.Instance);

        act.Should().NotThrow();
        second.AcmeAccounts.Any().Should().BeFalse();
    }

    [Fact]
    public void LegacyDatabaseAtCurrentSchema_IsAdopted_AndDataSurvives()
    {
        // A database created by EnsureCreated on the current model: same schema,
        // no migration history. This is every existing install at upgrade time.
        using (var legacy = CreateContext())
        {
            legacy.Database.EnsureCreated();
            legacy.AcmeAccounts.Add(new AcmeAccount
            {
                AccountId = "acct-legacy",
                JwkThumbprint = "thumb-legacy",
                JwkJson = "{}",
                CreatedAt = DateTime.UtcNow,
            });
            legacy.SaveChanges();
        }

        using var db = CreateContext();
        DatabaseInitializer.Initialize(db, enableWalMode: false, NullLogger.Instance);

        var applied = ReadAppliedMigrations(db);
        applied.Should().Equal(db.Database.GetMigrations(),
            "an adopted database is stamped with every defined migration");
        db.AcmeAccounts.Single().AccountId.Should().Be("acct-legacy");
    }

    [Fact]
    public void LegacyDatabaseMissingTable_FailsWithResetMessage()
    {
        using (var legacy = CreateContext())
        {
            legacy.Database.EnsureCreated();
            legacy.Database.ExecuteSqlRaw("DROP TABLE AcmeChallenges;");
        }

        using var db = CreateContext();
        var act = () => DatabaseInitializer.Initialize(db, enableWalMode: false, NullLogger.Instance);

        act.Should().Throw<InvalidOperationException>()
            .Which.Message.Should()
            .Contain("missing table AcmeChallenges").And
            .Contain(_dbPath).And
            .Contain("troubleshooting");
    }

    [Fact]
    public void LegacyDatabaseMissingColumn_FailsWithResetMessage()
    {
        using (var legacy = CreateContext())
        {
            legacy.Database.EnsureCreated();
            // The dropped column has to be one no index covers: SQLite refuses
            // DROP COLUMN while an index still references it, and that is a
            // failure of the fixture rather than the behaviour under test. This
            // used to drop Requestor, which became indexed when the certificate
            // list learned to sort by it (issue #156). DispositionMessage is
            // detail-only and deliberately unindexed, so it stays a safe stand in
            // for "some column the model expects and the database lacks".
            legacy.Database.ExecuteSqlRaw(
                "ALTER TABLE SyncedCertificates DROP COLUMN DispositionMessage;");
        }

        using var db = CreateContext();
        var act = () => DatabaseInitializer.Initialize(db, enableWalMode: false, NullLogger.Instance);

        act.Should().Throw<InvalidOperationException>()
            .Which.Message.Should().Contain("table SyncedCertificates: missing column DispositionMessage");
    }

    [Fact]
    public void WalMode_IsEnabledWhenRequested()
    {
        using var db = CreateContext();

        DatabaseInitializer.Initialize(db, enableWalMode: true, NullLogger.Instance);

        var connection = db.Database.GetDbConnection();
        connection.Open();
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA journal_mode;";
            var mode = (string?)command.ExecuteScalar();
            mode.Should().Be("wal");
        }
        finally
        {
            connection.Close();
        }
    }

    /// <summary>A synced row with the given subject, otherwise minimally valid.</summary>
    private static SyncedCertificate SyncedRow(int requestId, string subject) => new()
    {
        RequestId = requestId,
        SerialNumber = $"44000000{requestId:X2}",
        Subject = subject,
        TemplateName = "WebServer",
        Status = "Issued",
        NotBefore = new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc),
        NotAfter = new DateTime(2028, 7, 1, 0, 0, 0, DateTimeKind.Utc),
        RequestDate = new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc)
    };

    [Fact]
    public void StoredSubjects_AreSanitizedAtStartup()
    {
        // The rows the sync never heals on its own: a subject the CA no longer
        // returns, and one that sanitizes away entirely, which UpdateEntity skips
        // on purpose so a blank pass cannot erase a good name (issue #224).
        var rlo = (char)0x202e;
        var zwsp = (char)0x200b;

        using (var seed = CreateContext())
        {
            DatabaseInitializer.Initialize(seed, enableWalMode: false, NullLogger.Instance);
            seed.SyncedCertificates.AddRange(
                SyncedRow(1, "CN=" + rlo + "moc.live"),
                SyncedRow(2, "CN=" + new string('x', 9000)),
                SyncedRow(3, rlo.ToString() + zwsp),
                SyncedRow(4, "CN=clean.example.com"));
            seed.SaveChanges();
        }

        using var db = CreateContext();
        DatabaseInitializer.Initialize(db, enableWalMode: false, NullLogger.Instance);

        var rows = db.SyncedCertificates.OrderBy(c => c.RequestId).ToList();
        rows[0].Subject.Should().Be("CN=moc.live");
        rows[1].Subject.Should().HaveLength(CertificateTextSanitizer.MaxSubjectLength);
        rows[2].Subject.Should().BeEmpty(
            "a subject that is nothing but format characters has no name left, and the "
            + "column is required, so empty is the established nothing here value");
        rows[3].Subject.Should().Be("CN=clean.example.com", "a clean row must be left alone");
    }

    [Fact]
    public void StoredSubjects_SanitizingIsANoOpOnCleanData()
    {
        // The pass runs unconditionally on every start, so it has to cost nothing
        // once the data is clean. LastSyncedAt standing still is the observable
        // proof that no row was rewritten.
        using (var seed = CreateContext())
        {
            DatabaseInitializer.Initialize(seed, enableWalMode: false, NullLogger.Instance);
            seed.SyncedCertificates.Add(SyncedRow(1, "CN=clean.example.com"));
            seed.SaveChanges();
        }

        DateTime before;
        using (var read = CreateContext())
            before = read.SyncedCertificates.Single().LastSyncedAt;

        using var db = CreateContext();
        DatabaseInitializer.Initialize(db, enableWalMode: false, NullLogger.Instance);

        var row = db.SyncedCertificates.Single();
        row.Subject.Should().Be("CN=clean.example.com");
        row.LastSyncedAt.Should().Be(before);
    }
}
