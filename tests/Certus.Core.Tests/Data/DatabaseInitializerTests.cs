using System.Data;
using System.Globalization;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using FluentAssertions.Execution;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Data;

/// <summary>
/// Verifies the startup schema flow that replaced EnsureCreated (issue #77):
/// fresh databases are created through migrations, databases created by
/// EnsureCreated before migrations existed are adopted when their schema
/// matches the current model, and older schemas fail fast with the documented
/// reset message instead of surfacing as a 500 later.
///
/// Also covers the journal mode step that follows the schema (issue #283).
/// Both halves of that are asserted, because both were wrong: the mode has to
/// actually change in both directions, and the log line has to state the mode
/// the database reports rather than the mode that was asked for.
/// </summary>
public class DatabaseInitializerTests : IDisposable
{
    // EF's own bookkeeping tables, which only the migrated database has:
    // __EFMigrationsHistory records what has been applied, and __EFMigrationsLock
    // serializes concurrent Migrate() calls. Matched on the prefix rather than by
    // name so a table EF adds later is excluded on the same grounds rather than
    // failing MigratedSchema_MatchesTheSchemaTheModelWouldCreate as a divergence.
    private const string EfBookkeepingTablePrefix = "__EF";

    private readonly string _tempDir;
    private readonly string _dbPath;
    private readonly string _modelDbPath;
    private readonly string _walPath;

    public DatabaseInitializerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-dbinit-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "certus.db");
        _modelDbPath = Path.Combine(_tempDir, "certus-from-model.db");
        _walPath = _dbPath + "-wal";
    }

    public void Dispose()
    {
        // This database's pool only. ClearAllPools is process wide, and xUnit
        // runs test classes in parallel, so it would reach into a sibling test's
        // connections. Needed here at all because the journal mode tests leave
        // pooled handles and WAL sidecars behind, which hold the temp directory
        // open against the delete below.
        using (var handle = new SqliteConnection($"Data Source={_dbPath}"))
            SqliteConnection.ClearPool(handle);
        using (var modelHandle = new SqliteConnection($"Data Source={_modelDbPath}"))
            SqliteConnection.ClearPool(modelHandle);

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

    /// <summary>
    /// A context on a second, separate database file, for the copy built straight
    /// from the model rather than by replaying the migrations.
    /// </summary>
    private CertusDbContext CreateModelContext()
    {
        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite($"Data Source={_modelDbPath}")
            .Options;
        return new CertusDbContext(options);
    }

    /// <summary>Records level and rendered message for every entry.</summary>
    private sealed class RecordingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public List<string> Informations =>
            Entries.Where(e => e.Level == LogLevel.Information).Select(e => e.Message).ToList();

        public List<string> Warnings =>
            Entries.Where(e => e.Level == LogLevel.Warning).Select(e => e.Message).ToList();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    /// <summary>
    /// The journal mode the database reports, read through the context's own
    /// connection. Deliberately not a second SqliteConnection: a spare handle in
    /// Microsoft.Data.Sqlite's pool is precisely what refuses a switch out of
    /// WAL mode, so a helper that opened one would arrange the failure some of
    /// these tests exist to prove does not happen.
    /// </summary>
    private static string ReadJournalMode(CertusDbContext db)
    {
        var mode = "";
        DatabaseInitializer.RunOnConnection(db, command =>
        {
            command.CommandText = "PRAGMA journal_mode;";
            mode = command.ExecuteScalar() as string ?? "";
        });
        return mode;
    }

    private static AcmeAccount NewAccount(string thumbprint) => new()
    {
        AccountId = thumbprint,
        JwkJson = "{}",
        JwkThumbprint = thumbprint,
    };

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
        var logger = new RecordingLogger();
        using var db = CreateContext();

        DatabaseInitializer.Initialize(db, enableWalMode: true, logger);

        ReadJournalMode(db).Should().Be("wal");
        logger.Informations.Should().ContainSingle(m => m == "SQLite journal mode changed from delete to wal",
            "a fresh database is created in SQLite's compiled default, so enabling WAL is a real change");
        logger.Warnings.Should().BeEmpty();
    }

    /// <summary>
    /// The headline case for issue #283. Turning the option off used to do
    /// nothing at all to an existing database, because the pragma only ever ran
    /// on the true branch and journal mode is persisted in the file header.
    ///
    /// The arrangement is load bearing and is the same one
    /// SqliteShutdownCheckpointTests uses. Disposing the first context returns
    /// its connection to the pool with the sqlite3 handle still open, and the
    /// second context uses a byte identical connection string, so it rents that
    /// same handle back rather than opening a second one. That is why the
    /// conversion can take the exclusive lock it needs. Holding the first
    /// context open, or pointing the second at a differently spelled path, would
    /// arrange a refusal and then assert a conversion.
    /// </summary>
    [Fact]
    public void WalMode_IsTurnedOff_WhenTheOptionIsTurnedOffOnAnExistingDatabase()
    {
        using (var walEnabled = CreateContext())
        {
            DatabaseInitializer.Initialize(walEnabled, enableWalMode: true, NullLogger.Instance);
            walEnabled.AcmeAccounts.Add(NewAccount("written-in-wal-mode"));
            walEnabled.SaveChanges();
            ReadJournalMode(walEnabled).Should().Be("wal",
                "the fixture has to start in the mode the test is about to leave");
        }

        var logger = new RecordingLogger();
        using var db = CreateContext();
        DatabaseInitializer.Initialize(db, enableWalMode: false, logger);

        ReadJournalMode(db).Should().Be("delete");
        logger.Informations.Should().ContainSingle(m => m == "SQLite journal mode changed from wal to delete");
        logger.Warnings.Should().BeEmpty();

        db.AcmeAccounts.Single().JwkThumbprint.Should().Be("written-in-wal-mode",
            "leaving WAL checkpoints the log into the database, so a row committed in WAL mode survives");

        // Accept an empty log as well as an absent one, the same tolerance
        // Checkpoint_EmptiesAndRemovesTheWriteAheadLog keeps.
        var walLength = File.Exists(_walPath) ? new FileInfo(_walPath).Length : 0;
        walLength.Should().Be(0, "the sidecar has nothing left in it once the database is out of WAL mode");
    }

    /// <summary>
    /// A start that changes nothing still says so. Before issue #283 a start
    /// with the option off logged nothing whatsoever, and an operator could not
    /// tell "already in the mode you asked for" from "this code never looked".
    /// </summary>
    [Fact]
    public void JournalMode_OnADatabaseAlreadyInTheRequestedMode_IsReportedAsANoOp()
    {
        var logger = new RecordingLogger();
        using var db = CreateContext();

        DatabaseInitializer.Initialize(db, enableWalMode: false, logger);

        ReadJournalMode(db).Should().Be("delete",
            "Migrate() creates the file in SQLite's compiled default, which is the rollback target");
        logger.Informations.Should().ContainSingle(m => m == "SQLite journal mode is delete");
        logger.Warnings.Should().BeEmpty();
    }

    /// <summary>
    /// An in memory database answers "memory" to any journal mode request and
    /// ignores it. That is neither a success nor a refusal, so it must not
    /// warn: StartupValidator already warns, more severely, that this
    /// configuration loses everything on restart.
    ///
    /// Doubles as the regression guard on RunOnConnection preserving the
    /// connection's open state. An in memory database exists only while a
    /// connection to it does, so closing it here would destroy the schema that
    /// was just created.
    /// </summary>
    [Fact]
    public void JournalMode_OnAnInMemoryDatabase_IsLeftAloneAndNotWarnedAbout()
    {
        var logger = new RecordingLogger();
        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite($"Data Source={CertusPaths.InMemoryDatabase}")
            .Options;
        using var db = new CertusDbContext(options);
        db.Database.OpenConnection();

        var act = () => DatabaseInitializer.Initialize(db, enableWalMode: true, logger);

        act.Should().NotThrow();
        db.Database.GetDbConnection().State.Should().Be(ConnectionState.Open,
            "an in memory database exists only while a connection to it does");
        db.AcmeAccounts.Any().Should().BeFalse("the schema has to exist and be queryable");
        logger.Warnings.Should().BeEmpty();
    }

    /// <summary>
    /// The refused path, and it is deterministic rather than racy. Leaving WAL
    /// mode needs an exclusive lock on the database file, and in WAL mode a
    /// connection that has read holds its shared lock until it closes, not
    /// merely until its read finishes. So a second connection with a read
    /// transaction in flight refuses the switch every time.
    ///
    /// Getting the holder's transaction right matters twice over. Opening the
    /// connection is not enough on its own, because SQLite takes no lock until a
    /// statement actually touches the database, so the holder runs a real read
    /// and leaves it open. And the transaction has to be deferred: the default
    /// isolation level is Serializable, which Microsoft.Data.Sqlite issues as
    /// BEGIN IMMEDIATE, taking the write lock. That blocks the lock EF acquires
    /// for Migrate(), so Initialize throws from the schema step and never
    /// reaches the journal mode step this test is about. A deferred transaction
    /// holding only a read lock lets the migration through, because WAL readers
    /// do not block writers, and still refuses the exclusive lock that leaving
    /// WAL mode needs.
    ///
    /// The assertions are deliberately agnostic to which refusal shape SQLite
    /// picks. A busy refusal is raised as an exception by the statement rather
    /// than reported in its result row, and other refusals come back as a row
    /// still naming the old mode; either way the observable outcome is the same
    /// and is the one that matters. If a future SQLite ever allows leaving WAL
    /// mode with another connection open, this test fails, and that is worth
    /// being told about rather than discovering in a lab.
    /// </summary>
    [Fact]
    public void WalMode_IsNotTurnedOff_WhenAnotherConnectionHoldsTheDatabase()
    {
        using (var walEnabled = CreateContext())
        {
            DatabaseInitializer.Initialize(walEnabled, enableWalMode: true, NullLogger.Instance);
            walEnabled.AcmeAccounts.Add(NewAccount("held-open"));
            walEnabled.SaveChanges();
        }

        var logger = new RecordingLogger();

        using (var holder = new SqliteConnection($"Data Source={_dbPath}"))
        {
            holder.Open();
            using var read = holder.BeginTransaction(deferred: true);
            using var probe = holder.CreateCommand();
            probe.Transaction = read;
            probe.CommandText = "SELECT count(*) FROM AcmeAccounts;";
            probe.ExecuteScalar();

            using var db = CreateContext();
            var act = () => DatabaseInitializer.Initialize(db, enableWalMode: false, logger);

            act.Should().NotThrow(
                "a journal mode Ducks in a Row could not change is never a reason to refuse to start");
            ReadJournalMode(db).Should().Be("wal", "the database keeps the mode it already had");
        }

        logger.Warnings.Should().ContainSingle()
            .Which.Should().Contain("wal").And.Contain("delete");
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

    /// <summary>
    /// The two ways this product can arrive at a schema have to agree: replaying every
    /// migration, which is what a real install does, and asking the model directly,
    /// which is what the model snapshot claims the migrations add up to. Nothing else
    /// checks that. <see cref="DatabaseInitializer.CompareSchemaToModel"/> compares
    /// table and column names only, by design, so a column the migrations create with
    /// the wrong type, the wrong nullability or the wrong default, a missing index, or
    /// a missing foreign key all pass it.
    ///
    /// This deliberately cannot see a declared width, and that is the point rather than
    /// a shortcoming. SQLite has no length bearing type, so <c>HasMaxLength</c> never
    /// reaches DDL, EF emits no AlterColumn when one is widened, and the recorded
    /// history disagrees with the model for ever on
    /// <c>AcmeAuthorizations.IdentifierType</c> (10 against 32) with nothing wrong.
    /// Issue #348 was filed on exactly that discrepancy. This test covers the
    /// divergences that do reach DDL; the width is covered where it is real, in
    /// CertusDbContextTests, against the vocabulary the column has to hold.
    ///
    /// Two details are load bearing. Columns are keyed by name and compared as a set,
    /// never by <c>cid</c>: a column added through AddColumn lands at the end of the
    /// migrated table and in model order in the EnsureCreated one, so an ordered
    /// compare would fail over an ordering neither side promises. And EF's own
    /// bookkeeping tables are excluded, because only the migrated side has them.
    /// </summary>
    [Fact]
    public void MigratedSchema_MatchesTheSchemaTheModelWouldCreate()
    {
        using (var migrated = CreateContext())
            DatabaseInitializer.Initialize(migrated, enableWalMode: false, NullLogger.Instance);

        using (var fromModel = CreateModelContext())
            fromModel.Database.EnsureCreated();

        using var a = CreateContext();
        using var b = CreateModelContext();

        var migratedSchema = ReadSchema(a);
        var modelSchema = ReadSchema(b);

        migratedSchema.Should().NotBeEmpty("both databases have to have been created at all");

        // Reported as the two one sided differences rather than as one collection
        // comparison. These are ~170 lines each, and a failure that dumps both in full
        // buries the handful of rows that actually differ.
        using var scope = new AssertionScope();
        migratedSchema.Except(modelSchema).OrderBy(line => line, StringComparer.Ordinal)
            .Should().BeEmpty("the migrations create schema the model does not describe");
        modelSchema.Except(migratedSchema).OrderBy(line => line, StringComparer.Ordinal)
            .Should().BeEmpty("the model describes schema the migrations do not create");
    }

    /// <summary>
    /// The schema as a flat set of comparable lines: one per column, per index, and per
    /// foreign key. Flat strings rather than a nested shape so a failure names the exact
    /// row that differs instead of dumping two object graphs.
    /// </summary>
    private static List<string> ReadSchema(CertusDbContext db)
    {
        var lines = new List<string>();

        // Materialized before the per table reads below: RunOnConnection hands out one
        // command at a time on one connection, so a reader still open would refuse them.
        var tables = Query(db, "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';", "name")
            .Select(row => row[0])
            .Where(name => !name.StartsWith(EfBookkeepingTablePrefix, StringComparison.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        foreach (var table in tables)
        {
            foreach (var column in Query(db, $"PRAGMA table_info({Quote(table)});",
                         "name", "type", "notnull", "dflt_value", "pk"))
            {
                lines.Add(
                    $"{table}.{column[0]} type={column[1]} notnull={column[2]} "
                    + $"default={column[3]} pk={column[4]}");
            }

            foreach (var fk in Query(db, $"PRAGMA foreign_key_list({Quote(table)});",
                         "from", "table", "to", "on_delete"))
            {
                lines.Add($"{table}.{fk[0]} references {fk[1]}.{fk[2]} onDelete={fk[3]}");
            }

            // Same materialization rule as the table list: index_info below needs the
            // connection back.
            var indexes = Query(db, $"PRAGMA index_list({Quote(table)});", "name", "unique", "origin");
            foreach (var index in indexes)
            {
                var columns = Query(db, $"PRAGMA index_info({Quote(index[0])});", "seqno", "name")
                    .OrderBy(row => int.Parse(row[0], CultureInfo.InvariantCulture))
                    .Select(row => row[1]);
                lines.Add(
                    $"{table} index {index[0]} unique={index[1]} origin={index[2]} "
                    + $"columns={string.Join(",", columns)}");
            }
        }

        return lines;
    }

    /// <summary>
    /// Every row of a query, every requested column rendered as a string. Strings
    /// throughout because these are PRAGMA results being compared for equality, not
    /// values being used: the driver is free to hand back an integer as long or int and
    /// a missing default as DBNull, and none of that is a difference worth reporting.
    /// </summary>
    private static List<string[]> Query(CertusDbContext db, string sql, params string[] columns)
    {
        var rows = new List<string[]>();
        DatabaseInitializer.RunOnConnection(db, command =>
        {
            command.CommandText = sql;
            using var reader = command.ExecuteReader();

            // Resolved once rather than per row: the ordinals cannot move while a
            // single reader is open, and PRAGMA results are read column by column.
            var ordinals = columns.Select(reader.GetOrdinal).ToArray();

            while (reader.Read())
            {
                var row = new string[columns.Length];
                for (var i = 0; i < columns.Length; i++)
                {
                    var value = reader.GetValue(ordinals[i]);
                    row[i] = value is DBNull
                        ? ""
                        : Convert.ToString(value, CultureInfo.InvariantCulture) ?? "";
                }
                rows.Add(row);
            }
        });
        return rows;
    }

    /// <summary>
    /// PRAGMA takes no parameters, so identifiers are quoted the same way
    /// <see cref="DatabaseInitializer"/> quotes them, with embedded quotes doubled.
    /// </summary>
    private static string Quote(string identifier) => $"\"{identifier.Replace("\"", "\"\"")}\"";
}
