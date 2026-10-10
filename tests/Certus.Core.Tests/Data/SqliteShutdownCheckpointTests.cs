using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Data;

/// <summary>
/// Verifies the shutdown checkpoint that issue #215 turned from an incidental
/// behaviour into a guarantee.
///
/// The property under test is not "the sidecar files are gone". It is the one
/// #215 was actually worried about: after a clean stop, every committed row is
/// in the database file itself, so losing the write ahead log afterwards loses
/// nothing. The headline test proves that the hard way, by deleting the
/// sidecars and reading the row back out of ducks.db alone.
///
/// The database is named ducks.db here rather than certus.db so the sidecar
/// paths read the same as the ones in the issue.
/// </summary>
public class SqliteShutdownCheckpointTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dbPath;
    private readonly string _walPath;
    private readonly string _shmPath;

    public SqliteShutdownCheckpointTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-wal-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "ducks.db");
        _walPath = _dbPath + "-wal";
        _shmPath = _dbPath + "-shm";
    }

    public void Dispose()
    {
        // This database's pool only. ClearAllPools is process wide, and xUnit
        // runs test classes in parallel, so it would reach into a sibling test's
        // connections and could delete a write ahead log the test is about to
        // assert on.
        using (var handle = new SqliteConnection($"Data Source={_dbPath}"))
            SqliteConnection.ClearPool(handle);

        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort; the OS temp cleaner picks up leftovers.
        }
    }

    private CertusDbContext CreateContext(string? dataSource = null)
    {
        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite($"Data Source={dataSource ?? _dbPath}")
            .Options;
        return new CertusDbContext(options);
    }

    private static AcmeAccount NewAccount(string thumbprint) => new()
    {
        AccountId = thumbprint,
        JwkJson = "{}",
        JwkThumbprint = thumbprint,
    };

    /// <summary>
    /// Commit a row through a WAL enabled context and leave the write ahead log
    /// holding it. Returns once the log is known to be non empty, so a test that
    /// asserts on the checkpoint is not silently asserting on an empty log.
    /// </summary>
    private void CommitRowLeavingItInTheLog(string thumbprint)
    {
        using var db = CreateContext();
        DatabaseInitializer.Initialize(db, enableWalMode: true, NullLogger.Instance);
        db.AcmeAccounts.Add(NewAccount(thumbprint));
        db.SaveChanges();

        File.Exists(_walPath).Should().BeTrue("WAL mode was enabled, so a committed write goes to the log first");
        new FileInfo(_walPath).Length.Should().BeGreaterThan(0, "the committed row should be sitting in the log");
    }

    [Fact]
    public void Checkpoint_WritesCommittedRowsIntoTheDatabaseFile_SoLosingTheSidecarsLosesNothing()
    {
        CommitRowLeavingItInTheLog("survives-the-sidecars");

        using (var db = CreateContext())
        {
            SqliteShutdownCheckpoint.Checkpoint(db, NullLogger.Instance);
        }

        // Whatever the sidecars look like now, the point is that they no longer
        // hold anything the database file does not. Prove it by removing them
        // outright, which is the exact scenario #215 described as silent data
        // loss, and then reading the row back.
        File.Delete(_walPath);
        File.Delete(_shmPath);

        using var reopened = CreateContext();
        reopened.AcmeAccounts.Any(a => a.JwkThumbprint == "survives-the-sidecars")
            .Should().BeTrue("the checkpoint moved the committed row into ducks.db before the log went away");
    }

    [Fact]
    public void DisposingTheContextAlone_StrandsTheLog_WhichIsWhyThisHookExists()
    {
        // The premise the whole class rests on. Microsoft.Data.Sqlite pools
        // connections by default, so disposing a DbContext returns the
        // connection to the pool with the underlying handle still open. SQLite
        // never sees a last connection close, so it never checkpoints and never
        // deletes the sidecars, and a process that exits here leaves committed
        // transactions sitting in the log.
        //
        // If a future Microsoft.Data.Sqlite changes that default, this test
        // fails and the shutdown hook becomes tidiness rather than a guarantee.
        // That is worth being told about rather than discovering in a lab.
        CommitRowLeavingItInTheLog("stranded-by-pooling");

        File.Exists(_walPath).Should().BeTrue(
            "disposing the context does not close the pooled handle, so SQLite cannot checkpoint on its own");
        new FileInfo(_walPath).Length.Should().BeGreaterThan(0,
            "the committed row is still only in the log at this point");
    }

    [Fact]
    public void Checkpoint_EmptiesAndRemovesTheWriteAheadLog()
    {
        CommitRowLeavingItInTheLog("tidy-directory");

        using (var db = CreateContext())
        {
            SqliteShutdownCheckpoint.Checkpoint(db, NullLogger.Instance);
        }

        // TRUNCATE empties the log, and clearing the pool closes the last handle
        // so SQLite deletes both sidecars. Either outcome is safe, so accept a
        // zero length log as well as an absent one: the assertion that matters
        // is that nothing is left in it.
        var walLength = File.Exists(_walPath) ? new FileInfo(_walPath).Length : 0;
        walLength.Should().Be(0, "the log should be empty or gone after a checkpoint on shutdown");
    }

    [Fact]
    public void Checkpoint_OnADatabaseInWalModeWhileTheOptionIsOff_StillChecksPoints()
    {
        // The case that makes gating on CertusOptions.EnableWalMode wrong.
        // Journal mode is persisted in the file header, so the option and the
        // file can disagree, and the checkpoint has to follow the file.
        CommitRowLeavingItInTheLog("option-off-but-still-wal");

        // Deliberately not arranged through DatabaseInitializer.Initialize.
        // Since issue #283 a start with the option off does convert the file
        // back to rollback journalling when it can take the database
        // exclusively, which is the opposite of the state this test needs. A
        // database can still be in WAL mode with the option off in three ways: a
        // conversion another handle refused, a backup restored from when the
        // option was on, and a host that has not started since the option
        // changed. Gating the checkpoint on the option would skip exactly those.
        using (var restarted = CreateContext())
        {
            restarted.AcmeAccounts.Add(NewAccount("written-after-the-option-went-off"));
            restarted.SaveChanges();
        }

        new FileInfo(_walPath).Length.Should().BeGreaterThan(0,
            "the database is still in WAL mode, whatever the option now says");

        using (var db = CreateContext())
        {
            SqliteShutdownCheckpoint.Checkpoint(db, NullLogger.Instance);
        }

        var walLength = File.Exists(_walPath) ? new FileInfo(_walPath).Length : 0;
        walLength.Should().Be(0, "the checkpoint must not be skipped on a database that is still in WAL mode");
    }

    [Fact]
    public void Checkpoint_OnARollbackJournalDatabase_IsAHarmlessNoOp()
    {
        using (var db = CreateContext())
        {
            DatabaseInitializer.Initialize(db, enableWalMode: false, NullLogger.Instance);
            db.AcmeAccounts.Add(NewAccount("rollback-journal"));
            db.SaveChanges();
        }

        File.Exists(_walPath).Should().BeFalse("a rollback journal database has no write ahead log");

        using (var db = CreateContext())
        {
            var act = () => SqliteShutdownCheckpoint.Checkpoint(db, NullLogger.Instance);
            act.Should().NotThrow();
        }

        // SQLite reports -1 frames here and does nothing, which is why the
        // checkpoint can run unconditionally.
        File.Exists(_walPath).Should().BeFalse();
        using var reopened = CreateContext();
        reopened.AcmeAccounts.Any(a => a.JwkThumbprint == "rollback-journal").Should().BeTrue();
    }

    [Fact]
    public void Checkpoint_OnAnInMemoryDatabase_LeavesItIntact()
    {
        // An in memory database exists only while a connection to it is open, so
        // the guard has to hold: clearing the pool here would destroy the data
        // rather than tidy it.
        using var db = CreateContext(CertusPaths.InMemoryDatabase);
        db.Database.OpenConnection();
        DatabaseInitializer.Initialize(db, enableWalMode: true, NullLogger.Instance);
        db.AcmeAccounts.Add(NewAccount("in-memory"));
        db.SaveChanges();

        var act = () => SqliteShutdownCheckpoint.Checkpoint(db, NullLogger.Instance);

        act.Should().NotThrow();
        db.AcmeAccounts.Any(a => a.JwkThumbprint == "in-memory").Should().BeTrue();
    }

    [Fact]
    public void Checkpoint_OnAnUnreachableDatabase_DoesNotThrow()
    {
        // The shutdown path must never turn a clean service stop into a failed
        // one, whatever state the database is in.
        using var db = CreateContext(Path.Combine(_tempDir, "no-such-dir", "ducks.db"));

        var act = () => SqliteShutdownCheckpoint.Checkpoint(db, NullLogger.Instance);

        act.Should().NotThrow();
    }
}
