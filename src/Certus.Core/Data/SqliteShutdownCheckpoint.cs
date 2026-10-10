using System.Data;
using Certus.Core.Configuration;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Data;

/// <summary>
/// Writes the write ahead log back into the database file when the host stops,
/// and closes the pooled connections so SQLite can clean up after itself
/// (issue #215).
///
/// The database runs in WAL mode (see <see cref="DatabaseInitializer"/>), so a
/// committed transaction lives in <c>ducks.db-wal</c> until a checkpoint moves
/// it into <c>ducks.db</c>. SQLite performs that checkpoint itself when the last
/// connection to the database closes, and then deletes the <c>-wal</c> and
/// <c>-shm</c> sidecar files.
///
/// That is what issue #215 actually observed, and it is why the issue was closed
/// as a false positive rather than fixed. Stopping the service on lab 2025 on
/// 2026-08-13, with no uninstall involved at all, removed both sidecars on its
/// own and left <c>ducks.db</c> byte for byte identical at 405,504:
///
///     1. running          ducks.db 405504  ducks.db-shm 32768  ducks.db-wal 4264232
///     2. after Stop-Service   ducks.db 405504  (no sidecars)
///
/// So the uninstall never touched the data directory. The service stop that
/// precedes it did, by way of the checkpoint above. The installer could not have
/// been the actor in any case: the database is in no WiX File table, the data
/// directory component is a bare CreateFolder, and there is no RemoveFile
/// anywhere in the installer sources. A missing sidecar after an uninstall is
/// the signature of a successful checkpoint, not of discarded data.
///
/// What that leaves is a guarantee resting on process teardown rather than on
/// anything the code says. Within a running process the cleanup does not happen
/// at all: Microsoft.Data.Sqlite pools connections by default, neither host sets
/// <c>Pooling=False</c>, and the test
/// <c>DisposingTheContextAlone_StrandsTheLog_WhichIsWhyThisHookExists</c> shows
/// that disposing a DbContext returns the connection to the pool with the handle
/// still open, so no checkpoint runs. A development host on the author's machine
/// left a 350 KB <c>ducks.db-wal</c> beside a 128 KB database with no service
/// installed at all, for that reason.
///
/// So this runs the checkpoint deliberately rather than leaving it to chance.
/// The two halves do different jobs and both are wanted:
///
/// 1. <c>PRAGMA wal_checkpoint(TRUNCATE)</c> is the one that matters. After it
///    returns, every committed transaction is in the database file, so nothing
///    is lost even if the process is killed a moment later or something deletes
///    the sidecars afterwards.
/// 2. Clearing the pool closes the handles, which lets SQLite delete the
///    sidecars. That part is about leaving an unambiguous directory behind: an
///    operator looking at the data folder after an uninstall should not have to
///    wonder whether a leftover <c>-wal</c> holds data the database does not.
///
/// Registered ahead of the other AddHostedService calls in both hosts, because
/// hosted services stop in reverse registration order, so first there means
/// this one stops after those background workers have finished writing.
/// </summary>
public sealed class SqliteShutdownCheckpoint : IHostedService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<SqliteShutdownCheckpoint> _logger;

    public SqliteShutdownCheckpoint(
        IServiceScopeFactory scopeFactory,
        ILogger<SqliteShutdownCheckpoint> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// The cancellation token is deliberately not threaded into the checkpoint.
    /// It is signalled when the shutdown timeout expires, and that is precisely
    /// the moment the write ahead log most needs writing back; the pragma is a
    /// single fast statement, so attempting it anyway costs almost nothing.
    /// </summary>
    public Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            Checkpoint(db, _logger);
        }
        catch (ObjectDisposedException)
        {
            // The host was torn down provider first, so there is no scope left
            // to reach a DbContext through. WebApplicationFactory.Dispose does
            // exactly this: it disposes the provider and then calls StopAsync.
            // Both hosts stop their hosted services before disposing, so this is
            // a test shutdown ordering rather than a production one. Swallowed
            // without logging, because the logger came from the same provider.
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SQLite checkpoint on shutdown could not reach the database context");
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Checkpoint the context's database and close its pooled connections.
    /// Mirrors <see cref="DatabaseInitializer.Initialize"/>'s shape so the pair
    /// reads as the two ends of the same lifecycle.
    ///
    /// Never throws. A failure here is worth logging but must not turn a clean
    /// service stop into a failed one, and the data is no worse off than it
    /// would have been without the attempt.
    ///
    /// Deliberately does not consult <c>CertusOptions.EnableWalMode</c>. That
    /// option says what the last startup asked for, not what the database is:
    /// journal mode is persisted in the file header, so the option and the file
    /// can disagree. Since issue #283 a start with the option off does convert
    /// an existing database back to rollback journalling, which narrows the
    /// disagreement but does not close it. Three cases still leave a database in
    /// WAL mode with the option off: a conversion another handle on the file
    /// refused, a backup restored from when the option was on, and a host that
    /// has not started since the option changed. Gating on the option would skip
    /// the checkpoint on exactly those. Running it unconditionally is safe: on a
    /// genuine rollback journal database the pragma reports <c>-1</c> frames and
    /// does nothing.
    /// </summary>
    public static void Checkpoint(CertusDbContext db, ILogger logger)
    {
        var connection = db.Database.GetDbConnection();

        // An in memory database exists only while a connection to it is open,
        // so clearing the pool would destroy it rather than tidy it. Read the
        // data source off the connection rather than off CertusOptions: the web
        // test factory deliberately points the context at a different file from
        // the one the options name.
        var dataSource = connection.DataSource;
        if (string.IsNullOrEmpty(dataSource) || dataSource == CertusPaths.InMemoryDatabase)
            return;

        try
        {
            DatabaseInitializer.RunOnConnection(db, command =>
            {
                // Returns one row: busy, then the size of the write ahead log in
                // frames, then how many of those frames were moved into the
                // database. TRUNCATE rather than PASSIVE so the log is emptied
                // and not merely copied, and busy is reported rather than
                // swallowed: a non zero value means a reader held the lock and
                // some frames are still only in the log.
                command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
                using var reader = command.ExecuteReader();
                if (!reader.Read())
                {
                    logger.LogInformation("SQLite checkpoint on shutdown returned no result for {DataSource}", dataSource);
                    return;
                }

                var busy = reader.IsDBNull(0) ? -1 : reader.GetInt32(0);
                var logFrames = reader.IsDBNull(1) ? -1 : reader.GetInt32(1);
                var moved = reader.IsDBNull(2) ? -1 : reader.GetInt32(2);

                if (logFrames < 0)
                {
                    // SQLite reports -1 frames when the database is not in WAL
                    // mode, which is the operator opt out arriving as a fact
                    // about the file rather than as a configuration flag.
                    logger.LogDebug(
                        "SQLite checkpoint on shutdown skipped: {DataSource} is not in write ahead logging mode",
                        dataSource);
                }
                else if (busy != 0)
                {
                    logger.LogWarning(
                        "SQLite checkpoint on shutdown was blocked (busy={Busy}); {Moved} of {LogFrames} " +
                        "write ahead log frame(s) reached the database. The remainder stay in the log and " +
                        "are replayed the next time the database is opened",
                        busy, moved, logFrames);
                }
                else
                {
                    logger.LogInformation(
                        "SQLite checkpoint on shutdown wrote {Moved} of {LogFrames} write ahead log frame(s) back",
                        moved, logFrames);
                }
            });

            // Close the pooled handles for this database only. ClearAllPools
            // would reach other databases in the process, which matters in a
            // test run where several hosts are alive at once.
            if (connection is SqliteConnection sqliteConnection)
                SqliteConnection.ClearPool(sqliteConnection);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "SQLite checkpoint on shutdown failed for {DataSource}; the write ahead log stays on disk " +
                "and is replayed the next time the database is opened", dataSource);
        }
    }
}
