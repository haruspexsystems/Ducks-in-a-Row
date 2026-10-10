using System.Data;
using Certus.Core.Adcs;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Data;

/// <summary>
/// Brings the SQLite database to the current schema at startup (issue #77).
///
/// Earlier versions created the schema with <c>EnsureCreated()</c>, which never
/// alters an existing database, so upgrades left old databases on the old
/// schema and the dashboard failed with "no such table". This initializer
/// replaces that call in both hosts with a migration based flow:
///
/// 1. Migration history table present: apply pending migrations.
/// 2. No user tables (fresh or empty database): apply all migrations.
/// 3. User tables but no history (a database created by EnsureCreated before
///    migrations existed): compare the live schema against the current EF
///    model, tables and columns only. On an exact match, stamp every defined
///    migration as applied (the schema is already current) and continue. On a
///    mismatch, fail startup with an operator message that names the reset
///    procedure — pre 1.0, databases older than the first migration cannot be
///    upgraded automatically.
///
/// The comparison deliberately ignores indexes and foreign key names: they are
/// not visible through PRAGMA table_info and EF generated names are brittle to
/// compare. Tables and columns are what the queries need.
///
/// Two data steps follow the schema, in order: the stored subject sweep
/// (<see cref="SanitizeStoredSubjects"/>, issue #224) and the journal mode
/// (<see cref="ApplyJournalMode"/>, issue #283). The journal mode step is the
/// only one here that reports a failure and carries on rather than throwing;
/// its doc comment says why.
/// </summary>
public static class DatabaseInitializer
{
    // EF turns a Contains over a list into one parameter per element, and
    // SQLite's older default ceiling is 999. Same reasoning, and the same value,
    // as SupersessionLinker.UpdateChunkSize.
    private const int SubjectUpdateChunkSize = 500;

    // SQLite reports a journal mode in lower case whatever case the pragma was
    // written in, so these double as the values the results are compared
    // against and the values that reach the log. DELETE is the rollback target
    // because it is SQLite's own compiled default: a database created with
    // EnableWalMode already off is in DELETE mode, so converting an existing one
    // lands it in exactly the same state rather than in a third mode nothing
    // else in the product expects. TRUNCATE and PERSIST would both leave a
    // permanent -journal sidecar, which is the question SqliteShutdownCheckpoint
    // exists to stop an operator having to ask about -wal.
    private const string WalJournalMode = "wal";
    private const string RollbackJournalMode = "delete";

    // What PRAGMA journal_mode reports for an in memory database, whatever is
    // asked of it. ":memory:" is a supported configuration, one StartupValidator
    // already warns loses everything on restart, and it has no journal to
    // configure, so it is neither a success nor a refusal.
    private const string InMemoryJournalMode = "memory";

    // Stands in for the mode when the pragma could not be read at all, so the
    // failure warning still has something honest to say.
    private const string UnknownJournalMode = "unknown";

    /// <summary>
    /// Ensure the database exists, its schema is current, and its journal mode
    /// matches <paramref name="enableWalMode"/>. Throws
    /// <see cref="InvalidOperationException"/> with operator instructions when
    /// the database predates migrations and does not match the current model.
    /// A journal mode that cannot be applied is logged and does not throw.
    /// </summary>
    public static void Initialize(CertusDbContext db, bool enableWalMode, ILogger logger)
    {
        var userTables = ListUserTables(db);
        var hasHistory = HistoryTableExists(db);

        if (hasHistory)
        {
            db.Database.Migrate();
        }
        else if (userTables.Count == 0)
        {
            logger.LogInformation("Database is new or empty; creating the schema via migrations");
            db.Database.Migrate();
        }
        else
        {
            // Legacy database created by EnsureCreated(): tables exist but there
            // is no migration history to reason from.
            var mismatch = CompareSchemaToModel(db, userTables);
            if (mismatch is null)
            {
                StampAllMigrations(db, logger);
                db.Database.Migrate();
            }
            else
            {
                throw new InvalidOperationException(BuildResetMessage(db, mismatch));
            }
        }

        SanitizeStoredSubjects(db, logger);

        // Last on purpose. The schema is the thing that can fail startup and it
        // should fail before the file is reconfigured, and leaving WAL
        // checkpoints this boot's own writes into the database on the way out,
        // so a converted database is fully consolidated on disk by the time this
        // method returns.
        ApplyJournalMode(db, enableWalMode, logger);
    }

    /// <summary>
    /// Bring the database's journal mode into line with
    /// <c>Certus:EnableWalMode</c>, in both directions (issue #283).
    ///
    /// The mode lives in the database file rather than in configuration, so the
    /// option is a request made once per start against a file that already has
    /// an answer. Before this method the request only ever went one way: with
    /// the option on the pragma ran, and with the option off nothing ran at all,
    /// so an existing database stayed in write ahead logging mode however the
    /// option was later set. The one case the option is documented for, a data
    /// directory whose filesystem cannot support WAL, was reachable only by
    /// deleting the database and starting again.
    ///
    /// The half that did run was unverified. <c>PRAGMA journal_mode=&lt;mode&gt;</c>
    /// answers with one row holding the mode the database ended up in, and that
    /// row is the only way to tell a switch that happened from one that was
    /// refused; <c>ExecuteSqlRaw</c> discards it. So "SQLite WAL mode enabled"
    /// was logged on a filesystem that had silently refused WAL exactly as
    /// confidently as on one that had taken it. Every branch below reports the
    /// mode the database itself reports, and says whether anything changed.
    ///
    /// A refusal is never fatal, and that is deliberate rather than lazy.
    /// Changing journal mode needs the database file exclusively, and startup is
    /// the only moment that can be true: both hosts call
    /// <see cref="Initialize"/> from a dedicated scope before the host runs, so
    /// no worker and no request has opened a connection yet. Anything else on
    /// the machine holding the file open still refuses it. Unlike the schema
    /// mismatch above, which throws because every later query would fail on it,
    /// a journal mode the operator did not ask for costs concurrency and
    /// portability and nothing else: every query works in either mode and the
    /// database is exactly as usable as it was a moment earlier. Refusing to
    /// start would take a working install down to enforce a preference, and
    /// would do it in a loop, because restarting does not close whatever handle
    /// refused the switch. It is retried on the next start instead, which needs
    /// no stored state and heals itself the moment the obstacle goes away.
    /// </summary>
    private static void ApplyJournalMode(CertusDbContext db, bool enableWalMode, ILogger logger)
    {
        var requested = enableWalMode ? WalJournalMode : RollbackJournalMode;

        // Hoisted out of the lambda so the catch below can still say where the
        // database stands. A SQLITE_BUSY arrives from the switch, after the read
        // has already succeeded, and "it is still in wal" is the fact an
        // operator chasing a refusal needs.
        var current = UnknownJournalMode;

        try
        {
            RunOnConnection(db, command =>
            {
                // Both statements share one command on one connection, on
                // purpose. The read decides whether the write is needed at all,
                // and a pooled handle taken twice is not guaranteed to be the
                // same handle. ExecuteScalar rather than a reader held across
                // the two, because SQLite refuses a journal mode change while
                // another statement is still live on the connection.
                command.CommandText = "PRAGMA journal_mode;";
                current = command.ExecuteScalar() as string ?? UnknownJournalMode;

                if (string.Equals(current, InMemoryJournalMode, StringComparison.OrdinalIgnoreCase))
                {
                    // An in memory database keeps its pages in memory and has no
                    // journal file to configure; it answers "memory" to any
                    // request and ignores it. That is neither a success nor a
                    // refusal, so it is not worth a warning: StartupValidator
                    // already warns that this configuration loses everything on
                    // restart, which is the larger fact about it.
                    logger.LogDebug(
                        "SQLite journal mode is {Mode}; an in memory database has no journal to configure",
                        current);
                    return;
                }

                if (string.Equals(current, requested, StringComparison.OrdinalIgnoreCase))
                {
                    // Already where the option asks for, said out loud rather
                    // than passed over in silence. This is the line that shows a
                    // start after the option changed did nothing because there
                    // was nothing to do, as opposed to nothing because the code
                    // never looked, which is what issue #283 could not tell
                    // apart.
                    logger.LogInformation("SQLite journal mode is {Mode}", current);
                    return;
                }

                // Two literals rather than an interpolated mode, so the SQL that
                // runs is readable here and nothing about this looks like a
                // statement built out of a value.
                command.CommandText = enableWalMode
                    ? "PRAGMA journal_mode=WAL;"
                    : "PRAGMA journal_mode=DELETE;";
                var applied = command.ExecuteScalar() as string ?? UnknownJournalMode;

                if (string.Equals(applied, requested, StringComparison.OrdinalIgnoreCase))
                {
                    // Leaving WAL checkpoints the log into the database file and
                    // removes the -wal and -shm sidecars on the way out, so the
                    // data directory an operator looks at afterwards matches
                    // what the option now says.
                    logger.LogInformation(
                        "SQLite journal mode changed from {PreviousMode} to {Mode}", current, applied);
                }
                else
                {
                    logger.LogWarning(
                        "SQLite journal mode is {Mode} after a request for {RequestedMode}; the change was " +
                        "refused and Ducks in a Row starts on the mode the database is in. Changing journal " +
                        "mode needs the database file exclusively, and write ahead logging additionally needs " +
                        "a filesystem that supports shared memory, which some network shares do not. It is " +
                        "retried on every start",
                        applied, requested);
                }
            });
        }
        catch (Exception ex)
        {
            // Deliberately broad and deliberately not a throw. The refusal this
            // is most likely to catch is SQLITE_BUSY raised by the switch itself
            // rather than reported in its result row: leaving WAL mode takes an
            // exclusive lock with no busy handler behind it, so another handle
            // on the file aborts the statement. That is an ordinary outcome
            // here, not an exceptional one. Enumerating the rest of what the
            // driver can raise would be guesswork against a guarantee that has
            // to hold for all of it, and the schema is already current by the
            // time this runs, so there is nothing left for a swallowed exception
            // to hide.
            //
            // No retry loop and no busy timeout: the lock this waits on does not
            // consult SQLite's busy handler, so a wait would be a sleep with no
            // mechanism behind it. The retry is the next start.
            logger.LogWarning(ex,
                "SQLite journal mode could not be changed from {Mode} to {RequestedMode}; the database is " +
                "left as it is and Ducks in a Row starts normally. Journal mode is a concurrency and " +
                "filesystem compatibility choice, not a correctness one, so it is never a reason to refuse " +
                "to start",
                current, requested);
        }
    }

    /// <summary>
    /// Rewrites any stored certificate subject that still carries the control or
    /// format characters the sanitizer strips, or that overflows the column
    /// (issue #224).
    ///
    /// The sync usually heals these on its own: the issued and revoked passes
    /// read the whole CA every cycle and overwrite the subject in place. Three
    /// kinds of row never get that treatment, which is what this pass is for.
    /// A subject that sanitizes away to nothing is skipped by UpdateEntity, on
    /// purpose, so a blank pass cannot erase a good name. A request row resolved
    /// longer ago than RequestHistoryDays falls outside the only bounded passes,
    /// so rows poisoned before issue #186 shipped were never revisited either.
    /// And nothing deletes a SyncedCertificate, so a row the CA has since
    /// archived keeps whatever it last held forever.
    ///
    /// Not a migration, for a reason worth stating: <see cref="StampAllMigrations"/>
    /// marks every migration as applied without running it, so a data fix in an
    /// Up() method would be silently skipped on exactly the oldest databases,
    /// the ones most likely to be carrying an unsanitized value. It is C# rather
    /// than SQL because SQLite has no Unicode category function.
    ///
    /// Unconditional rather than one shot, so it stays a proven no op on every
    /// later start and self heals anything a future regression writes.
    /// </summary>
    private static void SanitizeStoredSubjects(CertusDbContext db, ILogger logger)
    {
        // Untracked projection first, so the common case (nothing to fix) reads
        // two short columns and allocates no entities at all. Only the rows that
        // actually change are loaded for real, below.
        var replacements = db.SyncedCertificates
            .AsNoTracking()
            .Select(c => new { c.Id, c.Subject })
            .ToList()
            // Null means the whole subject was strippable. The column is
            // required, so an empty string is the established "nothing here"
            // value, and the ACME backfill treats it as a row to name.
            .Select(row => (row.Id, Cleaned: CertificateTextSanitizer.SanitizeSubject(row.Subject) ?? "", row.Subject))
            .Where(row => !string.Equals(row.Cleaned, row.Subject, StringComparison.Ordinal))
            .ToDictionary(row => row.Id, row => row.Cleaned);

        if (replacements.Count == 0)
            return;

        // Chunked for the same reason SupersessionLinker chunks: EF turns a
        // Contains over a list into one parameter per element, against SQLite's
        // older default ceiling of 999.
        foreach (var chunk in replacements.Keys.Chunk(SubjectUpdateChunkSize))
        {
            var ids = chunk.ToList();
            foreach (var entity in db.SyncedCertificates.Where(c => ids.Contains(c.Id)))
                entity.Subject = replacements[entity.Id];
        }

        db.SaveChanges();
        logger.LogInformation(
            "Sanitized {Count} stored certificate subject(s) that carried control or format "
            + "characters, or exceeded the column width", replacements.Count);
    }

    /// <summary>
    /// True when the EF migrations history table exists in the database.
    /// </summary>
    private static bool HistoryTableExists(CertusDbContext db)
    {
        return ListTables(db).Contains(HistoryRepository.DefaultTableName, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// All table names except SQLite internals and the migrations history table.
    /// </summary>
    private static IReadOnlyList<string> ListUserTables(CertusDbContext db)
    {
        return ListTables(db)
            .Where(t => !t.Equals(HistoryRepository.DefaultTableName, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private static IReadOnlyList<string> ListTables(CertusDbContext db)
    {
        var tables = new List<string>();
        RunOnConnection(db, command =>
        {
            command.CommandText =
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';";
            using var reader = command.ExecuteReader();
            while (reader.Read())
                tables.Add(reader.GetString(0));
        });
        return tables;
    }

    /// <summary>
    /// Compare the live schema against the current EF relational model, tables
    /// and columns only. Returns null on an exact match, otherwise a short
    /// human readable list of the differences.
    /// </summary>
    private static string? CompareSchemaToModel(CertusDbContext db, IReadOnlyList<string> actualTables)
    {
        var expected = db.Model.GetRelationalModel().Tables.ToDictionary(
            t => t.Name,
            t => t.Columns.Select(c => c.Name).ToHashSet(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);

        var actual = actualTables.ToDictionary(
            t => t,
            t => GetTableColumns(db, t),
            StringComparer.OrdinalIgnoreCase);

        var differences = new List<string>();

        foreach (var table in expected.Keys.Where(t => !actual.ContainsKey(t)).Order())
            differences.Add($"missing table {table}");
        foreach (var table in actual.Keys.Where(t => !expected.ContainsKey(t)).Order())
            differences.Add($"unexpected table {table}");

        foreach (var (table, expectedColumns) in expected)
        {
            if (!actual.TryGetValue(table, out var actualColumns))
                continue;

            foreach (var column in expectedColumns.Where(c => !actualColumns.Contains(c)).Order())
                differences.Add($"table {table}: missing column {column}");
            foreach (var column in actualColumns.Where(c => !expectedColumns.Contains(c)).Order())
                differences.Add($"table {table}: unexpected column {column}");
        }

        return differences.Count == 0 ? null : string.Join("; ", differences);
    }

    private static HashSet<string> GetTableColumns(CertusDbContext db, string tableName)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        RunOnConnection(db, command =>
        {
            // PRAGMA does not accept parameters; the table name comes from
            // sqlite_master, quoted with doubled embedded quotes.
            command.CommandText = $"PRAGMA table_info(\"{tableName.Replace("\"", "\"\"")}\");";
            using var reader = command.ExecuteReader();
            while (reader.Read())
                columns.Add(reader.GetString(reader.GetOrdinal("name")));
        });
        return columns;
    }

    /// <summary>
    /// Record every defined migration as applied. Only called after the live
    /// schema was verified to match the current model, which is by construction
    /// the model of the latest migration.
    /// </summary>
    private static void StampAllMigrations(CertusDbContext db, ILogger logger)
    {
        var history = db.GetService<IHistoryRepository>();
        db.Database.ExecuteSqlRaw(history.GetCreateIfNotExistsScript());

        var migrations = db.Database.GetMigrations().ToList();
        foreach (var migrationId in migrations)
        {
            db.Database.ExecuteSqlRaw(history.GetInsertScript(
                new HistoryRow(migrationId, ProductInfo.GetVersion())));
        }

        logger.LogWarning(
            "Adopted a database created before migrations were introduced: schema matches the " +
            "current model; stamped {Count} migration(s) as applied (latest: {Latest})",
            migrations.Count, migrations.LastOrDefault());
    }

    private static string BuildResetMessage(CertusDbContext db, string mismatch)
    {
        var dataSource = db.Database.GetDbConnection().DataSource;
        return
            "The existing database was created by an earlier version and its schema does not " +
            $"match this version ({mismatch}). Databases created before schema migrations were " +
            "introduced cannot be upgraded automatically. To reset: stop the service, move or " +
            $"delete '{dataSource}' together with its -wal and -shm sidecar files, then start " +
            "the service to recreate the database at the current schema. The synced certificate " +
            "inventory repopulates from the CA on the next sync; ACME accounts, orders, " +
            "challenge state, and alert history are lost. See docs/troubleshooting.md, section " +
            "'Database schema mismatch'.";
    }

    /// <summary>
    /// Run a command on the context's connection, preserving its open state.
    /// A shared in memory test connection must stay open; a file connection is
    /// opened and closed around the call.
    ///
    /// Internal rather than private so <see cref="SqliteShutdownCheckpoint"/>
    /// can run its checkpoint pragma the same way, instead of keeping a second
    /// copy of this in the same namespace.
    /// </summary>
    internal static void RunOnConnection(CertusDbContext db, Action<IDbCommand> action)
    {
        var connection = db.Database.GetDbConnection();
        var wasOpen = connection.State == ConnectionState.Open;
        if (!wasOpen)
            connection.Open();
        try
        {
            using var command = connection.CreateCommand();
            action(command);
        }
        finally
        {
            if (!wasOpen)
                connection.Close();
        }
    }
}
