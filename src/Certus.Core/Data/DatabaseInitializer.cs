using System.Data;
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
/// </summary>
public static class DatabaseInitializer
{
    /// <summary>
    /// Ensure the database exists and its schema is current. Throws
    /// <see cref="InvalidOperationException"/> with operator instructions when
    /// the database predates migrations and does not match the current model.
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

        if (enableWalMode)
        {
            // WAL improves concurrent read/write performance. The mode is
            // persisted in the database file, so running this every start is a
            // cheap no op after the first time.
            db.Database.ExecuteSqlRaw("PRAGMA journal_mode=WAL;");
            logger.LogInformation("SQLite WAL mode enabled");
        }
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
    /// </summary>
    private static void RunOnConnection(CertusDbContext db, Action<IDbCommand> action)
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
