using Certus.Core.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Certus.Core.Tests.Data;

/// <summary>
/// The migration that adds AlertSent.DeliveredChannels (issue #206) fills it on
/// the rows already there. A successful row meant every attempted channel
/// delivered, so it is known; a failed one recorded only that at least one
/// channel failed, so it must stay null rather than claim nobody was told.
/// </summary>
public class AlertSentDeliveredChannelsMigrationTests : IDisposable
{
    private const string MigrationBefore = "20261024065924_AddAdminAuditTrail";

    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;

    public AlertSentDeliveredChannelsMigrationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _db = new CertusDbContext(new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options);
    }

    private void Execute(string sql)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private string? DeliveredChannels(int id)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = $"SELECT \"DeliveredChannels\" FROM \"AlertsSent\" WHERE \"Id\" = {id};";
        return command.ExecuteScalar() as string;
    }

    [Fact]
    public void ExistingRows_SuccessKnowsItsChannels_FailureStaysUnknown()
    {
        var migrator = _db.GetService<IMigrator>();
        migrator.Migrate(MigrationBefore);

        // The rows only need to exist as an older version wrote them, not to
        // point at a real certificate.
        Execute("PRAGMA foreign_keys = OFF;");
        Execute(
            "INSERT INTO \"AlertsSent\" (\"Id\", \"CertificateId\", \"ThresholdDays\", \"SentAt\", \"Channels\", \"Success\", \"ErrorMessage\") VALUES " +
            "(1, 1, 30, '2026-10-01 00:00:00', 'email,webhook', 1, NULL), " +
            "(2, 1, 14, '2026-10-17 00:00:00', 'email,webhook', 0, 'Webhook returned 500');");

        migrator.Migrate();

        DeliveredChannels(1).Should().Be("email,webhook");
        DeliveredChannels(2).Should().BeNull();
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }
}
