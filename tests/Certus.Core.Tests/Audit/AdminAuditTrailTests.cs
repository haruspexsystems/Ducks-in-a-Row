using Certus.Core.Audit;
using Certus.Core.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Audit;

/// <summary>
/// The audit trail writer (issue #634): one row per event on the fixed clock,
/// the same words logged at Warning so a raised minimum level keeps them, and
/// every column held to its declared width.
/// </summary>
public class AdminAuditTrailTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 24, 9, 30, 0, DateTimeKind.Utc);

    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CertusDbContext> _dbOptions;
    private readonly CertusDbContext _db;
    private readonly RecordingLogger _logger = new();
    private readonly AdminAuditTrail _sut;

    public AdminAuditTrailTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _dbOptions = new DbContextOptionsBuilder<CertusDbContext>().UseSqlite(_connection).Options;
        _db = new CertusDbContext(_dbOptions);
        _db.Database.EnsureCreated();
        _sut = new AdminAuditTrail(_db, _logger, new FakeTimeProvider(new DateTimeOffset(Now)));
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Record_WritesTheRow_AndLogsItAtWarning()
    {
        var entry = await _sut.RecordAsync(new AdminAuditEvent(
            "CORP\\admin", "settings.allowed-domains.changed", "allowed domains", "off", "on: example.com"));

        entry.Id.Should().BePositive();
        entry.OccurredAt.Should().Be(Now);
        _sut.Recorded.Should().Be(1);

        await using var verify = new CertusDbContext(_dbOptions);
        var row = await verify.AdminAuditEntries.SingleAsync();
        row.Actor.Should().Be("CORP\\admin");
        row.Action.Should().Be("settings.allowed-domains.changed");
        row.Target.Should().Be("allowed domains");
        row.BeforeValue.Should().Be("off");
        row.AfterValue.Should().Be("on: example.com");

        _logger.Lines.Should().ContainSingle()
            .Which.Should().Match<(LogLevel Level, string Message)>(l =>
                l.Level == LogLevel.Warning
                && l.Message.Contains("settings.allowed-domains.changed")
                && l.Message.Contains("CORP\\admin")
                && l.Message.Contains("on: example.com"));
    }

    [Fact]
    public async Task Record_WithNoActor_AttributesTheRowToAnonymous()
    {
        var entry = await _sut.RecordAsync(new AdminAuditEvent("  ", "alerts.test-sent"));

        entry.Actor.Should().Be(AdminAuditTrail.AnonymousActor);
        entry.Target.Should().BeNull();
        entry.BeforeValue.Should().BeNull();
        entry.AfterValue.Should().BeNull();
    }

    [Fact]
    public async Task Record_HoldsEveryColumnToItsDeclaredWidth()
    {
        var longValue = new string('x', AdminAuditTrail.MaxValueLength + 50);
        var longTarget = new string('t', AdminAuditTrail.MaxTargetLength + 1);
        var longActor = new string('a', AdminAuditTrail.MaxActorLength + 1);

        var entry = await _sut.RecordAsync(new AdminAuditEvent(longActor, "x.y", longTarget, longValue, longValue));

        entry.Actor.Should().HaveLength(AdminAuditTrail.MaxActorLength);
        entry.Target.Should().HaveLength(AdminAuditTrail.MaxTargetLength);
        entry.BeforeValue.Should().HaveLength(AdminAuditTrail.MaxValueLength);
        entry.AfterValue.Should().HaveLength(AdminAuditTrail.MaxValueLength);
    }

    [Fact]
    public async Task Record_WithoutAnAction_Refuses()
    {
        var act = () => _sut.RecordAsync(new AdminAuditEvent("CORP\\admin", " "));

        await act.Should().ThrowAsync<ArgumentException>();
        (await _db.AdminAuditEntries.CountAsync()).Should().Be(0);
    }

    private sealed class RecordingLogger : ILogger<AdminAuditTrail>
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
}
