using Certus.Core.Audit;
using Certus.Core.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Audit;

/// <summary>
/// The failed sign in counter (issue #634): one row per source address, status
/// and UTC hour, so a brute force attempt grows a count rather than the table;
/// a source the server cannot name is counted as unknown.
/// </summary>
public class AdminSignInFailureRecorderTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 24, 9, 30, 0, DateTimeKind.Utc);

    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CertusDbContext> _dbOptions;
    private readonly CertusDbContext _db;
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(Now));
    private readonly AdminSignInFailureRecorder _sut;

    public AdminSignInFailureRecorderTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _dbOptions = new DbContextOptionsBuilder<CertusDbContext>().UseSqlite(_connection).Options;
        _db = new CertusDbContext(_dbOptions);
        _db.Database.EnsureCreated();
        _sut = new AdminSignInFailureRecorder(_db, NullLogger<AdminSignInFailureRecorder>.Instance, _clock);
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task RepeatedFailures_InOneHour_GrowOneRow()
    {
        await _sut.RecordAsync("198.51.100.7", 401);
        _clock.Advance(TimeSpan.FromMinutes(10));
        await _sut.RecordAsync("198.51.100.7", 401);
        _clock.Advance(TimeSpan.FromMinutes(10));
        await _sut.RecordAsync("198.51.100.7", 401);

        await using var verify = new CertusDbContext(_dbOptions);
        var row = await verify.AdminSignInFailures.SingleAsync();
        row.SourceAddress.Should().Be("198.51.100.7");
        row.StatusCode.Should().Be(401);
        row.Count.Should().Be(3);
        row.BucketStart.Should().Be(new DateTime(2026, 10, 24, 9, 0, 0, DateTimeKind.Utc));
        row.FirstAt.Should().Be(Now);
        row.LastAt.Should().Be(Now.AddMinutes(20));
    }

    [Fact]
    public async Task ANewHour_Source_OrStatus_StartsItsOwnRow()
    {
        await _sut.RecordAsync("198.51.100.7", 401);
        await _sut.RecordAsync("198.51.100.7", 403);
        await _sut.RecordAsync("198.51.100.8", 401);
        _clock.Advance(TimeSpan.FromHours(1));
        await _sut.RecordAsync("198.51.100.7", 401);

        await using var verify = new CertusDbContext(_dbOptions);
        var rows = await verify.AdminSignInFailures.ToListAsync();
        rows.Should().HaveCount(4);
        rows.Should().OnlyContain(r => r.Count == 1);
        rows.Select(r => r.BucketStart).Distinct().Should().HaveCount(2);
    }

    [Fact]
    public async Task ASourceTheServerCannotName_IsCountedAsUnknown()
    {
        await _sut.RecordAsync(null, 401);
        await _sut.RecordAsync("   ", 401);

        await using var verify = new CertusDbContext(_dbOptions);
        var row = await verify.AdminSignInFailures.SingleAsync();
        row.SourceAddress.Should().Be(AdminSignInFailureRecorder.UnknownSource);
        row.Count.Should().Be(2);
    }

    [Fact]
    public async Task ARecorderWhoseDatabaseIsGone_DoesNotThrow()
    {
        // The counter sits on the sign in path; a storage failure there must
        // never turn a refusal into a 500.
        _connection.Close();

        var act = () => _sut.RecordAsync("198.51.100.7", 401);

        await act.Should().NotThrowAsync();
    }
}
