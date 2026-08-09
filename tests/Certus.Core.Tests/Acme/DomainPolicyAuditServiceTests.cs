using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for the domain policy audit writer: rows persist with all fields,
/// the table is pruned to its cap on insert, over long identifier lists are
/// truncated to the column size, and a failing write never throws back into
/// the rejection path.
/// </summary>
public class DomainPolicyAuditServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly DomainPolicyAuditService _sut;

    public DomainPolicyAuditServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _sut = new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance);
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }

    private static AcmeIdentifier[] Identifiers(params string[] values)
    {
        return values.Select(v => new AcmeIdentifier { Type = "dns", Value = v }).ToArray();
    }

    [Fact]
    public async Task RecordAsync_PersistsAllFields()
    {
        await _sut.RecordAsync(
            "acct-1", "WebServer",
            Identifiers("ok.home.local", "bad.other.local"),
            ["bad.other.local"],
            "192.168.10.20", "newOrder", CancellationToken.None);

        var row = await _db.DomainPolicyRejections.SingleAsync();
        row.AccountId.Should().Be("acct-1");
        row.TemplateId.Should().Be("WebServer");
        row.RequestedIdentifiers.Should().Be("ok.home.local, bad.other.local");
        row.RejectedIdentifiers.Should().Be("bad.other.local");
        row.ClientIp.Should().Be("192.168.10.20");
        row.Stage.Should().Be("newOrder");
        row.OccurredAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task RecordAsync_PrunesOldestRowsBeyondTheCap()
    {
        var baseTime = DateTime.UtcNow.AddHours(-1);
        for (var i = 0; i < DomainPolicyAuditService.MaxRows + 5; i++)
        {
            _db.DomainPolicyRejections.Add(new DomainPolicyRejection
            {
                OccurredAt = baseTime.AddSeconds(i),
                AccountId = $"acct-{i}",
                TemplateId = "WebServer",
                RequestedIdentifiers = "x.other.local",
                RejectedIdentifiers = "x.other.local",
                Stage = "newOrder",
            });
        }
        await _db.SaveChangesAsync();

        await _sut.RecordAsync(
            "acct-new", "WebServer",
            Identifiers("y.other.local"), ["y.other.local"],
            null, "newOrder", CancellationToken.None);

        // 1005 seeded plus 1 recorded, pruned back to the cap: the six
        // oldest seeded rows are gone, the newest recorded row remains.
        (await _db.DomainPolicyRejections.CountAsync())
            .Should().Be(DomainPolicyAuditService.MaxRows);
        (await _db.DomainPolicyRejections.AnyAsync(r => r.AccountId == "acct-0"))
            .Should().BeFalse();
        (await _db.DomainPolicyRejections.AnyAsync(r => r.AccountId == "acct-5"))
            .Should().BeFalse();
        (await _db.DomainPolicyRejections.AnyAsync(r => r.AccountId == "acct-6"))
            .Should().BeTrue();
        (await _db.DomainPolicyRejections.AnyAsync(r => r.AccountId == "acct-new"))
            .Should().BeTrue();
    }

    [Fact]
    public async Task RecordAsync_TruncatesOverlongIdentifierLists()
    {
        var many = Enumerable.Range(0, 300)
            .Select(i => $"host{i:D3}.home.local")
            .ToArray();

        await _sut.RecordAsync(
            "acct-1", "WebServer",
            Identifiers(many), many,
            null, "newOrder", CancellationToken.None);

        var row = await _db.DomainPolicyRejections.SingleAsync();
        row.RequestedIdentifiers.Length.Should().Be(2000);
        row.RejectedIdentifiers.Length.Should().Be(2000);
    }

    [Fact]
    public async Task RecordAsync_WriteFailure_IsSwallowed()
    {
        // Killing the connection makes SaveChanges fail. The audit write is
        // best effort and must never throw back into the rejection path.
        _connection.Dispose();

        var record = () => _sut.RecordAsync(
            "acct-1", "WebServer",
            Identifiers("x.other.local"), ["x.other.local"],
            null, "newOrder", CancellationToken.None);

        await record.Should().NotThrowAsync();
    }
}
