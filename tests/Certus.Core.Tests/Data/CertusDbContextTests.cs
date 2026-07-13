using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Certus.Core.Tests.Data;

/// <summary>
/// Verifies the CertusDbContext can be created and migrated with SQLite.
/// </summary>
public class CertusDbContextTests : IDisposable
{
    private readonly CertusDbContext _context;

    public CertusDbContextTests()
    {
        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        _context = new CertusDbContext(options);
        _context.Database.OpenConnection();
        _context.Database.EnsureCreated();
    }

    [Fact]
    public void DbContext_CanBeCreated()
    {
        _context.Should().NotBeNull();
    }

    [Fact]
    public void DbContext_DatabaseIsCreated()
    {
        var canConnect = _context.Database.CanConnect();
        canConnect.Should().BeTrue();
    }

    [Fact]
    public void DbContext_ProviderIsSqlite()
    {
        var providerName = _context.Database.ProviderName;
        providerName.Should().Contain("Sqlite");
    }

    [Fact]
    public void DateTime_RoundTripsAsUtc()
    {
        // Store a UTC stamp, then force a real read back from SQLite (clearing the
        // change tracker) so the value converter runs. Without the converter the Kind
        // comes back Unspecified; with it the UTC intent is preserved.
        var account = new AcmeAccount
        {
            AccountId = "acct-utc-roundtrip",
            JwkThumbprint = "thumb-utc-roundtrip",
            JwkJson = "{}",
            CreatedAt = DateTime.UtcNow
        };
        _context.AcmeAccounts.Add(account);
        _context.SaveChanges();
        _context.ChangeTracker.Clear();

        var loaded = _context.AcmeAccounts.Single(a => a.AccountId == "acct-utc-roundtrip");

        loaded.CreatedAt.Kind.Should().Be(DateTimeKind.Utc);
        loaded.CreatedAt.Should().BeCloseTo(account.CreatedAt, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void AcmeChallenge_IsIndexedOnStatus()
    {
        var indexes = _context.Model
            .FindEntityType(typeof(AcmeChallenge))!
            .GetIndexes();

        indexes.Should().Contain(
            i => i.Properties.Count == 1 && i.Properties[0].Name == nameof(AcmeChallenge.Status),
            "the background validation sweep filters challenges by Status");
    }

    public void Dispose()
    {
        _context.Database.CloseConnection();
        _context.Dispose();
    }
}
