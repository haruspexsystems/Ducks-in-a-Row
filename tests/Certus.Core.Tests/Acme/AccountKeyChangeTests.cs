using System.Data.Common;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// The save half of ACME account key rollover (RFC 8555 §7.3.5), which the controller
/// reaches only once its own pre-check found the new key unregistered. What can still go
/// wrong at the save is the subject here, and issue #127 found two defects in it: a lost race
/// on the unique key index answered 409 without the Location header the RFC requires, because
/// the service never said who held the key, and every other save failure, a busy database
/// included, was reported to the client as "key already in use".
///
/// <para>
/// Each test owns a private in memory connection. The shared one the web tests once used is
/// what produced "database is locked" under load, and nothing here runs a background worker.
/// </para>
/// </summary>
public class AccountKeyChangeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CertusDbContext> _dbOptions;
    private readonly FailingUpdateInterceptor _failures = new();
    private readonly CertusDbContext _db;
    private readonly AccountService _sut;

    public AccountKeyChangeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        _dbOptions = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(_failures)
            .Options;
        _db = new CertusDbContext(_dbOptions);
        _db.Database.EnsureCreated();

        _sut = new AccountService(_db, NullLogger<AccountService>.Instance);
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }

    [Fact]
    public async Task ChangeKey_ToAFreeKey_SwapsTheKey()
    {
        var account = await SeedAccountAsync("free-key-a");
        var newJwk = Jwk("free-key-new");

        var result = await _sut.ChangeKeyAsync(account, newJwk);

        result.Outcome.Should().Be(KeyChangeOutcome.Changed);
        result.KeyHolder.Should().BeNull("only a conflict names a holder");
        (await ReadThumbprintAsync(account.AccountId))
            .Should().Be(JwsService.ComputeThumbprint(newJwk));
    }

    [Fact]
    public async Task ChangeKey_ToAKeyAnotherAccountHolds_ReportsAConflictNamingTheHolder()
    {
        // The race the controller's pre-check cannot close: the key was free when it looked
        // and taken by the time it saved. Driven here with no pre-check at all, so the real
        // unique index on JwkThumbprint refuses the swap, which is the only honest witness of
        // the error code the conflict filter keys on. A synthetic exception would only prove
        // the filter agrees with itself.
        var account = await SeedAccountAsync("held-key-a");
        var holder = await SeedAccountAsync("held-key-b");
        var originalThumbprint = account.JwkThumbprint;

        var result = await _sut.ChangeKeyAsync(account, Jwk("held-key-b"));

        result.Outcome.Should().Be(KeyChangeOutcome.Conflict);
        result.KeyHolder.Should().NotBeNull(
            "RFC 8555 §7.3.5 makes the 409 name the account holding the key, so the caller needs it");
        result.KeyHolder!.AccountId.Should().Be(holder.AccountId);

        account.JwkThumbprint.Should().Be(originalThumbprint,
            "a refused swap must not leave the caller's object claiming a key it never got");
        _db.Entry(account).State.Should().Be(EntityState.Unchanged,
            "a later save on the same context must not retry the refused swap");
        (await ReadThumbprintAsync(account.AccountId)).Should().Be(originalThumbprint);
        (await ReadThumbprintAsync(holder.AccountId)).Should().Be(holder.JwkThumbprint);
    }

    [Theory]
    [InlineData(5, 5, "SQLITE_BUSY")]
    [InlineData(6, 6, "SQLITE_LOCKED")]
    [InlineData(19, 1299, "SQLITE_CONSTRAINT_NOTNULL")]
    [InlineData(19, 787, "SQLITE_CONSTRAINT_FOREIGNKEY")]
    public async Task ChangeKey_SaveFailsForAnotherReason_PropagatesRatherThanReportingAConflict(
        int errorCode, int extendedErrorCode, string name)
    {
        // Issue #127. Before the fix every DbUpdateException became a conflict, so a transient
        // "database is locked" told the client its new key was already in use when it was not.
        // The holder is seeded to show that the presence of a holder is not what decides it:
        // the refusal has to come from the unique index for the answer to be a conflict.
        var account = await SeedAccountAsync("other-failure-a");
        await SeedAccountAsync("other-failure-b");
        _failures.FailNextUpdate(new SqliteException(
            $"SQLite Error {errorCode}: injected {name}.", errorCode, extendedErrorCode));

        var act = () => _sut.ChangeKeyAsync(account, Jwk("other-failure-b"));

        var thrown = await act.Should().ThrowAsync<DbUpdateException>(
            "a {0} failure says nothing about who holds the key", name);
        thrown.Which.InnerException.Should().BeOfType<SqliteException>()
            .Which.SqliteExtendedErrorCode.Should().Be(extendedErrorCode,
                "the failure the client sees must be the one the database reported");
    }

    [Fact]
    public async Task ChangeKey_UniqueViolationWithNoHolderToName_Propagates()
    {
        // A unique violation the holder lookup cannot explain has no account to put in the
        // Location header, and a 409 without one is the defect issue #127 closes. So it
        // propagates, which is what CreateAccountAsync does when its winner lookup misses.
        var account = await SeedAccountAsync("unexplained-a");
        _failures.FailNextUpdate(new SqliteException(
            "SQLite Error 19: 'UNIQUE constraint failed: AcmeAccounts.JwkThumbprint'.", 19, 2067));

        var act = () => _sut.ChangeKeyAsync(account, Jwk("unexplained-new"));

        await act.Should().ThrowAsync<DbUpdateException>();
    }

    private static string Jwk(string seed) =>
        $$"""{"kty":"RSA","n":"{{seed}}","e":"AQAB"}""";

    private async Task<AcmeAccount> SeedAccountAsync(string seed)
    {
        var jwk = Jwk(seed);
        var account = new AcmeAccount
        {
            AccountId = "key-change-" + seed,
            JwkJson = jwk,
            JwkThumbprint = JwsService.ComputeThumbprint(jwk),
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        _db.AcmeAccounts.Add(account);
        await _db.SaveChangesAsync();
        return account;
    }

    /// <summary>Reads a stored thumbprint on a fresh change tracker, so the answer is the row's.</summary>
    private async Task<string> ReadThumbprintAsync(string accountId)
    {
        await using var verify = new CertusDbContext(_dbOptions);
        return (await verify.AcmeAccounts.AsNoTracking().SingleAsync(a => a.AccountId == accountId))
            .JwkThumbprint;
    }

    /// <summary>
    /// Throws a given SqliteException in place of the next UPDATE, the way the driver throws
    /// one for a failure the engine reports. EF then wraps it in a DbUpdateException itself,
    /// so the service sees exactly the shape a real busy or locked database produces.
    /// </summary>
    private sealed class FailingUpdateInterceptor : DbCommandInterceptor
    {
        private SqliteException? _next;

        public void FailNextUpdate(SqliteException exception) =>
            Interlocked.Exchange(ref _next, exception);

        private void ThrowIfArmed(DbCommand command)
        {
            if (!command.CommandText.Contains("UPDATE ", StringComparison.Ordinal))
                return;
            var exception = Interlocked.Exchange(ref _next, null);
            if (exception != null)
                throw exception;
        }

        public override InterceptionResult<DbDataReader> ReaderExecuting(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
        {
            ThrowIfArmed(command);
            return result;
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData,
            InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            ThrowIfArmed(command);
            return ValueTask.FromResult(result);
        }

        public override InterceptionResult<int> NonQueryExecuting(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
        {
            ThrowIfArmed(command);
            return result;
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            ThrowIfArmed(command);
            return ValueTask.FromResult(result);
        }
    }
}
