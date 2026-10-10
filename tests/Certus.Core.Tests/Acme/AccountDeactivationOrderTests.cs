using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// What deactivating an account does to the orders underneath it. RFC 8555 §7.3.6
/// tells the server to cancel any pending operations authorized by the account's
/// key, and the question issue #312 settles is which of an account's orders still
/// count as pending operations this server can cancel.
/// </summary>
public class AccountDeactivationOrderTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CertusDbContext> _dbOptions;
    private readonly CertusDbContext _db;
    private readonly AccountService _sut;
    private readonly AcmeAccount _account;

    public AccountDeactivationOrderTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        // Kept as a field so an assertion can read the rows back on a fresh change
        // tracker, rather than on the one that wrote them.
        _dbOptions = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(_dbOptions);
        _db.Database.EnsureCreated();

        _sut = new AccountService(_db, NullLogger<AccountService>.Instance);

        _account = new AcmeAccount
        {
            AccountId = "deactivation-account-001",
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = "deactivation-thumbprint-001",
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        _db.AcmeAccounts.Add(_account);
        _db.SaveChanges();
    }

    [Fact]
    public async Task Deactivate_CancelsOpenOrdersButLeavesAClaimedOneAlone()
    {
        // Issue #312. A "processing" order has been claimed by a finalize and its
        // CSR is already at the CA, which has no idea this account just died. It is
        // therefore not a pending operation this server can still cancel, and
        // writing to it would collide with the completion: either the completion
        // overwrites this write and a client is told "invalid" for an order that
        // then reads "valid", or this write wins and leaves an "invalid" order
        // holding a live certificate.
        //
        // The count is the discriminator, and it is also the number the dashboard
        // shows the administrator, so it has to mean rows actually written.
        var pending = await SeedOrderAsync("pending");
        var ready = await SeedOrderAsync("ready");
        var claimed = await SeedOrderAsync("processing");
        var alreadyIssued = await SeedOrderAsync("valid");

        var result = await _sut.DeactivateAsync(
            _account.Id, AccountDeactivationOrigin.Dashboard);

        result.Outcome.Should().Be(AccountDeactivationOutcome.Deactivated);
        result.InvalidatedOrders.Should().Be(2, "only pending and ready orders are cancellable");

        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.SingleAsync(o => o.Id == pending.Id)).Status.Should().Be("invalid");
        (await verify.AcmeOrders.SingleAsync(o => o.Id == ready.Id)).Status.Should().Be("invalid");
        (await verify.AcmeOrders.SingleAsync(o => o.Id == claimed.Id))
            .Status.Should().Be("processing", "its CSR is at the CA and the finalize owns the outcome");
        (await verify.AcmeOrders.SingleAsync(o => o.Id == alreadyIssued.Id))
            .Status.Should().Be("valid");
        (await verify.AcmeAccounts.SingleAsync(a => a.Id == _account.Id))
            .Status.Should().Be("deactivated");
    }

    [Fact]
    public async Task Deactivate_WritesTheReasonOntoEveryOrderItInvalidates()
    {
        // Issue #320. RFC 8555 section 7.1.3 gives an order an error field for the
        // problem document that says why it became invalid, and this demoter wrote
        // the status alone. ToResponse projects that column since issue #330, but
        // not reachably on this path: a deactivated account is refused 401 on every
        // later kid authenticated request, before an order object is built. So here
        // the column stays a durable record, and these assertions and an operator
        // reading the row are what it is written for.
        var pending = await SeedOrderAsync("pending");
        var ready = await SeedOrderAsync("ready");
        var claimed = await SeedOrderAsync("processing");

        await _sut.DeactivateAsync(_account.Id, AccountDeactivationOrigin.Dashboard);

        await using var verify = new CertusDbContext(_dbOptions);
        foreach (var id in new[] { pending.Id, ready.Id })
        {
            var order = await verify.AcmeOrders.SingleAsync(o => o.Id == id);
            order.ErrorJson.Should().NotBeNull("an invalidated order says why it died");

            var error = JsonSerializer.Deserialize<AcmeError>(order.ErrorJson!);
            error!.Type.Should().Be(AcmeErrorType.Unauthorized,
                "the account that authorized this order no longer authorizes anything, " +
                "which is the same type the deactivated authorization path writes");
            error.Detail.Should().Contain("administrator",
                "an operator reading this row should not have to guess which " +
                "of the two origins cancelled the order");
        }

        (await verify.AcmeOrders.SingleAsync(o => o.Id == claimed.Id))
            .ErrorJson.Should().BeNull(
                "an order this deactivation did not touch carries no error either");
    }

    [Fact]
    public async Task Deactivate_ByTheClientItself_SaysSoRatherThanBlamingAnAdministrator()
    {
        // The same field, worded from the other origin. A client that retired its
        // own key (RFC 8555 section 7.3.6) should not read that an administrator
        // did it, and an administrator reading the log should not read the reverse.
        var ready = await SeedOrderAsync("ready");

        await _sut.DeactivateAsync(_account.Id, AccountDeactivationOrigin.AcmeClient);

        await using var verify = new CertusDbContext(_dbOptions);
        var order = await verify.AcmeOrders.SingleAsync(o => o.Id == ready.Id);
        var error = JsonSerializer.Deserialize<AcmeError>(order.ErrorJson!);

        error!.Type.Should().Be(AcmeErrorType.Unauthorized);
        error.Detail.Should().Contain("client's own request");
        error.Detail.Should().NotContain("administrator");
    }

    [Fact]
    public async Task Deactivate_OnAnAccountWithNoOpenOrders_ReportsNone()
    {
        await SeedOrderAsync("valid");

        var result = await _sut.DeactivateAsync(
            _account.Id, AccountDeactivationOrigin.AcmeClient);

        result.Outcome.Should().Be(AccountDeactivationOutcome.Deactivated);
        result.InvalidatedOrders.Should().Be(0);
    }

    private async Task<AcmeOrder> SeedOrderAsync(string status)
    {
        var order = new AcmeOrder
        {
            OrderId = $"order-{status}-{Guid.NewGuid():N}",
            AccountId = _account.Id,
            Status = status,
            TemplateId = "WebServer",
            IdentifiersJson = """[{"type":"dns","value":"example.com"}]""",
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };
        _db.AcmeOrders.Add(order);
        await _db.SaveChangesAsync();
        return order;
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }
}
