using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Unit tests for the dashboard account inventory query: the filter axes, the
/// sort keys, and the paging tiebreaker. The filters are independent by
/// design, so most of what is worth pinning here is how they combine and
/// where two of them deliberately disagree.
/// </summary>
public class AccountQueryServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly AccountService _sut;
    private readonly DateTime _now = DateTime.UtcNow;

    private EabCredential _active = null!;
    private EabCredential _revoked = null!;

    public AccountQueryServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _sut = new AccountService(_db, NullLogger<AccountService>.Instance);

        Seed();
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Four accounts covering every axis: bound and valid, bound to a revoked
    /// credential, unbound and valid (the grandfathered shape), and unbound
    /// and deactivated. Order history is seeded to separate "ordered
    /// recently", "ordered long ago", and "never ordered".
    /// </summary>
    private void Seed()
    {
        _active = new EabCredential
        {
            KeyId = "kid-active",
            Name = "Alpha Team",
            SecretProtected = "x",
            Status = "active",
            CreatedAt = _now.AddDays(-100),
        };
        _revoked = new EabCredential
        {
            KeyId = "kid-revoked",
            Name = "Zulu Team",
            SecretProtected = "x",
            Status = "revoked",
            CreatedAt = _now.AddDays(-100),
        };
        _db.EabCredentials.AddRange(_active, _revoked);
        _db.SaveChanges();

        // Distinct CreatedAt values so the default newest first order is
        // unambiguous; the tiebreaker gets its own test below.
        AddAccount("aaa-bound-recent", "valid", _active.Id, _now.AddDays(-40));
        AddAccount("bbb-orphaned", "valid", _revoked.Id, _now.AddDays(-30));
        AddAccount("ccc-grandfathered", "valid", null, _now.AddDays(-20));
        AddAccount("ddd-gone", "deactivated", null, _now.AddDays(-10));
        _db.SaveChanges();

        // aaa ordered two days ago, bbb ordered 120 days ago, ccc and ddd
        // have never ordered at all.
        AddOrder("aaa-bound-recent", _now.AddDays(-2));
        AddOrder("aaa-bound-recent", _now.AddDays(-200));
        AddOrder("bbb-orphaned", _now.AddDays(-120));
        _db.SaveChanges();
    }

    private void AddAccount(string accountId, string status, int? credentialId, DateTime createdAt)
    {
        _db.AcmeAccounts.Add(new AcmeAccount
        {
            AccountId = accountId,
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = $"thumb-{accountId}",
            ContactJson = $"""["mailto:{accountId}@example.com"]""",
            Status = status,
            ExternalAccountCredentialId = credentialId,
            CreatedAt = createdAt,
        });
    }

    private void AddOrder(string accountId, DateTime createdAt)
    {
        var account = _db.AcmeAccounts.Single(a => a.AccountId == accountId);
        _db.AcmeOrders.Add(new AcmeOrder
        {
            OrderId = $"order-{accountId}-{createdAt.Ticks}",
            AccountId = account.Id,
            TemplateId = "WebServer",
            IdentifiersJson = """[{"type":"dns","value":"test.example.com"}]""",
            Status = "valid",
            CreatedAt = createdAt,
        });
    }

    private async Task<List<string>> IdsAsync(AcmeAccountQuery query)
    {
        var page = await _sut.QueryAsync(query);
        return page.Items.Select(a => a.AccountId).ToList();
    }

    // ---- Envelope ----

    [Fact]
    public async Task Query_ReturnsThePagedEnvelopeWithTheUnpagedTotal()
    {
        var page = await _sut.QueryAsync(new AcmeAccountQuery(Take: 2));

        page.Items.Should().HaveCount(2);
        page.TotalCount.Should().Be(4, "the count is of the filtered set, not the page");
        page.Skip.Should().Be(0);
        page.Take.Should().Be(2);
        page.HasMore.Should().BeTrue();
    }

    [Fact]
    public async Task Query_DefaultOrder_IsNewestFirst()
    {
        var ids = await IdsAsync(new AcmeAccountQuery());

        ids.Should().Equal("ddd-gone", "ccc-grandfathered", "bbb-orphaned", "aaa-bound-recent");
    }

    // ---- Filter axes ----

    [Fact]
    public async Task Query_StatusAndBinding_CombineWithAnd()
    {
        // The whole reason status is a separate control: neither filter alone
        // isolates the grandfathered set, and a single combined dropdown
        // could not ask for both at once.
        (await IdsAsync(new AcmeAccountQuery(Status: AcmeAccountStatusFilter.Valid)))
            .Should().HaveCount(3);
        (await IdsAsync(new AcmeAccountQuery(Binding: AcmeAccountBindingFilter.Unbound)))
            .Should().HaveCount(2);

        (await IdsAsync(new AcmeAccountQuery(
            Status: AcmeAccountStatusFilter.Valid,
            Binding: AcmeAccountBindingFilter.Unbound)))
            .Should().Equal("ccc-grandfathered");
    }

    [Fact]
    public async Task Query_BoundToRevoked_FindsOnlyAccountsWhoseCredentialWasRevoked()
    {
        (await IdsAsync(new AcmeAccountQuery(Binding: AcmeAccountBindingFilter.BoundToRevoked)))
            .Should().Equal("bbb-orphaned");

        (await IdsAsync(new AcmeAccountQuery(Binding: AcmeAccountBindingFilter.Bound)))
            .Should().BeEquivalentTo(new[] { "aaa-bound-recent", "bbb-orphaned" },
                "revoked is a narrowing of bound, not a separate state");
    }

    [Fact]
    public async Task Query_CredentialId_FiltersToOneCredential()
    {
        (await IdsAsync(new AcmeAccountQuery(CredentialId: _active.Id)))
            .Should().Equal("aaa-bound-recent");

        (await IdsAsync(new AcmeAccountQuery(CredentialId: 99999)))
            .Should().BeEmpty("an unknown id is an empty page, never an error");
    }

    [Fact]
    public async Task Query_Search_MatchesAccountIdContactAndCredential()
    {
        (await IdsAsync(new AcmeAccountQuery(Search: "ccc-grand")))
            .Should().Equal("ccc-grandfathered");
        (await IdsAsync(new AcmeAccountQuery(Search: "ddd-gone@example.com")))
            .Should().Equal("ddd-gone");
        // The reason goes through the array overload: Equal on a string
        // collection is params string[], so a bare reason would read as one
        // more expected element.
        (await IdsAsync(new AcmeAccountQuery(Search: "alpha")))
            .Should().Equal(new[] { "aaa-bound-recent" },
                "search matches the bound credential name");
        (await IdsAsync(new AcmeAccountQuery(Search: "kid-revoked")))
            .Should().Equal(new[] { "bbb-orphaned" },
                "search matches the bound credential key id");
    }

    // ---- Activity, and where it disagrees with the last order range ----

    [Fact]
    public async Task Query_NeverOrdered_FindsOnlyAccountsWithNoOrdersAtAll()
    {
        (await IdsAsync(new AcmeAccountQuery(Activity: AcmeAccountActivityFilter.NeverOrdered)))
            .Should().BeEquivalentTo(new[] { "ccc-grandfathered", "ddd-gone" });
    }

    [Fact]
    public async Task Query_IdleWindow_IncludesAccountsThatNeverOrdered()
    {
        // An account with no orders has indeed not ordered in the last 90
        // days, so it belongs in the idle set. Losing this is the most likely
        // regression from someone "simplifying" the predicate into a Max.
        (await IdsAsync(new AcmeAccountQuery(Activity: AcmeAccountActivityFilter.IdleFor90Days)))
            .Should().BeEquivalentTo(new[] { "bbb-orphaned", "ccc-grandfathered", "ddd-gone" });

        (await IdsAsync(new AcmeAccountQuery(Activity: AcmeAccountActivityFilter.IdleFor180Days)))
            .Should().BeEquivalentTo(new[] { "ccc-grandfathered", "ddd-gone" },
                "bbb ordered 120 days ago, which is inside 180");
    }

    [Fact]
    public async Task Query_ActiveWindow_LooksAtTheNewestOrderNotTheOldest()
    {
        // aaa has an order from 200 days ago as well as one from 2 days ago.
        // An existence check over the window is what makes the old one
        // irrelevant.
        (await IdsAsync(new AcmeAccountQuery(Activity: AcmeAccountActivityFilter.ActiveWithin7Days)))
            .Should().Equal("aaa-bound-recent");
        (await IdsAsync(new AcmeAccountQuery(Activity: AcmeAccountActivityFilter.IdleFor30Days)))
            .Should().NotContain("aaa-bound-recent");
    }

    [Fact]
    public async Task Query_LastOrderBefore_ExcludesAccountsThatNeverOrdered()
    {
        // The counterpart of the idle test above, and the pair is the point:
        // a range filter on a date an account does not have must not match
        // it, while an idle window must. A null max compares false in SQL,
        // which is what makes this work; Any(o => o.CreatedAt < cutoff) would
        // instead wrongly match aaa on its 200 day old order.
        var ids = await IdsAsync(new AcmeAccountQuery(LastOrderBefore: _now.AddDays(-60)));

        ids.Should().Equal("bbb-orphaned");
        ids.Should().NotContain("ccc-grandfathered");
        ids.Should().NotContain("aaa-bound-recent");
    }

    [Fact]
    public async Task Query_LastOrderAfter_MatchesTheNewestOrder()
    {
        (await IdsAsync(new AcmeAccountQuery(LastOrderAfter: _now.AddDays(-7))))
            .Should().Equal("aaa-bound-recent");
    }

    // ---- Registered range ----

    [Fact]
    public async Task Query_RegisteredRange_IsInclusiveBelowAndExclusiveAbove()
    {
        (await IdsAsync(new AcmeAccountQuery(RegisteredAfter: _now.AddDays(-25))))
            .Should().BeEquivalentTo(new[] { "ccc-grandfathered", "ddd-gone" });

        (await IdsAsync(new AcmeAccountQuery(RegisteredBefore: _now.AddDays(-25))))
            .Should().BeEquivalentTo(new[] { "aaa-bound-recent", "bbb-orphaned" });

        (await IdsAsync(new AcmeAccountQuery(
            RegisteredAfter: _now.AddDays(-35),
            RegisteredBefore: _now.AddDays(-15))))
            .Should().BeEquivalentTo(new[] { "bbb-orphaned", "ccc-grandfathered" });
    }

    // ---- Sorting ----

    [Theory]
    [InlineData("accountId")]
    [InlineData("status")]
    [InlineData("createdAt")]
    public async Task Query_SortKey_ReversesWithSortDesc(string sortBy)
    {
        var ascending = await IdsAsync(new AcmeAccountQuery(SortBy: sortBy));
        var descending = await IdsAsync(new AcmeAccountQuery(SortBy: sortBy, SortDesc: true));

        ascending.Should().HaveCount(4);
        descending.Should().BeEquivalentTo(ascending, "the same rows, in the other order");
        descending.Should().NotEqual(ascending);
    }

    [Fact]
    public async Task Query_SortByAccountId_OrdersAlphabetically()
    {
        (await IdsAsync(new AcmeAccountQuery(SortBy: "accountId")))
            .Should().Equal("aaa-bound-recent", "bbb-orphaned", "ccc-grandfathered", "ddd-gone");
    }

    [Fact]
    public async Task Query_SortByCredential_PutsUnboundFirstAscendingAndLastDescending()
    {
        // The credential sort is a left join through a nullable navigation,
        // and SQLite emits no NULLS FIRST/LAST clause, so the unbound
        // accounts land at whichever end nulls sort to.
        var ascending = await IdsAsync(new AcmeAccountQuery(SortBy: "credential"));
        ascending.Take(2).Should().BeEquivalentTo(new[] { "ccc-grandfathered", "ddd-gone" });
        ascending.Skip(2).Should().Equal("aaa-bound-recent", "bbb-orphaned");

        var descending = await IdsAsync(new AcmeAccountQuery(SortBy: "credential", SortDesc: true));
        descending.Take(2).Should().Equal("bbb-orphaned", "aaa-bound-recent");
        descending.Skip(2).Should().BeEquivalentTo(new[] { "ccc-grandfathered", "ddd-gone" });
    }

    [Fact]
    public async Task Query_UnknownSortKey_FallsThroughToTheDefaultSilently()
    {
        // Deliberately not an error, unlike an unknown filter name: a sort
        // that quietly uses the default cannot misrepresent which rows are in
        // the list, where a filter that quietly matched everything would.
        (await IdsAsync(new AcmeAccountQuery(SortBy: "ordersCount")))
            .Should().Equal(await IdsAsync(new AcmeAccountQuery()));
    }

    [Fact]
    public async Task Query_TiesBreakOnIdAscendingInBothDirections()
    {
        // Every account below shares one CreatedAt, so the primary key gives
        // no order at all and only the tiebreaker decides. Without it a
        // Skip/Take page boundary could repeat or drop a row.
        var shared = _now.AddDays(-500);
        for (var i = 0; i < 5; i++)
            AddAccount($"tied-{i}", "valid", null, shared);
        await _db.SaveChangesAsync();

        var ascending = await _sut.QueryAsync(new AcmeAccountQuery(
            Search: "tied-", SortBy: "createdAt"));
        var descending = await _sut.QueryAsync(new AcmeAccountQuery(
            Search: "tied-", SortBy: "createdAt", SortDesc: true));

        ascending.Items.Select(a => a.Id).Should().BeInAscendingOrder();
        descending.Items.Select(a => a.Id).Should().BeInAscendingOrder(
            "the tiebreak is ascending regardless of the primary direction");
    }

    [Fact]
    public async Task Query_Pagination_WithDuplicateSortKeys_IsStableAndComplete()
    {
        var shared = _now.AddDays(-500);
        for (var i = 0; i < 6; i++)
            AddAccount($"tied-{i}", "valid", null, shared);
        await _db.SaveChangesAsync();

        var seen = new List<int>();
        for (var skip = 0; skip < 6; skip += 2)
        {
            var page = await _sut.QueryAsync(new AcmeAccountQuery(
                Search: "tied-", SortBy: "createdAt", Skip: skip, Take: 2));
            seen.AddRange(page.Items.Select(a => a.Id));
        }

        seen.Should().HaveCount(6);
        seen.Should().OnlyHaveUniqueItems("no row may repeat across a page boundary");
    }

    // ---- Row projection ----

    [Fact]
    public async Task Query_Row_CarriesTheOrderCountAndTheNewestOrderDate()
    {
        var page = await _sut.QueryAsync(new AcmeAccountQuery(Search: "aaa-bound-recent"));

        var row = page.Items.Single();
        row.OrdersCount.Should().Be(2);
        row.LastOrderAt.Should().NotBeNull();
        row.LastOrderAt!.Value.Should().BeCloseTo(_now.AddDays(-2), TimeSpan.FromSeconds(5),
            "the newest order, not the oldest");
        row.Contacts.Should().Equal("mailto:aaa-bound-recent@example.com");
        row.Credential!.Name.Should().Be("Alpha Team");
    }

    [Fact]
    public async Task Query_Row_ForAnAccountWithNoOrders_HasNoLastOrderDate()
    {
        var page = await _sut.QueryAsync(new AcmeAccountQuery(Search: "ccc-grandfathered"));

        var row = page.Items.Single();
        row.OrdersCount.Should().Be(0);
        row.LastOrderAt.Should().BeNull();
        row.Credential.Should().BeNull();
    }

    // ---- Filter name parsing ----

    [Theory]
    [InlineData(null, AcmeAccountBindingFilter.All)]
    [InlineData("", AcmeAccountBindingFilter.All)]
    [InlineData("all", AcmeAccountBindingFilter.All)]
    [InlineData("Bound", AcmeAccountBindingFilter.Bound)]
    [InlineData("boundtorevoked", AcmeAccountBindingFilter.BoundToRevoked)]
    public void ParseBinding_AcceptsTheVocabularyCaseInsensitively(
        string? input, AcmeAccountBindingFilter expected)
    {
        AccountService.ParseBinding(input).Should().Be(expected);
    }

    [Theory]
    [InlineData("sideways")]
    [InlineData("revoked")]
    public void ParseBinding_RejectsAnythingElse(string input)
    {
        AccountService.ParseBinding(input).Should().BeNull();
    }

    [Fact]
    public void ParseStatus_OffersOnlyTheTwoValuesAnythingWrites()
    {
        AccountService.ParseStatus(null).Should().Be(AcmeAccountStatusFilter.All);
        AccountService.ParseStatus("valid").Should().Be(AcmeAccountStatusFilter.Valid);
        AccountService.ParseStatus("deactivated").Should().Be(AcmeAccountStatusFilter.Deactivated);

        // RFC 8555 defines it, but nothing in this product ever writes it, so
        // the filter refuses it rather than offering a control that could
        // only return an empty list.
        AccountService.ParseStatus("revoked").Should().BeNull();
    }

    [Theory]
    [InlineData("any", AcmeAccountActivityFilter.Any)]
    [InlineData("never", AcmeAccountActivityFilter.NeverOrdered)]
    [InlineData("idle30", AcmeAccountActivityFilter.IdleFor30Days)]
    [InlineData("idle90", AcmeAccountActivityFilter.IdleFor90Days)]
    [InlineData("idle180", AcmeAccountActivityFilter.IdleFor180Days)]
    [InlineData("active7", AcmeAccountActivityFilter.ActiveWithin7Days)]
    [InlineData("active30", AcmeAccountActivityFilter.ActiveWithin30Days)]
    public void ParseActivity_AcceptsEveryNameTheDropdownSends(
        string input, AcmeAccountActivityFilter expected)
    {
        AccountService.ParseActivity(input).Should().Be(expected);
    }

    [Fact]
    public void ParseActivity_RejectsAnythingElse()
    {
        AccountService.ParseActivity("idle45").Should().BeNull();
        AccountService.ParseActivity("sometimes").Should().BeNull();
    }
}
