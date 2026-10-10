using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Services;

public class CertificateQueryServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly CertificateQueryService _sut;

    public CertificateQueryServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _sut = CreateSut();

        // Seed test data
        SeedTestCertificates();
    }

    /// <summary>
    /// Builds the service over a given set of alert thresholds, normalized the
    /// way both hosts do at startup. Passing none yields the default install
    /// (30, 14, 7, 1), so the widest window is 30. Issue #152.
    /// </summary>
    private CertificateQueryService CreateSut(params int[] thresholdDays)
    {
        var alerts = new AlertOptions { ThresholdDays = thresholdDays };
        alerts.NormalizeThresholdDays();
        return new CertificateQueryService(
            _db, NullLogger<CertificateQueryService>.Instance, Options.Create(alerts),
            BuildEligibilityService());
    }

    /// <summary>
    /// A real eligibility service over a data directory that does not exist:
    /// the scope policy reads the missing status file as the ducks-managed
    /// default with empty sets, which is fine here because these tests
    /// assert on query shapes, not on revocation eligibility.
    /// </summary>
    private RevocationEligibilityService BuildEligibilityService()
    {
        var options = new CertusOptions
        {
            DatabasePath = Path.Combine(
                Path.GetTempPath(), $"certus-missing-{Guid.NewGuid():N}", "certus.db"),
        };
        var enabledTemplates = new EnabledTemplatesPolicy(
            Options.Create(options), Options.Create(new AcmeOptions()),
            NullLogger<EnabledTemplatesPolicy>.Instance);
        return new RevocationEligibilityService(
            _db,
            new TemplateService(new MockAdcsClient(), enabledTemplates,
                NullLogger<TemplateService>.Instance),
            new RevocationScopePolicy(
                Options.Create(options), NullLogger<RevocationScopePolicy>.Instance),
            NullLogger<RevocationEligibilityService>.Instance);
    }

    [Fact]
    public async Task Query_NoFilters_ReturnsAll()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery());

        result.TotalCount.Should().Be(6);
        result.Items.Should().HaveCount(6);
    }

    [Fact]
    public async Task Query_SearchBySubject_FiltersResults()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "web-server"));

        result.TotalCount.Should().Be(1);
        result.Items[0].Subject.Should().Contain("web-server");
    }

    [Fact]
    public async Task Query_FilterByTemplate_ReturnsOnlyMatching()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(TemplateName: "WebServer"));

        result.TotalCount.Should().Be(3);
        result.Items.Should().OnlyContain(c => c.TemplateName == "WebServer");
    }

    [Fact]
    public async Task Query_FilterByStatus_ReturnsOnlyMatching()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Status: "Revoked"));

        result.TotalCount.Should().Be(2);
        result.Items.Should().OnlyContain(c => c.Status == "Revoked");
    }

    [Fact]
    public async Task Query_ExpiringBefore_ReturnsExpiringSoon()
    {
        var cutoff = DateTime.UtcNow.AddDays(15);
        var result = await _sut.QueryAsync(
            new CertificateSearchQuery(ExpiringBefore: cutoff));

        // Should return certs expiring within 15 days
        result.Items.Should().OnlyContain(c => c.NotAfter <= cutoff);
    }

    // ── Lifecycle state chips (issue #155) ───────────────────────────────────
    //
    // The seed holds, against the default 30 day window: two valid issued certs
    // (+335d, +275d), one expiring issued cert (+10d), one expired issued cert
    // (-35d), and two revoked certs, one still inside its validity (+185d) and
    // one long past it (-60d).

    [Fact]
    public async Task Query_StateValid_ReturnsOnlyIssuedBeyondTheWarningWindow()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(State: "valid"));

        result.TotalCount.Should().Be(2);
        result.Items.Should().OnlyContain(c => c.Status == "Issued");
        result.Items.Should().OnlyContain(c => c.NotAfter > DateTime.UtcNow.AddDays(30));
    }

    [Fact]
    public async Task Query_StateExpiring_ReturnsOnlyIssuedInsideTheWarningWindow()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(State: "expiring"));

        result.TotalCount.Should().Be(1);
        result.Items[0].SerialNumber.Should().Be("SERIAL002");
    }

    [Fact]
    public async Task Query_StateExpired_ExcludesRevokedCertificates()
    {
        // The whole point of the state parameter. Two certificates are past
        // their NotAfter, but one of them is revoked: a revoked certificate is
        // reported as revoked, not counted a second time as expired. Filtering
        // on the expiry date alone would return both and disagree with the
        // Expired stat card.
        var result = await _sut.QueryAsync(new CertificateSearchQuery(State: "expired"));

        result.TotalCount.Should().Be(1);
        result.Items[0].SerialNumber.Should().Be("SERIAL004");
        result.Items.Should().NotContain(c => c.SerialNumber == "SERIAL008");
    }

    [Fact]
    public async Task Query_StateRevoked_ReturnsRevokedWhateverTheirExpiry()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(State: "revoked"));

        result.TotalCount.Should().Be(2);
        result.Items.Should().OnlyContain(c => c.Status == "Revoked");
    }

    [Fact]
    public async Task Query_StateExpiring_WidensWithTheOperatorsThreshold()
    {
        // Proves the window comes from AlertOptions and not a literal 30. At 30
        // days only the +10d certificate is expiring; at 300 the two certificates
        // at +275d and +335d split, and +275d joins it.
        var wide = CreateSut(300);

        var narrow = await _sut.QueryAsync(new CertificateSearchQuery(State: "expiring"));
        var widened = await wide.QueryAsync(new CertificateSearchQuery(State: "expiring"));

        narrow.TotalCount.Should().Be(1);
        widened.TotalCount.Should().Be(2);
        widened.Items.Should().Contain(c => c.SerialNumber == "SERIAL003");
    }

    [Fact]
    public async Task Query_StatesPartitionTheIssuedCertificates()
    {
        // valid + expiring + expired covers every issued certificate exactly
        // once, and revoked covers the rest. This is what keeps the four
        // dashboard cards and the four list chips in agreement: they are the
        // same predicates, so the counts cannot drift.
        var stats = await _sut.GetStatsAsync();

        var valid = await _sut.QueryAsync(new CertificateSearchQuery(State: "valid"));
        var expiring = await _sut.QueryAsync(new CertificateSearchQuery(State: "expiring"));
        var expired = await _sut.QueryAsync(new CertificateSearchQuery(State: "expired"));
        var revoked = await _sut.QueryAsync(new CertificateSearchQuery(State: "revoked"));

        (valid.TotalCount + expiring.TotalCount + expired.TotalCount)
            .Should().Be(stats.IssuedCertificates);
        revoked.TotalCount.Should().Be(stats.RevokedCertificates);

        // And each chip returns exactly the number its card shows.
        expiring.TotalCount.Should().Be(stats.ExpiringSoon);
        expired.TotalCount.Should().Be(stats.Expired);
    }

    [Fact]
    public async Task Query_StateComposesWithTemplateAndSearch()
    {
        var byTemplate = await _sut.QueryAsync(
            new CertificateSearchQuery(State: "valid", TemplateName: "InternalServer"));
        var bySearch = await _sut.QueryAsync(
            new CertificateSearchQuery(State: "valid", Search: "db-server"));

        byTemplate.TotalCount.Should().Be(1);
        byTemplate.Items[0].SerialNumber.Should().Be("SERIAL003");
        bySearch.TotalCount.Should().Be(1);
        bySearch.Items[0].SerialNumber.Should().Be("SERIAL003");
    }

    [Theory]
    [InlineData("VALID")]
    [InlineData("Expiring")]
    [InlineData("eXpIrEd")]
    public async Task Query_StateIsCaseInsensitive(string state)
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(State: state));

        result.TotalCount.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Query_UnknownState_ReturnsNothingRatherThanEverything()
    {
        // The API rejects unknown names before they reach the service, so this
        // only happens on an internal typo. Returning the whole inventory would
        // look like a valid answer to a question about expiry.
        var result = await _sut.QueryAsync(new CertificateSearchQuery(State: "lapsed"));

        result.TotalCount.Should().Be(0);
    }

    [Theory]
    [InlineData("valid", true)]
    [InlineData("expiring", true)]
    [InlineData("expired", true)]
    [InlineData("revoked", true)]
    [InlineData("Expired", true)]
    [InlineData("lapsed", false)]
    [InlineData("issued", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsKnownState_MatchesTheStatesTheQueryCanApply(string? state, bool known)
    {
        CertificateQueryService.IsKnownState(state).Should().Be(known);
    }

    [Fact]
    public async Task Query_Pagination_RespectsSkipAndTake()
    {
        var page1 = await _sut.QueryAsync(new CertificateSearchQuery(Skip: 0, Take: 2));
        var page2 = await _sut.QueryAsync(new CertificateSearchQuery(Skip: 2, Take: 2));

        page1.Items.Should().HaveCount(2);
        page2.Items.Should().HaveCount(2);
        page1.TotalCount.Should().Be(6);
        page1.HasMore.Should().BeTrue();

        // Pages should not overlap
        page1.Items.Select(c => c.Id).Should()
            .NotIntersectWith(page2.Items.Select(c => c.Id));
    }

    [Fact]
    public async Task Query_Pagination_WithDuplicateSortKeys_IsStableAndComplete()
    {
        // Seed several certs that all share one primary sort key (NotAfter), under a
        // unique template so the test can isolate them. Without a deterministic
        // tiebreaker, paging over equal sort keys could repeat or drop rows.
        var sameExpiry = DateTime.UtcNow.AddDays(500);
        for (var i = 0; i < 6; i++)
        {
            _db.SyncedCertificates.Add(new SyncedCertificate
            {
                RequestId = 1000 + i,
                SerialNumber = $"TIE{i:D3}",
                Subject = $"CN=tie-{i}.example.com",
                TemplateName = "TieBreaker",
                NotBefore = DateTime.UtcNow,
                NotAfter = sameExpiry,
                Status = "Issued",
                RequestDate = DateTime.UtcNow
            });
        }
        await _db.SaveChangesAsync();

        var seen = new List<int>();
        for (var skip = 0; skip < 6; skip += 2)
        {
            var page = await _sut.QueryAsync(
                new CertificateSearchQuery(TemplateName: "TieBreaker", Skip: skip, Take: 2));
            seen.AddRange(page.Items.Select(c => c.Id));
        }

        // Every row appears exactly once across the pages (no repeats, no drops),
        // and the Id tiebreaker yields a stable ascending order.
        seen.Should().HaveCount(6);
        seen.Should().OnlyHaveUniqueItems();
        seen.Should().BeInAscendingOrder();
    }

    [Fact]
    public async Task Query_SortBySubject_OrdersCorrectly()
    {
        var result = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "subject", SortDesc: false));

        var subjects = result.Items.Select(c => c.Subject).ToList();
        subjects.Should().BeInAscendingOrder();
    }

    [Fact]
    public async Task Query_SortByExpiry_DefaultOrder()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery());

        var expiries = result.Items.Select(c => c.NotAfter).ToList();
        expiries.Should().BeInAscendingOrder();
    }

    [Fact]
    public async Task Query_SortByRequestor_OrdersAscending()
    {
        var result = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "requestor"));

        var requestors = result.Items.Select(c => c.Requestor).ToList();
        requestors.Should().BeInAscendingOrder();
    }

    [Fact]
    public async Task Query_SortByRequestor_OrdersDescending()
    {
        var result = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "requestor", SortDesc: true));

        var requestors = result.Items.Select(c => c.Requestor).ToList();
        requestors.Should().BeInDescendingOrder();
    }

    // The seed gives three certificates the requestor "admin". ThenBy(c => c.Id)
    // is ascending whichever way the primary key sorts, so a descending sort is
    // not the reverse of the ascending one: inside an equal requester group the
    // ids still climb. That is what stops Skip/Take paging repeating or dropping
    // a row, and it is the property issue #156 asks any new sort to preserve.
    [Fact]
    public async Task Query_SortByRequestor_TiesBreakOnIdAscendingInBothDirections()
    {
        var ascending = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "requestor"));
        var descending = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "requestor", SortDesc: true));

        foreach (var page in new[] { ascending, descending })
        {
            var tiedIds = page.Items
                .Where(c => c.Requestor == "admin")
                .Select(c => c.Id)
                .ToList();

            tiedIds.Should().HaveCount(3);
            tiedIds.Should().BeInAscendingOrder();
        }
    }

    // A blank requester is real rather than hypothetical: AdcsClient reads the
    // column with GetValueOrDefault, so it is null whenever the CA view does not
    // return RequesterName. SQLite sorts NULL below every value and the EF SQLite
    // provider emits no NULLS FIRST or NULLS LAST clause, so those rows head the
    // list ascending and tail it descending. The list renders them as an em dash.
    [Fact]
    public async Task Query_SortByRequestor_MissingRequesterSortsFirstAscendingAndLastDescending()
    {
        var now = DateTime.UtcNow;
        _db.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 900,
            SerialNumber = "SERIAL900",
            Subject = "CN=no-requester.example.com",
            TemplateName = "WebServer",
            NotBefore = now.AddDays(-5),
            NotAfter = now.AddDays(360),
            Status = "Issued",
            Requestor = null,
            RequestDate = now.AddDays(-5)
        });
        await _db.SaveChangesAsync();

        var ascending = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "requestor"));
        var descending = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "requestor", SortDesc: true));

        ascending.Items.First().Requestor.Should().BeNull();
        descending.Items.Last().Requestor.Should().BeNull();
    }

    // The Expires column sends "notAfter", which matched no case and sorted
    // correctly only because the fallback arm happened to be NotAfter as well.
    // The key now has a case of its own, so this pins both that it still agrees
    // with the fallback and that the ToLower normalisation keeps accepting the
    // camelCase spelling the frontend actually puts on the wire (issue #156).
    [Fact]
    public async Task Query_SortByNotAfter_MatchesTheDefaultOrder()
    {
        var explicitAscending = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "notAfter"));
        var defaultAscending = await _sut.QueryAsync(
            new CertificateSearchQuery());

        explicitAscending.Items.Select(c => c.Id).ToList()
            .Should().Equal(defaultAscending.Items.Select(c => c.Id).ToList());

        var explicitDescending = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "notAfter", SortDesc: true));
        var defaultDescending = await _sut.QueryAsync(
            new CertificateSearchQuery(SortDesc: true));

        explicitDescending.Items.Select(c => c.Id).ToList()
            .Should().Equal(defaultDescending.Items.Select(c => c.Id).ToList());
    }

    // The Issued column made the notbefore arm UI reachable; these pin the
    // ordering the same way the requestor tests above do.
    [Fact]
    public async Task Query_SortByNotBefore_OrdersAscending()
    {
        var result = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "notBefore"));

        var notBefores = result.Items.Select(c => c.NotBefore).ToList();
        notBefores.Should().BeInAscendingOrder();
    }

    [Fact]
    public async Task Query_SortByNotBefore_OrdersDescending()
    {
        var result = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "notBefore", SortDesc: true));

        var notBefores = result.Items.Select(c => c.NotBefore).ToList();
        notBefores.Should().BeInDescendingOrder();
    }

    [Fact]
    public async Task GetDetail_Existing_ReturnsCert()
    {
        var all = await _db.SyncedCertificates.FirstAsync();

        var cert = await _sut.GetDetailByIdAsync(all.Id);

        cert.Should().NotBeNull();
        cert!.Id.Should().Be(all.Id);
        cert.FirstSyncedAt.Should().Be(all.FirstSyncedAt);
        cert.LastSyncedAt.Should().Be(all.LastSyncedAt);
    }

    [Fact]
    public async Task GetDetail_NonExistent_ReturnsNull()
    {
        var cert = await _sut.GetDetailByIdAsync(99999);
        cert.Should().BeNull();
    }

    [Fact]
    public async Task GetStats_ReturnsAccurateCounts()
    {
        var stats = await _sut.GetStatsAsync();

        stats.TotalCertificates.Should().Be(6);
        stats.IssuedCertificates.Should().Be(4); // 4 with "Issued" status
        stats.RevokedCertificates.Should().Be(2);
    }

    // ── "Expiring soon" is the operator's widest alert threshold (issue #152) ──
    // The seeded issued certificates expire in 335, 10, and 275 days, plus one
    // that expired 35 days ago; the two revoked rows (185 days, and 60 days ago)
    // are never counted.

    [Fact]
    public async Task GetStats_DefaultThresholds_CountsOnlyTheThirtyDayWindow()
    {
        var stats = await _sut.GetStatsAsync();

        // Unchanged behaviour on a default install: only the 10 day certificate.
        stats.ExpiringSoon.Should().Be(1);
    }

    [Fact]
    public async Task GetStats_WiderThreshold_WidensTheExpiringSoonCount()
    {
        var sut = CreateSut(300, 30, 7);

        var stats = await sut.GetStatsAsync();

        // 10 and 275 days are inside a 300 day window; 335 is not, the expired
        // one is counted as expired rather than expiring, and revoked is excluded.
        stats.ExpiringSoon.Should().Be(2);
    }

    [Fact]
    public async Task GetStats_AlertingDisabled_StillHonoursTheConfiguredThreshold()
    {
        // Enabled is deliberately not consulted. An operator who wrote 300 keeps
        // 300 with delivery switched off, rather than silently getting 30 back;
        // an install that configured nothing normalizes to 30 regardless, which
        // is what makes the default path safe without a second rule.
        var alerts = new AlertOptions { Enabled = false, ThresholdDays = [300] };
        alerts.NormalizeThresholdDays();
        var sut = new CertificateQueryService(
            _db, NullLogger<CertificateQueryService>.Instance, Options.Create(alerts),
            BuildEligibilityService());

        var stats = await sut.GetStatsAsync();

        stats.ExpiringSoon.Should().Be(2);
    }

    [Fact]
    public async Task Query_RevokedRow_CarriesRevocationFields()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL005"));

        var revoked = result.Items.Should().ContainSingle().Subject;
        revoked.RevokedAt.Should().NotBeNull();
        revoked.RevokedReason.Should().Be(4); // Superseded
    }

    [Fact]
    public async Task Query_IssuedRow_HasNullRevocationFields()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL001"));

        var issued = result.Items.Should().ContainSingle().Subject;
        issued.RevokedAt.Should().BeNull();
        issued.RevokedReason.Should().BeNull();
    }

    // ── Request rows (issue #151) ───────────────────────────────────────

    [Fact]
    public async Task Query_Unfiltered_ExcludesRequestRows()
    {
        // Pending, denied, and failed rows carry no certificate: no serial, no
        // subject from the CA, and a placeholder expiry. On the default expiry
        // sort they would take the whole first page and bury the real
        // certificates, so the unfiltered inventory leaves them out.
        var result = await _sut.QueryAsync(new CertificateSearchQuery());

        result.Items.Should().OnlyContain(c => c.Status == "Issued" || c.Status == "Revoked");
        result.TotalCount.Should().Be(6);
    }

    [Theory]
    [InlineData("Pending", 6)]
    [InlineData("Denied", 7)]
    public async Task Query_ExplicitStatusFilter_ReachesRequestRows(string status, int requestId)
    {
        // The status filter is how an admin reaches these rows. The dropdown has
        // always offered Pending, Denied, and Failed; before this change all
        // three returned nothing.
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Status: status));

        var row = result.Items.Should().ContainSingle().Subject;
        row.RequestId.Should().Be(requestId);

        // The message itself is detail endpoint only, so the list row is the
        // route to it rather than the carrier of it.
        var detail = await _sut.GetDetailByIdAsync(row.Id);
        detail!.DispositionMessage.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Query_NeverCarriesTheCaDispositionMessage()
    {
        // Mirrors the crypto detail boundary from #150: CertificateDetail derives
        // from CertificateSummary, so the list projection structurally cannot
        // carry these, and this test is what keeps that true. Here the reason is
        // not the paid tier line but the payload: the message is CA authored text
        // partly influenced by whoever submitted the request, and only the detail
        // page renders it.
        typeof(CertificateSummary).GetProperty(nameof(CertificateDetail.DispositionMessage))
            .Should().BeNull("the CA's disposition message must not reach the list endpoint");
        typeof(CertificateSummary).GetProperty(nameof(CertificateDetail.StatusCode))
            .Should().BeNull("the CA's status code must not reach the list endpoint");
    }

    [Fact]
    public void Supersession_IsAnAnnotationAndNeverAFilterSortKeyOrAggregate()
    {
        // Issue #154. SupersededById is the one field that deliberately sits on
        // CertificateSummary rather than below the CertificateDetail boundary,
        // because a list row has to be badged and a page of 25 rows cannot work
        // the answer out for itself. What keeps that from becoming a breach is
        // the rest of this test: the moment supersession is something you can
        // filter, sort, or count by, it has stopped being a per row annotation
        // and become the fleet wide inventory reporting the paid tier is. The
        // prose comment on the property says so; this is what makes it true.
        typeof(CertificateSearchQuery).GetProperties()
            .Should().NotContain(
                p => p.Name.Contains("Supersed", StringComparison.OrdinalIgnoreCase),
                "supersession must not become a query filter");

        typeof(CertificateStats).GetProperties()
            .Should().NotContain(
                p => p.Name.Contains("Supersed", StringComparison.OrdinalIgnoreCase),
                "supersession must not become a dashboard aggregate");

        // The resolved ends stay detail only; only the bare id reaches the list.
        typeof(CertificateSummary).GetProperty(nameof(CertificateDetail.SupersededBy))
            .Should().BeNull("the resolved successor is detail endpoint only");
        typeof(CertificateSummary).GetProperty(nameof(CertificateDetail.Supersedes))
            .Should().BeNull("the resolved predecessors are detail endpoint only");
    }

    [Fact]
    public async Task Query_SortBySupersession_IsNotASortKey()
    {
        // Asking to sort by it is not an error, it simply is not a sort key: the
        // switch falls through to the default expiry order. Behavioural half of
        // the boundary above, so adding a case to that switch breaks a test
        // rather than quietly shipping.
        var bySupersession = await _sut.QueryAsync(
            new CertificateSearchQuery(SortBy: "supersededById"));
        var byDefault = await _sut.QueryAsync(new CertificateSearchQuery());

        bySupersession.Items.Select(c => c.Id)
            .Should().Equal(byDefault.Items.Select(c => c.Id));
    }

    [Fact]
    public async Task Query_SearchDoesNotResurrectRequestRows()
    {
        // A search still runs inside the certificate inventory. Reaching a
        // request row is a deliberate act via the status filter, not something
        // a subject search stumbles into.
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "refused"));

        result.TotalCount.Should().Be(0);
    }

    [Fact]
    public async Task GetDetail_DeniedRequest_CarriesTheCaExplanation()
    {
        var denied = await _db.SyncedCertificates.SingleAsync(c => c.RequestId == 7);

        var detail = await _sut.GetDetailByIdAsync(denied.Id);

        detail.Should().NotBeNull();
        detail!.Status.Should().Be("Denied");
        detail.DispositionMessage.Should().Be("Denied by HOME\\admin");
        detail.StatusCode.Should().Be(unchecked((int)0x80094801));
    }

    [Fact]
    public async Task GetDetail_IssuedCertificate_HasNoDispositionFields()
    {
        var issued = await _db.SyncedCertificates.SingleAsync(c => c.RequestId == 1);

        var detail = await _sut.GetDetailByIdAsync(issued.Id);

        detail.Should().NotBeNull();
        detail!.DispositionMessage.Should().BeNull();
        detail.StatusCode.Should().BeNull();
    }

    [Fact]
    public async Task GetStats_TotalMatchesTheUnfilteredList()
    {
        // The stat card sits directly above the list. If the total counted
        // request rows the list hides, the two would contradict each other on
        // screen.
        var stats = await _sut.GetStatsAsync();
        var list = await _sut.QueryAsync(new CertificateSearchQuery());

        stats.TotalCertificates.Should().Be(list.TotalCount);
    }

    [Fact]
    public async Task Query_AcmeLinkedCertificate_CarriesContactEmail()
    {
        await SeedAcmeChainAsync(adcsRequestId: 1, contactJson: "[\"mailto:ops@example.com\"]");

        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL001"));

        result.Items.Should().ContainSingle()
            .Which.AcmeContactEmail.Should().Be("ops@example.com");
    }

    [Fact]
    public async Task Query_NoAcmeLinkage_ContactEmailIsNull()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL001"));

        result.Items.Should().ContainSingle()
            .Which.AcmeContactEmail.Should().BeNull();
    }

    [Fact]
    public async Task Query_AccountWithoutMailtoContact_ContactEmailIsNull()
    {
        await SeedAcmeChainAsync(adcsRequestId: 1, contactJson: "[\"tel:+15551234567\"]");

        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL001"));

        result.Items.Should().ContainSingle()
            .Which.AcmeContactEmail.Should().BeNull();
    }

    [Fact]
    public async Task GetDetail_AcmeLinkedCertificate_CarriesContactEmail()
    {
        await SeedAcmeChainAsync(adcsRequestId: 1, contactJson: "[\"mailto:ops@example.com\"]");
        var entity = await _db.SyncedCertificates.FirstAsync(c => c.RequestId == 1);

        var detail = await _sut.GetDetailByIdAsync(entity.Id);

        detail.Should().NotBeNull();
        detail!.AcmeContactEmail.Should().Be("ops@example.com");
    }

    [Fact]
    public async Task Query_AcmeLinkedCertificate_IsFlaggedIssuedByAcme()
    {
        await SeedAcmeChainAsync(adcsRequestId: 1, contactJson: "[\"mailto:ops@example.com\"]");

        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL001"));

        result.Items.Should().ContainSingle()
            .Which.IssuedByAcme.Should().BeTrue();
    }

    [Fact]
    public async Task Query_NoAcmeLinkage_IsNotFlaggedIssuedByAcme()
    {
        // A certificate the sync discovered in the CA database and Ducks never
        // issued: auto enrolment, the Certification Authority console, or a
        // person with certreq. Nothing in Ducks will renew it.
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL001"));

        result.Items.Should().ContainSingle()
            .Which.IssuedByAcme.Should().BeFalse();
    }

    [Fact]
    public async Task Query_AccountWithoutMailtoContact_IsStillFlaggedIssuedByAcme()
    {
        // The flag is not the contact email in disguise. The email resolves
        // through the ACME account's contact list, so it is null here, on a
        // certificate Ducks demonstrably did issue. Collapsing the flag into a
        // null check on the email would label this row manual.
        await SeedAcmeChainAsync(adcsRequestId: 1, contactJson: "[\"tel:+15551234567\"]");

        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL001"));

        var summary = result.Items.Should().ContainSingle().Subject;
        summary.AcmeContactEmail.Should().BeNull();
        summary.IssuedByAcme.Should().BeTrue();
    }

    [Fact]
    public async Task GetDetail_AcmeLinkedCertificate_IsFlaggedIssuedByAcme()
    {
        await SeedAcmeChainAsync(adcsRequestId: 1, contactJson: "[\"mailto:ops@example.com\"]");
        var entity = await _db.SyncedCertificates.FirstAsync(c => c.RequestId == 1);

        var detail = await _sut.GetDetailByIdAsync(entity.Id);

        detail.Should().NotBeNull();
        detail!.IssuedByAcme.Should().BeTrue();
    }

    [Fact]
    public async Task GetDetail_AccountWithoutMailtoContact_IsStillFlaggedIssuedByAcme()
    {
        // The list case above proves the flag is not the contact email in
        // disguise. Pinned on the detail endpoint too, because that endpoint
        // resolves the two through separate queries and only this scenario
        // separates them.
        await SeedAcmeChainAsync(adcsRequestId: 1, contactJson: "[\"tel:+15551234567\"]");
        var entity = await _db.SyncedCertificates.FirstAsync(c => c.RequestId == 1);

        var detail = await _sut.GetDetailByIdAsync(entity.Id);

        detail.Should().NotBeNull();
        detail!.AcmeContactEmail.Should().BeNull();
        detail.IssuedByAcme.Should().BeTrue();
    }

    [Fact]
    public async Task GetDetail_NoAcmeLinkage_IsNotFlaggedIssuedByAcme()
    {
        // Pinned alongside the list case so the two endpoints answer the same
        // question with the same predicate and cannot drift apart.
        var entity = await _db.SyncedCertificates.FirstAsync(c => c.RequestId == 1);

        var detail = await _sut.GetDetailByIdAsync(entity.Id);

        detail.Should().NotBeNull();
        detail!.IssuedByAcme.Should().BeFalse();
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("not json", null)]
    [InlineData("[]", null)]
    [InlineData("[\"tel:+15551234567\"]", null)]
    [InlineData("[\"mailto:\"]", null)]
    [InlineData("[\"mailto:admin@example.com\"]", "admin@example.com")]
    [InlineData("[\"MAILTO:Admin@Example.com\"]", "Admin@Example.com")]
    [InlineData("[null,\"mailto:second@example.com\"]", "second@example.com")]
    [InlineData("[\"tel:+15551234567\",\"mailto:second@example.com\"]", "second@example.com")]
    public void ExtractFirstMailto_HandlesContactShapes(string? contactJson, string? expected)
    {
        CertificateQueryService.ExtractFirstMailto(contactJson).Should().Be(expected);
    }

    [Fact]
    public async Task Query_SearchBySerialNumber_Works()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Search: "SERIAL001"));

        result.TotalCount.Should().Be(1);
    }

    private void SeedTestCertificates()
    {
        var now = DateTime.UtcNow;
        _db.SyncedCertificates.AddRange(
            new SyncedCertificate
            {
                RequestId = 1,
                SerialNumber = "SERIAL001",
                Subject = "CN=web-server.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-30),
                NotAfter = now.AddDays(335),
                Status = "Issued",
                Requestor = "admin",
                RequestDate = now.AddDays(-30)
            },
            new SyncedCertificate
            {
                RequestId = 2,
                SerialNumber = "SERIAL002",
                Subject = "CN=api.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-60),
                NotAfter = now.AddDays(10), // Expiring soon
                Status = "Issued",
                Requestor = "admin",
                RequestDate = now.AddDays(-60)
            },
            new SyncedCertificate
            {
                RequestId = 3,
                SerialNumber = "SERIAL003",
                Subject = "CN=db-server.internal",
                TemplateName = "InternalServer",
                NotBefore = now.AddDays(-90),
                NotAfter = now.AddDays(275),
                Status = "Issued",
                Requestor = "dba-team",
                RequestDate = now.AddDays(-90)
            },
            new SyncedCertificate
            {
                RequestId = 4,
                SerialNumber = "SERIAL004",
                Subject = "CN=old-server.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-400),
                NotAfter = now.AddDays(-35), // Already expired
                Status = "Issued",
                Requestor = "admin",
                RequestDate = now.AddDays(-400)
            },
            new SyncedCertificate
            {
                RequestId = 5,
                SerialNumber = "SERIAL005",
                Subject = "CN=revoked-server.example.com",
                TemplateName = "InternalServer",
                NotBefore = now.AddDays(-180),
                NotAfter = now.AddDays(185),
                Status = "Revoked",
                Requestor = "security-team",
                RequestDate = now.AddDays(-180),
                RevokedAt = now.AddDays(-5),
                RevokedReason = 4 // Superseded
            },
            // Revoked *and* past its expiry. This is the row the "expired" state
            // must not return (issue #155): filtering on the expiry date alone
            // picks it up, but the Expired stat card counts issued certificates
            // only, so the card and the list used to disagree by exactly this
            // row. InternalServer on purpose, to leave the WebServer counts
            // above unchanged.
            new SyncedCertificate
            {
                RequestId = 8,
                SerialNumber = "SERIAL008",
                Subject = "CN=retired-server.internal",
                TemplateName = "InternalServer",
                NotBefore = now.AddDays(-500),
                NotAfter = now.AddDays(-60),
                Status = "Revoked",
                Requestor = "security-team",
                RequestDate = now.AddDays(-500),
                RevokedAt = now.AddDays(-70),
                RevokedReason = 1 // Key compromise
            },
            // Two request rows: no certificate, so no serial and no validity
            // period. They exist only so the detail page can show the CA's own
            // explanation, and they stay out of the unfiltered inventory.
            new SyncedCertificate
            {
                RequestId = 6,
                SerialNumber = string.Empty,
                Subject = "CN=waiting.example.com",
                TemplateName = "WebServer",
                NotBefore = DateTime.MinValue,
                NotAfter = DateTime.MinValue,
                Status = "Pending",
                Requestor = "HOME\\app-svc",
                RequestDate = now.AddDays(-2),
                DispositionMessage = "Taken Under Submission"
            },
            new SyncedCertificate
            {
                RequestId = 7,
                SerialNumber = string.Empty,
                Subject = "CN=refused.example.com",
                TemplateName = "WebServer",
                NotBefore = DateTime.MinValue,
                NotAfter = DateTime.MinValue,
                Status = "Denied",
                Requestor = "HOME\\app-svc",
                RequestDate = now.AddDays(-1),
                DispositionMessage = "Denied by HOME\\admin",
                StatusCode = unchecked((int)0x80094801)
            });
        _db.SaveChanges();
    }

    /// <summary>
    /// Seeds the ACME side of the value bridge: an account with the given
    /// contact list, an order for it, and an issued ACME certificate whose
    /// AdcsRequestId matches a seeded SyncedCertificate row.
    /// </summary>
    private async Task SeedAcmeChainAsync(int adcsRequestId, string? contactJson)
    {
        var account = new AcmeAccount
        {
            AccountId = $"acct-{adcsRequestId}",
            JwkJson = "{}",
            JwkThumbprint = $"thumb-{adcsRequestId}",
            ContactJson = contactJson
        };
        // "valid" with a matching CertificateId is the only shape a stored certificate
        // can have in production: the row and the status flip commit together. Left at
        // the entity default this seeded a certificate under a pending order, which no
        // path can produce (issue #318).
        var order = new AcmeOrder
        {
            OrderId = $"order-{adcsRequestId}",
            Account = account,
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = "[]",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            AdcsRequestId = adcsRequestId,
            CertificateId = $"cert-{adcsRequestId}"
        };
        _db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = $"cert-{adcsRequestId}",
            Order = order,
            CertificatePem = "-----BEGIN CERTIFICATE-----",
            AdcsRequestId = adcsRequestId,
            SerialNumber = $"ACMESERIAL{adcsRequestId:D3}"
        });
        await _db.SaveChangesAsync();
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }
}
