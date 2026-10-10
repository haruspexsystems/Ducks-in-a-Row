using System.Net;
using System.Text.Json;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the Dashboard API endpoints:
///   GET /api/certificates
///   GET /api/certificates/{id}
///   GET /api/certificates/stats
///   GET /api/templates
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class DashboardIntegrationTests
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public DashboardIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    /// <summary>Seed test certificates and return the scope so the DB is committed.</summary>
    private async Task SeedCertificatesAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        // Only seed if our specific data doesn't exist yet (tests share factory)
        if (await db.SyncedCertificates.AnyAsync(c => c.RequestId == 1001))
            return;

        var now = DateTime.UtcNow;
        db.SyncedCertificates.AddRange(
            new SyncedCertificate
            {
                RequestId = 1001,
                SerialNumber = "DASHSERIAL001",
                Subject = "CN=dash-web.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-30),
                NotAfter = now.AddDays(335),
                Status = "Issued",
                Requestor = "admin",
                RequestDate = now.AddDays(-30),
                // Cryptographic detail, to prove it reaches the detail endpoint
                // and never reaches the list.
                KeyAlgorithm = "RSA",
                KeySizeBits = 2048,
                SignatureAlgorithmOid = "1.2.840.113549.1.1.11",
                Sha256Thumbprint = new string('D', 64),
                ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2",
                KeyUsage = 160
            },
            new SyncedCertificate
            {
                RequestId = 1002,
                SerialNumber = "DASHSERIAL002",
                Subject = "CN=dash-api.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-60),
                NotAfter = now.AddDays(10), // Expiring soon
                Status = "Issued",
                Requestor = "admin",
                RequestDate = now.AddDays(-60)
            },
            new SyncedCertificate
            {
                RequestId = 1003,
                SerialNumber = "DASHSERIAL003",
                Subject = "CN=dash-db.internal",
                TemplateName = "InternalServer",
                NotBefore = now.AddDays(-90),
                NotAfter = now.AddDays(275),
                Status = "Revoked",
                Requestor = "dba-team",
                RequestDate = now.AddDays(-90)
            },
            // A request that the CA refused. No certificate, so no serial and no
            // validity period; it exists only to carry the CA's explanation.
            new SyncedCertificate
            {
                RequestId = 1004,
                SerialNumber = string.Empty,
                Subject = "CN=dash-denied.example.com",
                TemplateName = "WebServer",
                NotBefore = DateTime.MinValue,
                NotAfter = DateTime.MinValue,
                Status = "Denied",
                Requestor = "HOME\\app-svc",
                RequestDate = now.AddDays(-1),
                DispositionMessage = "Denied by HOME\\admin",
                StatusCode = unchecked((int)0x80094801)
            });

        await db.SaveChangesAsync();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    #region POST /api/certificates/sync

    [Fact]
    public async Task TriggerSync_Returns200WithSyncCounts()
    {
        // The test host runs the mock ADCS client, so the sync completes
        // against the mock inventory (possibly empty, depending on sibling
        // tests in the shared collection).
        var response = await _client.PostAsync("/api/certificates/sync", null);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var processed = body.GetProperty("processed").GetInt32();
        var created = body.GetProperty("created").GetInt32();
        var updated = body.GetProperty("updated").GetInt32();

        processed.Should().BeGreaterThanOrEqualTo(0);
        (created + updated).Should().Be(processed);
        body.GetProperty("completedAtUtc").GetDateTime()
            .Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(2));
    }

    #endregion

    #region GET /api/certificates

    [Fact]
    public async Task ListCertificates_Returns200WithPagedResult()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("items").GetArrayLength().Should().BeGreaterThan(0);
        body.GetProperty("totalCount").GetInt32().Should().BeGreaterThan(0);
        body.TryGetProperty("hasMore", out _).Should().BeTrue();
        body.TryGetProperty("skip", out _).Should().BeTrue();
        body.TryGetProperty("take", out _).Should().BeTrue();
    }

    [Fact]
    public async Task ListCertificates_SearchBySubject_FiltersResults()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates?search=dash-web");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var items = body.GetProperty("items");
        items.GetArrayLength().Should().Be(1);
        items[0].GetProperty("subject").GetString().Should().Contain("dash-web");
    }

    [Fact]
    public async Task ListCertificates_SortByRequestor_OrdersByTheCaRequester()
    {
        // Issue #156. The core tests build CertificateSearchQuery directly, so
        // this is the only level that proves the query string the frontend puts
        // on the wire binds and reaches the sort switch. Scoped to the seeded
        // subjects because the factory is shared across the class.
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates?search=dash-&sortBy=requestor");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var requestors = body.GetProperty("items")
            .EnumerateArray()
            .Select(item => item.GetProperty("requestor").GetString())
            .ToList();

        // dash-denied carries a requestor as well, but a Denied request never
        // became a certificate and stays out of the unfiltered inventory.
        requestors.Should().Equal("admin", "admin", "dba-team");
    }

    [Fact]
    public async Task ListCertificates_SortByNotBefore_OrdersByTheIssuedDate()
    {
        // The Issued column sends sortBy=notBefore. Like the requestor test
        // above, this is the level that proves the exact query string the
        // frontend puts on the wire binds and reaches the sort switch.
        await SeedCertificatesAsync();

        var response = await _client.GetAsync(
            "/api/certificates?search=dash-&sortBy=notBefore&sortDesc=true");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var notBefores = body.GetProperty("items")
            .EnumerateArray()
            .Select(item => item.GetProperty("notBefore").GetDateTime())
            .ToList();

        notBefores.Should().HaveCount(3);
        notBefores.Should().BeInDescendingOrder();
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("expiring")]
    [InlineData("expired")]
    [InlineData("revoked")]
    public async Task ListCertificates_KnownState_Returns200(string state)
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync($"/api/certificates?state={state}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ParseJsonAsync(response)).TryGetProperty("items", out _).Should().BeTrue();
    }

    [Fact]
    public async Task ListCertificates_UnknownState_Returns400RatherThanIgnoringTheFilter()
    {
        // Issue #155. Silently dropping an unrecognised state would answer a
        // question about expiry with the entire inventory, which reads as
        // "nothing is expiring" instead of as a bad request.
        var response = await _client.GetAsync("/api/certificates?state=lapsed");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var body = await ParseJsonAsync(response);
        body.GetProperty("detail").GetString().Should().Contain("expiring");
    }

    [Theory]
    [InlineData("expiring", "expiringSoon")]
    [InlineData("expired", "expired")]
    [InlineData("revoked", "revokedCertificates")]
    public async Task ListCertificates_StateFilter_MatchesTheStatCardItLinksFrom(
        string state, string cardProperty)
    {
        // The two surfaces the dashboard puts side by side: a stat card and the
        // list its Quick Action links to. They read the same predicate now, so
        // the numbers cannot drift (issue #155).
        //
        // All three pairs, not just expired. Issue #214 reported the revoked
        // pair disagreeing on a live install, and CI could not answer it: the
        // expired pair was pinned here and the other two were not. The report
        // turned out to be a QA harness misreading the card's property name,
        // but the gap it walked into was real, and an invariant worth stating
        // for one card is worth proving for all of them.
        //
        // The card property is named as a literal on purpose. Deserializing
        // into CertificateStats would follow a rename on both sides at once and
        // prove nothing about the wire; these strings are the contract the
        // dashboard and every external reader actually bind to.
        //
        // Relational, not absolute. The factory is shared, so what matters is
        // that the two numbers agree, never what they are.
        await SeedCertificatesAsync();

        var listed = await ParseJsonAsync(await _client.GetAsync($"/api/certificates?state={state}"));
        var stats = await ParseJsonAsync(await _client.GetAsync("/api/certificates/stats"));

        listed.GetProperty("totalCount").GetInt32()
            .Should().Be(stats.GetProperty(cardProperty).GetInt32());
    }

    [Fact]
    public async Task ListCertificates_ValidExpiringExpired_PartitionTheIssuedStatCard()
    {
        // The invariant StatePredicate's own remarks assert: the three issued
        // states partition Status == Issued with no gap and no overlap, so
        // valid + expiring + expired always equals the issued count.
        //
        // Proved rather than trusted, because it is the one check that catches a
        // boundary drift in either direction. A certificate counted twice or
        // dropped between two states breaks the sum even when all four counts
        // still look individually plausible, and the per card pairing above
        // would pass throughout.
        await SeedCertificatesAsync();

        var valid = await ParseJsonAsync(await _client.GetAsync("/api/certificates?state=valid"));
        var expiring = await ParseJsonAsync(await _client.GetAsync("/api/certificates?state=expiring"));
        var expired = await ParseJsonAsync(await _client.GetAsync("/api/certificates?state=expired"));
        var stats = await ParseJsonAsync(await _client.GetAsync("/api/certificates/stats"));

        var partitioned = valid.GetProperty("totalCount").GetInt32()
                        + expiring.GetProperty("totalCount").GetInt32()
                        + expired.GetProperty("totalCount").GetInt32();

        partitioned.Should().Be(stats.GetProperty("issuedCertificates").GetInt32());
    }

    [Fact]
    public async Task ListCertificates_FilterByTemplate_ReturnsOnlyMatching()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates?template=InternalServer");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var items = body.GetProperty("items");
        items.GetArrayLength().Should().BeGreaterThan(0);

        // All returned items should have the InternalServer template
        foreach (var item in items.EnumerateArray())
        {
            item.GetProperty("templateName").GetString().Should().Be("InternalServer");
        }
    }

    [Fact]
    public async Task ListCertificates_FilterByStatus_ReturnsOnlyMatching()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates?status=Revoked");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        var items = body.GetProperty("items");
        items.GetArrayLength().Should().BeGreaterThan(0);

        foreach (var item in items.EnumerateArray())
        {
            item.GetProperty("status").GetString().Should().Be("Revoked");
        }
    }

    [Fact]
    public async Task ListCertificates_Pagination_RespectsSkipAndTake()
    {
        await SeedCertificatesAsync();

        // Use search filter to isolate our seeded data
        var page1 = await _client.GetAsync("/api/certificates?search=dash-&skip=0&take=1");
        var page2 = await _client.GetAsync("/api/certificates?search=dash-&skip=1&take=1");

        page1.StatusCode.Should().Be(HttpStatusCode.OK);
        page2.StatusCode.Should().Be(HttpStatusCode.OK);

        var body1 = await ParseJsonAsync(page1);
        var body2 = await ParseJsonAsync(page2);

        body1.GetProperty("items").GetArrayLength().Should().Be(1);
        body2.GetProperty("items").GetArrayLength().Should().BeGreaterThan(0);

        // Different items
        var id1 = body1.GetProperty("items")[0].GetProperty("id").GetInt32();
        var id2 = body2.GetProperty("items")[0].GetProperty("id").GetInt32();
        id1.Should().NotBe(id2);
    }

    [Fact]
    public async Task ListCertificates_ZSuffixedExpiryRange_IsComparedAgainstUtcRows()
    {
        // Mirrors Accounts_List_FiltersByRegisteredRange: end to end cover for
        // the UTC contract, proving a real instant on the query string reaches
        // the comparison still meaning the instant it named.
        //
        // Two things have to hold for that, and this test does not distinguish
        // them: MVC's DateTimeModelBinder delivers a Z suffixed instant as
        // Kind=Utc, and UtcWallClock holds it there. The second alone is a no op
        // on this path, so what this catches is a later change to the first, or
        // a move off the MVC binder onto something that parses to a local wall
        // clock.
        //
        // The windows below are one minute wide, so any host with a nonzero UTC
        // offset would fail one of the two directions: a positive offset pushes
        // expiringAfter past the row, a negative one pulls expiringBefore back
        // in front of it. A host running in UTC cannot tell them apart, which is
        // what UtcWallClockTests covers instead.
        await SeedBoundaryCertificateAsync();

        var justAfter = Instant(BoundaryExpiryUtc.AddMinutes(1));
        var justBefore = Instant(BoundaryExpiryUtc.AddMinutes(-1));

        (await CountBoundaryAsync($"&expiringBefore={justAfter}")).Should().Be(1);
        (await CountBoundaryAsync($"&expiringAfter={justBefore}")).Should().Be(1);

        // The row leaves the window when the bound genuinely excludes it, so
        // the two assertions above are not just a filter that never bit.
        (await CountBoundaryAsync($"&expiringBefore={justBefore}")).Should().Be(0);
        (await CountBoundaryAsync($"&expiringAfter={justAfter}")).Should().Be(0);
    }

    [Fact]
    public async Task ListCertificates_ExpiryBoundsAreInclusive()
    {
        // Documented in CertificatesController.ListCertificates and deliberately
        // different from the ACME accounts inventory, whose Before bounds are
        // exclusive so a caller can express a whole local day. These take an
        // arbitrary instant rather than a day, and links built before the
        // lifecycle chips (issue #155) keep the boundary they were built with.
        await SeedBoundaryCertificateAsync();

        var exactly = Instant(BoundaryExpiryUtc);

        (await CountBoundaryAsync($"&expiringBefore={exactly}")).Should().Be(1);
        (await CountBoundaryAsync($"&expiringAfter={exactly}")).Should().Be(1);
    }

    /// <summary>
    /// The expiry the two range filter tests aim at. Second aligned so it round
    /// trips through SQLite exactly and an inclusive bound can be asserted right
    /// on it, and far enough out that it cannot collide with the relative dates
    /// the other seeds in this shared factory use.
    /// </summary>
    private static readonly DateTime BoundaryExpiryUtc = new(2031, 3, 15, 9, 30, 0, DateTimeKind.Utc);

    /// <summary>
    /// When the boundary certificate was requested and issued. Fixed in the past
    /// rather than derived from the expiry above, because a future RequestDate
    /// breaks a sibling test in this shared collection: the registrations series
    /// counts rows whose RequestDate is on or after the start of its window but
    /// buckets only the days inside it, so a date past the window end is counted
    /// by the expectation Registrations_ReturnsDailyBucketsWithZeroRenewals
    /// computes and dropped from the series it compares against.
    /// </summary>
    private static readonly DateTime BoundaryIssuedUtc = new(2020, 1, 6, 9, 30, 0, DateTimeKind.Utc);

    /// <summary>One issued certificate expiring exactly on <see cref="BoundaryExpiryUtc"/>.</summary>
    private async Task SeedBoundaryCertificateAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        if (await db.SyncedCertificates.AnyAsync(c => c.RequestId == 1201))
            return;

        db.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 1201,
            SerialNumber = "BOUNDARYSERIAL001",
            Subject = "CN=boundary-utc.example.com",
            TemplateName = "WebServer",
            NotBefore = BoundaryIssuedUtc,
            NotAfter = BoundaryExpiryUtc,
            Status = "Issued",
            Requestor = "admin",
            RequestDate = BoundaryIssuedUtc.AddDays(-1)
        });

        await db.SaveChangesAsync();
    }

    /// <summary>An instant on the wire the way a caller sends one: round trip format, Z suffixed.</summary>
    private static string Instant(DateTime utc) => Uri.EscapeDataString(utc.ToString("O"));

    /// <summary>
    /// How many rows the seeded boundary certificate's search term returns under
    /// the given extra filters. Scoped by search because the factory is shared
    /// across the class.
    /// </summary>
    private async Task<int> CountBoundaryAsync(string extraQuery)
    {
        var response = await _client.GetAsync($"/api/certificates?search=boundary-utc{extraQuery}");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await ParseJsonAsync(response)).GetProperty("totalCount").GetInt32();
    }

    [Fact]
    public async Task ListCertificates_TakeExceedsMax_ClampedTo200()
    {
        await SeedCertificatesAsync();

        // Request take=999, should be clamped to 200 (controller logic)
        var response = await _client.GetAsync("/api/certificates?take=999");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("take").GetInt32().Should().BeLessThanOrEqualTo(200);
    }

    #endregion

    #region GET /api/certificates/{id}

    [Fact]
    public async Task GetCertificate_Existing_Returns200()
    {
        await SeedCertificatesAsync();

        // First, list to get an actual ID
        var listResponse = await _client.GetAsync("/api/certificates?take=1");
        var listBody = await ParseJsonAsync(listResponse);
        var id = listBody.GetProperty("items")[0].GetProperty("id").GetInt32();

        var response = await _client.GetAsync($"/api/certificates/{id}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("id").GetInt32().Should().Be(id);
        body.TryGetProperty("subject", out _).Should().BeTrue();
        body.TryGetProperty("serialNumber", out _).Should().BeTrue();
    }

    [Fact]
    public async Task GetCertificate_NonExistent_Returns404()
    {
        var response = await _client.GetAsync("/api/certificates/999999");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task GetCertificates_Unfiltered_OmitsRequestRows()
    {
        await SeedCertificatesAsync();

        var body = await ParseJsonAsync(await _client.GetAsync("/api/certificates?take=200"));

        var statuses = body.GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("status").GetString())
            .ToList();

        statuses.Should().NotBeEmpty();
        statuses.Should().OnlyContain(s => s == "Issued" || s == "Revoked");
    }

    [Fact]
    public async Task GetCertificate_DeniedRequest_CarriesTheCaExplanationOnTheWire()
    {
        await SeedCertificatesAsync();

        // The status filter is the documented route to a request row.
        var listBody = await ParseJsonAsync(
            await _client.GetAsync("/api/certificates?status=Denied&take=1"));
        var id = listBody.GetProperty("items")[0].GetProperty("id").GetInt32();

        var body = await ParseJsonAsync(await _client.GetAsync($"/api/certificates/{id}"));

        body.GetProperty("dispositionMessage").GetString()
            .Should().Be("Denied by HOME\\admin");
        body.GetProperty("statusCode").GetInt32()
            .Should().Be(unchecked((int)0x80094801));
    }

    [Fact]
    public async Task GetCertificate_IssuedCertificate_OmitsTheDispositionFields()
    {
        await SeedCertificatesAsync();

        var listBody = await ParseJsonAsync(
            await _client.GetAsync("/api/certificates?status=Issued&take=1"));
        var id = listBody.GetProperty("items")[0].GetProperty("id").GetInt32();

        var body = await ParseJsonAsync(await _client.GetAsync($"/api/certificates/{id}"));

        // WhenWritingNull: the keys are absent rather than null, so the frontend
        // renders no disposition block at all for an issued certificate.
        body.TryGetProperty("dispositionMessage", out _).Should().BeFalse();
        body.TryGetProperty("statusCode", out _).Should().BeFalse();
    }

    [Fact]
    public async Task GetCertificate_ReturnsCryptographicDetail()
    {
        await SeedCertificatesAsync();

        var id = await FindSeededCertificateIdAsync("dash-web");

        var response = await _client.GetAsync($"/api/certificates/{id}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("keyAlgorithm").GetString().Should().Be("RSA");
        body.GetProperty("keySizeBits").GetInt32().Should().Be(2048);
        body.GetProperty("signatureAlgorithmOid").GetString().Should().Be("1.2.840.113549.1.1.11");
        body.GetProperty("sha256Thumbprint").GetString().Should().Be(new string('D', 64));
        body.GetProperty("extendedKeyUsageOids").GetString()
            .Should().Be("1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2");
        body.GetProperty("keyUsage").GetInt32().Should().Be(160);
    }

    [Fact]
    public async Task ListCertificates_NeverCarriesCryptographicDetail()
    {
        // Free tier boundary, held by not building the other side rather than by
        // a feature flag. One certificate's own key detail on its own page is
        // what any certificate viewer does and is free; the same detail as a
        // list column, a filter, or an estate wide count is the paid Compliance
        // tier inventory feature. CertificateDetail derives from
        // CertificateSummary so the list projection structurally cannot carry
        // these, and this test is what keeps that true.
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates?take=200");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var items = (await ParseJsonAsync(response)).GetProperty("items").EnumerateArray().ToList();
        items.Should().NotBeEmpty();

        string[] detailOnly =
        {
            "keyAlgorithm", "keySizeBits", "signatureAlgorithmOid",
            "sha256Thumbprint", "extendedKeyUsageOids", "keyUsage",
            // Same boundary, different reason: the CA's disposition message is
            // text authored outside Ducks and partly influenced by whoever
            // submitted the request, and only the detail page renders it.
            "dispositionMessage", "statusCode",
            // The resolved ends of the supersession inference (issue #154). The
            // list carries the bare "supersededById" so a row can be badged;
            // naming and dating the other certificate is a detail page concern.
            "supersededBy", "supersedes"
        };

        foreach (var item in items)
        {
            foreach (var property in detailOnly)
            {
                item.TryGetProperty(property, out _).Should().BeFalse(
                    "'{0}' is detail endpoint only and must never appear in the certificate list",
                    property);
            }
        }
    }

    [Fact]
    public async Task ListCertificates_CarriesSupersededById()
    {
        // The badge on a list row is the whole point of putting this one field on
        // the summary: a page of 25 rows can never work the answer out for itself.
        var lineage = await SeedSupersessionLineageAsync();

        var response = await _client.GetAsync("/api/certificates?search=lineage&take=200");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var items = (await ParseJsonAsync(response)).GetProperty("items").EnumerateArray()
            .ToDictionary(item => item.GetProperty("id").GetInt32());

        items[lineage.OldId].GetProperty("supersededById").GetInt32().Should().Be(lineage.NewId);
        items[lineage.MiddleId].GetProperty("supersededById").GetInt32().Should().Be(lineage.NewId);
        // The newest in a lineage is never marked superseded, and the field is
        // omitted rather than sent as null.
        items[lineage.NewId].TryGetProperty("supersededById", out _).Should().BeFalse();
    }

    [Fact]
    public async Task GetCertificate_ReturnsBothSupersessionDirections()
    {
        var lineage = await SeedSupersessionLineageAsync();

        var oldest = await ParseJsonAsync(await _client.GetAsync($"/api/certificates/{lineage.OldId}"));
        var newest = await ParseJsonAsync(await _client.GetAsync($"/api/certificates/{lineage.NewId}"));

        // Forward: resolved, so the page can name the successor and show the
        // dates and requester the reader needs to judge the inference.
        var supersededBy = oldest.GetProperty("supersededBy");
        supersededBy.GetProperty("id").GetInt32().Should().Be(lineage.NewId);
        supersededBy.GetProperty("subject").GetString().Should().Contain("lineage");
        supersededBy.GetProperty("requestor").GetString().Should().Be("platform-team");
        supersededBy.GetProperty("notBefore").ValueKind.Should().NotBe(JsonValueKind.Null);
        oldest.GetProperty("supersedes").GetArrayLength().Should().Be(0);

        // Backward: two predecessors, which is correct rather than a bug. The
        // middle certificate is revoked, so it never supersedes, which leaves it
        // and the one before it both naming the newest as their replacement.
        newest.TryGetProperty("supersededBy", out _).Should().BeFalse();
        var supersedes = newest.GetProperty("supersedes").EnumerateArray().ToList();
        supersedes.Should().HaveCount(2);
        supersedes.Select(link => link.GetProperty("id").GetInt32())
            .Should().Equal(lineage.OldId, lineage.MiddleId);
    }

    /// <summary>
    /// A three certificate lineage with the links already recorded, which is what
    /// the sync time pass leaves behind. The middle one is revoked, so both it and
    /// the oldest name the newest as their replacement.
    /// </summary>
    private async Task<(int OldId, int MiddleId, int NewId)> SeedSupersessionLineageAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var now = DateTime.UtcNow;
        var existing = await db.SyncedCertificates
            .Where(c => c.RequestId >= 1101 && c.RequestId <= 1103)
            .OrderBy(c => c.RequestId)
            .ToListAsync();

        if (existing.Count != 3)
        {
            var rows = new[] { 1101, 1102, 1103 }.Select((requestId, index) => new SyncedCertificate
            {
                RequestId = requestId,
                SerialNumber = $"LINEAGESERIAL{requestId}",
                Subject = "CN=lineage.example.com",
                SubjectAlternativeNames = "dns:lineage.example.com",
                TemplateName = "WebServer",
                NotBefore = now.AddDays(-900 + (index * 400)),
                NotAfter = now.AddDays(-535 + (index * 400)),
                Status = requestId == 1102 ? "Revoked" : "Issued",
                Requestor = "platform-team",
                RequestDate = now.AddDays(-901 + (index * 400))
            }).ToList();

            db.SyncedCertificates.AddRange(rows);
            await db.SaveChangesAsync();

            // Ids are assigned on save, so the links are a second pass. Both the
            // oldest and the revoked middle name the newest, because a revoked
            // certificate never supersedes and is skipped over as a successor.
            rows[0].SupersededByCertificateId = rows[2].Id;
            rows[1].SupersededByCertificateId = rows[2].Id;
            await db.SaveChangesAsync();
            existing = rows;
        }

        return (existing[0].Id, existing[1].Id, existing[2].Id);
    }

    /// <summary>Resolves a seeded certificate's internal ID by a subject fragment.</summary>
    private async Task<int> FindSeededCertificateIdAsync(string subjectFragment)
    {
        var response = await _client.GetAsync($"/api/certificates?search={subjectFragment}&take=1");
        var body = await ParseJsonAsync(response);
        return body.GetProperty("items")[0].GetProperty("id").GetInt32();
    }

    #endregion

    #region GET /api/certificates/stats

    [Fact]
    public async Task GetStats_Returns200WithStatistics()
    {
        await SeedCertificatesAsync();

        var response = await _client.GetAsync("/api/certificates/stats");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("totalCertificates").GetInt32().Should().BeGreaterThan(0);
        body.TryGetProperty("issuedCertificates", out _).Should().BeTrue();
        body.TryGetProperty("expiringSoon", out _).Should().BeTrue();
        body.TryGetProperty("expired", out _).Should().BeTrue();
        // Seed 1003 is Revoked; the factory is shared across tests, so assert
        // presence and a lower bound rather than an exact count.
        body.GetProperty("revokedCertificates").GetInt32().Should().BeGreaterThan(0);
    }

    #endregion

    #region GET /api/templates

    [Fact]
    public async Task ListTemplates_Returns200()
    {
        var response = await _client.GetAsync("/api/templates");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.ValueKind.Should().Be(JsonValueKind.Array);
        // MockAdcsClient returns default templates: WebServer, CodeSigning, User
        body.GetArrayLength().Should().BeGreaterThan(0);
    }

    #endregion
}
