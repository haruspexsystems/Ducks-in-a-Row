using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

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

        _sut = new CertificateQueryService(_db, NullLogger<CertificateQueryService>.Instance);

        // Seed test data
        SeedTestCertificates();
    }

    [Fact]
    public async Task Query_NoFilters_ReturnsAll()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery());

        result.TotalCount.Should().Be(5);
        result.Items.Should().HaveCount(5);
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

        result.TotalCount.Should().Be(1);
        result.Items[0].Status.Should().Be("Revoked");
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

    [Fact]
    public async Task Query_Pagination_RespectsSkipAndTake()
    {
        var page1 = await _sut.QueryAsync(new CertificateSearchQuery(Skip: 0, Take: 2));
        var page2 = await _sut.QueryAsync(new CertificateSearchQuery(Skip: 2, Take: 2));

        page1.Items.Should().HaveCount(2);
        page2.Items.Should().HaveCount(2);
        page1.TotalCount.Should().Be(5);
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

        stats.TotalCertificates.Should().Be(5);
        stats.IssuedCertificates.Should().Be(4); // 4 with "Issued" status
        stats.RevokedCertificates.Should().Be(1);
    }

    [Fact]
    public async Task Query_RevokedRow_CarriesRevocationFields()
    {
        var result = await _sut.QueryAsync(new CertificateSearchQuery(Status: "Revoked"));

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
        var order = new AcmeOrder
        {
            OrderId = $"order-{adcsRequestId}",
            Account = account,
            TemplateId = "WebServer",
            IdentifiersJson = "[]",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            AdcsRequestId = adcsRequestId
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
