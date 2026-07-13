using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Services;

/// <summary>
/// Tests for CertificateSyncService. Verifies the inventory sync queries the CA for
/// both issued and revoked certificates and reflects revocation in the local database.
/// Regression cover for the adcs review finding where a revoked certificate kept a
/// stale "Issued" status forever because only issued rows were ever synced.
/// </summary>
public class CertificateSyncServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _serviceProvider;
    private readonly IAdcsClient _adcs;
    private readonly List<IServiceScope> _scopes = new();

    public CertificateSyncServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        _adcs = Substitute.For<IAdcsClient>();

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(options =>
            options.UseSqlite(_connection));

        _serviceProvider = services.BuildServiceProvider();

        // Create the database schema on the shared in-memory connection.
        using var scope = _serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        db.Database.EnsureCreated();
    }

    private CertificateSyncService CreateService()
    {
        return new CertificateSyncService(
            _serviceProvider.GetRequiredService<IServiceScopeFactory>(),
            _adcs,
            new CertificateSyncTrigger(),
            Options.Create(new CertusOptions()),
            NullLogger<CertificateSyncService>.Instance);
    }

    private CertusDbContext GetDb()
    {
        var scope = _serviceProvider.CreateScope();
        _scopes.Add(scope);
        return scope.ServiceProvider.GetRequiredService<CertusDbContext>();
    }

    private void SetCaCertificates(
        IReadOnlyList<CertificateInfo> issued,
        IReadOnlyList<CertificateInfo> revoked)
    {
        _adcs.QueryCertificatesAsync(
                Arg.Is<CertificateQuery>(q => q.Status == CertificateStatus.Issued),
                Arg.Any<CancellationToken>())
            .Returns(issued);
        _adcs.QueryCertificatesAsync(
                Arg.Is<CertificateQuery>(q => q.Status == CertificateStatus.Revoked),
                Arg.Any<CancellationToken>())
            .Returns(revoked);
    }

    private static CertificateInfo Cert(int requestId, string subject, CertificateStatus status)
    {
        var now = DateTime.UtcNow;
        return new CertificateInfo(
            RequestId: requestId,
            SerialNumber: $"SERIAL{requestId:D4}",
            Subject: subject,
            SubjectAlternativeNames: null,
            TemplateName: "WebServer",
            NotBefore: now.AddDays(-10),
            NotAfter: now.AddDays(355),
            Status: status,
            Requestor: "HOME\\admin",
            RequestDate: now.AddDays(-10));
    }

    [Fact]
    public async Task Sync_QueriesBothIssuedAndRevokedDispositions()
    {
        SetCaCertificates(
            issued: new[] { Cert(1, "CN=issued.example.com", CertificateStatus.Issued) },
            revoked: new[] { Cert(2, "CN=revoked.example.com", CertificateStatus.Revoked) });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q => q.Status == CertificateStatus.Issued),
            Arg.Any<CancellationToken>());
        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q => q.Status == CertificateStatus.Revoked),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Sync_PersistsIssuedAndRevokedCerts()
    {
        SetCaCertificates(
            issued: new[] { Cert(1, "CN=issued.example.com", CertificateStatus.Issued) },
            revoked: new[] { Cert(2, "CN=revoked.example.com", CertificateStatus.Revoked) });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var rows = await db.SyncedCertificates.OrderBy(c => c.RequestId).ToListAsync();

        rows.Should().HaveCount(2);
        rows[0].Status.Should().Be("Issued");
        rows[1].Status.Should().Be("Revoked");
    }

    [Fact]
    public async Task Sync_CertRevokedOnCa_UpdatesStaleIssuedStatus()
    {
        // A certificate that was previously synced while it was still issued.
        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 5,
            SerialNumber = "SERIAL0005",
            Subject = "CN=rotated.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-100),
            NotAfter = DateTime.UtcNow.AddDays(200),
            Status = "Issued",
            RequestDate = DateTime.UtcNow.AddDays(-100),
        });
        await seed.SaveChangesAsync();

        // The CA no longer lists it as issued; it now comes back under the revoked pass.
        SetCaCertificates(
            issued: Array.Empty<CertificateInfo>(),
            revoked: new[] { Cert(5, "CN=rotated.example.com", CertificateStatus.Revoked) });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var rows = await db.SyncedCertificates.Where(c => c.RequestId == 5).ToListAsync();

        rows.Should().HaveCount(1); // updated in place, not duplicated
        rows[0].Status.Should().Be("Revoked");
    }

    [Fact]
    public async Task Sync_RevokedCert_PersistsRevocationFields()
    {
        var revokedWhen = DateTime.UtcNow.AddDays(-3);
        var revokedCert = Cert(9, "CN=revoked.example.com", CertificateStatus.Revoked) with
        {
            RevokedWhen = revokedWhen,
            RevokedReason = 1 // Key Compromise
        };
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: new[] { revokedCert });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 9);
        row.Status.Should().Be("Revoked");
        row.RevokedAt.Should().BeCloseTo(revokedWhen, TimeSpan.FromSeconds(1));
        row.RevokedReason.Should().Be(1);
    }

    [Fact]
    public async Task Sync_CertReleasedFromHold_ClearsRevocationFields()
    {
        // A certificate previously synced as revoked (CertificateHold) that the
        // CA has since released: it reappears in the Issued pass with null
        // revocation values, which must clear the local fields.
        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 12,
            SerialNumber = "SERIAL0012",
            Subject = "CN=held.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-30),
            NotAfter = DateTime.UtcNow.AddDays(335),
            Status = "Revoked",
            RequestDate = DateTime.UtcNow.AddDays(-30),
            RevokedAt = DateTime.UtcNow.AddDays(-7),
            RevokedReason = 6 // Certificate Hold
        });
        await seed.SaveChangesAsync();

        SetCaCertificates(
            issued: new[] { Cert(12, "CN=held.example.com", CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 12);
        row.Status.Should().Be("Issued");
        row.RevokedAt.Should().BeNull();
        row.RevokedReason.Should().BeNull();
    }

    [Fact]
    public async Task Sync_ReturnsProcessedCreatedAndUpdatedCounts()
    {
        // One row already known locally (will be updated), two new ones.
        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 1,
            SerialNumber = "SERIAL0001",
            Subject = "CN=known.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-10),
            NotAfter = DateTime.UtcNow.AddDays(355),
            Status = "Issued",
            RequestDate = DateTime.UtcNow.AddDays(-10),
        });
        await seed.SaveChangesAsync();

        SetCaCertificates(
            issued: new[]
            {
                Cert(1, "CN=known.example.com", CertificateStatus.Issued),
                Cert(2, "CN=new1.example.com", CertificateStatus.Issued),
            },
            revoked: new[] { Cert(3, "CN=new2.example.com", CertificateStatus.Revoked) });

        var sut = CreateService();
        var result = await sut.SyncCertificatesAsync(CancellationToken.None);

        result.Processed.Should().Be(3);
        result.Created.Should().Be(2);
        result.Updated.Should().Be(1);
        result.CompletedAtUtc.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task Sync_PullsEachDispositionOnce_AndPagesInMemory()
    {
        // A result set larger than the in-memory batch size (100): the sync must
        // pull it in a single CA call and page it locally, not re-query per batch.
        var issued = Enumerable.Range(1, 250)
            .Select(i => Cert(i, $"CN=cert{i:D4}.example.com", CertificateStatus.Issued))
            .ToArray();
        SetCaCertificates(issued: issued, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        // Exactly one CA enumeration for the issued disposition (no Skip re-paging).
        await _adcs.Received(1).QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q => q.Status == CertificateStatus.Issued),
            Arg.Any<CancellationToken>());

        // Every certificate from that single pull is persisted.
        var db = GetDb();
        (await db.SyncedCertificates.CountAsync()).Should().Be(250);
    }

    [Fact]
    public async Task Sync_EmptyIncomingSubject_PreservesExistingSubjectAndSans()
    {
        // A revoked row the CA hands back without a RawCertificate blob has
        // an empty subject and null SANs; the sync must not blank the name it
        // already captured while the certificate was issued.
        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 5,
            SerialNumber = "SERIAL0005",
            Subject = "keep.example.com",
            SubjectAlternativeNames = "dns:keep.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-30),
            NotAfter = DateTime.UtcNow.AddDays(335),
            Status = "Issued",
            RequestDate = DateTime.UtcNow.AddDays(-30),
        });
        await seed.SaveChangesAsync();

        SetCaCertificates(
            issued: Array.Empty<CertificateInfo>(),
            revoked: new[] { Cert(5, "", CertificateStatus.Revoked) });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 5);
        row.Status.Should().Be("Revoked");
        row.Subject.Should().Be("keep.example.com");
        row.SubjectAlternativeNames.Should().Be("dns:keep.example.com");
    }

    [Fact]
    public async Task Sync_EmptySubjectRow_BackfillsFromAcmeStoreBySerial()
    {
        // The CA gives an empty subject and the serial in CA form (lowercase,
        // no leading zero pad); the ACME store has the certificate under the
        // X509Certificate2 form (uppercase, possibly padded). The backfill
        // must bridge both and take the name from the stored leaf.
        using var leaf = CreateLeaf("CN=backfill.example.com");
        var caSerial = leaf.SerialNumber.TrimStart('0').ToLowerInvariant();

        await SeedAcmeCertificateAsync(leaf.SerialNumber, leaf.ExportCertificatePem(),
            identifiersJson: "[]");

        var caCert = Cert(21, "", CertificateStatus.Revoked) with { SerialNumber = caSerial };
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: new[] { caCert });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 21);
        row.Subject.Should().Be("CN=backfill.example.com");
    }

    [Fact]
    public async Task Sync_EmptySubjectRow_UnreadablePem_FallsBackToOrderIdentifiers()
    {
        await SeedAcmeCertificateAsync("ABCD1234", "not a pem",
            identifiersJson: """[{"type":"dns","value":"ident.example.com"}]""");

        var caCert = Cert(22, "", CertificateStatus.Revoked) with { SerialNumber = "abcd1234" };
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: new[] { caCert });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 22);
        row.Subject.Should().Be("ident.example.com");
    }

    private static X509Certificate2 CreateLeaf(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private async Task SeedAcmeCertificateAsync(
        string serialNumber, string certificatePem, string identifiersJson)
    {
        var db = GetDb();
        var account = new AcmeAccount
        {
            AccountId = $"acct-{serialNumber}",
            JwkJson = "{}",
            JwkThumbprint = $"thumb-{serialNumber}",
        };
        var order = new AcmeOrder
        {
            OrderId = $"order-{serialNumber}",
            Account = account,
            TemplateId = "WebServer",
            IdentifiersJson = identifiersJson,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
        };
        db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = $"cert-{serialNumber}",
            Order = order,
            CertificatePem = certificatePem,
            AdcsRequestId = 999,
            SerialNumber = serialNumber,
        });
        await db.SaveChangesAsync();
    }

    public void Dispose()
    {
        foreach (var scope in _scopes)
            scope.Dispose();
        _serviceProvider.Dispose();
        _connection.Dispose();
    }
}
