using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
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
    private readonly SyncedCertificateStatementCounter _sql = new();
    private readonly List<IServiceScope> _scopes = new();

    /// <summary>
    /// Counts statements against SyncedCertificates as they go to SQLite, split
    /// into the writes and the reads.
    ///
    /// Needed because both sides of the sync's cheap path are invisible from the
    /// data. A row the CA still describes exactly as stored is never loaded and
    /// never tracked, and the one write it still earns sets the same LastSyncedAt
    /// the expensive path sets, so every assertion on the resulting row passes
    /// whether the optimisation ran or not.
    ///
    /// The two counts answer two different issues and neither stands in for the
    /// other. Updates covers issue #184: a build that went back to a full load and
    /// write per row. Reads covers issue #191, the per row FirstOrDefaultAsync,
    /// which the update count cannot see at all, because a per row read followed
    /// by the same batched ExecuteUpdate writes exactly the same statements.
    ///
    /// Statements rather than commands, because EF packs several into one command
    /// text, and that is the number both issues are about.
    ///
    /// FROM rather than SELECT is the read needle, because EF puts the projection
    /// list ahead of the table name, so a SELECT prefix could not tell one table
    /// from another. Nothing in the product deletes a SyncedCertificate, so a
    /// DELETE FROM cannot inflate the count today, and if a sweep ever adds one,
    /// counting its read of the table is the answer we want anyway.
    /// </summary>
    private sealed class SyncedCertificateStatementCounter : DbCommandInterceptor
    {
        private const string UpdateNeedle = "UPDATE \"SyncedCertificates\"";
        private const string ReadNeedle = "FROM \"SyncedCertificates\"";

        private int _updates;
        private int _reads;

        public int Updates => Volatile.Read(ref _updates);

        public int Reads => Volatile.Read(ref _reads);

        public void Reset()
        {
            Volatile.Write(ref _updates, 0);
            Volatile.Write(ref _reads, 0);
        }

        private void Count(DbCommand command)
        {
            var text = command.CommandText;
            Add(ref _updates, text, UpdateNeedle);
            Add(ref _reads, text, ReadNeedle);
        }

        private static void Add(ref int counter, string text, string needle)
        {
            var found = 0;
            for (var i = text.IndexOf(needle, StringComparison.Ordinal); i >= 0;
                 i = text.IndexOf(needle, i + needle.Length, StringComparison.Ordinal))
            {
                found++;
            }
            if (found > 0)
                Interlocked.Add(ref counter, found);
        }

        public override InterceptionResult<DbDataReader> ReaderExecuting(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
        {
            Count(command);
            return result;
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData,
            InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Count(command);
            return ValueTask.FromResult(result);
        }

        public override InterceptionResult<int> NonQueryExecuting(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
        {
            Count(command);
            return result;
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Count(command);
            return ValueTask.FromResult(result);
        }
    }

    public CertificateSyncServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        _adcs = Substitute.For<IAdcsClient>();

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(options =>
            options.UseSqlite(_connection).AddInterceptors(_sql));

        _serviceProvider = services.BuildServiceProvider();

        // Create the database schema on the shared in-memory connection.
        using var scope = _serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        db.Database.EnsureCreated();
    }

    private CertificateSyncService CreateService(int? requestHistoryDays = null)
    {
        var options = new CertusOptions();
        if (requestHistoryDays.HasValue)
            options.RequestHistoryDays = requestHistoryDays.Value;

        return new CertificateSyncService(
            _serviceProvider.GetRequiredService<IServiceScopeFactory>(),
            _adcs,
            new CertificateSyncTrigger(),
            Options.Create(options),
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

    /// <summary>
    /// Points a single request disposition (Pending, Denied, or Failed) at a
    /// fixed result set. These three are the passes the sync bounds by the
    /// history window: Pending by SubmittedAfter, Denied and Failed by
    /// ResolvedAfter (issue #187); see CertusOptions.RequestHistoryDays.
    /// </summary>
    private void SetCaRequests(CertificateStatus status, IReadOnlyList<CertificateInfo> rows)
    {
        _adcs.QueryCertificatesAsync(
                Arg.Is<CertificateQuery>(q => q.Status == status),
                Arg.Any<CancellationToken>())
            .Returns(rows);
    }

    private static CertificateInfo Cert(
        int requestId,
        string subject,
        CertificateStatus status,
        string? dispositionMessage = null,
        int? statusCode = null)
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
            RequestDate: now.AddDays(-10),
            DispositionMessage: dispositionMessage,
            StatusCode: statusCode);
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
    public async Task Sync_QueriesThePendingDisposition_BoundedBySubmittedWhen()
    {
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());

        var before = DateTime.UtcNow.AddDays(-7);
        var sut = CreateService(requestHistoryDays: 7);
        await sut.SyncCertificatesAsync(CancellationToken.None);
        var after = DateTime.UtcNow.AddDays(-7);

        // The request dispositions accumulate without limit on a busy CA, so
        // each pass must carry a time floor rather than enumerating the whole
        // table. An undecided request only has an arrival time, so the pending
        // pass floors on SubmittedWhen and must never carry a ResolvedWhen
        // bound, which would exclude every pending row (issue #187).
        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == CertificateStatus.Pending &&
                q.SubmittedAfter != null &&
                q.SubmittedAfter >= before &&
                q.SubmittedAfter <= after &&
                q.ResolvedAfter == null),
            Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(CertificateStatus.Denied)]
    [InlineData(CertificateStatus.Failed)]
    public async Task Sync_QueriesDecidedDispositions_BoundedByResolvedWhen(
        CertificateStatus status)
    {
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());

        var before = DateTime.UtcNow.AddDays(-7);
        var sut = CreateService(requestHistoryDays: 7);
        await sut.SyncCertificatesAsync(CancellationToken.None);
        var after = DateTime.UtcNow.AddDays(-7);

        // Denied and failed rows are windowed by when the CA decided, not when
        // the request arrived (issue #187): a request submitted before the
        // window and denied inside it must still be returned, or its local row
        // says Pending forever after the CA refused it. A SubmittedWhen bound
        // here was exactly that bug, so these passes must not carry one.
        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == status &&
                q.ResolvedAfter != null &&
                q.ResolvedAfter >= before &&
                q.ResolvedAfter <= after &&
                q.SubmittedAfter == null),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Sync_CertificateDispositions_AreNotTimeBounded()
    {
        // The certificate inventory is always pulled in full; only the request
        // dispositions are windowed.
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == CertificateStatus.Issued &&
                q.SubmittedAfter == null &&
                q.ResolvedAfter == null),
            Arg.Any<CancellationToken>());
        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == CertificateStatus.Revoked &&
                q.SubmittedAfter == null &&
                q.ResolvedAfter == null),
            Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task Sync_HistoryWindowOff_SkipsTheRequestDispositions(int days)
    {
        // The escape hatch for a CA whose request table is too large to sweep.
        // Zero and negative both mean off, and the behaviour reverts to exactly
        // what shipped before issue #151.
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService(requestHistoryDays: days);
        await sut.SyncCertificatesAsync(CancellationToken.None);

        await _adcs.DidNotReceive().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == CertificateStatus.Pending ||
                q.Status == CertificateStatus.Denied ||
                q.Status == CertificateStatus.Failed),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Sync_DeniedRequest_PersistsTheCaExplanation()
    {
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Denied, new[]
        {
            Cert(9, "CN=denied.example.com", CertificateStatus.Denied,
                dispositionMessage: "Denied by HOME\\admin",
                statusCode: unchecked((int)0x80094801))
        });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 9);

        row.Status.Should().Be("Denied");
        row.DispositionMessage.Should().Be("Denied by HOME\\admin");
        row.StatusCode.Should().Be(unchecked((int)0x80094801));
    }

    [Fact]
    public async Task Sync_PendingRequestApproved_ClearsTheStaleExplanation()
    {
        // The reason UpdateEntity overwrites these two straight rather than
        // guarding against nulls: once the CA manager approves, the request
        // reappears in the Issued pass and the "waiting for approval" text has
        // to go with it.
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Pending, new[]
        {
            Cert(11, "CN=pending.example.com", CertificateStatus.Pending,
                dispositionMessage: "Taken Under Submission")
        });

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        (await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 11))
            .DispositionMessage.Should().Be("Taken Under Submission");

        // Next cycle: the CA manager approved it, so it moves to the Issued pass
        // with no explanation attached.
        SetCaRequests(CertificateStatus.Pending, Array.Empty<CertificateInfo>());
        SetCaCertificates(
            issued: new[] { Cert(11, "CN=pending.example.com", CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 11);
        row.Status.Should().Be("Issued");
        row.DispositionMessage.Should().BeNull();
        row.StatusCode.Should().BeNull();
    }

    [Fact]
    public async Task Sync_UnreadableDispositionColumn_KeepsTheExplanationAlreadyCaptured()
    {
        // The column guard in AdcsClient lets a CA that stops exposing
        // DispositionMessage degrade instead of killing the sync. That
        // degradation must not also erase what a healthy pass already stored:
        // the row would then show a denied request with no reason at all, and
        // only a log warning to explain the difference.
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Denied, new[]
        {
            Cert(13, "CN=denied.example.com", CertificateStatus.Denied,
                dispositionMessage: "Denied by HOME\\admin",
                statusCode: unchecked((int)0x80094801))
        });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        // Next cycle: the column no longer resolves, so the row comes back with
        // the same disposition and nothing to say about it.
        SetCaRequests(CertificateStatus.Denied, new[]
        {
            Cert(13, "CN=denied.example.com", CertificateStatus.Denied)
        });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 13);
        row.Status.Should().Be("Denied");
        row.DispositionMessage.Should().Be("Denied by HOME\\admin");
        row.StatusCode.Should().Be(unchecked((int)0x80094801));
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
    public async Task Sync_PersistsCryptoDetailFromTheCertificateBlob()
    {
        var cert = Cert(15, "CN=crypto.example.com", CertificateStatus.Issued) with
        {
            CryptoDetail = new CertificateCryptoDetail(
                KeyAlgorithm: "ECDSA",
                KeySizeBits: 256,
                SignatureAlgorithmOid: "1.2.840.10045.4.3.2",
                Sha256Thumbprint: new string('A', 64),
                ExtendedKeyUsageOids: "1.3.6.1.5.5.7.3.1",
                KeyUsage: (int)X509KeyUsageFlags.DigitalSignature)
        };
        SetCaCertificates(issued: new[] { cert }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 15);
        row.KeyAlgorithm.Should().Be("ECDSA");
        row.KeySizeBits.Should().Be(256);
        row.SignatureAlgorithmOid.Should().Be("1.2.840.10045.4.3.2");
        row.Sha256Thumbprint.Should().Be(new string('A', 64));
        row.ExtendedKeyUsageOids.Should().Be("1.3.6.1.5.5.7.3.1");
        row.KeyUsage.Should().Be((int)X509KeyUsageFlags.DigitalSignature);
    }

    [Fact]
    public async Task Sync_ExistingRowPredatingTheFeature_IsBackfilled()
    {
        // Rows synced before these columns existed carry nulls. UpdateEntity runs
        // over every existing row on every full sync, so the next cycle fills
        // them with no re-import and no extra CA call.
        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 17,
            SerialNumber = "SERIAL0017",
            Subject = "CN=legacy.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-40),
            NotAfter = DateTime.UtcNow.AddDays(325),
            Status = "Issued",
            RequestDate = DateTime.UtcNow.AddDays(-40),
        });
        await seed.SaveChangesAsync();

        var cert = Cert(17, "CN=legacy.example.com", CertificateStatus.Issued) with
        {
            CryptoDetail = new CertificateCryptoDetail(
                KeyAlgorithm: "RSA",
                KeySizeBits: 3072,
                SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
                Sha256Thumbprint: new string('C', 64),
                ExtendedKeyUsageOids: "1.3.6.1.5.5.7.3.1",
                KeyUsage: (int)X509KeyUsageFlags.DigitalSignature)
        };
        SetCaCertificates(issued: new[] { cert }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 17);
        row.KeyAlgorithm.Should().Be("RSA");
        row.KeySizeBits.Should().Be(3072);
        row.Sha256Thumbprint.Should().Be(new string('C', 64));
    }

    [Fact]
    public async Task Sync_LaterPassWithoutCryptoDetail_KeepsWhatTheIssuedPassCaptured()
    {
        // The trap this guards. The CA can hand back a revoked row with no
        // RawCertificate blob, which parses to no crypto detail at all. If the
        // sync overwrote unconditionally, revoking a certificate would silently
        // blank every cryptographic field the issued pass had captured.
        var issued = Cert(16, "CN=survives.example.com", CertificateStatus.Issued) with
        {
            CryptoDetail = new CertificateCryptoDetail(
                KeyAlgorithm: "RSA",
                KeySizeBits: 2048,
                SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
                Sha256Thumbprint: new string('B', 64),
                ExtendedKeyUsageOids: "1.3.6.1.5.5.7.3.1",
                KeyUsage: (int)X509KeyUsageFlags.KeyEncipherment)
        };
        SetCaCertificates(issued: new[] { issued }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        // Next cycle: the same request comes back revoked, blob free.
        var revoked = Cert(16, "CN=survives.example.com", CertificateStatus.Revoked) with
        {
            RevokedWhen = DateTime.UtcNow.AddMinutes(-5),
            RevokedReason = 4,
            CryptoDetail = null
        };
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: new[] { revoked });

        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 16);
        row.Status.Should().Be("Revoked");
        row.KeyAlgorithm.Should().Be("RSA");
        row.KeySizeBits.Should().Be(2048);
        row.SignatureAlgorithmOid.Should().Be("1.2.840.113549.1.1.11");
        row.Sha256Thumbprint.Should().Be(new string('B', 64));
        row.ExtendedKeyUsageOids.Should().Be("1.3.6.1.5.5.7.3.1");
        row.KeyUsage.Should().Be((int)X509KeyUsageFlags.KeyEncipherment);
    }

    [Fact]
    public async Task Sync_PersistsTheCertificateDerForDownload()
    {
        var der = TestDer(1);
        var issued = Cert(30, "CN=downloadable.example.com", CertificateStatus.Issued) with
        {
            RawCertificate = der
        };
        SetCaCertificates(issued: new[] { issued }, revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 30);
        row.RawCertificate.Should().Equal(der);
    }

    [Fact]
    public async Task Sync_RowWithNoCertificateBlob_StoresNullAndKeepsItsSiblings()
    {
        // A pending request has no certificate, and a CA pass can hand back an
        // issued row without one. Neither may take the rest of the sync down.
        var withBlob = Cert(31, "CN=has-blob.example.com", CertificateStatus.Issued) with
        {
            RawCertificate = TestDer(2)
        };
        var withoutBlob = Cert(32, "CN=no-blob.example.com", CertificateStatus.Issued);
        SetCaCertificates(
            issued: new[] { withBlob, withoutBlob },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        (await db.SyncedCertificates.SingleAsync(c => c.RequestId == 31))
            .RawCertificate.Should().NotBeNull();
        (await db.SyncedCertificates.SingleAsync(c => c.RequestId == 32))
            .RawCertificate.Should().BeNull();
    }

    [Fact]
    public async Task Sync_LaterPassWithoutTheDer_KeepsTheStoredCertificate()
    {
        // Same trap as the crypto detail above, and the reason the download has
        // to answer for revoked certificates at all: the revoked pass routinely
        // arrives with no blob, and overwriting would delete the only copy of
        // the certificate the moment it is revoked.
        var der = TestDer(3);
        var issued = Cert(33, "CN=revoke-me.example.com", CertificateStatus.Issued) with
        {
            RawCertificate = der
        };
        SetCaCertificates(issued: new[] { issued }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var revoked = Cert(33, "CN=revoke-me.example.com", CertificateStatus.Revoked) with
        {
            RevokedWhen = DateTime.UtcNow.AddMinutes(-5),
            RevokedReason = 1,
            RawCertificate = null
        };
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: new[] { revoked });

        await sut.SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var row = await db.SyncedCertificates.SingleAsync(c => c.RequestId == 33);
        row.Status.Should().Be("Revoked");
        row.RawCertificate.Should().Equal(der);
    }

    [Fact]
    public async Task Sync_BackfillsTheDerOnARowThatHasNone()
    {
        // The upgrade path. Every row synced before the column existed has a
        // null there, and the first pass that carries a blob fills it in with
        // no migration data step and no extra CA call.
        var withoutBlob = Cert(34, "CN=backfill.example.com", CertificateStatus.Issued);
        SetCaCertificates(issued: new[] { withoutBlob }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);
        (await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 34))
            .RawCertificate.Should().BeNull();

        var der = TestDer(4);
        SetCaCertificates(
            issued: new[] { withoutBlob with { RawCertificate = der } },
            revoked: Array.Empty<CertificateInfo>());

        await sut.SyncCertificatesAsync(CancellationToken.None);

        (await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 34))
            .RawCertificate.Should().Equal(der);
    }

    [Fact]
    public async Task Sync_SecondPass_DoesNotRewriteTheStoredDer()
    {
        // Write once, and the reason for it. Every CA pass decodes a fresh
        // byte[] from base64, so reassigning would hand the change tracker a
        // new array instance for every certificate on every cycle and risk an
        // UPDATE across the whole table on a sync that changed nothing. The
        // stored bytes are also asserted to survive a pass that carries
        // different ones, since a certificate's own DER never legitimately
        // changes and the stored copy is the one already handed to admins.
        var original = TestDer(5);
        var issued = Cert(35, "CN=write-once.example.com", CertificateStatus.Issued) with
        {
            RawCertificate = original
        };
        SetCaCertificates(issued: new[] { issued }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        SetCaCertificates(
            issued: new[] { issued with { RawCertificate = TestDer(6) } },
            revoked: Array.Empty<CertificateInfo>());
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 35);
        row.RawCertificate.Should().Equal(original);
    }

    /// <summary>
    /// Stand in certificate bytes. The sync never inspects them, it only stores
    /// what the client says decoded, so a distinguishable byte pattern is
    /// enough here and keeps these tests off the key generation path. The
    /// endpoints that do parse the bytes are covered by the web integration
    /// tests, against a real self signed certificate.
    /// </summary>
    private static byte[] TestDer(byte seed) => Enumerable.Repeat(seed, 32).ToArray();

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

    // ---- Releasing a hold clears the ACME stamp too (issue #375) ----------
    //
    // The test above covers the inventory row, which has always healed itself.
    // These cover the other row, AcmeCertificates.RevokedAt, which nothing
    // healed: renewalInfo answered a renew now window off that stamp for the
    // certificate's whole remaining life, and revoke-cert kept refusing as
    // alreadyRevoked.
    //
    // Five of the six are refusals, because the costly mistake here is clearing
    // a stamp that should have stood. Each one holds exactly one term of the
    // predicate and passes only because of it, so reverting that term fails it.

    private const int HeldRequestId = 30;

    /// <summary>
    /// An ACME certificate bridged to a CA request id, carrying a revocation
    /// stamp unless <paramref name="revokedAt"/> says otherwise. Separate from
    /// <see cref="SeedAcmeCertificateAsync"/>, which fixes the request id at 999
    /// because its own tests bridge on the serial instead.
    /// </summary>
    private async Task SeedBridgedAcmeCertificateAsync(
        int adcsRequestId, DateTime? revokedAt, int? revokedReason = 6)
    {
        var db = GetDb();
        var account = new AcmeAccount
        {
            AccountId = $"acct-{adcsRequestId}",
            JwkJson = "{}",
            JwkThumbprint = $"thumb-{adcsRequestId}",
        };
        var order = new AcmeOrder
        {
            OrderId = $"order-{adcsRequestId}",
            Account = account,
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = "[]",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CertificateId = $"cert-{adcsRequestId}",
        };
        db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = $"cert-{adcsRequestId}",
            Order = order,
            CertificatePem = "pem",
            AdcsRequestId = adcsRequestId,
            SerialNumber = $"SERIAL{adcsRequestId:D4}",
            RevokedAt = revokedAt,
            RevokedReason = revokedAt == null ? null : revokedReason,
        });
        await db.SaveChangesAsync();
    }

    /// <summary>The inventory row the bridge lands on, as a held certificate.</summary>
    private async Task SeedHeldInventoryRowAsync(
        int requestId, string status = "Revoked", DateTime? lastSyncedAt = null)
    {
        var db = GetDb();
        db.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = requestId,
            SerialNumber = $"SERIAL{requestId:D4}",
            Subject = "CN=held.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-30),
            NotAfter = DateTime.UtcNow.AddDays(335),
            Status = status,
            RequestDate = DateTime.UtcNow.AddDays(-30),
            RevokedAt = status == "Revoked" ? DateTime.UtcNow.AddDays(-7) : null,
            RevokedReason = status == "Revoked" ? 6 : null,
            LastSyncedAt = lastSyncedAt ?? DateTime.UtcNow,
        });
        await db.SaveChangesAsync();
    }

    private async Task<AcmeCertificate> ReadBridgedAcmeCertificateAsync(int adcsRequestId)
    {
        var db = GetDb();
        return await db.AcmeCertificates.AsNoTracking()
            .SingleAsync(a => a.AdcsRequestId == adcsRequestId);
    }

    [Fact]
    public async Task Sync_CertReleasedFromHold_ClearsTheAcmeStamp()
    {
        // The fix itself. The CA reports the held certificate issued again, so
        // the stamp the revocation left is no longer the CA's answer.
        await SeedHeldInventoryRowAsync(HeldRequestId);
        await SeedBridgedAcmeCertificateAsync(HeldRequestId, DateTime.UtcNow.AddDays(-7));

        SetCaCertificates(
            issued: new[] { Cert(HeldRequestId, "CN=held.example.com", CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var acme = await ReadBridgedAcmeCertificateAsync(HeldRequestId);
        acme.RevokedAt.Should().BeNull();
        acme.RevokedReason.Should().BeNull();
    }

    [Fact]
    public async Task Sync_CertStillRevokedAtTheCa_KeepsTheAcmeStamp()
    {
        // The ordinary case, and the one that must never move: the CA still
        // reports the certificate revoked, so the stamp is still its answer.
        var stampedAt = DateTime.UtcNow.AddDays(-7);
        await SeedHeldInventoryRowAsync(HeldRequestId);
        await SeedBridgedAcmeCertificateAsync(HeldRequestId, stampedAt);

        SetCaCertificates(
            issued: Array.Empty<CertificateInfo>(),
            revoked: new[] { Cert(HeldRequestId, "CN=held.example.com", CertificateStatus.Revoked) });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var acme = await ReadBridgedAcmeCertificateAsync(HeldRequestId);
        acme.RevokedAt.Should().NotBeNull();
        acme.RevokedReason.Should().Be(6);
    }

    [Fact]
    public async Task Sync_IssuedRowStillCarryingARevocationInstant_KeepsTheAcmeStamp()
    {
        // Holds the inventory RevokedAt term, which the Issued allow list does
        // not already cover. UpdateEntity writes the disposition and the
        // revocation instant from the CA independently, so a CA that reports a
        // row issued while still carrying a revocation instant produces a row
        // that is Issued and freshly synced and yet contradicts itself. It is
        // not the unambiguous release this repair requires.
        await SeedHeldInventoryRowAsync(HeldRequestId);
        await SeedBridgedAcmeCertificateAsync(HeldRequestId, DateTime.UtcNow.AddDays(-7));

        var contradictory = Cert(HeldRequestId, "CN=held.example.com", CertificateStatus.Issued)
            with { RevokedWhen = DateTime.UtcNow.AddDays(-7) };
        SetCaCertificates(issued: new[] { contradictory }, revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var inventory = await GetDb().SyncedCertificates
            .AsNoTracking().SingleAsync(s => s.RequestId == HeldRequestId);
        inventory.Status.Should().Be("Issued", "the row has to be the contradictory shape to test");
        inventory.RevokedAt.Should().NotBeNull("the row has to be the contradictory shape to test");

        var acme = await ReadBridgedAcmeCertificateAsync(HeldRequestId);
        acme.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task Sync_RowTheCaDidNotReturn_KeepsTheAcmeStamp()
    {
        // Holds the LastSyncedAt term. The inventory row already looks released
        // (Issued, no revocation) and the ACME row is still stamped, which is
        // exactly the stuck state this repair exists for. It is still refused,
        // because the CA said nothing about it this cycle and a stale row is
        // not evidence. Repair waits for the CA to confirm.
        await SeedHeldInventoryRowAsync(
            HeldRequestId, status: "Issued", lastSyncedAt: DateTime.UtcNow.AddDays(-1));
        await SeedBridgedAcmeCertificateAsync(HeldRequestId, DateTime.UtcNow.AddDays(-7));

        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var acme = await ReadBridgedAcmeCertificateAsync(HeldRequestId);
        acme.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task Sync_RequestRowDisposition_KeepsTheAcmeStamp()
    {
        // Holds the Issued allow list. The CA returns the request id in a
        // disposition that carries no live certificate, so it says nothing
        // about whether the certificate is revoked and must clear nothing.
        // Written against Denied rather than "not Revoked" so a disposition
        // added later inherits the refusal.
        await SeedHeldInventoryRowAsync(HeldRequestId);
        await SeedBridgedAcmeCertificateAsync(HeldRequestId, DateTime.UtcNow.AddDays(-7));

        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Denied,
            new[] { RequestRow(HeldRequestId, CertificateStatus.Denied) });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var acme = await ReadBridgedAcmeCertificateAsync(HeldRequestId);
        acme.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task Sync_AcmeRowWithNoCaRequestId_KeepsTheAcmeStamp()
    {
        // Holds the identity guard. An unset request id selects by an unset
        // value rather than by identity, so a freshly issued row that also
        // carries request id zero must not reach across to it.
        await SeedBridgedAcmeCertificateAsync(adcsRequestId: 0, DateTime.UtcNow.AddDays(-7));

        SetCaCertificates(
            issued: new[] { Cert(0, "CN=unrelated.example.com", CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var acme = await ReadBridgedAcmeCertificateAsync(0);
        acme.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task Sync_RevocationLandingMidCycle_KeepsTheAcmeStamp()
    {
        // Holds the passesStartedAt term, and the reason it is not merely
        // defensive. The CA answered "issued" for this certificate, and only
        // afterwards did a revocation land and stamp the row. That CA reading
        // predates the revocation, so it is not evidence about it, and clearing
        // on it would silently undo a revocation the CA has already performed.
        //
        // The stamp is written from a second scope while the issued pass is
        // being answered, which is where a real revoke-cert would write it.
        await SeedHeldInventoryRowAsync(HeldRequestId, status: "Issued");
        await SeedBridgedAcmeCertificateAsync(HeldRequestId, revokedAt: null);

        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: Array.Empty<CertificateInfo>());
        _adcs.QueryCertificatesAsync(
                Arg.Is<CertificateQuery>(q => q.Status == CertificateStatus.Issued),
                Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                var db = GetDb();
                var row = db.AcmeCertificates.Single(a => a.AdcsRequestId == HeldRequestId);
                row.RevokedAt = DateTime.UtcNow;
                row.RevokedReason = 1;
                db.SaveChanges();

                return (IReadOnlyList<CertificateInfo>)new[]
                {
                    Cert(HeldRequestId, "CN=held.example.com", CertificateStatus.Issued),
                };
            });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var acme = await ReadBridgedAcmeCertificateAsync(HeldRequestId);
        acme.RevokedAt.Should().NotBeNull("a revocation the CA data predates must survive the sweep");
        acme.RevokedReason.Should().Be(1);
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

    // ---- Request row names from the ACME store (issue #186) ---------------

    /// <summary>
    /// A CA request row in the shape the request dispositions actually arrive
    /// in: no serial number, because nothing was issued, and by default no
    /// subject, because an ACME CSR carries no subject DN and the CA's request
    /// subject columns are then empty too. This is the row issue #186 is about.
    /// </summary>
    private static CertificateInfo RequestRow(
        int requestId, CertificateStatus status, string subject = "") =>
        Cert(requestId, subject, status) with { SerialNumber = "" };

    [Theory]
    [InlineData(CertificateStatus.Pending)]
    [InlineData(CertificateStatus.Denied)]
    [InlineData(CertificateStatus.Failed)]
    public async Task Sync_RequestRowWithNoName_TakesItFromTheAcmeOrder(CertificateStatus status)
    {
        // The serial match cannot reach these rows, so before the order lookup
        // they rendered as "Request 40" and an admin filtering to Denied could
        // not tell which stuck enrolment an explanation belonged to.
        await SeedAcmeOrderAsync(40, """[{"type":"dns","value":"acme.example.com"}]""");

        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(status, new[] { RequestRow(40, status) });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 40);
        row.Subject.Should().Be("acme.example.com");
    }

    [Fact]
    public async Task Sync_DeviceAttestationOrder_NamesTheRequestByItsPermanentIdentifier()
    {
        // FirstIdentifier reads the value whatever the identifier type is, so a
        // device order names its request by the device serial with no extra
        // handling.
        await SeedAcmeOrderAsync(41,
            """[{"type":"permanent-identifier","value":"F4GTX9K2LM"}]""");

        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Pending,
            new[] { RequestRow(41, CertificateStatus.Pending) });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 41);
        row.Subject.Should().Be("F4GTX9K2LM");
    }

    // ---- Subject sanitizing at the entity writers (issue #224) ------------

    [Fact]
    public async Task Sync_PoisonedSubjectFromTheClient_IsSanitizedOnTheWayIn()
    {
        // The client interface, not the real client. AdcsClient sanitizes what it
        // reads from the CA, but MockAdcsClient signs the CSR subject verbatim and
        // is registered as a real IAdcsClient in both hosts, so the guard has to
        // hold at the writer rather than only in one implementation.
        var rlo = (char)0x202e;

        SetCaCertificates(
            issued: new[] { Cert(50, "CN=" + rlo + "moc.live", CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 50);
        row.Subject.Should().Be("CN=moc.live");
    }

    [Fact]
    public async Task Sync_OverWideSubject_IsBoundedToTheColumn()
    {
        // SQLite does not enforce the declared width, so nothing downstream of
        // here would refuse it, and the column is indexed.
        SetCaCertificates(
            issued: new[] { Cert(51, "CN=" + new string('x', 9000), CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 51);
        row.Subject.Should().HaveLength(CertificateTextSanitizer.MaxSubjectLength);
    }

    [Fact]
    public async Task Sync_ExistingPoisonedRow_IsRewrittenOnTheNextPass()
    {
        // Why issue #224 needs no explicit backfill for the common case: the
        // issued and revoked passes read the whole CA every cycle and overwrite
        // the subject in place, so rows that synced before the fix heal on the
        // next sync. The rows this does not reach are covered by the startup
        // sweep in DatabaseInitializer instead.
        var rlo = (char)0x202e;

        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 52,
            SerialNumber = "SERIAL0052",
            Subject = "CN=" + rlo + "moc.live",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-30),
            NotAfter = DateTime.UtcNow.AddDays(335),
            Status = "Issued",
            RequestDate = DateTime.UtcNow.AddDays(-30),
        });
        await seed.SaveChangesAsync();

        SetCaCertificates(
            issued: new[] { Cert(52, "CN=" + rlo + "moc.live", CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 52);
        row.Subject.Should().Be("CN=moc.live");
    }

    // ---- The template column takes the same guard (issue #378) ------------
    //
    // A different exposure from the subject above it, although the same strip:
    // this value is compared by RevocationEligibilityService and carried out of
    // the process by the expiry mail and the webhook notifier, so it is not only
    // a screen.

    /// <summary>A CA row whose template carries the poison, subject clean.</summary>
    private static CertificateInfo WithTemplate(int requestId, string templateName) =>
        Cert(requestId, $"CN=tmpl{requestId:D4}.example.com", CertificateStatus.Issued)
            with { TemplateName = templateName };

    [Fact]
    public async Task Sync_PoisonedTemplateFromTheClient_IsSanitizedOnTheWayIn()
    {
        // The client interface, not the real client, for the reason the subject
        // test above gives: AdcsClient strips what it reads, but MockAdcsClient
        // is a real IAdcsClient in both hosts and does not, so the guard has to
        // hold at the writer.
        var rlo = (char)0x202e;

        SetCaCertificates(
            issued: new[] { WithTemplate(60, "Web" + rlo + "Server") },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 60);
        row.TemplateName.Should().Be("WebServer");
    }

    [Fact]
    public async Task Sync_OverWideTemplate_IsBoundedToTheColumn()
    {
        // SQLite does not enforce the declared width, and this column is indexed.
        SetCaCertificates(
            issued: new[] { WithTemplate(61, new string('x', 9000)) },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 61);
        row.TemplateName.Should().HaveLength(CertificateTextSanitizer.MaxTemplateNameLength);
    }

    [Fact]
    public async Task Sync_TemplateThatSanitizesAwayEntirely_StoresTheEmptyString()
    {
        // The column is declared required, and the sanitizer answers null when
        // nothing usable survives, so the writer has to coalesce or the sync
        // faults on a row the CA is perfectly happy with.
        SetCaCertificates(
            issued: new[] { WithTemplate(62, "\u202e\u200b\u2028") },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 62);
        row.TemplateName.Should().BeEmpty();
    }

    [Fact]
    public async Task Sync_ExistingPoisonedTemplateRow_IsRewrittenOnTheNextPass()
    {
        // Why this needs no startup sweep where issue #224 needed one for
        // subjects: IsUnchanged compares the stored value against the sanitized
        // incoming one, so a row stored before this fix reads as changed exactly
        // once, is rewritten clean, and is cheap from then on.
        var rlo = (char)0x202e;

        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 63,
            SerialNumber = "SERIAL0063",
            Subject = "CN=tmpl0063.example.com",
            TemplateName = "Web" + rlo + "Server",
            NotBefore = DateTime.UtcNow.AddDays(-30),
            NotAfter = DateTime.UtcNow.AddDays(335),
            Status = "Issued",
            RequestDate = DateTime.UtcNow.AddDays(-30),
        });
        await seed.SaveChangesAsync();

        SetCaCertificates(
            issued: new[] { WithTemplate(63, "Web" + rlo + "Server") },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 63);
        row.TemplateName.Should().Be("WebServer");
    }

    [Fact]
    public async Task Sync_PoisonedTemplateSteadyState_StillTakesTheCheapPath()
    {
        // The half the assertions above cannot make, and the reason IsUnchanged
        // sanitizes the incoming value rather than comparing it raw. The stored
        // name is clean and the CA keeps handing back the poisoned one, so a raw
        // comparison calls every row changed on every cycle, for ever: the row is
        // loaded, rewritten, and reported as moved, which is exactly the per row
        // cost issue #184 removed. The data cannot show it, because both paths
        // leave the same clean value behind.
        var rlo = (char)0x202e;
        const int rows = 250;
        var issued = Enumerable.Range(1, rows)
            .Select(i => FullyDetailed(i, $"CN=poison{i:D4}.example.com")
                with { TemplateName = "Web" + rlo + "Server" })
            .ToArray();
        SetCaCertificates(issued: issued, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        _sql.Reset();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        _sql.Updates.Should().BeGreaterThan(0, "the rows were still seen");
        _sql.Updates.Should().BeLessThan(10,
            "the poisoned name sanitizes to what is already stored, so nothing moved");
        (await GetDb().SyncedCertificates.CountAsync(c => c.TemplateName == "WebServer"))
            .Should().Be(rows);
    }

    [Fact]
    public async Task Sync_EmptySubjectRow_SanitizesTheBackfilledPemSubject()
    {
        // The ACME backfill reads X509Certificate2.Subject off a leaf this proxy
        // issued, which passes format characters through untouched.
        var rlo = (char)0x202e;
        using var leaf = CreateLeaf("CN=" + rlo + "moc.live");
        var caSerial = leaf.SerialNumber.TrimStart('0').ToLowerInvariant();

        await SeedAcmeCertificateAsync(leaf.SerialNumber, leaf.ExportCertificatePem(),
            identifiersJson: "[]");

        var caCert = Cert(53, "", CertificateStatus.Revoked) with { SerialNumber = caSerial };
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(), revoked: new[] { caCert });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 53);
        row.Subject.Should().Be("CN=moc.live");
    }

    [Fact]
    public async Task Sync_DeviceAttestationOrder_SanitizesThePermanentIdentifier()
    {
        // A gap worth its own test: PermanentIdentifierValue refuses control
        // characters but says nothing about the format class the bidirectional
        // overrides live in, so this identifier passes validation at newOrder and
        // arrives here intact.
        var rlo = (char)0x202e;

        await SeedAcmeOrderAsync(54,
            $$"""[{"type":"permanent-identifier","value":"{{rlo}}F4GTX9K2LM"}]""");

        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Pending,
            new[] { RequestRow(54, CertificateStatus.Pending) });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 54);
        row.Subject.Should().Be("F4GTX9K2LM");
    }

    [Fact]
    public async Task Sync_RequestRowTheCaNamed_KeepsTheCaName()
    {
        // The precedence guard for the local fallback. Whatever the CA's own
        // request subject columns supplied is authoritative; the order
        // identifiers only fill a gap, and must never overwrite.
        await SeedAcmeOrderAsync(42, """[{"type":"dns","value":"order.example.com"}]""");

        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Denied,
            new[] { RequestRow(42, CertificateStatus.Denied, "CN=from-the-ca.example.com") });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 42);
        row.Subject.Should().Be("CN=from-the-ca.example.com");
    }

    [Fact]
    public async Task Sync_RequestRowWithNoMatchingOrder_SyncsWithAnEmptySubject()
    {
        // A request that did not come from ACME at all, and whose CSR carried no
        // subject either. Nothing can name it, and that has to stay survivable:
        // the row still syncs, and the dashboard falls back to "Request 43".
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Denied,
            new[] { RequestRow(43, CertificateStatus.Denied) });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 43);
        row.Subject.Should().BeEmpty();
    }

    [Fact]
    public async Task Sync_OrderThatNeverReachedTheCa_DoesNotNameAnUnrelatedRequest()
    {
        // AdcsRequestId is null until the order is submitted. A null must not
        // match a request row, or an abandoned order would hand its name to
        // whichever unrelated request happened to be nameless.
        await SeedAcmeOrderAsync(44, """[{"type":"dns","value":"never-submitted.example.com"}]""",
            submitted: false);

        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Denied,
            new[] { RequestRow(44, CertificateStatus.Denied) });

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 44);
        row.Subject.Should().BeEmpty();
    }

    /// <summary>
    /// Seeds an ACME order that reached the CA but produced no certificate: the
    /// shape a pending or denied order is left in.
    /// </summary>
    private async Task SeedAcmeOrderAsync(
        int orderKey, string identifiersJson, bool submitted = true)
    {
        var db = GetDb();
        var account = new AcmeAccount
        {
            AccountId = $"acct-req-{orderKey}",
            JwkJson = "{}",
            JwkThumbprint = $"thumb-req-{orderKey}",
        };
        db.AcmeOrders.Add(new AcmeOrder
        {
            OrderId = $"order-req-{orderKey}",
            Account = account,
            TemplateId = "WebServer",
            IdentifiersJson = identifiersJson,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            Status = "processing",
            // Null until the order is actually submitted to ADCS.
            AdcsRequestId = submitted ? orderKey : null,
        });
        await db.SaveChangesAsync();
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
        // "valid" with a matching CertificateId is the only shape a stored certificate
        // can have in production; see the same note in CertificateQueryServiceTests
        // (issue #318).
        var order = new AcmeOrder
        {
            OrderId = $"order-{serialNumber}",
            Account = account,
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = identifiersJson,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CertificateId = $"cert-{serialNumber}",
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

    // ---- Supersession linking (issue #154) -------------------------------

    [Fact]
    public async Task Sync_LinksSupersessionAcrossRowsFromTheSameCycle()
    {
        var older = CertWithNames(1, "dns:app.example.com", new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var newer = CertWithNames(2, "dns:app.example.com", new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        SetCaCertificates(new[] { older, newer }, Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var rows = await db.SyncedCertificates.OrderBy(c => c.RequestId).ToListAsync();
        rows.Should().HaveCount(2);
        rows[0].SupersededByCertificateId.Should().Be(rows[1].Id);
        rows[1].SupersededByCertificateId.Should().BeNull();
    }

    [Fact]
    public async Task Sync_BackfillsSupersessionOnRowsThatPredateTheColumn()
    {
        // A row synced before the feature existed carries no link. The pass
        // rebuilds the whole map every cycle, so it is picked up for free rather
        // than needing a one-off migration step.
        var seedDb = GetDb();
        seedDb.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 1,
            SerialNumber = "SERIAL0001",
            Subject = "",
            SubjectAlternativeNames = "dns:app.example.com",
            TemplateName = "WebServer",
            NotBefore = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Status = "Issued",
            RequestDate = new DateTime(2023, 12, 31, 0, 0, 0, DateTimeKind.Utc),
            SupersededByCertificateId = null
        });
        await seedDb.SaveChangesAsync();

        var newer = CertWithNames(2, "dns:app.example.com", new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        SetCaCertificates(new[] { newer }, Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        var rows = await db.SyncedCertificates.OrderBy(c => c.RequestId).ToListAsync();
        rows.Should().HaveCount(2);
        rows[0].SupersededByCertificateId.Should().Be(rows[1].Id);
    }

    /// <summary>A CA row with a chosen SAN list and issue date.</summary>
    private static CertificateInfo CertWithNames(int requestId, string sans, DateTime notBefore)
    {
        return new CertificateInfo(
            RequestId: requestId,
            SerialNumber: $"SERIAL{requestId:D4}",
            Subject: "",
            SubjectAlternativeNames: sans,
            TemplateName: "WebServer",
            NotBefore: notBefore,
            NotAfter: notBefore.AddYears(1),
            Status: CertificateStatus.Issued,
            Requestor: "HOME\\admin",
            RequestDate: notBefore.AddDays(-1));
    }

    // ---- Sync attempt recording (issue #157) -----------------------------

    private static CaUnavailableException CaDown()
        => new("simulated CA outage",
            new COMException("RPC server unavailable",
                CaUnavailableException.RpcServerUnavailableHResult));

    private static CaAccessDeniedException CaDenied()
        => new(CaAccessDeniedException.SyncReadPermissionMessage,
            new COMException("access denied",
                CaAccessDeniedException.AccessDeniedHResult));

    [Fact]
    public async Task Sync_CaUnavailable_PropagatesAndRecordsTheAttempt()
    {
        // Before issue #157 the per pass catch swallowed this, the sync
        // reported success with zero counts, and the manual sync endpoint's
        // 503 mapping was unreachable.
        _adcs.QueryCertificatesAsync(Arg.Any<CertificateQuery>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException<IReadOnlyList<CertificateInfo>>(CaDown()));

        var sut = CreateService();
        var act = () => sut.SyncCertificatesAsync(CancellationToken.None);
        await act.Should().ThrowAsync<CaUnavailableException>();

        sut.LastAttempt.Should().NotBeNull();
        sut.LastAttempt!.Outcome.Should().Be(CertificateSyncOutcome.CaUnavailable);
        sut.LastAttempt.Message.Should().Be("simulated CA outage");
        sut.LastAttempt.Result.Should().BeNull();
        sut.LastSuccess.Should().BeNull();
    }

    [Fact]
    public async Task Sync_CaAccessDenied_PropagatesAndRecordsTheAttempt()
    {
        _adcs.QueryCertificatesAsync(Arg.Any<CertificateQuery>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException<IReadOnlyList<CertificateInfo>>(CaDenied()));

        var sut = CreateService();
        var act = () => sut.SyncCertificatesAsync(CancellationToken.None);
        await act.Should().ThrowAsync<CaAccessDeniedException>();

        sut.LastAttempt.Should().NotBeNull();
        sut.LastAttempt!.Outcome.Should().Be(CertificateSyncOutcome.CaAccessDenied);
        // The remediation text the sync endpoint hands to the dashboard.
        sut.LastAttempt.Message.Should().Be(CaAccessDeniedException.SyncReadPermissionMessage);
        sut.LastSuccess.Should().BeNull();
    }

    [Fact]
    public async Task Sync_RequestPassFailure_ContinuesAndRecordsSuccess()
    {
        // PR #185's stance, preserved: a CA build refusing the mixed operator
        // request query must not cost the certificate inventory. Only the two
        // typed CA level exceptions propagate out of the pass loop.
        SetCaCertificates(
            issued: new[] { Cert(31, "CN=survives.example.com", CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());
        _adcs.QueryCertificatesAsync(
                Arg.Is<CertificateQuery>(q => q.Status == CertificateStatus.Pending),
                Arg.Any<CancellationToken>())
            .Returns(Task.FromException<IReadOnlyList<CertificateInfo>>(
                new InvalidOperationException("query shape refused")));

        var sut = CreateService(requestHistoryDays: 7);
        var result = await sut.SyncCertificatesAsync(CancellationToken.None);

        result.Processed.Should().Be(1);
        sut.LastAttempt!.Outcome.Should().Be(CertificateSyncOutcome.Success);
        (await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 31))
            .Status.Should().Be("Issued");
        // The passes after the failing one still ran.
        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q => q.Status == CertificateStatus.Failed),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Sync_Success_RecordsLastAttemptAndLastSuccessWithCounts()
    {
        SetCaCertificates(
            issued: new[] { Cert(33, "CN=recorded.example.com", CertificateStatus.Issued) },
            revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        var result = await sut.SyncCertificatesAsync(CancellationToken.None);

        sut.LastAttempt.Should().NotBeNull();
        sut.LastAttempt!.Outcome.Should().Be(CertificateSyncOutcome.Success);
        sut.LastAttempt.Message.Should().BeNull();
        sut.LastAttempt.Result.Should().Be(result);
        // The same record: a successful attempt is its own last success.
        sut.LastSuccess.Should().BeSameAs(sut.LastAttempt);
    }

    [Fact]
    public async Task Sync_Cancellation_RecordsNoAttempt()
    {
        // Shutdown and client disconnect are not outcomes the operator should
        // see on the dashboard.
        _adcs.QueryCertificatesAsync(Arg.Any<CertificateQuery>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException<IReadOnlyList<CertificateInfo>>(
                new OperationCanceledException()));

        var sut = CreateService();
        var act = () => sut.SyncCertificatesAsync(CancellationToken.None);
        await act.Should().ThrowAsync<OperationCanceledException>();

        sut.LastAttempt.Should().BeNull();
        sut.LastSuccess.Should().BeNull();
    }

    // ── Skipping work for rows already captured (issue #184) ────────────

    /// <summary>
    /// A certificate reading with everything the DER parse produces, so a row
    /// synced from it satisfies every term of the skip predicate.
    /// </summary>
    private static CertificateInfo FullyDetailed(int requestId, string subject) =>
        Cert(requestId, subject, CertificateStatus.Issued) with
        {
            SubjectAlternativeNames = "dns:full.example.com",
            CryptoDetail = new CertificateCryptoDetail(
                KeyAlgorithm: "RSA",
                KeySizeBits: 2048,
                SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
                Sha256Thumbprint: $"THUMB{requestId:D4}",
                ExtendedKeyUsageOids: "1.3.6.1.5.5.7.3.1",
                KeyUsage: 5),
            RawCertificate = TestDer((byte)requestId)
        };

    [Fact]
    public async Task Sync_AsksTheCaToSkipDetailForARowAlreadyFullyDetailed()
    {
        // The whole point of the issue: the sweep re-parsed every certificate
        // the CA had ever issued on every interval tick, to reproduce values
        // that were stored the first time and cannot legitimately change.
        var cert = FullyDetailed(50, "CN=detailed.example.com");
        SetCaCertificates(issued: new[] { cert }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        // First cycle created the row, so it could not have been in the set.
        await _adcs.Received(1).QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == CertificateStatus.Issued &&
                (q.AlreadyDetailed == null || !q.AlreadyDetailed.Contains(50))),
            Arg.Any<CancellationToken>());

        await sut.SyncCertificatesAsync(CancellationToken.None);

        await _adcs.Received(1).QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == CertificateStatus.Issued &&
                q.AlreadyDetailed != null &&
                q.AlreadyDetailed.Contains(50)),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Sync_StillParsesARowStoredBeforeTheDerColumnExisted()
    {
        // The trap the obvious version of this optimisation falls into. The
        // crypto columns and the DER column arrived in separate migrations four
        // days apart, so a database that synced between them holds a row with
        // full crypto detail and a null blob. Skipping it on the strength of its
        // crypto columns would strand it with nothing to download, for ever,
        // because the write once assignment in UpdateEntity is the only thing
        // that ever fills that column.
        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 51,
            SerialNumber = "SERIAL0051",
            Subject = "CN=preblob.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-10),
            NotAfter = DateTime.UtcNow.AddDays(355),
            Status = "Issued",
            RequestDate = DateTime.UtcNow.AddDays(-10),
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithmOid = "1.2.840.113549.1.1.11",
            Sha256Thumbprint = "THUMB0051",
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1",
            KeyUsage = 5,
            RawCertificate = null
        });
        await seed.SaveChangesAsync();

        var der = TestDer(51);
        SetCaCertificates(
            issued: new[] { FullyDetailed(51, "CN=preblob.example.com") with { RawCertificate = der } },
            revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == CertificateStatus.Issued &&
                (q.AlreadyDetailed == null || !q.AlreadyDetailed.Contains(51))),
            Arg.Any<CancellationToken>());

        (await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 51))
            .RawCertificate.Should().Equal(der);
    }

    [Fact]
    public async Task Sync_StillParsesARowWhoseSubjectIsStillBlank()
    {
        // The parsed subject is the last link in the chain that names a row, so
        // a row the CA has never managed to name has to keep being offered it.
        var seed = GetDb();
        seed.SyncedCertificates.Add(new SyncedCertificate
        {
            RequestId = 52,
            SerialNumber = "SERIAL0052",
            Subject = "",
            TemplateName = "WebServer",
            NotBefore = DateTime.UtcNow.AddDays(-10),
            NotAfter = DateTime.UtcNow.AddDays(355),
            Status = "Issued",
            RequestDate = DateTime.UtcNow.AddDays(-10),
            Sha256Thumbprint = "THUMB0052",
            RawCertificate = TestDer(52)
        });
        await seed.SaveChangesAsync();

        SetCaCertificates(issued: new[] { FullyDetailed(52, "") }, revoked: Array.Empty<CertificateInfo>());

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        await _adcs.Received().QueryCertificatesAsync(
            Arg.Is<CertificateQuery>(q =>
                q.Status == CertificateStatus.Issued &&
                (q.AlreadyDetailed == null || !q.AlreadyDetailed.Contains(52))),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Sync_SkippedRow_KeepsTheDetailTheFirstPassCaptured()
    {
        // What a skipped pass looks like coming back: null SANs, null crypto,
        // null blob, and a subject the CA database columns could not supply.
        // That is the same shape a row whose blob was missing has always had,
        // and every writer in UpdateEntity already guards against it.
        var cert = FullyDetailed(53, "CN=survives.example.com");
        SetCaCertificates(issued: new[] { cert }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        SetCaCertificates(
            issued: new[]
            {
                cert with
                {
                    Subject = "",
                    SubjectAlternativeNames = null,
                    CryptoDetail = null,
                    RawCertificate = null
                }
            },
            revoked: Array.Empty<CertificateInfo>());
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 53);
        row.Subject.Should().Be("CN=survives.example.com");
        row.SubjectAlternativeNames.Should().Be("dns:full.example.com");
        row.KeyAlgorithm.Should().Be("RSA");
        row.KeySizeBits.Should().Be(2048);
        row.SignatureAlgorithmOid.Should().Be("1.2.840.113549.1.1.11");
        row.Sha256Thumbprint.Should().Be("THUMB0053");
        row.ExtendedKeyUsageOids.Should().Be("1.3.6.1.5.5.7.3.1");
        row.KeyUsage.Should().Be(5);
        row.RawCertificate.Should().Equal(TestDer(53));
    }

    [Fact]
    public async Task Sync_UnchangedRow_StillRecordsThatTheCaWasSeen()
    {
        // "Last Synced" means when the CA last handed this row back, not when
        // something about it last moved, and the dashboard detail page shows it
        // under that name. A row taking the cheap path still earns that write.
        var cert = FullyDetailed(54, "CN=touched.example.com");
        SetCaCertificates(issued: new[] { cert }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        // Backdated rather than compared against the previous cycle's stamp, so
        // the assertion does not rest on two syncs landing on different ticks.
        var backdate = GetDb();
        var seeded = await backdate.SyncedCertificates.SingleAsync(c => c.RequestId == 54);
        seeded.LastSyncedAt = DateTime.UtcNow.AddDays(-1);
        var firstSynced = seeded.FirstSyncedAt;
        await backdate.SaveChangesAsync();

        await sut.SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 54);
        row.LastSyncedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
        // And nothing else moved, FirstSyncedAt included.
        row.FirstSyncedAt.Should().Be(firstSynced);
        row.Subject.Should().Be("CN=touched.example.com");
        row.Sha256Thumbprint.Should().Be("THUMB0054");
    }

    [Fact]
    public async Task Sync_UnchangedRow_IsStillCountedAsUpdated()
    {
        // The manual sync endpoint reports this number to an operator. It has
        // always meant "rows the CA handed back that we already had", and taking
        // the cheap path for one must not quietly change what it counts.
        var cert = FullyDetailed(55, "CN=counted.example.com");
        SetCaCertificates(issued: new[] { cert }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);
        var second = await sut.SyncCertificatesAsync(CancellationToken.None);

        second.Processed.Should().Be(1);
        second.Created.Should().Be(0);
        second.Updated.Should().Be(1);
    }

    /// <summary>
    /// The guard on the one place in the product where the same rules are
    /// written twice. IsUnchanged decides whether a row is loaded at all, so a
    /// column added to UpdateEntity and forgotten there would stop being synced
    /// with nothing to say why. Each case moves exactly one column and asserts a
    /// cycle writes it through.
    /// </summary>
    [Theory]
    [InlineData("SerialNumber")]
    [InlineData("Subject")]
    [InlineData("SubjectAlternativeNames")]
    [InlineData("TemplateName")]
    [InlineData("NotBefore")]
    [InlineData("NotAfter")]
    [InlineData("Status")]
    [InlineData("Requestor")]
    [InlineData("RequestDate")]
    [InlineData("RevokedAt")]
    [InlineData("RevokedReason")]
    [InlineData("KeyAlgorithm")]
    [InlineData("KeySizeBits")]
    [InlineData("SignatureAlgorithmOid")]
    [InlineData("Sha256Thumbprint")]
    [InlineData("ExtendedKeyUsageOids")]
    [InlineData("KeyUsage")]
    public async Task Sync_WritesThroughAColumnTheCaChanged(string column)
    {
        var baseline = FullyDetailed(56, "CN=baseline.example.com");
        SetCaCertificates(issued: new[] { baseline }, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var crypto = baseline.CryptoDetail!;
        var moved = column switch
        {
            "SerialNumber" => baseline with { SerialNumber = "SERIALMOVED" },
            "Subject" => baseline with { Subject = "CN=moved.example.com" },
            "SubjectAlternativeNames" => baseline with { SubjectAlternativeNames = "dns:moved.example.com" },
            "TemplateName" => baseline with { TemplateName = "MovedTemplate" },
            "NotBefore" => baseline with { NotBefore = baseline.NotBefore.AddDays(-3) },
            "NotAfter" => baseline with { NotAfter = baseline.NotAfter.AddDays(3) },
            "Status" => baseline with { Status = CertificateStatus.Revoked },
            "Requestor" => baseline with { Requestor = "HOME\\moved" },
            "RequestDate" => baseline with { RequestDate = baseline.RequestDate.AddDays(-3) },
            "RevokedAt" => baseline with { RevokedWhen = DateTime.UtcNow.AddDays(-1) },
            "RevokedReason" => baseline with { RevokedReason = 4 },
            "KeyAlgorithm" => baseline with { CryptoDetail = crypto with { KeyAlgorithm = "ECDSA" } },
            "KeySizeBits" => baseline with { CryptoDetail = crypto with { KeySizeBits = 384 } },
            "SignatureAlgorithmOid" => baseline with
            {
                CryptoDetail = crypto with { SignatureAlgorithmOid = "1.2.840.10045.4.3.3" }
            },
            "Sha256Thumbprint" => baseline with { CryptoDetail = crypto with { Sha256Thumbprint = "THUMBMOVED" } },
            "ExtendedKeyUsageOids" => baseline with
            {
                CryptoDetail = crypto with { ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.2" }
            },
            "KeyUsage" => baseline with { CryptoDetail = crypto with { KeyUsage = 128 } },
            _ => throw new ArgumentOutOfRangeException(nameof(column), column, "Unhandled column")
        };

        // Revoked readings arrive on the revoked pass, and revocation values are
        // only ever populated there.
        var revokedPass = column is "Status" or "RevokedAt" or "RevokedReason";
        SetCaCertificates(
            issued: revokedPass ? Array.Empty<CertificateInfo>() : new[] { moved },
            revoked: revokedPass ? new[] { moved with { Status = CertificateStatus.Revoked } } : Array.Empty<CertificateInfo>());

        await sut.SyncCertificatesAsync(CancellationToken.None);

        var row = await GetDb().SyncedCertificates.SingleAsync(c => c.RequestId == 56);
        var actual = column switch
        {
            "SerialNumber" => row.SerialNumber,
            "Subject" => row.Subject,
            "SubjectAlternativeNames" => row.SubjectAlternativeNames,
            "TemplateName" => row.TemplateName,
            "NotBefore" => row.NotBefore.ToString("O"),
            "NotAfter" => row.NotAfter.ToString("O"),
            "Status" => row.Status,
            "Requestor" => row.Requestor,
            "RequestDate" => row.RequestDate.ToString("O"),
            "RevokedAt" => row.RevokedAt?.ToString("O"),
            "RevokedReason" => row.RevokedReason?.ToString(),
            "KeyAlgorithm" => row.KeyAlgorithm,
            "KeySizeBits" => row.KeySizeBits?.ToString(),
            "SignatureAlgorithmOid" => row.SignatureAlgorithmOid,
            "Sha256Thumbprint" => row.Sha256Thumbprint,
            "ExtendedKeyUsageOids" => row.ExtendedKeyUsageOids,
            "KeyUsage" => row.KeyUsage?.ToString(),
            _ => throw new ArgumentOutOfRangeException(nameof(column), column, "Unhandled column")
        };
        var expected = column switch
        {
            "SerialNumber" => "SERIALMOVED",
            "Subject" => "CN=moved.example.com",
            "SubjectAlternativeNames" => "dns:moved.example.com",
            "TemplateName" => "MovedTemplate",
            "NotBefore" => moved.NotBefore.ToString("O"),
            "NotAfter" => moved.NotAfter.ToString("O"),
            "Status" => "Revoked",
            "Requestor" => "HOME\\moved",
            "RequestDate" => moved.RequestDate.ToString("O"),
            "RevokedAt" => moved.RevokedWhen?.ToString("O"),
            "RevokedReason" => "4",
            "KeyAlgorithm" => "ECDSA",
            "KeySizeBits" => "384",
            "SignatureAlgorithmOid" => "1.2.840.10045.4.3.3",
            "Sha256Thumbprint" => "THUMBMOVED",
            "ExtendedKeyUsageOids" => "1.3.6.1.5.5.7.3.2",
            "KeyUsage" => "128",
            _ => throw new ArgumentOutOfRangeException(nameof(column), column, "Unhandled column")
        };

        actual.Should().Be(expected);
    }

    [Fact]
    public async Task Sync_SteadyStateCycle_WritesOncePerBatchRatherThanOncePerRow()
    {
        // The assertion the rest of this section cannot make. A row taking the
        // cheap path is invisible from the data, because it writes the same
        // LastSyncedAt the expensive path writes, so every other test here passes
        // whether the optimisation ran or not. Counting the statements is what
        // separates "it works" from "it silently does nothing".
        const int rows = 250;
        var issued = Enumerable.Range(1, rows)
            .Select(i => FullyDetailed(i, $"CN=steady{i:D4}.example.com"))
            .ToArray();
        SetCaCertificates(issued: issued, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        _sql.Reset();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        // Three batches of 100, 100 and 50, so three ExecuteUpdate statements.
        // The bound is loose enough not to pin the batch size and tight enough
        // that one statement per row (250) fails it by two orders of magnitude.
        _sql.Updates.Should().BeGreaterThan(0, "the rows were still seen");
        _sql.Updates.Should().BeLessThan(10,
            "a steady state cycle writes once per batch, not once per row");
    }

    [Fact]
    public async Task Sync_CycleThatChangedEverything_StillWritesEveryRow()
    {
        // The other direction, so the bound above cannot be met by simply not
        // writing. When the CA really has moved every row, every row is written.
        const int rows = 120;
        var first = Enumerable.Range(1, rows)
            .Select(i => FullyDetailed(i, $"CN=moving{i:D4}.example.com"))
            .ToArray();
        SetCaCertificates(issued: first, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var second = first
            .Select(c => c with { Requestor = "HOME\\somebodyelse" })
            .ToArray();
        SetCaCertificates(issued: second, revoked: Array.Empty<CertificateInfo>());

        _sql.Reset();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        _sql.Updates.Should().BeGreaterThanOrEqualTo(rows,
            "every row genuinely moved, so every row is written");
        (await GetDb().SyncedCertificates.CountAsync(c => c.Requestor == "HOME\\somebodyelse"))
            .Should().Be(rows);
    }

    [Fact]
    public async Task Sync_SteadyStateCycle_ReadsOncePerBatchRatherThanOncePerRow()
    {
        // The read side of the pair above, and the half the update count cannot
        // see (issue #191). A per row FirstOrDefaultAsync followed by the same
        // batched ExecuteUpdate writes exactly the statements the test above
        // allows, so that test stays green while the sync issues one query per
        // certificate. This is the one that fails.
        const int rows = 250;
        var issued = Enumerable.Range(1, rows)
            .Select(i => FullyDetailed(i, $"CN=steadyread{i:D4}.example.com"))
            .ToArray();
        SetCaCertificates(issued: issued, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        _sql.Reset();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        // Measured at 5 on the current build: one read for the already detailed
        // set, three for the batch projections of 100, 100 and 50, one for the
        // supersession lineage projection. A per row FirstOrDefaultAsync makes it
        // 252, so the bound sits two orders of magnitude clear of the regression.
        //
        // It is a bound on batches, not a bound independent of them: the count is
        // one plus one per batch plus one, so it holds for any batch size down to
        // about 14 and would need raising below that. Unlike the write bound above
        // this one cannot be read as indifferent to the batch size.
        _sql.Reads.Should().BeGreaterThan(0, "the rows were still read");
        _sql.Reads.Should().BeLessThan(20,
            "a steady state cycle reads once per batch, not once per row");
    }

    [Fact]
    public async Task Sync_CycleThatChangedEverything_StillReadsOncePerBatch()
    {
        // The direction the steady state cycle cannot cover. Every row moves, so
        // every row lands in the changed list and the second read fires for each
        // batch. A build that batched the first read but reloaded changed
        // entities one at a time would pass the test above and fail this one.
        const int rows = 120;
        var first = Enumerable.Range(1, rows)
            .Select(i => FullyDetailed(i, $"CN=movingread{i:D4}.example.com"))
            .ToArray();
        SetCaCertificates(issued: first, revoked: Array.Empty<CertificateInfo>());

        var sut = CreateService();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        var second = first
            .Select(c => c with { Requestor = "HOME\\somebodyelse" })
            .ToArray();
        SetCaCertificates(issued: second, revoked: Array.Empty<CertificateInfo>());

        _sql.Reset();
        await sut.SyncCertificatesAsync(CancellationToken.None);

        // Measured at 6: the steady state five, plus one reload per batch for the
        // rows that moved. Reloading those one at a time makes it 124. Two reads
        // per batch rather than one, so this is the tighter of the pair against a
        // shrinking batch size and holds down to a batch of about 16.
        _sql.Reads.Should().BeGreaterThan(0, "the rows were still read");
        _sql.Reads.Should().BeLessThan(20,
            "the changed rows are reloaded once per batch, not once per row");

        // The read bound cannot be met by a build that simply stopped reading,
        // because a cycle that skipped the reload would write nothing through.
        (await GetDb().SyncedCertificates.CountAsync(c => c.Requestor == "HOME\\somebodyelse"))
            .Should().Be(rows);
    }

    [Fact]
    public async Task Sync_BackfillsSubjectsForRowsSpreadAcrossSeveralBatches()
    {
        // The disposition passes no longer keep every row attached: they clear
        // the change tracker after each batch of 100. So the backfill can no
        // longer be handed entity references, and this is the shape that catches
        // it if it ever is again, because the rows it must name were detached
        // several batches before it ran.
        const int rows = 150;
        for (var i = 0; i < rows; i++)
            await SeedAcmeOrderAsync(200 + i, $$"""[{"type":"dns","value":"batch{{i}}.example.com"}]""");

        var requests = Enumerable.Range(0, rows)
            .Select(i => RequestRow(200 + i, CertificateStatus.Denied))
            .ToArray();
        SetCaCertificates(issued: Array.Empty<CertificateInfo>(),
            revoked: Array.Empty<CertificateInfo>());
        SetCaRequests(CertificateStatus.Denied, requests);

        await CreateService().SyncCertificatesAsync(CancellationToken.None);

        var db = GetDb();
        (await db.SyncedCertificates.CountAsync(c => c.Subject == "")).Should().Be(0);
        (await db.SyncedCertificates.SingleAsync(c => c.RequestId == 200)).Subject
            .Should().Be("batch0.example.com");
        (await db.SyncedCertificates.SingleAsync(c => c.RequestId == 200 + rows - 1)).Subject
            .Should().Be($"batch{rows - 1}.example.com");
    }

    public void Dispose()
    {
        foreach (var scope in _scopes)
            scope.Dispose();
        _serviceProvider.Dispose();
        _connection.Dispose();
    }
}
