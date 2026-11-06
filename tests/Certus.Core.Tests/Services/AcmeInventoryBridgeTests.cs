using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Certus.Core.Setup;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Services;

/// <summary>
/// Issue #442: every site that crosses the bridge between an ACME certificate and
/// its row in the CA inventory, after the install has been pointed at another CA.
///
/// <para>
/// The ACME row is the old CA's certificate under request id 5. Each site is a
/// theory over the inventory row that now holds request id 5:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>sameCertificate: true</c> is that same certificate as the CA view spells its
/// serial, lowercase and without the sign pad the ACME row keeps. The bridge must
/// hold. This is the positive control, and it is as load bearing as the other case:
/// a bridge that compared the serials without normalizing them would refuse every
/// real pair, which would silently switch the #375 hold repair and every other site
/// off while each cross CA test still passed.
/// </description></item>
/// <item><description>
/// <c>sameCertificate: false</c> is another CA's certificate that reused the request
/// number. The bridge must not hold, and the site must land on its safe side.
/// </description></item>
/// </list>
/// </summary>
public class AcmeInventoryBridgeTests : IDisposable
{
    private const int RequestId = 5;
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string Contact = "ops@example.com";

    /// <summary>
    /// The X509Certificate2.SerialNumber spelling the ACME row stores: uppercase, and
    /// with the 00 pad a DER integer carries when its top bit is set.
    /// </summary>
    private const string AcmeSerial = "008AB12CD34EF0";

    /// <summary>The same serial as the CA view returns it: lowercase, no pad.</summary>
    private const string SameCertificateCaSerial = "8ab12cd34ef0";

    /// <summary>A certificate from another CA that carries the same request id.</summary>
    private const string OtherCaSerial = "61000000059c2e";

    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _services;
    private readonly List<IServiceScope> _scopes = new();
    private readonly IAdcsClient _ca = Substitute.For<IAdcsClient>();
    private readonly string _tempDir;
    private readonly CertusOptions _options;

    public AcmeInventoryBridgeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(options => options.UseSqlite(_connection));
        _services = services.BuildServiceProvider();
        GetDb().Database.EnsureCreated();

        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-bridge-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _options = new CertusOptions { DatabasePath = Path.Combine(_tempDir, "certus.db") };

        CaReports();
    }

    public void Dispose()
    {
        foreach (var scope in _scopes)
            scope.Dispose();
        _services.Dispose();
        _connection.Dispose();
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: a stray temp folder is harmless.
        }
        GC.SuppressFinalize(this);
    }

    private static string InventorySerial(bool sameCertificate) =>
        sameCertificate ? SameCertificateCaSerial : OtherCaSerial;

    // ---- The sites ---------------------------------------------------------

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HoldRepair_ClearsTheAcmeStamp_OnlyForTheSameCertificate(bool sameCertificate)
    {
        // CertificateSyncService.ClearReleasedRevocationStampsAsync, issue #375.
        // The inventory row starts as the old CA's revoked row for request 5, the
        // ACME row carries the stamp that revocation left, and the CA now reports
        // request 5 issued. For the same certificate that is a release from hold.
        // For another CA's certificate it is no evidence about this one at all.
        var stampedAt = DateTime.UtcNow.AddDays(-7);
        await SeedAcmeRowAsync(revokedAt: stampedAt);
        await SeedInventoryRowAsync(SameCertificateCaSerial, status: "Revoked", revokedAt: stampedAt);
        CaReports(issued: CaRow(InventorySerial(sameCertificate), CertificateStatus.Issued));

        await CreateSyncService().SyncCertificatesAsync(CancellationToken.None);

        var inventory = await ReadInventoryRowAsync();
        inventory.Status.Should().Be("Issued", "the CA's issued row has to have landed for the test to mean anything");
        inventory.SerialNumber.Should().Be(InventorySerial(sameCertificate));

        var acme = await ReadAcmeRowAsync();
        if (sameCertificate)
        {
            acme.RevokedAt.Should().BeNull("the CA released this certificate from hold");
            acme.RevokedReason.Should().BeNull();
        }
        else
        {
            acme.RevokedAt.Should().NotBeNull("another CA's issued certificate cannot clear this one's revocation");
            acme.RevokedReason.Should().Be(6);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AcmeRevoke_StampsTheInventoryRow_OnlyForTheSameCertificate(bool sameCertificate)
    {
        // OrderService.StampInventoryRowAsync, issue #202. A revoke-cert for the old
        // CA's certificate must not mark the new CA's live certificate revoked.
        await SeedAcmeRowAsync();
        await SeedInventoryRowAsync(InventorySerial(sameCertificate));

        var db = GetDb();
        var certificate = await db.AcmeCertificates.SingleAsync(a => a.AdcsRequestId == RequestId);
        var outcome = await CreateOrderService(db).RevokeCertificateAsync(certificate, reason: 1);

        outcome.Should().Be(RevokeOutcome.Revoked);
        var inventory = await ReadInventoryRowAsync();
        if (sameCertificate)
        {
            inventory.Status.Should().Be("Revoked");
            inventory.RevokedReason.Should().Be(1);
        }
        else
        {
            inventory.Status.Should().Be("Issued", "the inventory row is another CA's certificate");
            inventory.RevokedAt.Should().BeNull();
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DucksManagedScope_TakesTheProvenanceLeg_OnlyForTheSameCertificate(bool sameCertificate)
    {
        // RevocationEligibilityService. With no template enabled, the provenance
        // leg is the only way into scope, so a wrong bridge here would widen what
        // the dashboard may revoke to a certificate Ducks never issued.
        WriteStatus("ducks-managed");
        await SeedAcmeRowAsync();

        var verdict = await CreateEligibilityService(GetDb())
            .EvaluateAsync(InventoryRow(InventorySerial(sameCertificate)));

        verdict.Allowed.Should().Be(sameCertificate);
        if (!sameCertificate)
            verdict.BlockedKind.Should().Be("out-of-scope");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DashboardRevoke_StampsTheAcmeRow_OnlyForTheSameCertificate(bool sameCertificate)
    {
        // CertificateRevocationService.RecordRevocationAsync. The scope is "all" so
        // the revocation goes through either way and only the stamp is under test.
        // Stamping the old CA's ACME row would make revoke-cert answer
        // alreadyRevoked, and renewalInfo ask for a renewal, for a certificate
        // nobody revoked.
        WriteStatus("all");
        await SeedAcmeRowAsync();
        var serial = InventorySerial(sameCertificate);
        var row = await SeedInventoryRowAsync(serial);
        CaReports(revoked: CaRow(serial, CertificateStatus.Revoked, revokedWhen: DateTime.UtcNow));

        var result = await CreateRevocationService(GetDb())
            .RevokeAsync(row.Id, reason: 1, expectedSerial: serial, actor: "bridge-test");

        result.Status.Should().Be(CertificateRevocationStatus.Revoked);
        var acme = await ReadAcmeRowAsync();
        if (sameCertificate)
        {
            acme.RevokedAt.Should().NotBeNull();
            acme.RevokedReason.Should().Be(1);
        }
        else
        {
            acme.RevokedAt.Should().BeNull("the revoked certificate is another CA's");
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RenewalInfo_ReadsTheInventoryRevocation_OnlyForTheSameCertificate(bool sameCertificate)
    {
        // OrderService.ResolveRevocationInstantAsync. A revocation done at the CA
        // reaches only the inventory, and renewalInfo reads it from there. Another
        // CA's revoked request of the same number says nothing about this one.
        using var leaf = CreateLeafWithAuthorityKeyId();
        await SeedAcmeRowAsync(serial: leaf.SerialNumber, pem: leaf.ExportCertificatePem());
        var inventorySerial = sameCertificate
            ? leaf.SerialNumber.TrimStart('0').ToLowerInvariant()
            : OtherCaSerial;
        await SeedInventoryRowAsync(inventorySerial, status: "Revoked",
            revokedAt: DateTime.UtcNow.AddDays(-2));
        AriCertificateId.TryFromCertificate(leaf, out var keyId, out var serialOctets)
            .Should().BeTrue();

        var match = await CreateOrderService(GetDb())
            .FindCertificateByAriOctetsAsync(keyId, serialOctets);

        match.Should().NotBeNull("the ACME row itself is found by its own serial");
        using var found = match!.Leaf;
        if (sameCertificate)
            match.RevokedAt.Should().NotBeNull();
        else
            match.RevokedAt.Should().BeNull("the revoked inventory row is another CA's certificate");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CertificateList_BadgesAndNamesTheContact_OnlyForTheSameCertificate(bool sameCertificate)
    {
        // CertificateQueryService.QueryAsync, both correlated subqueries.
        await SeedAcmeRowAsync();
        await SeedInventoryRowAsync(InventorySerial(sameCertificate));

        var result = await CreateQueryService(GetDb()).QueryAsync(new CertificateSearchQuery());

        var summary = result.Items.Should().ContainSingle().Subject;
        summary.IssuedByAcme.Should().Be(sameCertificate);
        summary.AcmeContactEmail.Should().Be(sameCertificate ? Contact : null);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CertificateDetail_BadgesAndNamesTheContact_OnlyForTheSameCertificate(bool sameCertificate)
    {
        // CertificateQueryService.GetDetailByIdAsync, both lookups.
        await SeedAcmeRowAsync();
        var row = await SeedInventoryRowAsync(InventorySerial(sameCertificate));

        var detail = await CreateQueryService(GetDb()).GetDetailByIdAsync(row.Id);

        detail.Should().NotBeNull();
        detail!.IssuedByAcme.Should().Be(sameCertificate);
        detail.AcmeContactEmail.Should().Be(sameCertificate ? Contact : null);
    }

    // ---- The request row name backfill, the one bridge with no serial ------

    [Fact]
    public async Task RequestRowName_IsNotTakenFromAnOrderThatHoldsACertificate()
    {
        // The old CA's order issued, so its request carried a serial at that CA. A
        // request row with no serial is therefore some other request, here the new
        // CA's pending request 5, dated inside the old order's life so that only
        // the certificate rule stands between them.
        await SeedAcmeRowAsync();
        CaReports(pending: CaRequestRow(CertificateStatus.Pending, submittedAt: DateTime.UtcNow));

        await CreateSyncService().SyncCertificatesAsync(CancellationToken.None);

        (await ReadInventoryRowAsync()).Subject.Should().BeEmpty();
    }

    [Theory]
    [InlineData("the order's mirror only")]
    [InlineData("the certificate's foreign key only")]
    public async Task RequestRowName_IsNotTakenFromAnOrderWhenEitherCertificateSignalIsSet(string signal)
    {
        // Either certificate signal is enough on its own: the order's own mirror,
        // or the authoritative foreign key on the certificate row, since nothing
        // keeps the two in step. The status is left at processing so it is not
        // what decides.
        await SeedAcmeRowAsync();
        var db = GetDb();
        var order = await db.AcmeOrders.SingleAsync();
        order.Status = "processing";
        if (signal == "the certificate's foreign key only")
            order.CertificateId = null;
        await db.SaveChangesAsync();
        if (signal == "the order's mirror only")
            await db.AcmeCertificates.ExecuteDeleteAsync();
        CaReports(pending: CaRequestRow(CertificateStatus.Pending, submittedAt: DateTime.UtcNow));

        await CreateSyncService().SyncCertificatesAsync(CancellationToken.None);

        (await ReadInventoryRowAsync()).Subject.Should().BeEmpty();
    }

    [Fact]
    public async Task RequestRowName_IsNotTakenFromAnOrderWhoseLifeEndedBeforeTheCaDatedTheRequest()
    {
        // An old CA order that never issued (denied there) and expired weeks ago.
        // The new CA dated its request 5 an hour ago, so it cannot be this order's
        // submission.
        await SeedUnissuedOrderAsync(
            createdAt: DateTime.UtcNow.AddDays(-30), expiresAt: DateTime.UtcNow.AddDays(-23),
            status: "invalid");
        CaReports(denied: CaRequestRow(CertificateStatus.Denied, submittedAt: DateTime.UtcNow.AddHours(-1)));

        await CreateSyncService().SyncCertificatesAsync(CancellationToken.None);

        (await ReadInventoryRowAsync()).Subject.Should().BeEmpty();
    }

    [Fact]
    public async Task RequestRowName_IsTakenFromTheOrderThatSubmittedIt()
    {
        // The positive control for the two refusals above: issue #186's own case,
        // an order held at the CA that dated the request inside the order's life.
        await SeedUnissuedOrderAsync(
            createdAt: DateTime.UtcNow.AddHours(-1), expiresAt: DateTime.UtcNow.AddDays(7),
            status: "processing");
        CaReports(pending: CaRequestRow(CertificateStatus.Pending, submittedAt: DateTime.UtcNow.AddMinutes(-30)));

        await CreateSyncService().SyncCertificatesAsync(CancellationToken.None);

        (await ReadInventoryRowAsync()).Subject.Should().Be("held.example.com");
    }

    public static TheoryData<int, bool> SubmissionOffsetsInMinutes => new()
    {
        // Relative to an order created at T and expiring at T + 7 days, with a
        // tolerance of one day on either side.
        { 0, true },
        { 60, true },
        { 7 * 24 * 60, true },
        { -24 * 60, true },
        { -24 * 60 - 1, false },
        { 8 * 24 * 60, true },
        { 8 * 24 * 60 + 1, false },
    };

    [Theory]
    [MemberData(nameof(SubmissionOffsetsInMinutes))]
    public void MayBeTheOrdersRequest_HoldsInsideTheOrdersLifeWithADayEitherSide(int offsetMinutes, bool expected)
    {
        var created = new DateTime(2026, 10, 1, 12, 0, 0, DateTimeKind.Utc);
        var expires = created.AddDays(7);

        AcmeInventoryBridge.MayBeTheOrdersRequest(created.AddMinutes(offsetMinutes), created, expires)
            .Should().Be(expected);
    }

    [Fact]
    public void MayBeTheOrdersRequest_ARowWithNoDate_IsOutsideAnyOrder()
    {
        // A CA row whose date column was missing arrives as MinValue. It must read
        // as outside the span, and the comparison must not overflow on the way.
        var created = new DateTime(2026, 10, 1, 12, 0, 0, DateTimeKind.Utc);

        AcmeInventoryBridge.MayBeTheOrdersRequest(DateTime.MinValue, created, created.AddDays(7))
            .Should().BeFalse();
        AcmeInventoryBridge.MayBeTheOrdersRequest(DateTime.MaxValue, created, created.AddDays(7))
            .Should().BeFalse();
    }

    // ---- The rule itself, against SQLite -----------------------------------

    [Theory]
    [InlineData("008AB12CD34EF0", "8ab12cd34ef0", true)] // X509 form against CA form: case and pad
    [InlineData("8AB12CD34EF0", "8ab12cd34ef0", true)]   // case only
    [InlineData("8ab12cd34ef0", "8AB12CD34EF0", true)]   // either side may carry either case
    [InlineData("0000AB12", "00ab12", true)]             // pads of different widths
    [InlineData("SERIAL0030", "SERIAL0030", true)]       // the same spelling on both sides
    [InlineData("8AB12CD34EF0", "8ab12cd34ef1", false)]  // a different serial
    [InlineData("8AB12CD34EF0", "", false)]              // a request row carries no serial
    [InlineData("", "", false)]                          // nor may an ACME row without one match it
    [InlineData("00", "0", false)]                       // a serial that normalizes to nothing
    public async Task Rule_AgreesWithTheSerialNormalizationItMirrors_InEveryShape(
        string acmeSerial, string inventorySerial, bool expected)
    {
        // The rule is written as ToUpper().TrimStart('0') so that EF can translate
        // it; SerialNumbers.Normalize is the definition it stands for. The three
        // shapes the sites use must all give the answer that definition gives,
        // evaluated by SQLite rather than in memory.
        var definition = SerialNumbers.Normalize(acmeSerial).Length > 0
            && SerialNumbers.NormalizedEquals(acmeSerial, inventorySerial);
        definition.Should().Be(expected, "the test data has to agree with the definition");

        await SeedAcmeRowAsync(serial: acmeSerial);
        var inventory = await SeedInventoryRowAsync(inventorySerial);
        var acme = await ReadAcmeRowAsync();

        var db = GetDb();
        (await db.AcmeCertificates.AnyAsync(AcmeInventoryBridge.AcmeRowsFor(inventory)))
            .Should().Be(expected, "AcmeRowsFor");
        (await db.SyncedCertificates.AnyAsync(AcmeInventoryBridge.InventoryRowsFor(acme)))
            .Should().Be(expected, "InventoryRowsFor");
        (await AcmeInventoryBridge.Pairs(db.AcmeCertificates, db.SyncedCertificates).AnyAsync())
            .Should().Be(expected, "Pairs");
    }

    [Theory]
    [InlineData(RequestId, RequestId + 1)] // the same serial under another request id
    [InlineData(0, 0)]                     // an ACME row stored without a request id
    public async Task Rule_RequiresARealAndAgreeingRequestId(int acmeRequestId, int inventoryRequestId)
    {
        await SeedAcmeRowAsync(requestId: acmeRequestId);
        var inventory = await SeedInventoryRowAsync(SameCertificateCaSerial, requestId: inventoryRequestId);
        var acme = await ReadAcmeRowAsync(acmeRequestId);

        var db = GetDb();
        (await db.AcmeCertificates.AnyAsync(AcmeInventoryBridge.AcmeRowsFor(inventory))).Should().BeFalse();
        (await db.SyncedCertificates.AnyAsync(AcmeInventoryBridge.InventoryRowsFor(acme))).Should().BeFalse();
        (await AcmeInventoryBridge.Pairs(db.AcmeCertificates, db.SyncedCertificates).AnyAsync())
            .Should().BeFalse();
    }

    // ---- Fixtures ----------------------------------------------------------

    private CertusDbContext GetDb()
    {
        var scope = _services.CreateScope();
        _scopes.Add(scope);
        return scope.ServiceProvider.GetRequiredService<CertusDbContext>();
    }

    /// <summary>
    /// The old CA's certificate as Ducks issued it over ACME: a valid order, its
    /// account with a mailto contact, and the certificate row.
    /// </summary>
    private async Task SeedAcmeRowAsync(
        string serial = AcmeSerial, DateTime? revokedAt = null, string pem = "pem",
        int requestId = RequestId)
    {
        var db = GetDb();
        var order = new AcmeOrder
        {
            OrderId = "order-old-ca",
            Account = new AcmeAccount
            {
                AccountId = "acct-old-ca",
                JwkJson = "{}",
                JwkThumbprint = "thumb-old-ca",
                ContactJson = $"[\"mailto:{Contact}\"]",
            },
            Status = "valid",
            TemplateId = "WebServer",
            IdentifiersJson = """[{"type":"dns","value":"old-ca.example.com"}]""",
            CreatedAt = DateTime.UtcNow.AddDays(-2),
            ExpiresAt = DateTime.UtcNow.AddDays(5),
            AdcsRequestId = requestId,
            CertificateId = "cert-old-ca",
        };
        db.AcmeCertificates.Add(new AcmeCertificate
        {
            CertificateId = "cert-old-ca",
            Order = order,
            CertificatePem = pem,
            AdcsRequestId = requestId,
            SerialNumber = serial,
            RevokedAt = revokedAt,
            RevokedReason = revokedAt == null ? null : 6,
        });
        await db.SaveChangesAsync();
    }

    /// <summary>An order that reached the CA and produced no certificate.</summary>
    private async Task SeedUnissuedOrderAsync(DateTime createdAt, DateTime expiresAt, string status)
    {
        var db = GetDb();
        db.AcmeOrders.Add(new AcmeOrder
        {
            OrderId = "order-held",
            Account = new AcmeAccount
            {
                AccountId = "acct-held",
                JwkJson = "{}",
                JwkThumbprint = "thumb-held",
            },
            Status = status,
            TemplateId = "WebServer",
            IdentifiersJson = """[{"type":"dns","value":"held.example.com"}]""",
            CreatedAt = createdAt,
            ExpiresAt = expiresAt,
            AdcsRequestId = RequestId,
        });
        await db.SaveChangesAsync();
    }

    /// <summary>An issued inventory row that passes the TLS capability ceiling.</summary>
    private static SyncedCertificate InventoryRow(string serial, int requestId = RequestId) => new()
    {
        RequestId = requestId,
        SerialNumber = serial,
        Subject = "CN=new-ca.example.com",
        TemplateName = "WebServer",
        Status = "Issued",
        NotBefore = DateTime.UtcNow.AddDays(-30),
        NotAfter = DateTime.UtcNow.AddDays(335),
        RequestDate = DateTime.UtcNow.AddDays(-30),
        ExtendedKeyUsageOids = ServerAuth,
        KeyUsage = 160,
        LastSyncedAt = DateTime.UtcNow,
    };

    private async Task<SyncedCertificate> SeedInventoryRowAsync(
        string serial, string status = "Issued", DateTime? revokedAt = null, int requestId = RequestId)
    {
        var row = InventoryRow(serial, requestId);
        row.Status = status;
        row.RevokedAt = revokedAt;
        row.RevokedReason = revokedAt == null ? null : 6;

        var db = GetDb();
        db.SyncedCertificates.Add(row);
        await db.SaveChangesAsync();
        return row;
    }

    private async Task<AcmeCertificate> ReadAcmeRowAsync(int requestId = RequestId) =>
        await GetDb().AcmeCertificates.AsNoTracking().SingleAsync(a => a.AdcsRequestId == requestId);

    private async Task<SyncedCertificate> ReadInventoryRowAsync() =>
        await GetDb().SyncedCertificates.AsNoTracking().SingleAsync(s => s.RequestId == RequestId);

    /// <summary>
    /// What the CA reports for each disposition the sync asks about. Every pass
    /// answers empty unless a row is given for it.
    /// </summary>
    private void CaReports(
        CertificateInfo? issued = null, CertificateInfo? revoked = null,
        CertificateInfo? pending = null, CertificateInfo? denied = null)
    {
        void Answer(CertificateStatus status, CertificateInfo? row)
        {
            IReadOnlyList<CertificateInfo> rows = row == null ? [] : [row];
            _ca.QueryCertificatesAsync(
                    Arg.Is<CertificateQuery>(q => q.Status == status), Arg.Any<CancellationToken>())
                .Returns(rows);
        }

        Answer(CertificateStatus.Issued, issued);
        Answer(CertificateStatus.Revoked, revoked);
        Answer(CertificateStatus.Pending, pending);
        Answer(CertificateStatus.Denied, denied);
        Answer(CertificateStatus.Failed, null);
    }

    private static CertificateInfo CaRow(
        string serial, CertificateStatus status, DateTime? revokedWhen = null) => new(
        RequestId: RequestId,
        SerialNumber: serial,
        Subject: "CN=new-ca.example.com",
        SubjectAlternativeNames: null,
        TemplateName: "WebServer",
        NotBefore: DateTime.UtcNow.AddDays(-30),
        NotAfter: DateTime.UtcNow.AddDays(335),
        Status: status,
        Requestor: "CORP\\someone",
        RequestDate: DateTime.UtcNow.AddDays(-30),
        RevokedWhen: revokedWhen,
        RevokedReason: revokedWhen == null ? null : 1);

    /// <summary>
    /// A request row as the request dispositions arrive: no serial because
    /// nothing was issued, and no subject because an ACME CSR carries none.
    /// </summary>
    private static CertificateInfo CaRequestRow(CertificateStatus status, DateTime submittedAt) =>
        CaRow("", status) with { Subject = "", RequestDate = submittedAt };

    private void WriteStatus(string scope)
    {
        new SetupStatus
        {
            SetupCompleted = true,
            EnabledTemplates = [],
            RevocationScope = scope,
            RevocableTemplates = [],
        }.Save(SetupStatus.GetStatusPath(_options));
    }

    private CertificateSyncService CreateSyncService() => new(
        _services.GetRequiredService<IServiceScopeFactory>(),
        _ca,
        new CertificateSyncTrigger(),
        Options.Create(new CertusOptions()),
        NullLogger<CertificateSyncService>.Instance);

    private OrderService CreateOrderService(CertusDbContext db) => new(
        db, _ca, new CertificateSyncTrigger(), new CertificateRevocationGate(),
        new DeviceAttestationPolicyService(db),
        new DomainPolicyAuditService(db, NullLogger<DomainPolicyAuditService>.Instance),
        NullLogger<OrderService>.Instance);

    private RevocationEligibilityService CreateEligibilityService(CertusDbContext db)
    {
        var enabledTemplates = new EnabledTemplatesPolicy(
            Options.Create(_options), Options.Create(new AcmeOptions()),
            NullLogger<EnabledTemplatesPolicy>.Instance);
        return new RevocationEligibilityService(
            db,
            new TemplateService(new MockAdcsClient(), enabledTemplates,
                NullLogger<TemplateService>.Instance),
            new RevocationScopePolicy(
                Options.Create(_options), NullLogger<RevocationScopePolicy>.Instance),
            CertusInstanceMode.Full,
            NullLogger<RevocationEligibilityService>.Instance);
    }

    private CertificateRevocationService CreateRevocationService(CertusDbContext db) => new(
        db, _ca, CreateSyncService(), new CertificateRevocationGate(),
        CreateEligibilityService(db), NullLogger<CertificateRevocationService>.Instance);

    private CertificateQueryService CreateQueryService(CertusDbContext db)
    {
        var alerts = new AlertOptions();
        alerts.NormalizeThresholdDays();
        return new CertificateQueryService(
            db, NullLogger<CertificateQueryService>.Instance, Options.Create(alerts),
            CreateEligibilityService(db));
    }

    /// <summary>
    /// A leaf renewalInfo can address: it carries an Authority Key Identifier, and
    /// its serial's top bit is set, so the X509 spelling carries the sign pad the CA
    /// spelling drops.
    /// </summary>
    private static X509Certificate2 CreateLeafWithAuthorityKeyId()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=old-ca.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(
                RandomNumberGenerator.GetBytes(20)));
        byte[] serial = [0x8a, 0xb1, 0x2c, 0xd3, 0x4e, 0xf0, 0x11, 0x22];
        var leaf = request.Create(
            new X500DistinguishedName("CN=old-ca.example.com"),
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(335),
            serial);
        return leaf;
    }
}
