using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Issue #319: an order the CA holds for manager approval is completed, failed,
/// or given up on, rather than resting in "processing" for ever.
///
/// Every test here runs against a CA that holds every request
/// (<see cref="MockAdcsClient.AutoApprove"/> false), which is what an ADCS
/// template with CT_FLAG_PEND_ALL_REQUESTS does. That is the configuration the
/// setup wizard warns about in its readiness checklist and then lets the
/// operator proceed with, so it is ordinary rather than exotic.
/// </summary>
public class PendingIssuanceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _serviceProvider;
    private readonly MockAdcsClient _adcs;
    private readonly CertificateSyncTrigger _syncTrigger = new();
    private readonly CertificateRevocationGate _revocationGate = new();

    public PendingIssuanceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        _adcs = new MockAdcsClient { AutoApprove = false };

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        services.AddSingleton<IAdcsClient>(_adcs);
        services.AddSingleton(_syncTrigger);
        services.AddSingleton(_revocationGate);
        services.AddScoped<DeviceAttestationPolicyService>();
        services.AddScoped<DomainPolicyAuditService>();
        services.AddScoped<OrderService>();
        services.AddLogging();
        _serviceProvider = services.BuildServiceProvider();

        using var scope = _serviceProvider.CreateScope();
        scope.ServiceProvider.GetRequiredService<CertusDbContext>().Database.EnsureCreated();
    }

    // ---------------------------------------------------------------------
    // The order service half: resolving one held order.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task ResolveHeldOrder_StillWaitingOnTheOperator_LeavesTheOrderProcessing()
    {
        var order = await FinalizeIntoHeldStateAsync("waiting.example.com");

        var resolution = await ResolveAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.StillHeld);
        var stored = await ReadOrderAsync(order.Id);
        stored.Status.Should().Be("processing");
        stored.ErrorJson.Should().BeNull("waiting on a human is not a failure");
        stored.CertificateId.Should().BeNull();
    }

    [Fact]
    public async Task ResolveHeldOrder_OperatorApproves_DeliversTheCertificate()
    {
        // The whole point of issue #319. Before the sweep existed this order
        // stayed "processing" for ever no matter what the operator did, because
        // IssueCertificateAsync had exactly one call site and it was the
        // finalize's own "issued" arm.
        var order = await FinalizeIntoHeldStateAsync("approved.example.com");
        var requestId = (await ReadOrderAsync(order.Id)).AdcsRequestId!.Value;

        _adcs.ApproveRequest(requestId);
        var resolution = await ResolveAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.Collected);
        var stored = await ReadOrderAsync(order.Id);
        stored.Status.Should().Be("valid");
        stored.ErrorJson.Should().BeNull();
        stored.CertificateId.Should().NotBeNull();

        await using var verify = NewDbContext();
        var cert = await verify.AcmeCertificates.SingleAsync(c => c.OrderId == order.Id);
        cert.AdcsRequestId.Should().Be(requestId);
        cert.CertificatePem.Should().Contain("BEGIN CERTIFICATE");
        cert.SerialNumber.Should().NotBeNullOrEmpty(
            "the serial is what a later revoke-cert request locates this row by");
        stored.CertificateId.Should().Be(cert.CertificateId,
            "the download path refuses a certificate its order does not name (issue #318)");
    }

    [Fact]
    public async Task ResolveHeldOrder_OperatorApproves_IssuesForTheNamesThatWereRequested()
    {
        // The certificate an approval produces has to be the one the client asked
        // for. This is the assertion that catches a CA, or a mock, that treats
        // approval as a fresh enrollment rather than a decision about the stored
        // PKCS#10: such a leaf carries a public key the client does not hold, so
        // it is useless to it even though every status column reads correct.
        var order = await FinalizeIntoHeldStateAsync("named.example.com");
        var requestId = (await ReadOrderAsync(order.Id)).AdcsRequestId!.Value;

        _adcs.ApproveRequest(requestId);
        await ResolveAsync(order.Id);

        await using var verify = NewDbContext();
        var cert = await verify.AcmeCertificates.SingleAsync(c => c.OrderId == order.Id);
        using var leaf = X509Certificate2.CreateFromPem(cert.CertificatePem);
        leaf.Subject.Should().Contain("named.example.com");
    }

    [Fact]
    public async Task ResolveHeldOrder_OperatorDenies_FailsTheOrderWithTheReason()
    {
        var order = await FinalizeIntoHeldStateAsync("denied.example.com");
        var requestId = (await ReadOrderAsync(order.Id)).AdcsRequestId!.Value;

        _adcs.DenyRequest(requestId);
        var resolution = await ResolveAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.Refused);
        var stored = await ReadOrderAsync(order.Id);
        stored.Status.Should().Be("invalid");
        stored.ErrorJson.Should().Contain("denied",
            "a client polling the order is entitled to learn the CA refused it");
        stored.CertificateId.Should().BeNull();
    }

    [Fact]
    public async Task ResolveHeldOrder_OperatorDenies_CarriesTheCaReason()
    {
        // Issue #365, the half of #356 that shipped without it. The settled rule is
        // that one refusal reads the same wherever it is discovered, and until this
        // the sweep's arm agreed with the finalize's on the status and the ACME error
        // type and said nothing about why.
        //
        // The reason is not read from GetLastStatus, which reflects only the latest
        // Submit, RetrievePending or GetCACertificate and so has nothing to say on a
        // path that reaches the CA through GetIssuedCertificate. It is read back off
        // the request row, where the CA recorded it either way.
        var order = await FinalizeIntoHeldStateAsync("denied-with-reason.example.com");
        var requestId = (await ReadOrderAsync(order.Id)).AdcsRequestId!.Value;

        _adcs.DenyRequest(requestId);
        await ResolveAsync(order.Id);

        var stored = await ReadOrderAsync(order.Id);
        var error = JsonSerializer.Deserialize<AcmeError>(stored.ErrorJson!)!;
        error.Type.Should().Be(AcmeErrorType.ServerInternal,
            "the refusal vocabulary is settled and this does not touch it");
        error.Detail.Should()
            .Contain(MockAdcsClient.ManagerDenialMessage, "the CA's own account leads")
            .And.Contain("0x80094014", "and its reason travels beside it")
            .And.Contain("denied by a certificate manager or CA administrator",
                "spelled out through the same CaStatusCode map the finalize reads");
    }

    [Fact]
    public async Task ResolveHeldOrder_CaExplainsNothing_KeepsTheWordingItAlwaysHad()
    {
        // A CA that records neither a message nor a code must not gain wording of its
        // own. DescribeRefusal answers null for that pair, and the arm's own fallback
        // is what it always was, asserted with Be rather than Contain for the reason
        // issue #362 gives: byte identical, not merely unparaphrased.
        var order = await FinalizeIntoHeldStateAsync("denied-no-reason.example.com");
        var requestId = (await ReadOrderAsync(order.Id)).AdcsRequestId!.Value;

        _adcs.DenyRequest(requestId, dispositionMessage: null, statusCode: null);
        await ResolveAsync(order.Id);

        var stored = await ReadOrderAsync(order.Id);
        var error = JsonSerializer.Deserialize<AcmeError>(stored.ErrorJson!)!;
        error.Detail.Should().Be("Certificate request was denied by the CA.");
    }

    [Fact]
    public async Task ResolveHeldOrder_TheReasonCannotBeRead_StillFailsTheOrder()
    {
        // The regression guard for issue #365. The reason read runs after the CA has
        // already answered and immediately before the order is written invalid, so a
        // failure there must cost the detail and nothing else.
        //
        // CaUnavailableException specifically, because that is the one the sweep
        // treats as "abandon the whole tick". If it escaped, an order the CA has
        // already denied would sit in "processing" because a diagnostic failed.
        var blind = new OutageAdcsClient();
        blind.Inner.AutoApprove = false;
        await using var provider = NewProviderOn(blind);

        var order = await FinalizeIntoHeldStateAsync("reason-unreadable.example.com", provider);
        var requestId = (await ReadOrderAsync(order.Id)).AdcsRequestId!.Value;
        blind.Inner.DenyRequest(requestId);
        blind.FailTheStatusReadWith = new CaUnavailableException("simulated RPC failure");

        using var scope = provider.CreateScope();
        var resolution = await scope.ServiceProvider.GetRequiredService<OrderService>()
            .ResolveHeldOrderAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.Refused,
            "the CA decided, and only the explanation was unavailable");
        var stored = await ReadOrderAsync(order.Id);
        stored.Status.Should().Be("invalid");
        var error = JsonSerializer.Deserialize<AcmeError>(stored.ErrorJson!)!;
        error.Detail.Should().Be("Certificate request was denied by the CA.",
            "the arm falls back to exactly the wording it had before there was " +
            "anything to add");
    }

    [Fact]
    public async Task Sweep_TheReasonCannotBeRead_DoesNotAbandonTheTick()
    {
        // The same fault one layer up. A CaUnavailableException reaching the sweep is
        // its signal to stop the whole tick, so the reason read escaping would leave
        // every later order in the batch untouched as well as this one.
        var blind = new OutageAdcsClient();
        blind.Inner.AutoApprove = false;
        await using var provider = NewProviderOn(blind);

        var refused = await FinalizeIntoHeldStateAsync("blind-refused.example.com", provider);
        var approved = await FinalizeIntoHeldStateAsync("blind-approved.example.com", provider);
        blind.Inner.DenyRequest((await ReadOrderAsync(refused.Id)).AdcsRequestId!.Value);
        blind.Inner.ApproveRequest((await ReadOrderAsync(approved.Id)).AdcsRequestId!.Value);
        blind.FailTheStatusReadWith = new CaUnavailableException("simulated RPC failure");

        var sweeper = new PendingIssuanceService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<PendingIssuanceService>.Instance,
            Options.Create(new PendingIssuanceOptions()));
        await sweeper.SweepHeldOrdersAsync(CancellationToken.None);

        (await ReadOrderAsync(refused.Id)).Status.Should().Be("invalid");
        (await ReadOrderAsync(approved.Id)).Status.Should().Be("valid",
            "the order after the faulted one still gets its certificate");
    }

    [Fact]
    public async Task ResolveHeldOrder_CaNoLongerHasTheRequest_KeepsTheFailedWording()
    {
        // The Failed arm of the same switch. A request the CA has no row for reads as
        // Failed, and the reason read answers null for a row that does not exist, so
        // the arm keeps its own wording. Pins that the two arms do not share one
        // fallback.
        //
        // A second CA whose database has never seen this request is what "no row"
        // looks like from here, and it is also what a database restored against a
        // different CA looks like.
        var order = await FinalizeIntoHeldStateAsync("forgotten.example.com");
        await using var provider = NewProviderOn(new OutageAdcsClient());

        using var scope = provider.CreateScope();
        var resolution = await scope.ServiceProvider.GetRequiredService<OrderService>()
            .ResolveHeldOrderAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.Refused);
        var stored = await ReadOrderAsync(order.Id);
        var error = JsonSerializer.Deserialize<AcmeError>(stored.ErrorJson!)!;
        error.Detail.Should().Be("The CA can no longer issue this request (it reads Failed).");
    }

    [Fact]
    public async Task ResolveHeldOrder_ExpiredWithTheCaStillUndecided_GivesUpOnTheOrder()
    {
        // The abandonment half of issue #319. The order's own advertised expiry is
        // the deadline, because RFC 8555 section 7.1.3 defines that field as the
        // point after which the server considers the order invalid, and it is the
        // only deadline the client was ever told about.
        var order = await FinalizeIntoHeldStateAsync("aged-out.example.com");
        await ExpireOrderAsync(order.Id);

        var resolution = await ResolveAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.Abandoned);
        var stored = await ReadOrderAsync(order.Id);
        stored.Status.Should().Be("invalid");
        stored.ErrorJson.Should().Contain("expired");
    }

    [Fact]
    public async Task ResolveHeldOrder_ExpiredButTheCaAlreadyIssued_DeliversRatherThanAbandons()
    {
        // The ordering that stops the expiry arm manufacturing orphans. The CA is
        // asked before the expiry is applied, so a certificate that already exists
        // is delivered rather than thrown away with a live leaf left behind at the
        // CA. Consistent with the download path, which deliberately does not
        // re-check expiry on what an order already issued (issue #318).
        var order = await FinalizeIntoHeldStateAsync("late-approval.example.com");
        var requestId = (await ReadOrderAsync(order.Id)).AdcsRequestId!.Value;
        _adcs.ApproveRequest(requestId);
        await ExpireOrderAsync(order.Id);

        var resolution = await ResolveAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.Collected);
        var stored = await ReadOrderAsync(order.Id);
        stored.Status.Should().Be("valid");
        stored.CertificateId.Should().NotBeNull();
        _adcs.RevokedSerials.Should().BeEmpty(
            "an expiry is not a reason to revoke a certificate the client asked for");
    }

    [Fact]
    public async Task ResolveHeldOrder_ClaimedWithNoRequestRecorded_IsLeftAlone()
    {
        // "processing" with no request id is a finalize in flight, between the
        // claim and the save that follows its submit. That order belongs to the
        // finalize, and a sweep that demoted it would be racing an issuance.
        var order = await CreateReadyOrderAsync("in-flight.example.com");
        await ClaimWithoutRequestIdAsync(order.Id);

        var resolution = await ResolveAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.NotHeld);
        (await ReadOrderAsync(order.Id)).Status.Should().Be("processing");
    }

    [Fact]
    public async Task ResolveHeldOrder_ClaimedWithNoRequestRecordedAndExpired_GivesUpOnTheOrder()
    {
        // The same shape long after the fact, which is a process that died between
        // the claim and the submit. Nobody knows what the CA was asked, so there is
        // no request to poll and nothing else will ever look at this row again. Its
        // own expiry is the only way out, and without this arm it would sit in
        // "processing" for ever, which is the very bug being fixed.
        var order = await CreateReadyOrderAsync("stranded.example.com");
        await ClaimWithoutRequestIdAsync(order.Id);
        await ExpireOrderAsync(order.Id);

        var resolution = await ResolveAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.Abandoned);
        (await ReadOrderAsync(order.Id)).Status.Should().Be("invalid");
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("invalid")]
    [InlineData("ready")]
    [InlineData("pending")]
    public async Task ResolveHeldOrder_OrderIsNotClaimed_TouchesNothing(string status)
    {
        // An allow list of one, so the sweep can never reach an order some other
        // part of the protocol owns.
        var order = await CreateReadyOrderAsync($"untouched-{status}.example.com");
        await SetStatusAsync(order.Id, status);

        var resolution = await ResolveAsync(order.Id);

        resolution.Should().Be(HeldOrderResolution.NotHeld);
        (await ReadOrderAsync(order.Id)).Status.Should().Be(status);
    }

    [Fact]
    public async Task ResolveHeldOrder_ApprovedLeafOutsideTheCapabilityCeiling_IsNeverDelivered()
    {
        // The finalize leaf guard has to hold on this path too. It is the hard
        // guarantee behind the advisory template metadata check, and an approval
        // that arrives minutes or days after the finalize is exactly the case
        // where a template could have been edited in between.
        var order = await FinalizeIntoHeldStateAsync("over-ceiling.example.com");
        var requestId = (await ReadOrderAsync(order.Id)).AdcsRequestId!.Value;

        _adcs.LeafIsCa = true;
        _adcs.ApproveRequest(requestId);
        await ResolveAsync(order.Id);

        var stored = await ReadOrderAsync(order.Id);
        stored.Status.Should().Be("invalid");
        stored.CertificateId.Should().BeNull("no certificate URL may ever exist for it");

        await using var verify = NewDbContext();
        (await verify.AcmeCertificates.AnyAsync(c => c.OrderId == order.Id))
            .Should().BeFalse();
        _adcs.RevokedSerials.Should().NotBeEmpty(
            "the breach path revokes what the CA issued");
    }

    // ---------------------------------------------------------------------
    // The worker half: one sweep over whatever is claimed for issuance.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Sweep_ResolvesEveryHeldOrderInOnePass()
    {
        var approved = await FinalizeIntoHeldStateAsync("sweep-approved.example.com");
        var denied = await FinalizeIntoHeldStateAsync("sweep-denied.example.com");
        var waiting = await FinalizeIntoHeldStateAsync("sweep-waiting.example.com");

        _adcs.ApproveRequest((await ReadOrderAsync(approved.Id)).AdcsRequestId!.Value);
        _adcs.DenyRequest((await ReadOrderAsync(denied.Id)).AdcsRequestId!.Value);

        await NewSweeper().SweepHeldOrdersAsync(CancellationToken.None);

        (await ReadOrderAsync(approved.Id)).Status.Should().Be("valid");
        (await ReadOrderAsync(denied.Id)).Status.Should().Be("invalid");
        (await ReadOrderAsync(waiting.Id)).Status.Should().Be("processing");
    }

    [Fact]
    public async Task Sweep_CaIsUnavailable_LeavesEveryOrderExactlyAsItWas()
    {
        // A CA outage must never be what fails an order. The sweep abandons the
        // tick and the orders wait for the next one; the alternative is that a
        // restart of CertSvc invalidates every order in flight.
        var held = await FinalizeIntoHeldStateAsync("outage.example.com");

        var offline = new ServiceCollection();
        offline.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        offline.AddSingleton<IAdcsClient>(new UnconfiguredAdcsClient());
        offline.AddSingleton(_syncTrigger);
        offline.AddSingleton(_revocationGate);
        offline.AddScoped<DeviceAttestationPolicyService>();
        offline.AddScoped<DomainPolicyAuditService>();
        offline.AddScoped<OrderService>();
        offline.AddLogging();
        await using var offlineProvider = offline.BuildServiceProvider();

        var sweeper = new PendingIssuanceService(
            offlineProvider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<PendingIssuanceService>.Instance,
            Options.Create(new PendingIssuanceOptions()));

        // The tick swallows the outage rather than throwing, so the worker loop
        // does not have to treat a stopped CA as an error.
        await sweeper.SweepHeldOrdersAsync(CancellationToken.None);

        var stored = await ReadOrderAsync(held.Id);
        stored.Status.Should().Be("processing");
        stored.ErrorJson.Should().BeNull();
        stored.AdcsRequestId.Should().NotBeNull();
    }

    [Fact]
    public async Task Sweep_CaDeniesAccess_LeavesEveryOrderExactlyAsItWas()
    {
        // Issue #336. The sweep's CaAccessDeniedException arm has existed since
        // #319 and never had a producer: nothing on the fetch path raised it, so
        // this was dead code. The reasoning is the outage's, with one difference
        // the arm itself states, that this one does not clear on its own, so it
        // logs at Error rather than Warning. The orders are untouched either way,
        // because the certificates behind them are real and safe at the CA.
        var held = await FinalizeIntoHeldStateAsync("denied.example.com");

        var denied = new ServiceCollection();
        denied.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        denied.AddSingleton<IAdcsClient>(new OutageAdcsClient
        {
            FailTheCollectionWith = new CaAccessDeniedException(
                CaAccessDeniedException.CollectPermissionMessage,
                new UnauthorizedAccessException("simulated E_ACCESSDENIED")),
        });
        denied.AddSingleton(_syncTrigger);
        denied.AddSingleton(_revocationGate);
        denied.AddScoped<DeviceAttestationPolicyService>();
        denied.AddScoped<DomainPolicyAuditService>();
        denied.AddScoped<OrderService>();
        denied.AddLogging();
        await using var deniedProvider = denied.BuildServiceProvider();

        var sweeper = new PendingIssuanceService(
            deniedProvider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<PendingIssuanceService>.Instance,
            Options.Create(new PendingIssuanceOptions()));

        // Swallowed like the outage, so a withdrawn permission does not turn the
        // worker loop into an error every poll interval until someone notices.
        await sweeper.SweepHeldOrdersAsync(CancellationToken.None);

        var stored = await ReadOrderAsync(held.Id);
        stored.Status.Should().Be("processing",
            "the certificate is live at the CA and is collected once the right is restored");
        stored.ErrorJson.Should().BeNull();
        stored.AdcsRequestId.Should().NotBeNull();
    }

    [Fact]
    public async Task Sweep_NothingIsClaimed_DoesNotTouchTheCa()
    {
        await CreateReadyOrderAsync("idle.example.com");

        await NewSweeper().SweepHeldOrdersAsync(CancellationToken.None);

        _adcs.RevokedSerials.Should().BeEmpty();
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private PendingIssuanceService NewSweeper() => new(
        _serviceProvider.GetRequiredService<IServiceScopeFactory>(),
        NullLogger<PendingIssuanceService>.Instance,
        Options.Create(new PendingIssuanceOptions { PollIntervalSeconds = 5 }));

    private CertusDbContext NewDbContext() =>
        new(new DbContextOptionsBuilder<CertusDbContext>().UseSqlite(_connection).Options);

    /// <summary>
    /// A second container over the same database, wired to a different CA. The
    /// shape the outage tests below already build by hand, for a test that needs
    /// the CA to misbehave without disturbing the shared one.
    /// </summary>
    private ServiceProvider NewProviderOn(IAdcsClient adcs)
    {
        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        services.AddSingleton(adcs);
        services.AddSingleton(_syncTrigger);
        services.AddSingleton(_revocationGate);
        services.AddScoped<DeviceAttestationPolicyService>();
        services.AddScoped<DomainPolicyAuditService>();
        services.AddScoped<OrderService>();
        services.AddLogging();
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Resolves one order on its own scope, the way the worker does. A fresh
    /// scope per call is not incidental: it is a fresh change tracker, so a test
    /// asserting on the row afterwards cannot be served a stale identity map
    /// copy of what the conditional UPDATEs wrote.
    /// </summary>
    private async Task<HeldOrderResolution> ResolveAsync(int orderId)
    {
        using var scope = _serviceProvider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<OrderService>()
            .ResolveHeldOrderAsync(orderId);
    }

    private async Task<AcmeOrder> ReadOrderAsync(int orderId)
    {
        await using var db = NewDbContext();
        return await db.AcmeOrders.AsNoTracking().SingleAsync(o => o.Id == orderId);
    }

    /// <summary>
    /// Drives a real finalize against a CA that holds every request, so the order
    /// reaches "processing" with a request id exactly the way production gets
    /// there. Building the row by hand would test a guess about that shape.
    /// </summary>
    private async Task<AcmeOrder> FinalizeIntoHeldStateAsync(
        string dnsName, IServiceProvider? provider = null)
    {
        provider ??= _serviceProvider;
        var order = await CreateReadyOrderAsync(dnsName, provider);

        using var scope = provider.CreateScope();
        var result = await scope.ServiceProvider.GetRequiredService<OrderService>()
            .FinalizeOrderAsync(order.OrderId, BuildCsr(dnsName));
        result.Success.Should().BeTrue();

        var held = await ReadOrderAsync(order.Id);
        held.Status.Should().Be("processing");
        held.AdcsRequestId.Should().NotBeNull();
        return held;
    }

    private async Task<AcmeOrder> CreateReadyOrderAsync(
        string dnsName, IServiceProvider? provider = null)
    {
        using var scope = (provider ?? _serviceProvider).CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var account = await db.AcmeAccounts.FirstOrDefaultAsync();
        if (account == null)
        {
            account = new AcmeAccount
            {
                AccountId = "pending-issuance-account",
                JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
                JwkThumbprint = "pending-issuance-thumbprint",
                Status = "valid",
                CreatedAt = DateTime.UtcNow,
            };
            db.AcmeAccounts.Add(account);
            await db.SaveChangesAsync();
        }

        var order = await scope.ServiceProvider.GetRequiredService<OrderService>()
            .CreateOrderAsync(
                account,
                "WebServer",
                new[] { new AcmeIdentifier { Type = "dns", Value = dnsName } },
                null,
                null);

        order.Status = "ready";
        foreach (var authz in order.Authorizations)
            authz.Status = "valid";
        await db.SaveChangesAsync();
        return order;
    }

    private async Task SetStatusAsync(int orderId, string status)
    {
        await using var db = NewDbContext();
        await db.AcmeOrders.Where(o => o.Id == orderId)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, status));
    }

    /// <summary>The claim without the save that follows the submit.</summary>
    private async Task ClaimWithoutRequestIdAsync(int orderId)
    {
        await using var db = NewDbContext();
        await db.AcmeOrders.Where(o => o.Id == orderId)
            .ExecuteUpdateAsync(s => s
                .SetProperty(o => o.Status, "processing")
                .SetProperty(o => o.AdcsRequestId, (int?)null));
    }

    private async Task ExpireOrderAsync(int orderId)
    {
        var past = DateTime.UtcNow.AddMinutes(-1);
        await using var db = NewDbContext();
        await db.AcmeOrders.Where(o => o.Id == orderId)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.ExpiresAt, past));
    }

    private static byte[] BuildCsr(string dnsName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={dnsName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(dnsName);
        request.CertificateExtensions.Add(sanBuilder.Build());

        return request.CreateSigningRequest();
    }

    public void Dispose()
    {
        _serviceProvider.Dispose();
        _connection.Dispose();
    }
}
