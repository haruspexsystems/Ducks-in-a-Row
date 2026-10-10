using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Certus.Core.Tests.Acme.Attestation;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

public class OrderServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CertusDbContext> _dbOptions;
    private readonly CertusDbContext _db;
    private readonly OrderService _sut;
    private readonly MockAdcsClient _adcsClient;
    private readonly CertificateSyncTrigger _syncTrigger;
    private readonly CertificateRevocationGate _revocationGate;
    private readonly AcmeAccount _account;
    private readonly List<ECDsa> _deviceKeys = new();

    public OrderServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        // Kept as a field so a test can open a second context on the same
        // database. A second context is a second change tracker, which is what
        // makes it stand in for a concurrent request: the two scopes see each
        // other's committed rows but not each other's in flight entities.
        _dbOptions = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(_dbOptions);
        _db.Database.EnsureCreated();

        _adcsClient = new MockAdcsClient();
        _syncTrigger = new CertificateSyncTrigger();
        _revocationGate = new CertificateRevocationGate();
        _sut = new OrderService(
            _db, _adcsClient, _syncTrigger, _revocationGate,
            new DeviceAttestationPolicyService(_db),
            new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);

        // Seed a test account
        _account = new AcmeAccount
        {
            AccountId = "test-account-001",
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = "test-thumbprint-001",
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        _db.AcmeAccounts.Add(_account);
        _db.SaveChanges();
    }

    [Fact]
    public async Task CreateOrder_ReturnsOrderWithPendingStatus()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Should().NotBeNull();
        order.Status.Should().Be("pending");
        order.OrderId.Should().NotBeNullOrEmpty();
        order.TemplateId.Should().Be("WebServer");
    }

    [Fact]
    public async Task CreateOrder_CreatesAuthorizationPerIdentifier()
    {
        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "dns", Value = "example.com" },
            new AcmeIdentifier { Type = "dns", Value = "www.example.com" }
        };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Authorizations.Should().HaveCount(2);
        order.Authorizations.Select(a => a.IdentifierValue)
            .Should().Contain("example.com")
            .And.Contain("www.example.com");
    }

    [Fact]
    public async Task CreateOrder_NonWildcard_CreatesAllThreeChallengeTypes()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var authz = order.Authorizations.Single();
        authz.Challenges.Should().HaveCount(3);
        authz.Challenges.Select(c => c.Type).Should()
            .Contain("http-01")
            .And.Contain("dns-01")
            .And.Contain("tls-alpn-01");

        // RFC 8555 §8.1 models the token as per challenge, so each gets its own.
        authz.Challenges.Select(c => c.Token).Distinct().Should().HaveCount(3);
        authz.Challenges.Should().OnlyContain(c => c.Status == "pending");
    }

    [Fact]
    public async Task CreateOrder_WildcardIdentifier_OnlyGetsDns01()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "*.example.com" } };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var authz = order.Authorizations.Single();
        authz.Wildcard.Should().BeTrue();
        authz.Challenges.Should().HaveCount(1);
        authz.Challenges[0].Type.Should().Be("dns-01");
    }

    [Fact]
    public async Task CreateOrder_SetsExpiresAt()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };

        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
        order.ExpiresAt.Should().BeBefore(DateTime.UtcNow.AddDays(8));
    }

    [Fact]
    public async Task GetOrder_ReturnsOrderWithNavigationProperties()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var created = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var fetched = await _sut.GetOrderAsync(created.OrderId);

        fetched.Should().NotBeNull();
        fetched!.OrderId.Should().Be(created.OrderId);
        fetched.Authorizations.Should().HaveCount(1);
        fetched.Authorizations[0].Challenges.Should().HaveCount(3); // http-01, dns-01, tls-alpn-01
    }

    [Fact]
    public async Task GetOrder_NonExistent_ReturnsNull()
    {
        var result = await _sut.GetOrderAsync("does-not-exist");
        result.Should().BeNull();
    }

    [Fact]
    public async Task RespondToChallenge_PendingChallenge_TransitionsToProcessing()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var challengeId = order.Authorizations[0].Challenges[0].ChallengeId;

        var result = await _sut.RespondToChallengeAsync(challengeId);

        result.Should().BeTrue();

        var challenge = await _sut.GetChallengeAsync(challengeId);
        challenge!.Status.Should().Be("processing");
    }

    [Fact]
    public async Task RespondToChallenge_NonPending_ReturnsFalse()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var challengeId = order.Authorizations[0].Challenges[0].ChallengeId;

        // First response succeeds
        await _sut.RespondToChallengeAsync(challengeId);
        // Second response fails (already processing)
        var result = await _sut.RespondToChallengeAsync(challengeId);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task RecalculateOrderStatus_AllAuthzValid_OrderBecomesReady()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        // Manually set authorization to valid
        order.Authorizations[0].Status = "valid";
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task RecalculateOrderStatus_ProcessingOrder_IsNotPutBackToReady()
    {
        // Issue #301. The finalize claim only ever moves an order out of
        // "ready", so anything that manufactures a fresh "ready" re-arms it.
        // This sweep is that path: responding to two challenges on one
        // authorization leaves the second queued when the first makes the
        // authorization valid, so it is still validating after the client has
        // finalized. Putting the order back to "ready" would let a second
        // finalize claim the same order and issue a second certificate.
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "claimed.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Authorizations[0].Status = "valid";
        order.Status = "processing";
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("processing");
    }

    [Fact]
    public async Task RecalculateOrderStatus_AnyAuthzInvalid_OrderBecomesInvalid()
    {
        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "dns", Value = "good.example.com" },
            new AcmeIdentifier { Type = "dns", Value = "bad.example.com" }
        };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Authorizations[0].Status = "valid";
        order.Authorizations[1].Status = "invalid";
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
    }

    [Fact]
    public async Task RecalculateOrderStatus_AnyAuthzDeactivated_OrderBecomesInvalid()
    {
        // RFC 8555 §7.5.2: a deactivated authorization is as fatal to the order as a
        // failed one. Before this arm existed the method was a silent no-op for it,
        // because "deactivated" satisfies neither the invalid test nor the all-valid
        // test, so the order would have sat pending for ever.
        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "dns", Value = "kept.example.com" },
            new AcmeIdentifier { Type = "dns", Value = "given-up.example.com" }
        };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Authorizations[0].Status = "valid";
        order.Authorizations[1].Status = "deactivated";
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
    }

    [Fact]
    public async Task RecalculateOrderStatus_DeactivatedAuthzOnAValidOrder_LeavesItValid()
    {
        // The early return is what stops an issued certificate losing the order row
        // that ties it to this account.
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "issued.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        order.Status = "valid";
        order.Authorizations[0].Status = "deactivated";
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task DeactivateAuthorization_Pending_SetsDeactivated_AndInvalidatesTheOrder()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "relinquish.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var result = await _sut.DeactivateAuthorizationAsync(order.Authorizations[0]);

        result.Outcome.Should().Be(AuthorizationDeactivationOutcome.Deactivated);
        result.Authorization.Status.Should().Be("deactivated");

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
        updated.ErrorJson.Should().NotBeNull();

        // Asserting the column alone was a false witness for as long as it stood:
        // it said the client learns why, and until issue #330 no client could read
        // this column at all. The projection is the half that makes it true, so it
        // is the half the test names.
        OrderService.ToResponse(updated, path => "https://ducks.example.com" + path)
            .Error.Should().NotBeNull("the client polling the order should learn why");
    }

    [Fact]
    public async Task DeactivateAuthorization_Valid_SetsDeactivated()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "was-valid.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        order.Authorizations[0].Status = "valid";
        order.Status = "ready";
        await _db.SaveChangesAsync();

        var result = await _sut.DeactivateAuthorizationAsync(order.Authorizations[0]);

        result.Outcome.Should().Be(AuthorizationDeactivationOutcome.Deactivated);
        result.Authorization.Status.Should().Be("deactivated");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("invalid");
    }

    [Fact]
    public async Task DeactivateAuthorization_AlreadyDeactivated_WritesNothing()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "twice.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        await _sut.DeactivateAuthorizationAsync(order.Authorizations[0]);

        // Put the order back, so a second demote would be visible if it happened.
        order.Status = "pending";
        await _db.SaveChangesAsync();

        var result = await _sut.DeactivateAuthorizationAsync(order.Authorizations[0]);

        result.Outcome.Should().Be(AuthorizationDeactivationOutcome.AlreadyDeactivated);
        result.Authorization.Status.Should().Be("deactivated");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("pending");
    }

    [Fact]
    public async Task DeactivateAuthorization_Invalid_IsRefused_AndWritesNothing()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "terminal.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        order.Authorizations[0].Status = "invalid";
        await _db.SaveChangesAsync();

        var result = await _sut.DeactivateAuthorizationAsync(order.Authorizations[0]);

        result.Outcome.Should().Be(AuthorizationDeactivationOutcome.NotDeactivatable);
        result.Authorization.Status.Should().Be("invalid");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("pending");
    }

    [Fact]
    public async Task DeactivateAuthorization_OnAValidOrder_LeavesTheOrderValid()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "already-issued.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        order.Status = "valid";
        await _db.SaveChangesAsync();

        var result = await _sut.DeactivateAuthorizationAsync(order.Authorizations[0]);

        result.Outcome.Should().Be(AuthorizationDeactivationOutcome.Deactivated);
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeOrder_NotReady_Fails()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var result = await _sut.FinalizeOrderAsync(order.OrderId, new byte[] { 1, 2, 3 });

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.OrderNotReady,
            "a finalize on an order that is not ready is not a complaint about the CSR");
    }

    [Fact]
    public async Task FinalizeOrder_WithADeactivatedAuthorization_NeverReachesTheCa()
    {
        // RFC 8555 §7.5.2: a deactivated authorization is never sufficient for
        // issuance. Force the order to "ready" so the status check cannot be what
        // refuses, which is the only way to exercise this guard.
        //
        // Asserting the bool alone would pass even with the guard placed after the
        // submit, so assert CsrDer too: it is written immediately before the ADCS
        // call, so its absence proves nothing reached the CA.
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "disowned.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        order.Authorizations[0].Status = "deactivated";
        order.Status = "ready";
        await _db.SaveChangesAsync();

        var result = await _sut.FinalizeOrderAsync(
            order.OrderId, BuildCsr("disowned.example.com"));

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.OrderNotReady,
            "RFC 8555 section 6.7 calls this orderNotReady, not badCSR");
        result.ErrorMessage.Should().Contain("deactivated");
        result.ErrorMessage.Should().Contain("disowned.example.com",
            "the refusal matches the controller's own pre-check word for word");

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.CsrDer.Should().BeNull("nothing may be submitted to the CA");
        updated.Status.Should().Be("ready", "the guard refuses, it does not transition");
    }

    [Fact]
    public async Task FinalizeOrder_OrderDemotedByAConcurrentRequest_NeverReachesTheCa()
    {
        // Issue #301. A finalize reads the order, passes every check, and only
        // then writes "processing". Another request committing a demote inside
        // that window used to lose its write: the tracked copy this scope holds
        // still said "ready", so the save put "processing" back over it and the
        // CSR went to the CA regardless.
        //
        // No authorization is deactivated here, deliberately. That keeps the
        // deactivation guard out of it, so the claim is the only thing that can
        // refuse. The demote itself is the shape AccountService.DeactivateAsync
        // writes when an account is deactivated mid finalize.
        var adcs = Substitute.For<IAdcsClient>();
        var sut = new OrderService(
            _db, adcs, _syncTrigger, _revocationGate,
            new DeviceAttestationPolicyService(_db),
            new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);
        var order = await CreateReadyOrderAsync("raced.example.com");
        var csr = BuildCsr("raced.example.com");

        // The concurrent request, on its own change tracker, committing first.
        await using (var concurrent = new CertusDbContext(_dbOptions))
        {
            var sameRow = await concurrent.AcmeOrders.SingleAsync(o => o.Id == order.Id);
            sameRow.Status = "invalid";
            await concurrent.SaveChangesAsync();
        }

        // The window the bug lived in: this scope has not noticed, which is the
        // whole premise. Asserting it makes the test fail loudly rather than
        // silently stop reproducing if EF's identity map behaviour ever changes.
        order.Status.Should().Be("ready");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.OrderNotReady,
            "losing the race must be indistinguishable from arriving late");
        result.ErrorMessage.Should().Contain(
            "invalid", "the refusal names the status that actually won");
        await adcs.DidNotReceive().SubmitCertificateRequestAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>());

        // Read the row back on a fresh tracker, so this asserts what is stored
        // rather than what this scope remembers.
        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("invalid", "the demote must survive");
        stored.CsrDer.Should().BeNull("nothing may be recorded as submitted");
    }

    [Fact]
    public async Task FinalizeOrder_UnknownOrderId_ReportsNotFound()
    {
        // Not a CSR problem either. The controller answers its own lookup with 404
        // malformed, so this arm has to carry an outcome that says the same thing
        // rather than falling into badCSR (issue #313).
        var result = await _sut.FinalizeOrderAsync("no-such-order", new byte[] { 1, 2, 3 });

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.NotFound);
    }

    [Fact]
    public async Task FinalizeOrder_CaRefuses_ReportsCaRefused()
    {
        // A CA that decides against the request is not a complaint about the CSR
        // and no longer answers badCSR (issue #324). Pin the outcome and the type
        // written into the order, so the wire and the record cannot drift apart
        // again: the mock denies a request for a template it does not publish.
        var order = await CreateReadyOrderAsync("ca-denies.example.com");
        var csr = BuildCsr("ca-denies.example.com");
        order.TemplateId = "NoSuchTemplate";
        await _db.SaveChangesAsync();

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.CaRefused);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid", "the CA had its say and the order is done");
        updated.ErrorJson.Should().Contain(AcmeErrorType.ServerInternal,
            "the type in the record is the type the client is now told");
    }

    #region Issue #362: CA authored text is sanitized before it reaches the wire

    [Fact]
    public async Task FinalizeOrder_CaRefuses_SanitizesTheMessageOnBothWires()
    {
        // The finalize writes the CA's words to two places at once: the problem
        // document the client is handed, through FinalizeResult.ErrorMessage, and
        // the order's own ErrorJson. Both are asserted, because gating one and not
        // the other is precisely the failure this closes.
        //
        // Assert on the deserialized detail rather than on the raw ErrorJson.
        // System.Text.Json escapes a bidirectional override to \u202E on its way
        // into the column, so a NotContain over the JSON text passes whether or not
        // the value was sanitized, and the test would be worthless.
        const char rlo = (char)0x202e;
        const char lineSep = (char)0x2028;
        var adcs = new RefusingAdcsClient
        {
            RefusalMessage = "Denied for " + rlo + "moc.elpmaxe" + lineSep + "FATAL forged",
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("refused.example.com");
        var csr = BuildCsr("refused.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Outcome.Should().Be(FinalizeOutcome.CaRefused);
        result.ErrorMessage.Should()
            .Be("Denied for moc.elpmaxeFATAL forged",
                "the client is told what the CA decided, in characters it cannot be deceived by");

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        var recorded = JsonSerializer.Deserialize<AcmeError>(stored.ErrorJson!);
        recorded!.Detail.Should().Be("Denied for moc.elpmaxeFATAL forged");
    }

    [Fact]
    public async Task FinalizeOrder_CaRefuses_BoundsAnOverLongMessage()
    {
        // The practical half. A disposition message may be 8192 characters by the
        // CA schema, and nothing between the CA and the client bounds it:
        // AcmeOrder.ErrorJson declares no width, SQLite would not enforce one if it
        // did, and a problem document has no cap of its own.
        var adcs = new RefusingAdcsClient { RefusalMessage = new string('x', 8192) };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("verbose.example.com");
        var csr = BuildCsr("verbose.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.ErrorMessage.Should().NotBeNull();
        result.ErrorMessage!.Length.Should()
            .BeLessThanOrEqualTo(CertificateTextSanitizer.MaxDispositionMessageLength);

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        var recorded = JsonSerializer.Deserialize<AcmeError>(stored.ErrorJson!);
        recorded!.Detail!.Length.Should()
            .BeLessThanOrEqualTo(CertificateTextSanitizer.MaxDispositionMessageLength);
    }

    [Fact]
    public async Task FinalizeOrder_CaRefusesWithABlankMessage_FallsBackToItsOwnWords()
    {
        // The sanitizer answers null for a blank value, which is what makes the
        // fallback fire. An empty string is not null, so before this the client got
        // an empty detail and the record kept one.
        var adcs = new RefusingAdcsClient { RefusalMessage = "   " };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("silent.example.com");
        var csr = BuildCsr("silent.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.ErrorMessage.Should().Be("CA denied the certificate request.");

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        var recorded = JsonSerializer.Deserialize<AcmeError>(stored.ErrorJson!);
        recorded!.Detail.Should().Be("Certificate request was denied by the CA.");
    }

    [Fact]
    public async Task FinalizeOrder_CaErrors_SanitizesTheMessageToo()
    {
        // The other arm of the same branch. An Error disposition carries the CA's
        // words onto the same two wires, so it needs the same guard as the denial.
        const char esc = (char)0x1b;
        var adcs = new RefusingAdcsClient
        {
            RefuseWith = SubmitStatus.Error,
            RefusalMessage = esc + "[31mThe request could not be decoded",
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("errored.example.com");
        var csr = BuildCsr("errored.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Outcome.Should().Be(FinalizeOutcome.CaRefused);
        result.ErrorMessage.Should().Be("[31mThe request could not be decoded");
    }

    [Fact]
    public async Task FinalizeOrder_CaRefuses_KeepsRealLineBreaksOnTheWire()
    {
        // The counterweight to the four above. The CA composes multi line messages
        // and the sanitizer keeps tab, CR and LF on purpose, so a client and the
        // certificate detail page both still see the message the CA wrote. Only
        // the log takes the flattened form, because it is the surface that reads a
        // break as the start of a record nobody wrote.
        const char cr = (char)0x0d;
        const char lf = (char)0x0a;
        var raw = "Error Constructing or Publishing Certificate" + cr + lf + "Invalid Request";
        var adcs = new RefusingAdcsClient { RefusalMessage = raw };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("multiline.example.com");
        var csr = BuildCsr("multiline.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.ErrorMessage.Should().Be(raw);
    }

    #endregion

    [Fact]
    public async Task FinalizeOrder_PendingAtTheCa_ReportsProcessing()
    {
        // Behaviour the #301 claim had to preserve rather than a bug it fixed.
        // The claim is now written by an UPDATE that goes round the change
        // tracker, so the order has to be reloaded or this scope keeps serving
        // "ready" out of its identity map. The controller re-reads the order
        // through this same scope to build its response, so without the reload
        // a client would be told its order is still ready while the CSR sits at
        // the CA. Held at the CA rather than auto approved, because that is the
        // one outcome where "processing" is the order's resting state.
        _adcsClient.AutoApprove = false;
        var order = await CreateReadyOrderAsync("held.example.com");
        var csr = BuildCsr("held.example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();

        var reread = await _sut.GetOrderAsync(order.OrderId);
        reread!.Status.Should().Be("processing");
        reread.CsrDer.Should().NotBeNull("the claim records the CSR it claimed for");
        reread.AdcsRequestId.Should().NotBeNull();
    }

    #region Issue #312: a demote landing while the CSR is at the CA

    // The window these tests live in is the gap issue #301's claim left open. The
    // claim moves the order to "processing" and the CSR goes to the CA, and only
    // when the CA answers does IssueCertificateAsync write the outcome. A demote
    // committed by another scope inside that gap used to be a straight lost update,
    // in whichever direction lost the race to SaveChanges, because neither write
    // carried a predicate.

    /// <summary>
    /// Builds a second OrderService over a second DbContext, so a test can drive the
    /// real service as a concurrent request rather than write a status by hand.
    /// </summary>
    private OrderService NewOrderServiceOn(CertusDbContext db, IAdcsClient? adcs = null) =>
        new(db, adcs ?? _adcsClient, _syncTrigger, _revocationGate,
            new DeviceAttestationPolicyService(db),
            new DomainPolicyAuditService(db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);

    [Fact]
    public async Task FinalizeOrder_AuthorizationDeactivatedWhileTheCsrIsAtTheCa_StillIssues()
    {
        // Issue #312, the direction the issue describes. The demote lands while the
        // certificate is at the CA, and the completion writes over it.
        //
        // Asserting only the final status would pass before the fix: the demote
        // writes "invalid" and the unpredicated completion writes "valid" back, so
        // the stored status reads "valid" either way. ErrorJson is what separates the
        // two worlds. The demote sets it and the completion never clears it, so
        // before the fix the row is Status="valid" carrying "an authorization for
        // this order was deactivated by the client", a self contradiction on its face
        // and the shortest description of the corruption.
        var adcs = new InterleavingAdcsClient();
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("mid-flight.example.com");
        var authorizationId = order.Authorizations[0].AuthorizationId;
        var csr = BuildCsr("mid-flight.example.com");

        adcs.WhileTheCertificateIsAtTheCa = async () =>
        {
            // The concurrent request, on its own change tracker, driving the real
            // service. Writing "invalid" by hand here would test a mock of the demote
            // and would keep passing after the demote learned to refuse.
            await using var concurrent = new CertusDbContext(_dbOptions);
            var concurrentService = NewOrderServiceOn(concurrent);
            var authz = await concurrentService.GetAuthorizationAsync(authorizationId);
            await concurrentService.DeactivateAuthorizationAsync(authz!);
        };

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();

        // A third tracker, so this asserts what is stored rather than what either
        // participant remembers.
        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("valid");
        stored.ErrorJson.Should().BeNull(
            "a claimed order is never demoted, so nothing may have written a refusal over it");
        stored.CertificateId.Should().NotBeNull();
        (await verify.AcmeCertificates.CountAsync(c => c.OrderId == order.Id))
            .Should().Be(1);

        // The client's own request still did what it asked for. Only the order it had
        // already finalized is left alone.
        var storedAuthz = await verify.AcmeAuthorizations
            .SingleAsync(a => a.AuthorizationId == authorizationId);
        storedAuthz.Status.Should().Be("deactivated");
    }

    [Fact]
    public async Task DeactivateAuthorization_WithTheOrderProcessing_LeavesTheOrderAlone()
    {
        // Issue #312 at the source, with no race staged: a claimed order is simply
        // not a thing this write may touch. Its CSR is at the CA and the finalize
        // that claimed it owns the outcome.
        var order = await CreateReadyOrderAsync("claimed.example.com");
        order.Status = "processing";
        await _db.SaveChangesAsync();

        var authz = await _sut.GetAuthorizationAsync(order.Authorizations[0].AuthorizationId);
        var result = await _sut.DeactivateAuthorizationAsync(authz!);

        result.Outcome.Should().Be(AuthorizationDeactivationOutcome.Deactivated);

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("processing");
        stored.ErrorJson.Should().BeNull();
        (await verify.AcmeAuthorizations.SingleAsync(a => a.Id == authz!.Id))
            .Status.Should().Be("deactivated", "the client's own request still stands");
    }

    [Fact]
    public async Task DeactivateAuthorization_OnAStaleReadOfAnOrderThatCompleted_WritesNothing()
    {
        // Issue #312, the direction the issue does not describe, and the worse one.
        // The demote reads its order status off an entity the controller loaded at
        // request start, so a completion landing in between is invisible to it. Its
        // UPDATE then writes "invalid" over "valid" while CertificateId and the
        // AcmeCertificate row survive, because it touches only Status and ErrorJson.
        // The download path gates on account ownership and never on order status, so
        // the client goes on downloading a certificate for an order that reads
        // invalid.
        //
        // The stale read has to be staged deliberately. Loading the authorization
        // after the finalize would see "valid" and the old exclusion list would
        // correctly skip, so a plain sequential version of this test passes before
        // the fix.
        await using var concurrent = new CertusDbContext(_dbOptions);
        var concurrentService = NewOrderServiceOn(concurrent);

        var order = await CreateReadyOrderAsync("stale.example.com");
        var csr = BuildCsr("stale.example.com");

        var authz = await concurrentService.GetAuthorizationAsync(
            order.Authorizations[0].AuthorizationId);
        authz!.Order.Status.Should().Be("ready", "the stale read is the whole premise");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);
        result.Success.Should().BeTrue();

        await concurrentService.DeactivateAuthorizationAsync(authz);

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("valid", "an order holding a certificate is terminal");
        stored.ErrorJson.Should().BeNull();
        stored.CertificateId.Should().NotBeNull(
            "the demote used to leave this standing under an invalid order, and the " +
            "certificate stayed downloadable");
    }

    [Fact]
    public async Task FinalizeOrder_AccountDeactivatedWhileTheCsrIsAtTheCa_StillIssues()
    {
        // The same race with the other demoter. Worth its own test because one of
        // that method's two call sites is the dashboard, so this interleaving is an
        // administrator and a client rather than an account racing itself.
        //
        // Two discriminators now. The count this demoter returns is the number the
        // dashboard shows the administrator: 1 before the fix, 0 after. And since
        // issue #320 it writes an ErrorJson on every order it does invalidate, so a
        // demote that reached this order would leave one behind. The stored status
        // reads "valid" either way in this direction, which is exactly the trap
        // CLAUDE.md warns about, so the error column is the assertion that separates
        // a fixed build from a broken one.
        var adcs = new InterleavingAdcsClient();
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("dashboard.example.com");
        var csr = BuildCsr("dashboard.example.com");

        AccountDeactivationResult? deactivation = null;
        adcs.WhileTheCertificateIsAtTheCa = async () =>
        {
            await using var concurrent = new CertusDbContext(_dbOptions);
            var accounts = new AccountService(concurrent, NullLogger<AccountService>.Instance);
            deactivation = await accounts.DeactivateAsync(
                _account.Id, AccountDeactivationOrigin.Dashboard);
        };

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();
        deactivation!.Outcome.Should().Be(AccountDeactivationOutcome.Deactivated);
        deactivation.InvalidatedOrders.Should().Be(
            0, "a claimed order is not a pending operation this server can still cancel");

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("valid");
        stored.ErrorJson.Should().BeNull(
            "a claimed order is never demoted, so nothing may have written a refusal over it");
        (await verify.AcmeCertificates.CountAsync(c => c.OrderId == order.Id))
            .Should().Be(1);

        // The certificate is stored but unreachable, which is the point: every kid
        // authenticated request rejects a non valid account.
        (await verify.AcmeAccounts.SingleAsync(a => a.Id == _account.Id))
            .Status.Should().Be("deactivated");
    }

    [Fact]
    public async Task RecalculateOrderStatus_WithAProcessingOrder_IsNotDemoted()
    {
        // The third demoter, and the only one that is not a client request: this runs
        // on the validation worker's own DbContext. Sibling of
        // RecalculateOrderStatus_ProcessingOrder_IsNotPutBackToReady, which issue
        // #301 added for the other arm of the same method.
        var order = await CreateReadyOrderAsync("swept.example.com");
        order.Status = "processing";
        order.Authorizations[0].Status = "invalid";
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id))
            .Status.Should().Be("processing");
    }

    [Fact]
    public async Task IssueCertificate_ThatLosesTheStatusCas_WritesNoCertificateRow()
    {
        // Pins the defensive arm rather than reproducing a reachable bug. After #312
        // no product writer can move a claimed order from another scope, so the loss
        // has to be forced, and a hand written UPDATE is the honest way to force it
        // precisely because no caller can.
        //
        // What is pinned is that losing leaves nothing behind: no AcmeCertificate row
        // for a certificate that will never be delivered, and the winner's status
        // intact rather than overwritten. AdcsRequestId survives because it is saved
        // before the transaction opens, and it is the only record of what the CA was
        // asked.
        var adcs = new InterleavingAdcsClient();
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("forced.example.com");
        var csr = BuildCsr("forced.example.com");

        adcs.WhileTheCertificateIsAtTheCa = async () =>
        {
            await using var concurrent = new CertusDbContext(_dbOptions);
            var sameRow = await concurrent.AcmeOrders.SingleAsync(o => o.Id == order.Id);
            sameRow.Status = "invalid";
            await concurrent.SaveChangesAsync();
        };

        await sut.FinalizeOrderAsync(order.OrderId, csr);

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("invalid", "the swap refuses rather than overwriting");
        stored.CertificateId.Should().BeNull();
        stored.AdcsRequestId.Should().NotBeNull(
            "the record of what the CA was asked is written before the transaction opens");
        (await verify.AcmeCertificates.CountAsync(c => c.OrderId == order.Id))
            .Should().Be(0, "an undelivered certificate leaves no row behind");
    }

    [Fact]
    public async Task FinalizeOrder_FailingAfterTheOrderLeftProcessing_DoesNotDemoteIt()
    {
        // The failure arm in FinalizeOrderAsync is a demote as well, so it names its
        // legal predecessor like every other one (issue #312). It normally catches a
        // submit that never reached the CA, where the order is the "processing" this
        // scope just claimed, but its try block also covers the far side of the
        // completion commit: the reload and the sync nudge that follow it are
        // ordinary calls that can throw, and by then the order is committed "valid"
        // with its certificate row stored. Writing "invalid" over that would put a
        // downloadable certificate under an invalid order, which is the corruption
        // the rest of this change removes, reintroduced by the error path.
        //
        // Staged by having the CA fetch commit the order out of processing and then
        // throw, which is the same state the catch would see in the real ordering.
        var adcs = new InterleavingAdcsClient();
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("threw-late.example.com");
        var csr = BuildCsr("threw-late.example.com");

        adcs.WhileTheCertificateIsAtTheCa = async () =>
        {
            await using var concurrent = new CertusDbContext(_dbOptions);
            var sameRow = await concurrent.AcmeOrders.SingleAsync(o => o.Id == order.Id);
            sameRow.Status = "valid";
            await concurrent.SaveChangesAsync();
            throw new InvalidOperationException("the tail of the completion threw");
        };

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse("the finalize did fail, and says so");

        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id))
            .Status.Should().Be("valid", "an order that already left processing is not demoted here");
    }

    [Fact]
    public async Task FinalizeOrder_IssuedAtTheCa_ReportsValidThroughTheSameScope()
    {
        // The win path twin of FinalizeOrder_PendingAtTheCa_ReportsProcessing, and the
        // only thing that catches a missing reload after the completion commits. The
        // status now moves through an UPDATE that goes round the change tracker, so
        // without the reload the controller, which re-reads the order through this
        // same scoped DbContext, is handed "processing" out of the identity map for an
        // order whose certificate is already issued and stored.
        var order = await CreateReadyOrderAsync("issued.example.com");
        var csr = BuildCsr("issued.example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();

        var reread = await _sut.GetOrderAsync(order.OrderId);
        reread!.Status.Should().Be("valid");
        reread.CertificateId.Should().NotBeNull();
    }

    #endregion

    #region Issue #321: the client hanging up while the CSR is at the CA

    // One window, walked once per CA outcome, and then the rule that keeps it shut.
    // The claim has moved the order to "processing" and handed its CSR to the CA, and
    // every column that will ever tie the order to what the CA issued is still
    // unwritten. Every write in that stretch used to run on the caller's token, so a
    // client that hung up mid finalize threw out of the first save, the failure arm
    // demoted the order to invalid, and its reload discarded the request id the throw
    // had left unsaved.
    //
    // Cancelling the test's own source inside the submit callback is the disconnect.
    // What token the submit itself was handed does not enter into the first three:
    // RequestAborted fires on the controller's token, and the fix is that nothing
    // past the claim reads it.

    [Fact]
    public async Task FinalizeOrder_ClientHangsUpWhileTheCsrIsAtTheCa_StillDeliversTheCertificate()
    {
        // The issued arm, and the orphan the issue is named for: a certificate live
        // at the CA, an order reading invalid, and no row pointing one at the other,
        // so the inventory sync surfaced it as an ordinary certificate with no ACME
        // order behind it.
        using var clientHungUp = new CancellationTokenSource();
        var adcs = new InterleavingAdcsClient
        {
            WhileTheCsrIsAtTheCa = () =>
            {
                clientHungUp.Cancel();
                return Task.CompletedTask;
            }
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("hung-up.example.com");
        var csr = BuildCsr("hung-up.example.com");

        var result = await sut.FinalizeOrderAsync(
            order.OrderId, csr, clientHungUp.Token);

        clientHungUp.IsCancellationRequested.Should().BeTrue(
            "the disconnect is the whole premise");
        result.Success.Should().BeTrue();
        result.Outcome.Should().Be(FinalizeOutcome.Submitted);
        result.ErrorMessage.Should().BeNull();

        // A fresh tracker, so this asserts what is stored rather than what the
        // finalize remembers.
        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("valid");
        stored.ErrorJson.Should().BeNull();
        stored.AdcsRequestId.Should().NotBeNull(
            "the record of what the CA was asked is what stops the certificate being an orphan");
        stored.CertificateId.Should().NotBeNull();
        (await verify.AcmeCertificates.CountAsync(c => c.OrderId == order.Id))
            .Should().Be(1);
    }

    [Fact]
    public async Task FinalizeOrder_ClientHangsUpWithTheCaHoldingTheRequest_StillRecordsTheRequestId()
    {
        // The pending arm. The request id is the only thing tying this order to the
        // certificate an operator approves later, and losing it to a disconnect
        // used to make that separation permanent. Since issue #319 the pending
        // issuance sweep is what follows the id up, which raises the stakes on this
        // save rather than lowering them: an order whose id went missing is now the
        // one case the sweep cannot rescue, because it has nothing to ask the CA
        // about.
        using var clientHungUp = new CancellationTokenSource();
        var adcs = new InterleavingAdcsClient
        {
            WhileTheCsrIsAtTheCa = () =>
            {
                clientHungUp.Cancel();
                return Task.CompletedTask;
            }
        };
        adcs.Inner.AutoApprove = false;
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("hung-up-held.example.com");
        var csr = BuildCsr("hung-up-held.example.com");

        var result = await sut.FinalizeOrderAsync(
            order.OrderId, csr, clientHungUp.Token);

        result.Success.Should().BeTrue();
        result.Outcome.Should().Be(FinalizeOutcome.Submitted);
        result.ErrorMessage.Should().BeNull();

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("processing", "a held request is not a failed one");
        stored.ErrorJson.Should().BeNull();
        stored.AdcsRequestId.Should().NotBeNull();
    }

    [Fact]
    public async Task FinalizeOrder_ClientHangsUpAndTheCaDenies_KeepsTheReasonTheCaGave()
    {
        // The denied arm. It reaches the same terminal status either way, so what a
        // disconnect used to cost here was the explanation: the CA's own reason was
        // written on the caller's token, the throw took it, and the failure arm put
        // the generic "failed to submit" over it. That is the difference between an
        // operator fixing a template and an operator guessing.
        //
        // The mock denies a template it does not have, so the order is pointed at
        // one. Nothing between the claim and the submit reads the template, so this
        // stages the denial without disturbing any other check.
        using var clientHungUp = new CancellationTokenSource();
        var adcs = new InterleavingAdcsClient
        {
            WhileTheCsrIsAtTheCa = () =>
            {
                clientHungUp.Cancel();
                return Task.CompletedTask;
            }
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("denied.example.com");
        order.TemplateId = "NoSuchTemplate";
        await _db.SaveChangesAsync();
        var csr = BuildCsr("denied.example.com");

        var result = await sut.FinalizeOrderAsync(
            order.OrderId, csr, clientHungUp.Token);

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.CaRefused,
            "a disconnect does not turn the CA's refusal into some other refusal");
        result.ErrorMessage.Should().Contain("NoSuchTemplate");

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("invalid");
        stored.ErrorJson.Should().Contain("NoSuchTemplate",
            "the client is told why the CA refused, not that something went wrong");
    }

    [Fact]
    public async Task FinalizeOrder_HandsTheCaATokenTheClientCannotCancel()
    {
        // Asserted on the token itself rather than through an outcome, because with
        // today's COM client no outcome can tell the two tokens apart: its Submit
        // runs inside Task.Run(work, token), an overload that only drops the work
        // before it starts and cannot interrupt a call already in flight. The rule
        // is about the claim, not about that implementation. Once the order has left
        // "ready" it is committed to this CSR, and a submit is not idempotent, so
        // the caller's token has no business reaching the CA at all.
        using var clientHungUp = new CancellationTokenSource();
        var adcs = new InterleavingAdcsClient();
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("no-token.example.com");
        var csr = BuildCsr("no-token.example.com");

        var result = await sut.FinalizeOrderAsync(
            order.OrderId, csr, clientHungUp.Token);

        result.Success.Should().BeTrue();
        clientHungUp.Token.CanBeCanceled.Should().BeTrue(
            "otherwise this asserts nothing about what was withheld");
        adcs.TokenTheSubmitReceived.CanBeCanceled.Should().BeFalse(
            "a claimed order's CSR goes to the CA whether or not the client is still listening");
    }

    #endregion

    [Fact]
    public async Task ToResponse_IncludesCorrectUrls()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var response = OrderService.ToResponse(order, path => $"https://certus{path}");

        response.Status.Should().Be("pending");
        response.Identifiers.Should().HaveCount(1);
        response.Identifiers[0].Value.Should().Be("example.com");
        response.Authorizations.Should().HaveCount(1);
        response.Authorizations[0].Should().Contain("/authz/");
        response.Finalize.Should().Contain($"/order/{order.OrderId}/finalize");
        response.Certificate.Should().BeNull(); // Not issued yet
    }

    [Fact]
    public async Task ToAuthorizationResponse_IncludesChallenges()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var authz = order.Authorizations[0];

        var response = OrderService.ToAuthorizationResponse(
            authz, "WebServer", path => $"https://certus{path}");

        response.Identifier.Type.Should().Be("dns");
        response.Identifier.Value.Should().Be("example.com");
        response.Status.Should().Be("pending");
        response.Challenges.Should().HaveCount(3);
        response.Challenges.Select(c => c.Type).Should()
            .Contain("http-01")
            .And.Contain("dns-01")
            .And.Contain("tls-alpn-01");
        response.Challenges.Should().OnlyContain(c => c.Url.Contains("/chall/"));
        response.Challenges.Should().OnlyContain(c => !string.IsNullOrEmpty(c.Token));
    }

    [Fact]
    public async Task ToAuthorizationResponse_WildcardIdentifier_StripsPrefixAndSetsWildcard()
    {
        // RFC 8555 §7.1.4: the authorization identifier carries the base domain
        // without the "*." prefix; the wildcard field signals the wildcard.
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "*.example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var authz = order.Authorizations[0];

        var response = OrderService.ToAuthorizationResponse(
            authz, "WebServer", path => $"https://certus{path}");

        response.Identifier.Type.Should().Be("dns");
        response.Identifier.Value.Should().Be("example.com");
        response.Wildcard.Should().BeTrue();
    }

    [Fact]
    public async Task FinalizeOrder_WildcardOrder_ApexCsr_Rejected()
    {
        // Order authorized for the wildcard, CSR asks for the apex. The wildcard marker must not
        // be stripped during comparison, so this is a mismatch and finalize must fail.
        var order = await CreateReadyOrderAsync("*.example.com");
        var csr = BuildCsr("example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("SANs do not match");
    }

    [Fact]
    public async Task FinalizeOrder_NonWildcardOrder_WildcardCsr_Rejected()
    {
        // The dangerous direction: an apex authorization (satisfiable by HTTP-01) must not be able
        // to finalize a wildcard CSR, which would yield a wildcard cert that was never DNS-01 validated.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsr("*.example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("SANs do not match");
    }

    [Fact]
    public async Task FinalizeOrder_ExactMatch_Succeeds()
    {
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsr("example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeOrder_Expired_RejectedAndMarkedInvalid()
    {
        // A ready order that has passed its expiry must not finalize (RFC 8555 §7.1.3).
        var order = await CreateReadyOrderAsync("example.com");
        order.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        await _db.SaveChangesAsync();
        var csr = BuildCsr("example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.Expired);
        result.ErrorMessage.Should().Contain("expired");

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
    }

    #region Non-DNS SAN smuggling (issue #100)

    [Fact]
    public async Task FinalizeOrder_UpnOtherNameSan_Rejected()
    {
        // The crown jewel smuggle: a valid DNS name the client controls plus a
        // UPN otherName for a domain user. On an enrollee supplies subject
        // template that identity would be issued. The proxy must refuse it.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteUpnOtherName(w, "attacker@home.local");
        });

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("must not carry subject alternative names");
        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("ready");
        updated.AdcsRequestId.Should().BeNull();
    }

    [Fact]
    public async Task FinalizeOrder_IpAddressSan_Rejected()
    {
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteIpAddress(w, new byte[] { 10, 0, 0, 1 });
        });

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("must not carry subject alternative names");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_Rfc822NameSan_Rejected()
    {
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteRfc822Name(w, "device@example.com");
        });

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("must not carry subject alternative names");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_DirectoryNameSan_Rejected()
    {
        // A directoryName is refused like any other non DNS SAN. Depending on how
        // strictly BouncyCastle reads the explicit tag the wording may be the SAN
        // refusal or the parse refusal, so assert only that the raw DER is refused
        // and the order stays retryable.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteDirectoryName(w, "evil");
        });

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().NotBeNullOrEmpty();
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_PermanentIdentifierSan_Rejected()
    {
        // A device PermanentIdentifier is a recognized SAN type, but a dns order
        // authorizes no device identifier, so a matching DNS name does not save it.
        var order = await CreateReadyOrderAsync("example.com");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(key, "CN=example.com", DeviceSerial, null, "example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("must not carry subject alternative names");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_CnFallbackMasksHostileSan_Rejected()
    {
        // Before the fix a CSR with no DNS SAN fell back to the subject CN, so a
        // hostile non DNS SAN alongside a matching CN would pass. It must not.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension(
            "CN=example.com", w => WriteUpnOtherName(w, "attacker@home.local"));

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("must not carry subject alternative names");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_CnOnlyNoSan_Succeeds()
    {
        // The CN fallback itself is unchanged: a CSR with no SAN extension at all
        // is still identified by its subject CN.
        var order = await CreateReadyOrderAsync("example.com");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(key, "CN=example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeOrder_GarbageCsr_Rejected()
    {
        // A CSR that does not parse now returns a clean rejection (mapped to
        // badCSR by the controller) instead of escaping as a 500.
        var order = await CreateReadyOrderAsync("example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, new byte[] { 1, 2, 3 });

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.BadCsr, "this one really is the CSR");
        result.ErrorMessage.Should().Contain("could not be parsed");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_HostileSan_NeverReachesTheCa()
    {
        // The raw DER must never be submitted to ADCS when the SAN check fails.
        var adcs = Substitute.For<IAdcsClient>();
        var sut = new OrderService(
            _db, adcs, _syncTrigger, _revocationGate,
            new DeviceAttestationPolicyService(_db),
            new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=example.com", w =>
        {
            WriteDnsName(w, "example.com");
            WriteUpnOtherName(w, "attacker@home.local");
        });

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        await adcs.DidNotReceive().SubmitCertificateRequestAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    #endregion

    #region Subject CN validation (issue #167)

    [Fact]
    public async Task FinalizeOrder_CnOutsideOrder_Rejected()
    {
        // The residual subject smuggle deferred from #100: the SAN matches the
        // order, so before the fix the CSR passed with an arbitrary CN, and on
        // an enrollee supplies subject template ADCS would have issued it.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=evil.attacker.test", w =>
            WriteDnsName(w, "example.com"));

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("subject CN");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_DescriptiveCn_Rejected()
    {
        // Policy decision on issue #167: a descriptive CN is refused even though
        // it names no competing identifier. Public ACME CAs enforce the same
        // rule, so clients that work against them are unaffected.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=My Web Server", w =>
            WriteDnsName(w, "example.com"));

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("subject CN");
    }

    [Fact]
    public async Task FinalizeOrder_NoCn_SanOnly_Succeeds()
    {
        // Modern clients are SAN only. The CN rule applies only when a CN is
        // present, so a subject naming no CN keeps finalizing.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("O=Certus Test", w =>
            WriteDnsName(w, "example.com"));

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeOrder_CnCaseDiffers_Succeeds()
    {
        // DNS names compare case insensitively; the CN check normalizes the
        // same way the SAN comparison does.
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=EXAMPLE.COM", w =>
            WriteDnsName(w, "example.com"));

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
    }

    [Fact]
    public async Task FinalizeOrder_MultiCnNoSan_SecondCnDiffers_Rejected()
    {
        // The no SAN fallback identifies the CSR by its first CN alone, so
        // before the fix a second, different CN rode through unexamined and
        // both landed in the raw DER handed to ADCS. The subject string is
        // reversed on encoding, so the DER carries example.com first, which
        // is exactly the shape that slipped past the SetEquals check.
        var order = await CreateReadyOrderAsync("example.com");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(key, "CN=evil.example, CN=example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("subject CN");
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeOrder_WildcardOrder_WildcardCn_Succeeds()
    {
        // Public CAs historically carry the wildcard name in the CN as well;
        // membership in the order's identifier set keeps that working, with
        // the wildcard marker compared verbatim.
        var order = await CreateReadyOrderAsync("*.example.com");
        var csr = BuildCsr("*.example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
    }

    [Fact]
    public async Task FinalizeOrder_HostileCn_NeverReachesTheCa()
    {
        // The raw DER must never be submitted to ADCS when the CN check fails.
        var adcs = Substitute.For<IAdcsClient>();
        var sut = new OrderService(
            _db, adcs, _syncTrigger, _revocationGate,
            new DeviceAttestationPolicyService(_db),
            new DomainPolicyAuditService(_db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);
        var order = await CreateReadyOrderAsync("example.com");
        var csr = BuildCsrWithSanExtension("CN=evil.attacker.test", w =>
            WriteDnsName(w, "example.com"));

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        await adcs.DidNotReceive().SubmitCertificateRequestAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    #endregion

    #region Finalize leaf guard (TLS capability ceiling)

    [Fact]
    public async Task FinalizeOrder_CeilingViolatingLeaf_FailsRevokesAndAudits()
    {
        // The mock CA minting a code signing leaf: the guard must keep the
        // certificate from the client, revoke it, create no ACME certificate
        // row, and write the finalize-guard audit row. Finalize itself
        // reports success with the failure on the order, the same contract
        // the CA retrieval failure path has always used.
        _adcsClient.LeafEkuOids = new[] { "1.3.6.1.5.5.7.3.3" };
        var order = await CreateReadyOrderAsync("guard.example.com");
        var csr = BuildCsr("guard.example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
        // A fragment with no apostrophe: the serializer's default encoder
        // escapes the apostrophe in the detail as a unicode sequence, so the
        // raw JSON never contains the human form of the whole sentence.
        updated.ErrorJson.Should().Contain("TLS certificate policy and was revoked");
        updated.CertificateId.Should().BeNull();
        (await _db.AcmeCertificates.AnyAsync(c => c.OrderId == order.Id)).Should().BeFalse();

        // The leaf the guard refused is the one that was revoked, reason 5.
        _adcsClient.RevokedSerials.Should().ContainSingle();

        var audit = await _db.DomainPolicyRejections.SingleAsync();
        audit.Stage.Should().Be("finalize-guard");
        audit.TemplateId.Should().Be("WebServer");
        audit.RejectedIdentifiers.Should().Contain("guard.example.com");
    }

    [Fact]
    public async Task FinalizeOrder_BareLeafWithNoEku_IsRefusedByTheGuard()
    {
        // No EKU extension means valid for every purpose, which the ceiling
        // refuses; before the mock grew leaf extensions this was every mock
        // issuance.
        _adcsClient.LeafEkuOids = null;
        var order = await CreateReadyOrderAsync("bare-guard.example.com");
        var csr = BuildCsr("bare-guard.example.com");

        await _sut.FinalizeOrderAsync(order.OrderId, csr);

        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("invalid");
        _adcsClient.RevokedSerials.Should().ContainSingle();
    }

    [Fact]
    public async Task FinalizeOrder_DefaultLeaf_PassesTheGuardAndDelivers()
    {
        // The mock's default extensions sit inside the ceiling, so the
        // ordinary path issues exactly as before the guard existed.
        var order = await CreateReadyOrderAsync("guard-pass.example.com");
        var csr = BuildCsr("guard-pass.example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
        var updated = await _sut.GetOrderAsync(order.OrderId);
        updated!.Status.Should().Be("valid");
        updated.CertificateId.Should().NotBeNull();
        _adcsClient.RevokedSerials.Should().BeEmpty();
        (await _db.DomainPolicyRejections.AnyAsync()).Should().BeFalse();
    }

    #endregion

    [Fact]
    public async Task GetOrderUrlsForAccount_ReturnsEveryOrderUrl()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order1 = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        var order2 = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var urls = await _sut.GetOrderUrlsForAccountAsync(_account.Id, path => $"https://certus{path}");

        urls.Should().HaveCount(2);
        urls.Should().Contain(u => u.Contains($"/order/{order1.OrderId}"));
        urls.Should().Contain(u => u.Contains($"/order/{order2.OrderId}"));
    }

    /// <summary>
    /// Creates an order for the given DNS identifiers and forces it into the "ready" state so the
    /// finalize path (which requires "ready") can be exercised directly.
    /// </summary>
    private async Task<AcmeOrder> CreateReadyOrderAsync(params string[] identifierValues)
    {
        var identifiers = identifierValues
            .Select(v => new AcmeIdentifier { Type = "dns", Value = v })
            .ToArray();
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);
        order.Status = "ready";
        await _db.SaveChangesAsync();
        return order;
    }

    #region Device order tests

    private const string DeviceSerial = "SN-DEVICE-0001";
    private const string DeviceTemplate = "WebServer";

    [Fact]
    public async Task CreateOrder_PermanentIdentifier_EmitsSingleDeviceChallenge()
    {
        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "permanent-identifier", Value = DeviceSerial }
        };

        var order = await _sut.CreateOrderAsync(_account, DeviceTemplate, identifiers, null, null);

        var authz = order.Authorizations.Single();
        authz.IdentifierType.Should().Be("permanent-identifier");
        authz.IdentifierValue.Should().Be(DeviceSerial);
        authz.Wildcard.Should().BeFalse();
        authz.Challenges.Should().ContainSingle()
            .Which.Type.Should().Be("device-attest-01");
        authz.Challenges[0].Token.Should().NotBeNullOrEmpty();
        authz.Challenges[0].Status.Should().Be("pending");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_CnBinding_CnMatches_Issues()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("valid");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_WrongKey_Rejected()
    {
        // The second leg of the three way binding: the CSR key must be the
        // attested key, with no configuration that can turn it off.
        var (order, _) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(otherKey, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("attested device key");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_CnBinding_WrongCn_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, "CN=SOME-OTHER-DEVICE");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("subject CN does not match");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_CnBinding_PiSanAlone_Issues()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet", DeviceSerial);

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_CnBinding_IdentifierNowhere_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("must carry the order identifier");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_SanRequired_CnOnly_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.SanRequired);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("PermanentIdentifier");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_SanRequired_WithPiSan_Issues()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.SanRequired);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}", DeviceSerial);

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_None_WithPiSan_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.None);
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet", DeviceSerial);

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("privacy");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_None_CnNamesIdentifier_Rejected()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.None);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("privacy");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_None_CleanCsr_Issues()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.None);
        var csr = DeviceCsrBuilder.Build(key, "O=Device Fleet");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_DnsSan_AlwaysRejected()
    {
        // A dns SAN on a device CSR rejects in every binding mode: the
        // attestation said nothing about any host name.
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(
            key, $"CN={DeviceSerial}", null, null, "sneaky.example.com");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("DNS");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_WrongPiValue_Rejected()
    {
        // A wrong identifier value anywhere rejects, even when the CN is
        // right: the certificate would name a device the attestation never
        // vouched for.
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}", "SOME-OTHER-DEVICE");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("does not match the order identifier");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_AssignerQualifiedIdentifier_MatchesStructuredSan()
    {
        // An order identifier in the full grammar form must octet match the
        // reassembly of the SAN's structured value and assigner fields.
        var qualified = $"{DeviceSerial}/1.3.6.1.4.1.99999.1";
        var (order, key) = await CreateReadyDeviceOrderAsync(
            CsrIdentifierBindingModes.SanRequired, qualified);
        var csr = DeviceCsrBuilder.Build(
            key, "O=Device Fleet", DeviceSerial, "1.3.6.1.4.1.99999.1");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_ProfileRemoved_FailsClosed()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        _db.DeviceAttestationProfiles.RemoveRange(_db.DeviceAttestationProfiles);
        await _db.SaveChangesAsync();
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("no longer accepts device orders");

        // Issue #323. A dead profile is a statement about the device, not about the
        // CSR, and the controller answers the identical condition rejectedIdentifier.
        // Which of the two checks fires depends only on when an administrator
        // clicked, so the outcome has to be the one the controller can act on.
        result.Outcome.Should().Be(FinalizeOutcome.DeviceNotOffered);

        // The order is untouched, so a client can finalize it again once the
        // profile comes back: this refusal happens before the claim.
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");

        // The audit row belongs to the controller, which re-runs its own gate for
        // this outcome and is the only layer holding the client IP. Writing one
        // here too would double count every refusal in the activity feed.
        (await _db.DomainPolicyRejections.AnyAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task FinalizeDeviceOrder_ProfileDisabled_IsADevicePolicyRefusalToo()
    {
        // Disabled is a distinct stored state from absent, and the two are folded
        // together only at the controller's notOffered flag. Cover it separately,
        // because it is the reachable one: disabling is a click, deleting is not.
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        _db.DeviceAttestationProfiles.Single().Enabled = false;
        await _db.SaveChangesAsync();
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Outcome.Should().Be(FinalizeOutcome.DeviceNotOffered);
        (await _sut.GetOrderAsync(order.OrderId))!.Status.Should().Be("ready");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_BadCsrOnADeadProfile_IsStillTheProfileRefusal()
    {
        // The profile decision now runs first, matching the controller's gate,
        // which fires before the CSR is even decoded. Before issue #323 this order
        // answered badCSR, which is the wrong half of a true statement: the CSR is
        // indeed wrong, and the template also accepts no device orders, and only
        // one of those is something the client can fix.
        var (order, _) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        _db.DeviceAttestationProfiles.Single().Enabled = false;
        await _db.SaveChangesAsync();
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(wrongKey, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Outcome.Should().Be(FinalizeOutcome.DeviceNotOffered);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_DelistedDevice_FailsClosed()
    {
        // Issue #335. The order was created and validated while the device was
        // listed; the delisting lands before the finalize reaches the submit.
        // Until this check existed the allowlist was read exactly once on the
        // finalize path, at the controller's gate, and an entry deleted after it
        // still got a certificate.
        var (order, key) = await CreateReadyDeviceOrderAsync(
            CsrIdentifierBindingModes.CnOrSan, DeviceSerial,
            DeviceAttestationGateModes.Allowlist, DeviceSerial);
        _db.DeviceAllowlistEntries.RemoveRange(_db.DeviceAllowlistEntries);
        await _db.SaveChangesAsync();
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("allowlist");

        // Its own outcome, not DeviceNotOffered: the template still takes device
        // orders, so telling this client otherwise would name the wrong fix.
        result.Outcome.Should().Be(FinalizeOutcome.DeviceNotOnAllowlist);

        // Refused before the claim, so the order is untouched and a client can
        // finalize it again once an administrator relists the device. No request
        // id means nothing reached the CA.
        var stored = (await _sut.GetOrderAsync(order.OrderId))!;
        stored.Status.Should().Be("ready");
        stored.AdcsRequestId.Should().BeNull();

        // The audit row belongs to the controller, which re-runs its own gate for
        // this outcome and is the only layer holding the client IP. Writing one
        // here too would double count every refusal in the activity feed.
        (await _db.DomainPolicyRejections.AnyAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task FinalizeDeviceOrder_BadCsrOnADelistedDevice_IsStillTheDelisting()
    {
        // The issue #323 shape, applied to the new arm: both policy decisions run
        // before any judgement about the CSR, so a delisted device whose CSR is
        // also wrong hears about the delisting. The CSR is indeed wrong and the
        // device is indeed refused, and only one of those is a thing the client
        // can fix by rebuilding anything.
        var (order, _) = await CreateReadyDeviceOrderAsync(
            CsrIdentifierBindingModes.CnOrSan, DeviceSerial,
            DeviceAttestationGateModes.Allowlist, DeviceSerial);
        _db.DeviceAllowlistEntries.RemoveRange(_db.DeviceAllowlistEntries);
        await _db.SaveChangesAsync();
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(wrongKey, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Outcome.Should().Be(FinalizeOutcome.DeviceNotOnAllowlist);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_ListedDevice_StillIssues()
    {
        // The control the refusal tests need. A gate that refuses everything also
        // passes both tests above, so pin that a device the allowlist admits still
        // finalizes in the mode where the allowlist is actually consulted.
        var (order, key) = await CreateReadyDeviceOrderAsync(
            CsrIdentifierBindingModes.CnOrSan, DeviceSerial,
            DeviceAttestationGateModes.Allowlist, DeviceSerial);
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
    }

    [Fact]
    public async Task FinalizeDeviceOrder_OpenMode_IgnoresTheAllowlistEntirely()
    {
        // Open mode admits any attested device, and the finalize honours that the
        // way the controller's gate and the challenge validator do. Seeded with a
        // populated allowlist that does not name this device, so the assertion is
        // that the list is skipped rather than that an empty list is tolerated.
        var (order, key) = await CreateReadyDeviceOrderAsync(
            CsrIdentifierBindingModes.CnOrSan, DeviceSerial,
            DeviceAttestationGateModes.Open, "SOME-OTHER-SN");
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue(result.ErrorMessage);
    }

    #region Issue #324: a CA outage is not a complaint about the CSR

    [Fact]
    public async Task FinalizeOrder_CaUnavailableBeforeTheSubmit_ReleasesTheClaim()
    {
        // Issue #324. The submit never reached the CA, which IAdcsClient promises
        // this exception means, so nothing was decided and the order must survive.
        // Before this it was burned to invalid and the client was told badCSR, so
        // a CertSvc restart cost the client every authorization it had completed.
        var adcs = new OutageAdcsClient
        {
            FailTheSubmitWith = new CaUnavailableException("RPC server is unavailable")
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("outage.example.com");
        var csr = BuildCsr("outage.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.CaUnavailable);
        result.ErrorMessage.Should().Contain("unavailable");

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("ready", "the claim bought nothing, so it was given back");
        stored.CsrDer.Should().BeNull(
            "CsrDer means the CSR this order was claimed for, and it is claimed for none");
        stored.AdcsRequestId.Should().BeNull();
        stored.ErrorJson.Should().BeNull("a ready order carrying an error is a contradiction");
    }

    [Fact]
    public async Task FinalizeOrder_CaComesBackAfterAnOutage_TheSameOrderStillFinalizes()
    {
        // The point of releasing the claim rather than leaving the order processing
        // or invalid. Without this the release is only a status write nobody uses.
        var adcs = new OutageAdcsClient
        {
            FailTheSubmitWith = new CaUnavailableException("RPC server is unavailable")
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("retried.example.com");
        var csr = BuildCsr("retried.example.com");

        (await sut.FinalizeOrderAsync(order.OrderId, csr)).Outcome
            .Should().Be(FinalizeOutcome.CaUnavailable);

        adcs.ComeBack();
        var second = await sut.FinalizeOrderAsync(order.OrderId, csr);

        second.Success.Should().BeTrue("the same order, the same CSR, and a CA that answers");
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id)).Status.Should().Be("valid");
        (await verify.AcmeCertificates.CountAsync(c => c.OrderId == order.Id)).Should().Be(1);
    }

    [Fact]
    public async Task FinalizeOrder_CaUnavailableWhileCollecting_LeavesTheOrderProcessing()
    {
        // The other half, and the one that used to strand a live certificate. The
        // CSR reached the CA and its request id is saved, so this is the pending
        // arm by another route: PendingIssuanceService finishes it (issue #319).
        var adcs = new OutageAdcsClient
        {
            FailTheCollectionWith = new CaUnavailableException("RPC server is unavailable")
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("collecting.example.com");
        var csr = BuildCsr("collecting.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue("the CA accepted the request; only the pickup failed");
        result.Outcome.Should().Be(FinalizeOutcome.Submitted);

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("processing");
        stored.AdcsRequestId.Should().NotBeNull(
            "the sweep finds the order by the request id, so losing it would strand the leaf");
        stored.ErrorJson.Should().BeNull();
    }

    [Fact]
    public async Task FinalizeOrder_SubmitFailsForAnyOtherReason_StillInvalidatesTheOrder()
    {
        // The new arm is a narrowing, not a widening. Anything that is not the CA
        // being unreachable keeps the old behaviour, including a submit that failed
        // after the CA had already accepted the request, which AdcsClient now
        // guarantees arrives as a plain InvalidOperationException.
        var adcs = new OutageAdcsClient
        {
            FailTheSubmitWith = new InvalidOperationException("Failed to submit certificate request")
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("other-failure.example.com");
        var csr = BuildCsr("other-failure.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Outcome.Should().Be(FinalizeOutcome.CaRefused);

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("invalid");
        stored.ErrorJson.Should().Contain(AcmeErrorType.ServerInternal);
    }

    #endregion

    #region Issue #336: a CA permissions failure is not an internal error

    /// <summary>
    /// The shape AdcsClient raises when the CA refuses this service's own
    /// credentials. Built here rather than inline so every test in the region
    /// throws the same thing.
    /// </summary>
    private static CaAccessDeniedException Denied(string message) =>
        new(message, new UnauthorizedAccessException("simulated E_ACCESSDENIED"));

    [Fact]
    public async Task FinalizeOrder_CaAccessDeniedBeforeTheSubmit_ReleasesTheClaim()
    {
        // Issue #336, and the twin of the outage's release arm. The submit never
        // reached the CA, so nothing was decided and the order must survive. Before
        // this it fell into the general catch and was burned to invalid, which cost
        // the client every authorization it had completed for a permission an
        // administrator can restore in a minute.
        var adcs = new OutageAdcsClient
        {
            FailTheSubmitWith = Denied(CaAccessDeniedException.EnrollPermissionMessage)
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("denied-submit.example.com");
        var csr = BuildCsr("denied-submit.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.Outcome.Should().Be(FinalizeOutcome.CaAccessDenied,
            "a refused credential is not a refused CSR and not an outage");

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("ready", "the claim bought nothing, so it was given back");
        stored.CsrDer.Should().BeNull(
            "CsrDer means the CSR this order was claimed for, and it is claimed for none");
        stored.AdcsRequestId.Should().BeNull();
        stored.ErrorJson.Should().BeNull("a ready order carrying an error is a contradiction");
    }

    [Fact]
    public async Task FinalizeOrder_TheClientIsNeverToldWhichAccountOrTemplate()
    {
        // The disclosure decision, pinned. The remediation names the service's own
        // computer account and the CA console, and it goes to the log and to the
        // administrator authenticated surfaces. An ACME client is neither, so the
        // detail it receives says only that the server could not submit.
        var adcs = new OutageAdcsClient
        {
            FailTheSubmitWith = Denied(CaAccessDeniedException.EnrollPermissionMessage)
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("quiet.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, BuildCsr("quiet.example.com"));

        result.ErrorMessage.Should().NotBeNull();
        result.ErrorMessage.Should().NotContain("Security",
            "the CA console's Security tab is operator guidance, not client guidance");
        result.ErrorMessage.Should().NotContain("permission",
            "naming the missing permission tells a client about our CA's access control");
        result.ErrorMessage.Should().NotContain(Environment.MachineName,
            "the service account is exactly what must not travel on this wire");
    }

    [Fact]
    public async Task FinalizeOrder_PermissionRestoredAfterADenial_TheSameOrderStillFinalizes()
    {
        // The point of releasing the claim rather than invalidating. Without this the
        // release is only a status write nobody uses, and the issue's own complaint
        // stands: the client starts again from new authorizations once someone grants
        // the permission.
        var adcs = new OutageAdcsClient
        {
            FailTheSubmitWith = Denied(CaAccessDeniedException.EnrollPermissionMessage)
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("restored.example.com");
        var csr = BuildCsr("restored.example.com");

        (await sut.FinalizeOrderAsync(order.OrderId, csr)).Outcome
            .Should().Be(FinalizeOutcome.CaAccessDenied);

        adcs.ComeBack();
        var second = await sut.FinalizeOrderAsync(order.OrderId, csr);

        second.Success.Should().BeTrue(
            "the same order, the same CSR, and an administrator who granted the right");
        await using var verify = new CertusDbContext(_dbOptions);
        (await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id)).Status.Should().Be("valid");
        (await verify.AcmeCertificates.CountAsync(c => c.OrderId == order.Id)).Should().Be(1);
    }

    [Fact]
    public async Task FinalizeOrder_CaAccessDeniedWhileCollecting_LeavesTheOrderProcessing()
    {
        // The half that used to strand a live certificate, and the sharper bug the
        // issue does not state. CaAccessDeniedException derives from
        // UnauthorizedAccessException, so it missed the outage arm entirely, landed on
        // the general catch, and demoted an order to invalid while its certificate was
        // live at the CA. The CA holds the request and its id is saved, so this is the
        // pending arm by another route and PendingIssuanceService finishes it.
        var adcs = new OutageAdcsClient
        {
            FailTheCollectionWith = Denied(CaAccessDeniedException.CollectPermissionMessage)
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("denied-collect.example.com");
        var csr = BuildCsr("denied-collect.example.com");

        var result = await sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeTrue("the CA accepted the request; only the pickup was refused");
        result.Outcome.Should().Be(FinalizeOutcome.Submitted);

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("processing", "invalid here would strand the live leaf");
        stored.AdcsRequestId.Should().NotBeNull(
            "the sweep finds the order by the request id, so losing it would strand the leaf");
        stored.ErrorJson.Should().BeNull();
    }

    [Fact]
    public async Task FinalizeOrder_CaDeniesTheRequest_IsUnchangedByTheNewArm()
    {
        // The regression pin for the enrichment. A policy module denial is the
        // commonest permissions failure by far and it does not throw: it comes back
        // as a Denied disposition carrying the CA's own explanation. That is a real CA
        // decision, so it stays terminal and it keeps answering CaRefused with the
        // CA's message.
        //
        // The mock denies a template it does not have, so pointing the order at one
        // stages the denial without disturbing any other check.
        var sut = NewOrderServiceOn(_db, new MockAdcsClient());
        var order = await CreateReadyOrderAsync("policy-denied.example.com");
        order.TemplateId = "NoSuchTemplate";
        await _db.SaveChangesAsync();

        var result = await sut.FinalizeOrderAsync(
            order.OrderId, BuildCsr("policy-denied.example.com"));

        result.Outcome.Should().Be(FinalizeOutcome.CaRefused,
            "a CA decision is not a CA credential failure");
        result.ErrorMessage.Should().Contain("NoSuchTemplate",
            "the CA's own reason is what reaches the client, as it always has");

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        stored.Status.Should().Be("invalid",
            "the CA decided, and it will decide the same way until an administrator acts");
        stored.ErrorJson.Should().Contain("NoSuchTemplate");
    }

    #endregion

    #region Issue #356: the denial reaches the client with its reason

    [Fact]
    public async Task FinalizeOrder_CaDeniesWithAStatusCode_PutsTheReasonInTheOrdersError()
    {
        // The lab run behind issue #356 found the CA answering a template Enroll
        // denial with the bare "Denied by Policy Module", so the order's error carried
        // a decision and no reason. The reason was in the request's status code the
        // whole time and nothing read it.
        //
        // The mock supplies CERTSRV_E_UNSUPPORTED_CERT_TYPE for a template it does not
        // publish, which is what a real CA answers for the same condition and is the
        // code that cost issue #194 a lab round trip.
        var sut = NewOrderServiceOn(_db, new MockAdcsClient());
        var order = await CreateReadyOrderAsync("says-why-now.example.com");
        order.TemplateId = "NoSuchTemplate";
        await _db.SaveChangesAsync();

        var result = await sut.FinalizeOrderAsync(
            order.OrderId, BuildCsr("says-why-now.example.com"));

        result.Outcome.Should().Be(FinalizeOutcome.CaRefused);
        result.ErrorMessage.Should()
            .Contain("0x80094800")
            .And.Contain("template is not supported by this CA");

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);
        var error = JsonSerializer.Deserialize<AcmeError>(stored.ErrorJson!)!;
        error.Type.Should().Be(AcmeErrorType.ServerInternal,
            "the refusal vocabulary is settled and this change does not touch it");
        error.Detail.Should()
            .Contain("NoSuchTemplate", "the CA's own account still leads")
            .And.Contain("0x80094800", "and its reason now travels beside it");
    }

    [Fact]
    public async Task FinalizeOrder_CaDeniesWithAStatusCode_TheClientCanReadItOffTheOrder()
    {
        // The two halves have to hold together. Issue #330 opened the channel by
        // projecting ErrorJson into the order object's error member, and issue #356 is
        // the content that travels down it; either alone leaves the client no better
        // off, which is what the issue said when both were still open.
        var sut = NewOrderServiceOn(_db, new MockAdcsClient());
        var order = await CreateReadyOrderAsync("client-reads-it.example.com");
        order.TemplateId = "NoSuchTemplate";
        await _db.SaveChangesAsync();

        await sut.FinalizeOrderAsync(order.OrderId, BuildCsr("client-reads-it.example.com"));

        await using var verify = new CertusDbContext(_dbOptions);
        var stored = await verify.AcmeOrders.SingleAsync(o => o.Id == order.Id);

        var response = Project(stored);

        response.Status.Should().Be("invalid");
        response.Error.Should().NotBeNull();
        response.Error!.Detail.Should().Contain("0x80094800",
            "RFC 8555 section 7.1.6 tells the client to read this member, and it is the " +
            "only place a client ever learns why the CA refused");
    }

    [Fact]
    public async Task FinalizeOrder_CaDeniesWithNoStatusCode_KeepsTheCaMessageAlone()
    {
        // A CA that records no code must not gain wording of its own. The explanation
        // was only ever meant to travel beside the CA's account, so with nothing to add
        // the answer is exactly what it was before issue #356.
        var adcs = Substitute.For<IAdcsClient>();
        adcs.SubmitCertificateRequestAsync(
                Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(new SubmitResult(51, SubmitStatus.Denied, "Denied by Policy Module"));

        var sut = NewOrderServiceOn(_db, adcs);
        var order = await CreateReadyOrderAsync("no-code.example.com");

        var result = await sut.FinalizeOrderAsync(
            order.OrderId, BuildCsr("no-code.example.com"));

        result.Outcome.Should().Be(FinalizeOutcome.CaRefused);
        result.ErrorMessage.Should().Be("Denied by Policy Module",
            "byte identical, not merely unparaphrased. With no code there is no second " +
            "sentence to join, so there is no boundary to punctuate, and issue #362 " +
            "pins this same value with Be rather than Contain for exactly that reason");
    }

    #endregion

    #region Issue #330: the order object carries the reason it failed

    /// <summary>
    /// ToResponse only needs a urlBuilder, and every assertion in this region is
    /// about the error member rather than the URLs, so one stub serves them all.
    /// </summary>
    private static OrderResponse Project(AcmeOrder order) =>
        OrderService.ToResponse(order, path => "https://ducks.example.com" + path);

    [Fact]
    public async Task ToResponse_InvalidOrder_ProjectsTheStoredProblemDocument()
    {
        // The whole of issue #330. Nine writers put an AcmeError into this column
        // and ToResponse returned without reading it, so RFC 8555 section 7.1.3
        // named a member the client never received and a failed order answered with
        // a status and nothing else.
        var order = await CreateReadyOrderAsync("says-why.example.com");
        order.Status = "invalid";
        order.ErrorJson = JsonSerializer.Serialize(new AcmeError
        {
            Type = AcmeErrorType.Unauthorized,
            Detail = "An authorization for this order was deactivated by the client."
        });
        await _db.SaveChangesAsync();

        var response = Project(order);

        response.Status.Should().Be("invalid");
        response.Error.Should().NotBeNull("section 7.1.6 tells the client to read this");
        response.Error!.Type.Should().Be(AcmeErrorType.Unauthorized,
            "the type the writer stored is the type the client is told");
        response.Error.Detail.Should().Be(
            "An authorization for this order was deactivated by the client.",
            "the detail travels verbatim; paraphrasing it here would describe one " +
            "event two ways depending on which surface the client read");
    }

    [Fact]
    public async Task ToResponse_CaRefusal_HandsTheClientTheCaSownMessage()
    {
        // The arm the issue singled out as needing a decision. It was already
        // decided: the finalize's 500 problem document has always carried
        // result.Message, so projecting it repeats what the client was told rather
        // than disclosing anything new, and the two now read the same string.
        var order = await CreateReadyOrderAsync("ca-said-no.example.com");
        order.TemplateId = "NoSuchTemplate";
        await _db.SaveChangesAsync();

        var result = await _sut.FinalizeOrderAsync(order.OrderId, BuildCsr("ca-said-no.example.com"));
        result.Outcome.Should().Be(FinalizeOutcome.CaRefused);

        var response = Project((await _sut.GetOrderAsync(order.OrderId))!);

        response.Error.Should().NotBeNull();
        response.Error!.Type.Should().Be(AcmeErrorType.ServerInternal);
        result.ErrorMessage.Should().NotBeNullOrEmpty(
            "asserted before the comparison below, which two empty strings would " +
            "satisfy without either wire carrying anything");
        response.Error.Detail.Should().Be(result.ErrorMessage,
            "one refusal reads the same on both wires (issue #324), so the order's " +
            "error and the finalize's problem document carry the same string");
    }

    [Fact]
    public async Task ToResponse_OrderWithNoError_OmitsTheMember()
    {
        // JsonIgnore WhenWritingNull is what keeps the member off a live order, so
        // the assertion is on the serialized bytes and not only on the property: a
        // "error": null on every pending order would be a wire change of its own.
        var order = await CreateReadyOrderAsync("healthy.example.com");

        var response = Project(order);

        response.Error.Should().BeNull();
        JsonSerializer.Serialize(response).Should().NotContain("\"error\"",
            "an order that has not failed says nothing about failure");
    }

    [Fact]
    public async Task ToResponse_ReadyOrder_CarriesNoError()
    {
        // The writer side invariant the unconditional projection rests on: this
        // column is only ever written in the same statement that writes "invalid",
        // and nothing brings an order back out of invalid. ToResponse deliberately
        // does not restate that as a status gate, so this is where it is held.
        // A future writer that leaves an error on a live order fails here rather
        // than being quietly hidden by a gate.
        var order = await CreateReadyOrderAsync("still-going.example.com");

        var released = Project(order);
        released.Status.Should().Be("ready");
        released.Error.Should().BeNull();

        // The finalize's own release arm is the one write out of "processing" that
        // is not a demotion (issue #324), and it is the realistic way a ready order
        // could come to carry a stale error.
        var adcs = new OutageAdcsClient
        {
            FailTheSubmitWith = new CaUnavailableException("RPC server is unavailable")
        };
        var sut = NewOrderServiceOn(_db, adcs);
        var result = await sut.FinalizeOrderAsync(
            order.OrderId, BuildCsr("still-going.example.com"));
        result.Outcome.Should().Be(FinalizeOutcome.CaUnavailable);

        var afterOutage = Project((await _sut.GetOrderAsync(order.OrderId))!);
        afterOutage.Status.Should().Be("ready");
        afterOutage.Error.Should().BeNull(
            "a ready order carrying an error is a contradiction, and the projection " +
            "trusts the writers to keep it that way");
    }

    [Fact]
    public async Task ToResponse_InvalidatedByAFailedChallenge_LeavesTheReasonOnTheAuthorization()
    {
        // The one demote that writes no error, and it is deliberate. This is what a
        // failed challenge produces, so it is the commonest death an order has.
        // RFC 8555 section 7.1.6 puts that reason on the authorization and its
        // challenge; the order response hands over the authorization URLs and the
        // challenge response carries the problem document. Pinned so the silence
        // cannot be "fixed" without deciding it again.
        var order = await CreateReadyOrderAsync("challenge-failed.example.com");
        order.Status = "pending";
        var authz = order.Authorizations.Single();
        authz.Status = "invalid";
        var challenge = authz.Challenges.First();
        challenge.Status = "invalid";
        challenge.ErrorJson = JsonSerializer.Serialize(new AcmeError
        {
            Type = AcmeErrorType.IncorrectResponse,
            Detail = "The key authorization file was not found."
        });
        await _db.SaveChangesAsync();

        await _sut.RecalculateOrderStatusAsync(order.Id);

        var response = Project((await _sut.GetOrderAsync(order.OrderId))!);
        response.Status.Should().Be("invalid");
        response.Error.Should().BeNull(
            "the order does not paraphrase a reason the authorization already states");
        response.Authorizations.Should().NotBeEmpty(
            "and the client is given somewhere to read it");

        var projectedChallenge = OrderService.ToChallengeResponse(
            challenge, "WebServer", path => "https://ducks.example.com" + path);
        projectedChallenge.Error.Should().NotBeNull();
        projectedChallenge.Error!.Detail.Should().Be("The key authorization file was not found.");
    }

    #endregion

    [Fact]
    public async Task FinalizeDeviceOrder_NoAttestedKey_FailsClosed()
    {
        var (order, key) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);
        order.Authorizations.Single().AttestedSpki = null;
        await _db.SaveChangesAsync();
        var csr = DeviceCsrBuilder.Build(key, $"CN={DeviceSerial}");

        var result = await _sut.FinalizeOrderAsync(order.OrderId, csr);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("No attested device key");
    }

    [Fact]
    public async Task FinalizeDeviceOrder_GarbageCsr_Rejected()
    {
        var (order, _) = await CreateReadyDeviceOrderAsync(CsrIdentifierBindingModes.CnOrSan);

        var result = await _sut.FinalizeOrderAsync(
            order.OrderId, new byte[] { 1, 2, 3 });

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("could not be parsed");
    }

    /// <summary>
    /// Seeds an enabled device attestation profile, creates a
    /// permanent-identifier order, marks its authorization valid with the
    /// returned key recorded as the attested key, and forces the order
    /// ready, so the finalize path can be exercised directly.
    ///
    /// The gate mode defaults to open, which is what every test that is not about
    /// the allowlist wants: the CSR binding tests are then never also allowlist
    /// tests. A test about admission passes allowlist mode and says which devices
    /// are listed.
    /// </summary>
    private async Task<(AcmeOrder Order, ECDsa Key)> CreateReadyDeviceOrderAsync(
        string csrIdentifierBinding,
        string identifierValue = DeviceSerial,
        string gateMode = DeviceAttestationGateModes.Open,
        params string[] allowlistedDevices)
    {
        var profile = new DeviceAttestationProfile
        {
            TemplateId = DeviceTemplate,
            Enabled = true,
            GateMode = gateMode,
            CsrIdentifierBinding = csrIdentifierBinding
        };
        foreach (var device in allowlistedDevices)
            profile.AllowlistEntries.Add(new DeviceAllowlistEntry { IdentifierValue = device });
        _db.DeviceAttestationProfiles.Add(profile);
        await _db.SaveChangesAsync();

        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _deviceKeys.Add(key);

        var identifiers = new[]
        {
            new AcmeIdentifier { Type = "permanent-identifier", Value = identifierValue }
        };
        var order = await _sut.CreateOrderAsync(_account, DeviceTemplate, identifiers, null, null);

        var authz = order.Authorizations.Single();
        authz.Status = "valid";
        authz.AttestedSpki = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        authz.AttestationFormat = "apple";
        order.Status = "ready";
        await _db.SaveChangesAsync();

        return (order, key);
    }

    #endregion

    [Fact]
    public async Task RevokeCertificate_FiresSyncTrigger()
    {
        var certificate = await SeedCertificateAsync();

        var outcome = await _sut.RevokeCertificateAsync(certificate, reason: 0);

        outcome.Should().Be(RevokeOutcome.Revoked);
        certificate.RevokedAt.Should().NotBeNull();

        // The revoke path must nudge the inventory sync so the revocation
        // reaches the dashboard without waiting for the next timer tick.
        var fired = await _syncTrigger.WaitAsync(TimeSpan.FromMilliseconds(500), CancellationToken.None);
        fired.Should().BeTrue();
    }

    [Fact]
    public async Task RevokeCertificate_AlreadyRevoked_DoesNotFireTrigger()
    {
        var certificate = await SeedCertificateAsync();
        certificate.RevokedAt = DateTime.UtcNow.AddHours(-1);
        await _db.SaveChangesAsync();

        var outcome = await _sut.RevokeCertificateAsync(certificate, reason: 0);

        outcome.Should().Be(RevokeOutcome.AlreadyRevoked);

        var fired = await _syncTrigger.WaitAsync(TimeSpan.FromMilliseconds(100), CancellationToken.None);
        fired.Should().BeFalse();
    }

    /// <summary>Seeds an order with a stored certificate row, ready to revoke.</summary>
    private async Task<AcmeCertificate> SeedCertificateAsync()
    {
        var identifiers = new[] { new AcmeIdentifier { Type = "dns", Value = "example.com" } };
        var order = await _sut.CreateOrderAsync(_account, "WebServer", identifiers, null, null);

        var certificate = new AcmeCertificate
        {
            CertificateId = "cert-revoke-test",
            OrderId = order.Id,
            CertificatePem = "-----BEGIN CERTIFICATE-----",
            AdcsRequestId = 42,
            SerialNumber = "AB01CD02EF03",
            IssuedAt = DateTime.UtcNow,
        };
        _db.AcmeCertificates.Add(certificate);

        // CreateOrderAsync leaves the order pending, but a stored certificate only
        // ever exists under a valid order that names it: the row and the status flip
        // commit together in IssueCertificateAsync (issue #318).
        order.Status = "valid";
        order.CertificateId = certificate.CertificateId;

        await _db.SaveChangesAsync();
        return certificate;
    }

    /// <summary>
    /// Builds a signed PKCS#10 CSR whose subject CN is the first name and whose SAN extension
    /// contains all of the given DNS names (verbatim, including any wildcard marker).
    /// </summary>
    private static byte[] BuildCsr(params string[] dnsNames)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={dnsNames[0]}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
            sanBuilder.AddDnsName(name);
        request.CertificateExtensions.Add(sanBuilder.Build());

        return request.CreateSigningRequest();
    }

    /// <summary>
    /// Builds a signed PKCS#10 CSR with the given subject and a Subject Alternative
    /// Name extension whose GeneralNames the caller writes raw. Lets a test express
    /// SAN shapes the typed builders cannot, such as a UPN otherName or an iPAddress
    /// alongside a DNS name. The key type is irrelevant: the dns path never inspects it.
    /// </summary>
    private static byte[] BuildCsrWithSanExtension(string subject, Action<AsnWriter> writeGeneralNames)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            writeGeneralNames(writer);
        request.CertificateExtensions.Add(
            new X509Extension("2.5.29.17", writer.Encode(), critical: false));
        return request.CreateSigningRequest();
    }

    private static void WriteDnsName(AsnWriter writer, string dns) =>
        writer.WriteCharacterString(
            UniversalTagNumber.IA5String, dns, new Asn1Tag(TagClass.ContextSpecific, 2));

    private static void WriteRfc822Name(AsnWriter writer, string email) =>
        writer.WriteCharacterString(
            UniversalTagNumber.IA5String, email, new Asn1Tag(TagClass.ContextSpecific, 1));

    private static void WriteIpAddress(AsnWriter writer, byte[] address) =>
        writer.WriteOctetString(address, new Asn1Tag(TagClass.ContextSpecific, 7));

    private static void WriteUpnOtherName(AsnWriter writer, string upn)
    {
        // otherName carrying the Microsoft UPN type id, not a PermanentIdentifier.
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            writer.WriteObjectIdentifier("1.3.6.1.4.1.311.20.2.3");
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, upn);
        }
    }

    private static void WriteDirectoryName(AsnWriter writer, string commonName)
    {
        // directoryName is [4] EXPLICIT Name. Name is a CHOICE, so the tag is explicit.
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4)))
        using (writer.PushSequence())
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("2.5.4.3");
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, commonName);
        }
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        foreach (var key in _deviceKeys)
            key.Dispose();
    }
}
