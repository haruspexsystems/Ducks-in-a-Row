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
/// What a challenge result does to its authorization (issue #481).
///
/// RFC 8555 section 7.1.6 has a pending authorization become invalid as soon as
/// a challenge under it fails. The worker used to invalidate it only once every
/// challenge in it had failed, and a network name is offered three, so one failed
/// answer left the authorization and its order pending until expiry. A client
/// that waits on the authorization, as cert-manager does, saw a timeout instead
/// of the failure.
///
/// The fix has three edges these tests hold it to: a valid authorization is never
/// demoted, because the processing order invariant in
/// OrderService.RecalculateOrderStatusAsync depends on it; an invalid or
/// deactivated authorization is never promoted or overwritten; and the order level
/// error stays empty for this death, as issue #330 decided.
///
/// The interleave tests stand a second request in for a client deactivating the
/// authorization while its challenge is being validated. That request drives the
/// real OrderService on a second CertusDbContext, never a hand written status, so
/// the tests exercise the same stale tracked copy production would.
/// </summary>
public class ChallengeFailureAuthorizationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CertusDbContext> _dbOptions;
    private readonly CertusDbContext _db;
    private readonly OrderService _orderService;
    private readonly DomainPolicyAuditService _auditService;
    private readonly ChallengeValidationOptions _options = new();
    private readonly ChallengeValidationService _sut;
    private readonly AcmeAccount _account;

    public ChallengeFailureAuthorizationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        _dbOptions = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(_dbOptions);
        _db.Database.EnsureCreated();

        _auditService = new DomainPolicyAuditService(
            _db, NullLogger<DomainPolicyAuditService>.Instance);
        _orderService = NewOrderServiceOn(_db);

        // The method under test takes its DbContext and services as parameters, so
        // the scope factory is never touched; it only has to be non null.
        _sut = new ChallengeValidationService(
            new ServiceCollection().BuildServiceProvider()
                .GetRequiredService<IServiceScopeFactory>(),
            NullLogger<ChallengeValidationService>.Instance,
            Options.Create(_options));

        _account = new AcmeAccount
        {
            AccountId = "challenge-failure-account",
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = "challenge-failure-thumbprint",
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };
        _db.AcmeAccounts.Add(_account);
        _db.SaveChanges();
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    // ---- The defect ----

    [Fact]
    public async Task AFailedChallenge_InvalidatesItsPendingAuthorization_AndTheOrder()
    {
        var order = await CreateOrderAsync("one-of-three.example.com");
        var authz = order.Authorizations.Single();
        authz.Challenges.Should().HaveCount(
            3, "the premise of the issue: a network name is offered three challenges");
        var answered = Challenge(authz, "http-01");
        answered.Status = "processing";
        await _db.SaveChangesAsync();

        var validator = new ScriptedValidator(
            "http-01",
            ChallengeValidationResult.Invalid("The key authorization file was not found."));
        await ValidateAsync(answered, validator);

        validator.Calls.Should().Be(1);

        var storedChallenge = await ReadChallengeAsync(answered.ChallengeId);
        storedChallenge.Status.Should().Be("invalid");
        var error = ReadError(storedChallenge);
        error.Type.Should().Be(AcmeErrorType.IncorrectResponse);
        error.Detail.Should().Be(
            "The key authorization file was not found.",
            "the reason lives on the challenge, where the client reads it");

        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be(
            "invalid",
            "RFC 8555 section 7.1.6: one failed challenge makes a pending authorization " +
            "invalid, whatever its unanswered siblings say");

        (await _db.AcmeChallenges.AsNoTracking()
                .Where(c => c.AuthorizationId == authz.Id && c.Id != answered.Id)
                .Select(c => c.Status)
                .ToListAsync())
            .Should().OnlyContain(
                s => s == "pending",
                "the siblings were never answered, and nothing needs to write them");

        var storedOrder = await ReadOrderAsync(order.OrderId);
        storedOrder.Status.Should().Be(
            "invalid", "an order holding an invalid authorization can never be finalized");
        storedOrder.ErrorJson.Should().BeNull(
            "issue #330: this death leaves its reason on the challenge, not on the order");
    }

    [Fact]
    public async Task TransientFailuresExhausted_InvalidateTheAuthorization()
    {
        // The second terminal arm. Below the limit the challenge is retried; on the
        // last attempt it fails with "connection", and the authorization goes with it.
        var order = await CreateOrderAsync("exhausted.example.com");
        var authz = order.Authorizations.Single();
        var answered = Challenge(authz, "http-01");
        answered.Status = "processing";
        answered.ValidationAttempts = _options.MaxValidationAttempts - 1;
        await _db.SaveChangesAsync();

        await ValidateAsync(answered, new ScriptedValidator(
            "http-01", ChallengeValidationResult.TransientFailure("Connection refused.")));

        var storedChallenge = await ReadChallengeAsync(answered.ChallengeId);
        storedChallenge.Status.Should().Be("invalid");
        ReadError(storedChallenge).Type.Should().Be(AcmeErrorType.Connection);
        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be("invalid");
        (await ReadOrderAsync(order.OrderId)).Status.Should().Be("invalid");
    }

    [Fact]
    public async Task ATransientFailureBelowTheLimit_LeavesTheAuthorizationPending()
    {
        // The control for the arm above: a retry is not a failure, so nothing may be
        // invalidated yet.
        var order = await CreateOrderAsync("retrying.example.com");
        var authz = order.Authorizations.Single();
        var answered = Challenge(authz, "http-01");
        answered.Status = "processing";
        await _db.SaveChangesAsync();

        await ValidateAsync(answered, new ScriptedValidator(
            "http-01", ChallengeValidationResult.TransientFailure("Connection refused.")));

        var storedChallenge = await ReadChallengeAsync(answered.ChallengeId);
        storedChallenge.Status.Should().Be("processing", "the next sweep retries it");
        storedChallenge.ValidationAttempts.Should().Be(1);
        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be("pending");
        (await ReadOrderAsync(order.OrderId)).Status.Should().Be("pending");
    }

    [Fact]
    public async Task NoValidatorForTheType_InvalidatesThePendingAuthorization()
    {
        // The third terminal arm. Unreachable while both hosts register a validator
        // for every type they offer, but it is still a challenge that failed.
        var order = await CreateOrderAsync("no-validator.example.com");
        var authz = order.Authorizations.Single();
        var answered = Challenge(authz, "tls-alpn-01");
        answered.Status = "processing";
        await _db.SaveChangesAsync();

        await ValidateAsync(answered);

        var storedChallenge = await ReadChallengeAsync(answered.ChallengeId);
        storedChallenge.Status.Should().Be("invalid");
        ReadError(storedChallenge).Type.Should().Be(AcmeErrorType.ServerInternal);
        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be("invalid");
        (await ReadOrderAsync(order.OrderId)).Status.Should().Be("invalid");
    }

    // ---- A valid authorization is never demoted ----

    [Theory]
    [InlineData("ready")]
    [InlineData("processing")]
    public async Task AFailedChallenge_UnderAValidAuthorization_LeavesTheAuthorizationAndTheOrderAlone(
        string orderStatus)
    {
        // A client may answer two challenges. dns-01 already made the authorization
        // valid; http-01 then fails. "processing" is the case the RecalculateOrder
        // StatusAsync comment depends on: the claim found every authorization valid,
        // and a later failure must not take that back.
        var order = await CreateOrderAsync("already-valid.example.com");
        var authz = order.Authorizations.Single();
        Challenge(authz, "dns-01").Status = "valid";
        var answered = Challenge(authz, "http-01");
        answered.Status = "processing";
        authz.Status = "valid";
        order.Status = orderStatus;
        await _db.SaveChangesAsync();

        await ValidateAsync(answered, new ScriptedValidator(
            "http-01", ChallengeValidationResult.Invalid("Wrong answer.")));

        (await ReadChallengeAsync(answered.ChallengeId)).Status.Should().Be(
            "invalid", "the challenge itself did fail, and says so");
        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be(
            "valid", "a sibling already proved it, and a failure never demotes");
        (await ReadOrderAsync(order.OrderId)).Status.Should().Be(orderStatus);
    }

    // ---- An invalid authorization is never resurrected ----

    [Fact]
    public async Task ASiblingUnderAnInvalidAuthorization_IsClosedOut_WithoutCallingTheValidator()
    {
        // http-01 failed and took the authorization with it. A dns-01 answer still in
        // flight can no longer make it valid, so it is not validated at all.
        var order = await CreateOrderAsync("closed.example.com");
        var authz = order.Authorizations.Single();
        Challenge(authz, "http-01").Status = "invalid";
        var sibling = Challenge(authz, "dns-01");
        sibling.Status = "processing";
        authz.Status = "invalid";
        order.Status = "invalid";
        await _db.SaveChangesAsync();

        var validator = new ScriptedValidator("dns-01", ChallengeValidationResult.Success());
        await ValidateAsync(sibling, validator);

        validator.Calls.Should().Be(0, "nothing this challenge does can change the authorization");
        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be("invalid");

        var storedSibling = await ReadChallengeAsync(sibling.ChallengeId);
        storedSibling.Status.Should().Be(
            "invalid", "leaving it processing would make it immortal in the sweep");
        ReadError(storedSibling).Type.Should().Be(AcmeErrorType.Malformed);
        (await ReadOrderAsync(order.OrderId)).Status.Should().Be("invalid");
    }

    [Fact]
    public async Task TwoAnswersInOneSweep_TheFailureClosesTheSecond()
    {
        // The sweep loads every processing challenge in one graph and validates them
        // in turn, so the second challenge holds the same tracked authorization the
        // first one wrote. If that copy were stale, the second answer would pass and
        // its promotion would be the only thing left to refuse.
        var order = await CreateOrderAsync("same-sweep.example.com");
        var authz = order.Authorizations.Single();
        Challenge(authz, "http-01").Status = "processing";
        Challenge(authz, "dns-01").Status = "processing";
        await _db.SaveChangesAsync();

        var http = new ScriptedValidator("http-01", ChallengeValidationResult.Invalid("Wrong answer."));
        var dns = new ScriptedValidator("dns-01", ChallengeValidationResult.Success());

        var swept = await _db.AcmeChallenges
            .Include(c => c.Authorization).ThenInclude(a => a.Order).ThenInclude(o => o.Account)
            .Include(c => c.Authorization).ThenInclude(a => a.Challenges)
            .Where(c => c.Status == "processing")
            .OrderBy(c => c.Id)
            .ToListAsync();
        swept.Select(c => c.Type).Should().Equal("http-01", "dns-01");

        foreach (var challenge in swept)
            await _sut.ValidateSingleChallengeAsync(
                _db, new IChallengeValidator[] { http, dns }, _orderService, _auditService,
                challenge, CancellationToken.None);

        http.Calls.Should().Be(1);
        dns.Calls.Should().Be(0);
        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be("invalid");
        (await ReadOrderAsync(order.OrderId)).Status.Should().Be("invalid");
    }

    // ---- A deactivation landing while the validator runs ----

    [Fact]
    public async Task ADeactivationDuringValidation_IsNotOverwrittenByAFailure()
    {
        // The worker's copy of the authorization was loaded before the validator
        // ran, so it still reads "pending". A tracked write from it would replace the
        // client's "deactivated" with "invalid" and disguise why the order died.
        var order = await CreateOrderAsync("deactivated-then-failed.example.com");
        var authz = order.Authorizations.Single();
        var answered = Challenge(authz, "http-01");
        answered.Status = "processing";
        await _db.SaveChangesAsync();

        var validator = new ScriptedValidator(
            "http-01",
            ChallengeValidationResult.Invalid("Wrong answer."),
            whileValidating: () => DeactivateFromAnotherRequestAsync(authz.AuthorizationId));
        await ValidateAsync(answered, validator);

        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be(
            "deactivated", "the client's deactivation is what it asked for and must survive");

        var storedChallenge = await ReadChallengeAsync(answered.ChallengeId);
        storedChallenge.Status.Should().Be("invalid");
        ReadError(storedChallenge).Type.Should().Be(
            AcmeErrorType.IncorrectResponse, "the challenge keeps its own reason");

        var storedOrder = await ReadOrderAsync(order.OrderId);
        storedOrder.Status.Should().Be("invalid");
        ReadOrderError(storedOrder).Type.Should().Be(
            AcmeErrorType.Unauthorized, "the deactivation's demote, written by its own request");
    }

    [Fact]
    public async Task ADeactivationDuringValidation_IsNotUndoneByASuccess()
    {
        // The older half of the same race. Before issue #481 the success arm set the
        // authorization to "valid" unconditionally, undoing the deactivation.
        var order = await CreateOrderAsync("deactivated-then-passed.example.com");
        var authz = order.Authorizations.Single();
        var answered = Challenge(authz, "http-01");
        answered.Status = "processing";
        await _db.SaveChangesAsync();

        var validator = new ScriptedValidator(
            "http-01",
            ChallengeValidationResult.Success(),
            whileValidating: () => DeactivateFromAnotherRequestAsync(authz.AuthorizationId));
        await ValidateAsync(answered, validator);

        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be("deactivated");

        var storedChallenge = await ReadChallengeAsync(answered.ChallengeId);
        storedChallenge.Status.Should().Be(
            "invalid",
            "closed out as the deactivated guard would have closed it a moment earlier, " +
            "rather than reading valid under an authorization it could not make valid");
        storedChallenge.ValidatedAt.Should().BeNull();
        ReadError(storedChallenge).Type.Should().Be(AcmeErrorType.Unauthorized);

        (await ReadOrderAsync(order.OrderId)).Status.Should().Be("invalid");
    }

    // ---- The pass path still promotes ----

    [Fact]
    public async Task APass_PromotesThePendingAuthorization_AndPersistsAnAttestedIdentity()
    {
        // The control for every refusal above, and the attested columns now travel in
        // the conditional UPDATE rather than on the tracked entity, so pin them too.
        // Finalize binds a device CSR to AttestedSpki and fails closed without it.
        var order = await CreateOrderAsync("passes.example.com");
        var authz = order.Authorizations.Single();
        var answered = Challenge(authz, "http-01");
        answered.Status = "processing";
        await _db.SaveChangesAsync();

        var attested = new AttestedDeviceData("c3BraQ==", "apple", """{"serial":"SN-1"}""");
        await ValidateAsync(answered, new ScriptedValidator(
            "http-01", ChallengeValidationResult.Success(attested)));

        var storedChallenge = await ReadChallengeAsync(answered.ChallengeId);
        storedChallenge.Status.Should().Be("valid");
        storedChallenge.ValidatedAt.Should().NotBeNull();

        var storedAuthz = await ReadAuthorizationAsync(authz.AuthorizationId);
        storedAuthz.Status.Should().Be("valid");
        storedAuthz.AttestedSpki.Should().Be("c3BraQ==");
        storedAuthz.AttestationFormat.Should().Be("apple");
        storedAuthz.AttestedPropertiesJson.Should().Be("""{"serial":"SN-1"}""");

        (await ReadOrderAsync(order.OrderId)).Status.Should().Be("ready");
    }

    // ---- Helpers ----

    private static OrderService NewOrderServiceOn(CertusDbContext db) =>
        new(db, new MockAdcsClient(), new CertificateSyncTrigger(), new CertificateRevocationGate(),
            new DeviceAttestationPolicyService(db),
            new DomainPolicyAuditService(db, NullLogger<DomainPolicyAuditService>.Instance),
            NullLogger<OrderService>.Instance);

    private Task<AcmeOrder> CreateOrderAsync(string domain) =>
        _orderService.CreateOrderAsync(
            _account, "WebServer",
            new[] { new AcmeIdentifier { Type = "dns", Value = domain } },
            null, null);

    private static AcmeChallenge Challenge(AcmeAuthorization authz, string type) =>
        authz.Challenges.Single(c => c.Type == type);

    /// <summary>
    /// Runs one challenge through the worker, reloaded through the same graph the
    /// sweep query builds, so the method under test sees what production hands it.
    /// </summary>
    private async Task ValidateAsync(AcmeChallenge challenge, params IChallengeValidator[] validators)
    {
        var swept = await _db.AcmeChallenges
            .Include(c => c.Authorization).ThenInclude(a => a.Order).ThenInclude(o => o.Account)
            .Include(c => c.Authorization).ThenInclude(a => a.Challenges)
            .FirstAsync(c => c.Id == challenge.Id);

        await _sut.ValidateSingleChallengeAsync(
            _db, validators, _orderService, _auditService, swept, CancellationToken.None);
    }

    /// <summary>
    /// A second request deactivating the authorization through the real service,
    /// on its own DbContext, the way the authorization endpoint would.
    /// </summary>
    private async Task DeactivateFromAnotherRequestAsync(string authorizationId)
    {
        await using var otherRequest = new CertusDbContext(_dbOptions);
        var service = NewOrderServiceOn(otherRequest);
        var authz = await service.GetAuthorizationAsync(authorizationId);
        authz.Should().NotBeNull();

        var result = await service.DeactivateAuthorizationAsync(authz!);
        result.Outcome.Should().Be(
            AuthorizationDeactivationOutcome.Deactivated,
            "the interleave is only meaningful if the deactivation really landed");
    }

    private async Task<AcmeAuthorization> ReadAuthorizationAsync(string authorizationId)
        => await _db.AcmeAuthorizations.AsNoTracking()
            .FirstAsync(a => a.AuthorizationId == authorizationId);

    private async Task<AcmeChallenge> ReadChallengeAsync(string challengeId)
        => await _db.AcmeChallenges.AsNoTracking()
            .FirstAsync(c => c.ChallengeId == challengeId);

    private async Task<AcmeOrder> ReadOrderAsync(string orderId)
        => await _db.AcmeOrders.AsNoTracking()
            .FirstAsync(o => o.OrderId == orderId);

    private static AcmeError ReadError(AcmeChallenge challenge)
    {
        challenge.ErrorJson.Should().NotBeNull();
        return JsonSerializer.Deserialize<AcmeError>(challenge.ErrorJson!)!;
    }

    private static AcmeError ReadOrderError(AcmeOrder order)
    {
        order.ErrorJson.Should().NotBeNull();
        return JsonSerializer.Deserialize<AcmeError>(order.ErrorJson!)!;
    }

    /// <summary>
    /// A validator that answers with a fixed result and counts its calls. The
    /// optional callback runs where a real validator would be waiting on the
    /// network, which is the window another request can land in.
    /// </summary>
    private sealed class ScriptedValidator : IChallengeValidator
    {
        private readonly ChallengeValidationResult _result;
        private readonly Func<Task>? _whileValidating;

        public ScriptedValidator(
            string challengeType,
            ChallengeValidationResult result,
            Func<Task>? whileValidating = null)
        {
            ChallengeType = challengeType;
            _result = result;
            _whileValidating = whileValidating;
        }

        public string ChallengeType { get; }

        public int Calls { get; private set; }

        public async Task<ChallengeValidationResult> ValidateAsync(
            ChallengeValidationContext context,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            if (_whileValidating != null)
                await _whileValidating();
            return _result;
        }
    }
}
