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
/// The background validator's half of RFC 8555 §7.5.2.
///
/// The sweep selects challenges on their own status ("processing") and knows
/// nothing about the authorization above them, so a challenge that was already in
/// flight when a deactivation landed still reaches the validator. Its success path
/// writes the authorization back to "valid", which would silently undo a
/// deactivation nobody asked to undo. These tests pin the guard that stops it, and
/// the control case that proves the guard did not swallow the normal path.
/// </summary>
public class ChallengeValidationDeactivationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly OrderService _orderService;
    private readonly DomainPolicyAuditService _auditService;
    private readonly ChallengeValidationService _sut;
    private readonly AcmeAccount _account;

    public ChallengeValidationDeactivationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _auditService = new DomainPolicyAuditService(
            _db, NullLogger<DomainPolicyAuditService>.Instance);
        _orderService = new OrderService(
            _db, new MockAdcsClient(), new CertificateSyncTrigger(), new CertificateRevocationGate(),
            new DeviceAttestationPolicyService(_db), _auditService,
            NullLogger<OrderService>.Instance);

        // The method under test takes its DbContext and services as parameters, so
        // the scope factory is never touched; it only has to be non null.
        _sut = new ChallengeValidationService(
            new ServiceCollection().BuildServiceProvider()
                .GetRequiredService<IServiceScopeFactory>(),
            NullLogger<ChallengeValidationService>.Instance,
            Options.Create(new ChallengeValidationOptions()));

        _account = new AcmeAccount
        {
            AccountId = "challenge-deactivation-account",
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = "challenge-deactivation-thumbprint",
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

    [Fact]
    public async Task DeactivatedAuthorization_AbandonsTheChallenge_AndNeverCallsTheValidator()
    {
        var (challenge, authz) = await SeedProcessingChallengeAsync("deactivated");
        var validator = new RecordingValidator(challenge.Type, ChallengeValidationResult.Success());

        await _sut.ValidateSingleChallengeAsync(
            _db, new[] { (IChallengeValidator)validator }, _orderService, _auditService,
            challenge, CancellationToken.None);

        validator.Called.Should().BeFalse(
            "nothing may be validated under an authorization the client relinquished");

        var storedAuthz = await ReadAuthorizationAsync(authz.AuthorizationId);
        storedAuthz.Status.Should().Be(
            "deactivated",
            "the sweep must not write the authorization back to valid, and must not " +
            "overwrite the client's deactivation with invalid either");

        var storedChallenge = await ReadChallengeAsync(challenge.ChallengeId);
        storedChallenge.Status.Should().Be(
            "invalid",
            "§7.1.6 gives challenges no deactivated status, and leaving it processing " +
            "would make it immortal in the sweep");
        storedChallenge.ErrorJson.Should().Contain("deactivated");
    }

    [Fact]
    public async Task PendingAuthorization_StillValidatesNormally()
    {
        // The control. Without it, a guard that matched too broadly would look green.
        var (challenge, authz) = await SeedProcessingChallengeAsync("pending");
        var validator = new RecordingValidator(challenge.Type, ChallengeValidationResult.Success());

        await _sut.ValidateSingleChallengeAsync(
            _db, new[] { (IChallengeValidator)validator }, _orderService, _auditService,
            challenge, CancellationToken.None);

        validator.Called.Should().BeTrue();
        (await ReadAuthorizationAsync(authz.AuthorizationId)).Status.Should().Be("valid");
        (await ReadChallengeAsync(challenge.ChallengeId)).Status.Should().Be("valid");
    }

    /// <summary>
    /// Creates a real order, puts its first challenge into "processing" as a client
    /// response would, and sets the authorization to the status under test.
    /// </summary>
    private async Task<(AcmeChallenge Challenge, AcmeAuthorization Authorization)>
        SeedProcessingChallengeAsync(string authorizationStatus)
    {
        var order = await _orderService.CreateOrderAsync(
            _account, "WebServer",
            new[] { new AcmeIdentifier { Type = "dns", Value = "sweep.example.com" } },
            null, null);

        var authz = order.Authorizations[0];
        var challenge = authz.Challenges.First();
        challenge.Status = "processing";
        authz.Status = authorizationStatus;
        await _db.SaveChangesAsync();

        // Reload through the same graph the sweep query builds, so the method under
        // test sees exactly what production hands it.
        return (await _db.AcmeChallenges
            .Include(c => c.Authorization).ThenInclude(a => a.Order).ThenInclude(o => o.Account)
            .Include(c => c.Authorization).ThenInclude(a => a.Challenges)
            .FirstAsync(c => c.ChallengeId == challenge.ChallengeId), authz);
    }

    private async Task<AcmeAuthorization> ReadAuthorizationAsync(string authorizationId)
        => await _db.AcmeAuthorizations.AsNoTracking()
            .FirstAsync(a => a.AuthorizationId == authorizationId);

    private async Task<AcmeChallenge> ReadChallengeAsync(string challengeId)
        => await _db.AcmeChallenges.AsNoTracking()
            .FirstAsync(c => c.ChallengeId == challengeId);

    /// <summary>
    /// A validator that records whether it was reached. The point of the guard is
    /// that it is NOT, so a stub that merely returns a value would not test it.
    /// </summary>
    private sealed class RecordingValidator : IChallengeValidator
    {
        private readonly ChallengeValidationResult _result;

        public RecordingValidator(string challengeType, ChallengeValidationResult result)
        {
            ChallengeType = challengeType;
            _result = result;
        }

        public string ChallengeType { get; }

        public bool Called { get; private set; }

        public Task<ChallengeValidationResult> ValidateAsync(
            ChallengeValidationContext context,
            CancellationToken cancellationToken = default)
        {
            Called = true;
            return Task.FromResult(_result);
        }
    }
}
