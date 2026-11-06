using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Background service that processes pending ACME challenges.
/// Polls the database for challenges in "processing" state and validates them
/// using the appropriate challenge validator (HTTP-01, DNS-01, etc.).
/// </summary>
public sealed class ChallengeValidationService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ChallengeValidationService> _logger;
    private readonly ChallengeValidationOptions _options;

    /// <summary>
    /// How often to poll for pending challenges. Configured through
    /// <see cref="ChallengeValidationOptions.PollIntervalSeconds"/> (default 5),
    /// clamped so a bad value can neither spin the database nor stall
    /// validation for good.
    /// </summary>
    private readonly TimeSpan _pollInterval;

    public ChallengeValidationService(
        IServiceScopeFactory scopeFactory,
        ILogger<ChallengeValidationService> logger,
        IOptions<ChallengeValidationOptions> options)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _options = options.Value;
        _pollInterval = TimeSpan.FromSeconds(
            Math.Clamp(_options.PollIntervalSeconds, 0.1, 3600));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Challenge validation service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessPendingChallengesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing challenges");
            }

            try
            {
                await Task.Delay(_pollInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("Challenge validation service stopped");
    }

    /// <summary>
    /// One sweep. Internal so Certus.Core.Tests can drive the whole loop through a
    /// real scope, which is the only way to see what one throwing challenge does to
    /// the ones after it (issue #632).
    /// </summary>
    internal async Task ProcessPendingChallengesAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var validators = scope.ServiceProvider.GetServices<IChallengeValidator>();
        var orderService = scope.ServiceProvider.GetRequiredService<OrderService>();
        var auditService = scope.ServiceProvider.GetRequiredService<DomainPolicyAuditService>();

        // Find all challenges in "processing" state
        var challenges = await db.AcmeChallenges
            .Include(c => c.Authorization)
                .ThenInclude(a => a.Order)
                    .ThenInclude(o => o.Account)
            .Include(c => c.Authorization)
                .ThenInclude(a => a.Challenges)
            .Where(c => c.Status == "processing")
            .ToListAsync(cancellationToken);

        if (challenges.Count == 0)
            return;

        _logger.LogDebug("Processing {Count} pending challenges", challenges.Count);

        foreach (var challenge in challenges)
        {
            // One catch per challenge, never one per sweep. The loop level catch in
            // ExecuteAsync kept the worker alive, but an exception a validator let
            // out (an IOException from a handshake that died mid stream) ended the
            // pass, so every challenge loaded after it went unvalidated, and the
            // next pass loaded the same list in the same order and stalled at the
            // same place, every tick, until the order expired (issue #632). The
            // throwing challenge stays "processing": nothing says the client's
            // answer was wrong, so the next sweep retries it, and the expiry guard
            // ends it if it never stops throwing. Cancellation is let through so a
            // stop request still ends the sweep. Pinned by
            // ChallengeValidationWorkerStallTests.
            try
            {
                await ValidateSingleChallengeAsync(
                    db, validators, orderService, auditService, challenge, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Challenge {ChallengeId} ({Type}) threw during validation and stays " +
                    "processing for the next sweep; the remaining challenges in this sweep " +
                    "are still being validated",
                    challenge.ChallengeId, challenge.Type);
            }
        }
    }

    /// <summary>
    /// Validates one swept challenge. Internal rather than private so
    /// Certus.Core.Tests can drive a single challenge through it: the guards here
    /// are about what must NOT happen (never call the validator, never overwrite a
    /// deactivated authorization), and neither is observable from the outside.
    /// </summary>
    internal async Task ValidateSingleChallengeAsync(
        CertusDbContext db,
        IEnumerable<IChallengeValidator> validators,
        OrderService orderService,
        DomainPolicyAuditService auditService,
        Data.Entities.AcmeChallenge challenge,
        CancellationToken cancellationToken)
    {
        var authz = challenge.Authorization;
        var order = authz.Order;

        // RFC 8555 §7.5.2: the client has said it no longer holds this authorization,
        // so nothing may validate under it. The sweep selects on the challenge's own
        // status, so a challenge that was already "processing" when the deactivation
        // landed still arrives here. The success path below used to set the
        // authorization back to "valid", undoing a deactivation nobody asked to undo.
        // Since issue #481 it promotes only from "pending", and this guard still
        // keeps the validator from being called at all.
        //
        // The authorization's own status is deliberately left alone. "deactivated" is
        // terminal and is what the client asked for; overwriting it with "invalid"
        // would lose that and disguise why the order died. This block is first in the
        // method for that reason, ahead of the expiry guard, which does write it.
        //
        // The challenge goes "invalid" because §7.1.6 gives challenges no
        // "deactivated" status, and invalid is the truthful terminal one: it can
        // never validate now. Leaving it "processing" would make it immortal, swept
        // and skipped on every pass for ever.
        if (string.Equals(authz.Status, "deactivated", StringComparison.Ordinal))
        {
            challenge.Status = "invalid";
            challenge.ErrorJson = JsonSerializer.Serialize(ClosedAuthorizationError(authz.Status));
            await db.SaveChangesAsync(cancellationToken);
            _logger.LogInformation(
                "Challenge {ChallengeId} ({Type}) abandoned: its authorization is deactivated",
                challenge.ChallengeId, challenge.Type);
            return;
        }

        // RFC 8555 §7.1.4: never validate a challenge whose authorization or order has
        // expired. Mark the authorization invalid and stop.
        if (DateTime.UtcNow > order.ExpiresAt || DateTime.UtcNow > authz.ExpiresAt)
        {
            challenge.Status = "invalid";
            challenge.ErrorJson = JsonSerializer.Serialize(new AcmeError
            {
                Type = AcmeErrorType.Malformed,
                Detail = "The authorization or order has expired."
            });
            authz.Status = "invalid";
            await db.SaveChangesAsync(cancellationToken);
            await orderService.RecalculateOrderStatusAsync(authz.OrderId, cancellationToken);
            return;
        }

        // RFC 8555 §7.1.6: a challenge can only ever move its authorization out of
        // "pending". Once a sibling has failed and made the authorization "invalid"
        // (issue #481), nothing this challenge does can change it, so close it out
        // without calling the validator, the way the deactivated guard above does.
        // The sweep loads every processing challenge in one graph, so a second
        // challenge answered on the same authorization reaches here holding the
        // status the first one just wrote.
        //
        // "valid" is let through on purpose. A client may answer a second challenge
        // on an authorization a sibling already proved, and the processing order
        // comment in OrderService.RecalculateOrderStatusAsync names exactly that
        // case. Neither outcome can change the authorization: a pass finds nothing
        // to promote, and a failure never demotes.
        //
        // An allow list, so a status added later fails closed.
        if (!string.Equals(authz.Status, "pending", StringComparison.Ordinal) &&
            !string.Equals(authz.Status, "valid", StringComparison.Ordinal))
        {
            challenge.Status = "invalid";
            challenge.ErrorJson = JsonSerializer.Serialize(ClosedAuthorizationError(authz.Status));
            await db.SaveChangesAsync(cancellationToken);
            _logger.LogInformation(
                "Challenge {ChallengeId} ({Type}) abandoned: its authorization is {Status}",
                challenge.ChallengeId, challenge.Type, authz.Status);
            // Normally a no-op, since whatever closed the authorization settled the
            // order too. Run anyway so this arm leaves the order agreeing with the
            // authorization on its own, as the expiry arm above does.
            await orderService.RecalculateOrderStatusAsync(authz.OrderId, cancellationToken);
            return;
        }

        var validator = validators.FirstOrDefault(v => v.ChallengeType == challenge.Type);
        if (validator == null)
        {
            _logger.LogWarning("No validator registered for challenge type {Type}", challenge.Type);
            await FailChallengeAsync(db, challenge, new AcmeError
            {
                Type = AcmeErrorType.ServerInternal,
                Detail = $"No validator available for challenge type '{challenge.Type}'."
            }, cancellationToken);
            await orderService.RecalculateOrderStatusAsync(authz.OrderId, cancellationToken);
            return;
        }

        var domain = authz.IdentifierValue;
        var accountThumbprint = JwsService.ComputeThumbprint(order.Account.JwkJson);

        challenge.LastAttemptAt = DateTime.UtcNow;
        var result = await validator.ValidateAsync(
            new ChallengeValidationContext(
                authz.IdentifierType,
                authz.IdentifierValue,
                challenge.Token,
                accountThumbprint,
                order.TemplateId,
                challenge.AttestationObject),
            cancellationToken);

        if (result.IsValid)
        {
            await PassChallengeAsync(db, challenge, result.Attested, cancellationToken);

            if (string.Equals(challenge.Status, "valid", StringComparison.Ordinal))
                _logger.LogInformation(
                    "Challenge {ChallengeId} ({Type}) for {Domain} validated successfully",
                    challenge.ChallengeId, challenge.Type, domain);
            else
                _logger.LogInformation(
                    "Challenge {ChallengeId} ({Type}) for {Domain} passed, but its " +
                    "authorization became {Status} while it was being validated, so it " +
                    "was not counted",
                    challenge.ChallengeId, challenge.Type, domain, authz.Status);
        }
        else if (result.Transient && challenge.ValidationAttempts + 1 < _options.MaxValidationAttempts)
        {
            // A transport failure, not a wrong answer. Leave the challenge in "processing"
            // so the next sweep retries it (RFC 8555 §8.2) instead of failing on a blip.
            challenge.ValidationAttempts++;
            _logger.LogInformation(
                "Challenge {ChallengeId} ({Type}) for {Domain} hit a transient failure " +
                "(attempt {Attempt}/{Max}); will retry: {Error}",
                challenge.ChallengeId, challenge.Type, domain,
                challenge.ValidationAttempts, _options.MaxValidationAttempts, result.ErrorDetail);
            await db.SaveChangesAsync(cancellationToken);
            return; // still processing — order stays pending
        }
        else
        {
            challenge.ValidationAttempts++;
            await FailChallengeAsync(db, challenge, new AcmeError
            {
                // A validator supplied type (badAttestationStatement) wins; otherwise
                // distinguish "we never got a usable answer" from "the answer was wrong".
                Type = result.ErrorType
                    ?? (result.Transient ? AcmeErrorType.Connection : AcmeErrorType.IncorrectResponse),
                Detail = result.ErrorDetail ?? "Challenge validation failed."
            }, cancellationToken);

            _logger.LogWarning(
                "Challenge {ChallengeId} ({Type}) for {Domain} failed: {Error}",
                challenge.ChallengeId, challenge.Type, domain, result.ErrorDetail);
        }

        // Recalculate order status using the scoped OrderService (real logger and ADCS client).
        await orderService.RecalculateOrderStatusAsync(authz.OrderId, cancellationToken);

        // A terminal device attestation failure gets an audit row, like a domain
        // policy refusal at newOrder or finalize: the challenge turning invalid is
        // otherwise visible only in this log. Last in the unit on purpose: RecordAsync
        // is best effort on the shared scoped DbContext, and a failed audit insert
        // would stay tracked, so nothing that matters may save after it. No client
        // address here: the worker validates asynchronously.
        if (!result.IsValid && challenge.Status == "invalid"
            && challenge.Type == DeviceAttest01ChallengeValidator.TypeName)
        {
            await auditService.RecordAsync(
                order.Account.AccountId,
                order.TemplateId,
                new[] { new AcmeIdentifier { Type = authz.IdentifierType, Value = authz.IdentifierValue } },
                new[] { authz.IdentifierValue },
                clientIp: null,
                stage: "challenge-device",
                cancellationToken);
        }
    }

    /// <summary>
    /// Records a terminal challenge failure, and with it the authorization's.
    /// RFC 8555 section 7.1.6 has a pending authorization become invalid when a
    /// challenge under it fails. Until issue #481 the authorization went invalid
    /// only once every one of its challenges had, and a network name is offered
    /// three, so one failed answer left the authorization and its order pending
    /// until they expired. A client that waits on the authorization rather than
    /// the challenge, as cert-manager does, then saw a timeout instead of the
    /// failure.
    ///
    /// <para>
    /// The authorization is written as a conditional UPDATE from "pending" only,
    /// never as a tracked assignment. The tracked copy was loaded by the sweep
    /// before the validator ran, which for a network challenge can take seconds,
    /// so a test of that copy is a stale read. Two outcomes depend on the
    /// predicate. A "valid" authorization is never demoted: a sibling challenge
    /// already proved it, and an order can only be "processing" because every
    /// authorization was valid at the finalize claim, which
    /// <see cref="OrderService.RecalculateOrderStatusAsync"/> relies on. And a
    /// deactivation another request committed meanwhile is never overwritten,
    /// because "deactivated" is what the client asked for.
    /// </para>
    ///
    /// <para>
    /// The challenge and the authorization commit together. One SaveChanges used to
    /// cover both, and ExecuteUpdate cannot be batched into SaveChanges, so an
    /// explicit transaction keeps a crash in between from leaving an invalid
    /// challenge under an authorization that still reads pending. No network call
    /// happens inside it. No retrying execution strategy is configured, so no
    /// strategy wrapper is needed; if one is ever added, this block and
    /// <see cref="PassChallengeAsync"/> have to be wrapped with the others.
    /// </para>
    /// </summary>
    private static async Task FailChallengeAsync(
        CertusDbContext db,
        Data.Entities.AcmeChallenge challenge,
        AcmeError error,
        CancellationToken cancellationToken)
    {
        var authz = challenge.Authorization;
        challenge.Status = "invalid";
        challenge.ErrorJson = JsonSerializer.Serialize(error);

        await using (var tx = await db.Database.BeginTransactionAsync(cancellationToken))
        {
            await db.SaveChangesAsync(cancellationToken);

            await db.AcmeAuthorizations
                .Where(a => a.Id == authz.Id && a.Status == "pending")
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(a => a.Status, "invalid"),
                    cancellationToken);

            await tx.CommitAsync(cancellationToken);
        }

        // ExecuteUpdate goes round the change tracker, and the caller goes on to
        // RecalculateOrderStatusAsync, which reads the authorizations through this
        // same scoped DbContext. Identity resolution would hand it the stale tracked
        // copy still reading "pending", and the order would never be demoted.
        await db.Entry(authz).ReloadAsync(cancellationToken);
    }

    /// <summary>
    /// Records a challenge that passed. The authorization is promoted from
    /// "pending" only, by a conditional UPDATE, for the reason
    /// <see cref="FailChallengeAsync"/> gives. Before issue #481 the promotion was
    /// an unconditional tracked write, so a validation that finished after another
    /// request deactivated the authorization set it back to "valid". Once a failure
    /// can make an authorization invalid while siblings remain, the same write
    /// would also have resurrected an invalid one.
    ///
    /// <para>
    /// When the authorization is no longer pending or valid by the time the result
    /// is recorded, the challenge is closed out as the guards at the top of
    /// ValidateSingleChallengeAsync would have closed it a moment earlier, rather
    /// than reading "valid" under an authorization it could not make valid.
    /// </para>
    /// </summary>
    private static async Task PassChallengeAsync(
        CertusDbContext db,
        Data.Entities.AcmeChallenge challenge,
        AttestedDeviceData? attested,
        CancellationToken cancellationToken)
    {
        var authz = challenge.Authorization;

        await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);

        await db.AcmeAuthorizations
            .Where(a => a.Id == authz.Id && a.Status == "pending")
            .ExecuteUpdateAsync(setters =>
            {
                setters.SetProperty(a => a.Status, "valid");

                // A device attestation carries the attested identity; persist it on
                // the authorization so finalize can bind the CSR key to the attested
                // key. In the same statement as the promotion, so a valid device
                // authorization never exists without it.
                if (attested is not null)
                {
                    setters.SetProperty(a => a.AttestedSpki, attested.SpkiBase64);
                    setters.SetProperty(a => a.AttestationFormat, attested.Format);
                    setters.SetProperty(a => a.AttestedPropertiesJson, attested.PropertiesJson);
                }
            },
            cancellationToken);

        // Read back what the row settled on, inside the transaction, so the
        // challenge is written to agree with it. The reload also keeps the tracked
        // copy current for RecalculateOrderStatusAsync, as in FailChallengeAsync.
        await db.Entry(authz).ReloadAsync(cancellationToken);

        if (string.Equals(authz.Status, "valid", StringComparison.Ordinal))
        {
            challenge.Status = "valid";
            challenge.ValidatedAt = DateTime.UtcNow;
        }
        else
        {
            challenge.Status = "invalid";
            challenge.ErrorJson = JsonSerializer.Serialize(ClosedAuthorizationError(authz.Status));
        }

        await db.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// The problem document for a challenge closed out because its authorization
    /// can no longer be made valid. A deactivation keeps the wording and type it
    /// had before issue #481, since "deactivated" is what the client asked for and
    /// says why the challenge stopped.
    /// </summary>
    private static AcmeError ClosedAuthorizationError(string authorizationStatus) =>
        string.Equals(authorizationStatus, "deactivated", StringComparison.Ordinal)
            ? new AcmeError
            {
                Type = AcmeErrorType.Unauthorized,
                Detail = "The authorization has been deactivated."
            }
            : new AcmeError
            {
                Type = AcmeErrorType.Malformed,
                Detail = "The authorization is no longer pending, so this challenge " +
                         "can no longer make it valid."
            };
}
