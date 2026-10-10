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

    private async Task ProcessPendingChallengesAsync(CancellationToken cancellationToken)
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
            await ValidateSingleChallengeAsync(
                db, validators, orderService, auditService, challenge, cancellationToken);
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
        // landed still arrives here, and the success path below would set the
        // authorization back to "valid", undoing a deactivation nobody asked to undo.
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
            challenge.ErrorJson = JsonSerializer.Serialize(new AcmeError
            {
                Type = AcmeErrorType.Unauthorized,
                Detail = "The authorization has been deactivated."
            });
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

        var validator = validators.FirstOrDefault(v => v.ChallengeType == challenge.Type);
        if (validator == null)
        {
            _logger.LogWarning("No validator registered for challenge type {Type}", challenge.Type);
            challenge.Status = "invalid";
            challenge.ErrorJson = JsonSerializer.Serialize(new AcmeError
            {
                Type = AcmeErrorType.ServerInternal,
                Detail = $"No validator available for challenge type '{challenge.Type}'."
            });
            await db.SaveChangesAsync(cancellationToken);
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
            challenge.Status = "valid";
            challenge.ValidatedAt = DateTime.UtcNow;
            // At least one valid challenge makes the authorization valid.
            authz.Status = "valid";

            // A device attestation carries the attested identity; persist it on the
            // authorization so finalize can bind the CSR key to the attested key.
            if (result.Attested is { } attested)
            {
                authz.AttestedSpki = attested.SpkiBase64;
                authz.AttestationFormat = attested.Format;
                authz.AttestedPropertiesJson = attested.PropertiesJson;
            }

            _logger.LogInformation(
                "Challenge {ChallengeId} ({Type}) for {Domain} validated successfully",
                challenge.ChallengeId, challenge.Type, domain);
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
            challenge.Status = "invalid";
            challenge.ErrorJson = JsonSerializer.Serialize(new AcmeError
            {
                // A validator supplied type (badAttestationStatement) wins; otherwise
                // distinguish "we never got a usable answer" from "the answer was wrong".
                Type = result.ErrorType
                    ?? (result.Transient ? AcmeErrorType.Connection : AcmeErrorType.IncorrectResponse),
                Detail = result.ErrorDetail ?? "Challenge validation failed."
            });

            // If every challenge in the authorization is now invalid, the authz is invalid.
            if (authz.Challenges.All(c => c.Status == "invalid"))
                authz.Status = "invalid";

            _logger.LogWarning(
                "Challenge {ChallengeId} ({Type}) for {Domain} failed: {Error}",
                challenge.ChallengeId, challenge.Type, domain, result.ErrorDetail);
        }

        await db.SaveChangesAsync(cancellationToken);

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
}
