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

    /// <summary>How often to poll for pending challenges.</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    public ChallengeValidationService(
        IServiceScopeFactory scopeFactory,
        ILogger<ChallengeValidationService> logger,
        IOptions<ChallengeValidationOptions> options)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _options = options.Value;
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
                await Task.Delay(PollInterval, stoppingToken);
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
            await ValidateSingleChallengeAsync(db, validators, orderService, challenge, cancellationToken);
        }
    }

    private async Task ValidateSingleChallengeAsync(
        CertusDbContext db,
        IEnumerable<IChallengeValidator> validators,
        OrderService orderService,
        Data.Entities.AcmeChallenge challenge,
        CancellationToken cancellationToken)
    {
        var authz = challenge.Authorization;
        var order = authz.Order;

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
            domain, challenge.Token, accountThumbprint, cancellationToken);

        if (result.IsValid)
        {
            challenge.Status = "valid";
            challenge.ValidatedAt = DateTime.UtcNow;
            // At least one valid challenge makes the authorization valid.
            authz.Status = "valid";
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
                // Distinguish "we never got a usable answer" from "the answer was wrong".
                Type = result.Transient ? AcmeErrorType.Connection : AcmeErrorType.IncorrectResponse,
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
    }
}
