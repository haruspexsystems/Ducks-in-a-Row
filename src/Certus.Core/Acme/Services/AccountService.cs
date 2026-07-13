using System.Security.Cryptography;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Manages ACME account creation, lookup, and updates.
/// RFC 8555 §7.3
/// </summary>
public sealed class AccountService
{
    private readonly CertusDbContext _db;
    private readonly ILogger<AccountService> _logger;

    public AccountService(CertusDbContext db, ILogger<AccountService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new ACME account.
    /// Returns null if an account with the same JWK already exists (caller should handle as lookup).
    /// </summary>
    public async Task<(AcmeAccount? Account, bool AlreadyExists)> CreateAccountAsync(
        string jwkJson,
        NewAccountRequest request,
        CancellationToken cancellationToken = default)
    {
        var thumbprint = JwsService.ComputeThumbprint(jwkJson);

        // Check if account already exists for this key
        var existing = await _db.AcmeAccounts
            .FirstOrDefaultAsync(a => a.JwkThumbprint == thumbprint, cancellationToken);

        if (existing != null)
        {
            _logger.LogDebug("Account already exists for JWK thumbprint {Thumbprint}", thumbprint);
            return (existing, AlreadyExists: true);
        }

        // Create new account
        var account = new AcmeAccount
        {
            AccountId = GenerateAccountId(),
            JwkJson = jwkJson,
            JwkThumbprint = thumbprint,
            ContactJson = request.Contact != null
                ? JsonSerializer.Serialize(request.Contact)
                : null,
            TermsOfServiceAgreed = request.TermsOfServiceAgreed,
            Status = "valid",
            CreatedAt = DateTime.UtcNow
        };

        _db.AcmeAccounts.Add(account);
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Lost a race with a concurrent new-account for the same key: the unique index on
            // JwkThumbprint rejected this insert. Return the account that won instead of letting
            // the violation surface as a 500. Detach the failed entity so the context is clean.
            _db.Entry(account).State = EntityState.Detached;
            var winner = await _db.AcmeAccounts
                .FirstOrDefaultAsync(a => a.JwkThumbprint == thumbprint, cancellationToken);
            if (winner != null)
            {
                _logger.LogDebug(
                    "Concurrent new-account race for thumbprint {Thumbprint}; returning the existing account",
                    thumbprint);
                return (winner, AlreadyExists: true);
            }
            throw;
        }

        _logger.LogInformation("Created ACME account {AccountId} for JWK thumbprint {Thumbprint}",
            account.AccountId, thumbprint);

        return (account, AlreadyExists: false);
    }

    /// <summary>
    /// Finds an account by its JWK thumbprint (for jwk-based lookups).
    /// </summary>
    public async Task<AcmeAccount?> FindByThumbprintAsync(
        string jwkJson,
        CancellationToken cancellationToken = default)
    {
        var thumbprint = JwsService.ComputeThumbprint(jwkJson);
        return await _db.AcmeAccounts
            .FirstOrDefaultAsync(a => a.JwkThumbprint == thumbprint, cancellationToken);
    }

    /// <summary>
    /// Finds an account by its account ID (from the kid URL).
    /// </summary>
    public async Task<AcmeAccount?> FindByAccountIdAsync(
        string accountId,
        CancellationToken cancellationToken = default)
    {
        return await _db.AcmeAccounts
            .FirstOrDefaultAsync(a => a.AccountId == accountId, cancellationToken);
    }

    /// <summary>
    /// Swaps an account's key to a new one (ACME account key rollover, RFC 8555 §7.3.5).
    /// The caller has already verified the inner JWS was signed by the new key, that the inner
    /// payload's oldKey matches this account, and (via <see cref="FindByThumbprintAsync"/>) that
    /// the new key is not already registered. This persists the swap. The unique index on
    /// JwkThumbprint is the final arbiter: if a concurrent request claimed the same new key in
    /// between the pre-check and here, SaveChanges throws and we report a conflict rather than
    /// letting the violation surface as a 500.
    /// </summary>
    public async Task<KeyChangeOutcome> ChangeKeyAsync(
        AcmeAccount account,
        string newJwkJson,
        CancellationToken cancellationToken = default)
    {
        var newThumbprint = JwsService.ComputeThumbprint(newJwkJson);

        account.JwkJson = newJwkJson;
        account.JwkThumbprint = newThumbprint;
        account.UpdatedAt = DateTime.UtcNow;

        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Lost a race: another request registered this key (or rolled another account onto
            // it) first, so the unique JwkThumbprint index rejected the swap. Report a conflict
            // so the controller returns 409 (RFC 8555 §7.3.5) instead of a 500. The scoped
            // DbContext is disposed at the end of this request, so leaving the entity in its
            // modified state is harmless — nothing re-saves it.
            _logger.LogDebug(
                "Key-change for account {AccountId} conflicted on thumbprint {Thumbprint}",
                account.AccountId, newThumbprint);
            return KeyChangeOutcome.Conflict;
        }

        _logger.LogInformation(
            "Rolled ACME account {AccountId} to a new key (thumbprint {Thumbprint})",
            account.AccountId, newThumbprint);
        return KeyChangeOutcome.Changed;
    }

    /// <summary>
    /// Builds the ACME account response object, including the orders list URL (RFC 8555 §7.1.2).
    /// </summary>
    public static AcmeAccountResponse ToResponse(
        AcmeAccount account, Func<string, string> urlBuilder, string template)
    {
        return new AcmeAccountResponse
        {
            Status = account.Status,
            Contact = !string.IsNullOrEmpty(account.ContactJson)
                ? JsonSerializer.Deserialize<string[]>(account.ContactJson)
                : null,
            TermsOfServiceAgreed = account.TermsOfServiceAgreed,
            Orders = urlBuilder($"/acme/{template}/acct/{account.AccountId}/orders")
        };
    }

    private static string GenerateAccountId()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>
/// Outcome of <see cref="AccountService.ChangeKeyAsync"/>.
/// </summary>
public enum KeyChangeOutcome
{
    /// <summary>The account key was swapped to the new key.</summary>
    Changed,

    /// <summary>A concurrent request claimed the new key first; the swap was rejected.</summary>
    Conflict
}
