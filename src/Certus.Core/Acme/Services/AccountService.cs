using System.Security.Cryptography;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
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
    /// Creates a new ACME account, optionally bound to an EAB credential the
    /// caller has already verified (RFC 8555 §7.3.4).
    /// Returns the existing account when one exists for the same JWK; the
    /// caller applies the bind and rebind rules for that case.
    /// </summary>
    public async Task<(AcmeAccount? Account, bool AlreadyExists)> CreateAccountAsync(
        string jwkJson,
        NewAccountRequest request,
        int? eabCredentialId = null,
        string? eabJwsJson = null,
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
            ExternalAccountCredentialId = eabCredentialId,
            EabJwsJson = eabCredentialId != null ? eabJwsJson : null,
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
    /// Binds an existing, unbound account to an EAB credential the caller has
    /// already verified (RFC 8555 §7.3.4). This is the deliberate adoption
    /// path for accounts that pre-date enforcement: the client re-runs
    /// registration with a valid binding and the account picks it up. The
    /// caller never invokes this for an account that is already bound.
    /// </summary>
    public async Task BindAsync(
        AcmeAccount account,
        int credentialId,
        string eabJwsJson,
        CancellationToken cancellationToken = default)
    {
        account.ExternalAccountCredentialId = credentialId;
        account.EabJwsJson = eabJwsJson;
        account.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Bound existing ACME account {AccountId} to EAB credential {CredentialId}",
            account.AccountId, credentialId);
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
    /// Searches, sorts, and pages the account inventory for the dashboard.
    /// Search matches the public account id, the contact list, and, for bound
    /// accounts, the credential name and key id, case insensitively. Binding,
    /// status, credential, and activity are independent axes and combine with
    /// AND, so "valid and still unbound" is one query. The caller clamps
    /// paging and rejects unknown filter names; this trusts its inputs.
    /// </summary>
    public async Task<PagedResult<AcmeAccountSummary>> QueryAsync(
        AcmeAccountQuery query,
        CancellationToken cancellationToken = default)
    {
        // One read of the clock for the whole query. Two reads could put
        // "no order in 30 days" and "ordered in the last 30 days" a tick
        // apart, and let a row at the boundary satisfy both or neither.
        var now = DateTime.UtcNow;

        var accounts = _db.AcmeAccounts.AsNoTracking();

        accounts = query.Binding switch
        {
            AcmeAccountBindingFilter.Bound =>
                accounts.Where(a => a.ExternalAccountCredentialId != null),
            AcmeAccountBindingFilter.Unbound =>
                accounts.Where(a => a.ExternalAccountCredentialId == null),
            // Bound, but to a credential that has since been revoked. These
            // accounts are refused at newOrder while still looking bound in
            // the list, so they are worth being able to single out.
            AcmeAccountBindingFilter.BoundToRevoked =>
                accounts.Where(a => a.ExternalAccountCredential != null &&
                                    a.ExternalAccountCredential.Status == "revoked"),
            _ => accounts,
        };

        accounts = query.Status switch
        {
            AcmeAccountStatusFilter.Valid => accounts.Where(a => a.Status == "valid"),
            AcmeAccountStatusFilter.Deactivated => accounts.Where(a => a.Status == "deactivated"),
            _ => accounts,
        };

        // Deliberately not validated by the caller: an id matching no
        // credential returns an empty page rather than a 400, so a stale
        // bookmark degrades to "no accounts" instead of an error.
        if (query.CredentialId is int credentialId)
            accounts = accounts.Where(a => a.ExternalAccountCredentialId == credentialId);

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var term = query.Search.Trim().ToLowerInvariant();
            accounts = accounts.Where(a =>
                a.AccountId.ToLower().Contains(term) ||
                (a.ContactJson != null && a.ContactJson.ToLower().Contains(term)) ||
                (a.ExternalAccountCredential != null &&
                    (a.ExternalAccountCredential.Name.ToLower().Contains(term) ||
                     a.ExternalAccountCredential.KeyId.ToLower().Contains(term))));
        }

        // Activity. Every arm is an existence check rather than a Max over the
        // order table: "has no order since the cutoff" and "max(CreatedAt) is
        // before the cutoff" select the same rows, and Any stops at the first
        // match where Max must read them all. The idle arms deliberately
        // include accounts that never ordered at all, which have indeed not
        // ordered in the last 30 days.
        if (query.Activity == AcmeAccountActivityFilter.NeverOrdered)
        {
            accounts = accounts.Where(a => !_db.AcmeOrders.Any(o => o.AccountId == a.Id));
        }
        else if (ActivityWindowDays(query.Activity) is int windowDays)
        {
            var cutoff = now.AddDays(-windowDays);
            var idle = query.Activity is AcmeAccountActivityFilter.IdleFor30Days
                or AcmeAccountActivityFilter.IdleFor90Days
                or AcmeAccountActivityFilter.IdleFor180Days;

            accounts = idle
                ? accounts.Where(a =>
                    !_db.AcmeOrders.Any(o => o.AccountId == a.Id && o.CreatedAt >= cutoff))
                : accounts.Where(a =>
                    _db.AcmeOrders.Any(o => o.AccountId == a.Id && o.CreatedAt >= cutoff));
        }

        if (query.RegisteredAfter is DateTime registeredAfter)
            accounts = accounts.Where(a => a.CreatedAt >= registeredAfter);

        // Exclusive upper bound. The caller sends the start of the day after
        // the one picked, so the whole picked day sits inside the range; see
        // the parameter docs on the controller.
        if (query.RegisteredBefore is DateTime registeredBefore)
            accounts = accounts.Where(a => a.CreatedAt < registeredBefore);

        // "The last order is at or after v" is the same set as "some order is
        // at or after v", so this one is an Any like the activity arms above.
        if (query.LastOrderAfter is DateTime lastOrderAfter)
            accounts = accounts.Where(a =>
                _db.AcmeOrders.Any(o => o.AccountId == a.Id && o.CreatedAt >= lastOrderAfter));

        // This one is NOT the mirror image, and must not be "simplified" into
        // one. Any(o => o.CreatedAt < v) matches an account whose oldest order
        // is old even when its newest is from today, which is the opposite of
        // what the filter says. It has to compare the max. A null max (no
        // orders at all) compares false in SQL, which is what keeps never
        // ordered accounts out of a range filter on a date they do not have;
        // the NeverOrdered activity filter is how you ask for those.
        if (query.LastOrderBefore is DateTime lastOrderBefore)
            accounts = accounts.Where(a =>
                _db.AcmeOrders.Where(o => o.AccountId == a.Id)
                    .Max(o => (DateTime?)o.CreatedAt) < lastOrderBefore);

        var total = await accounts.CountAsync(cancellationToken);

        // Sorting. The switch picks the primary key, then Id is appended as a
        // unique tiebreaker in every case: rows sharing a primary value have
        // no defined order without it, so Skip/Take paging could repeat or
        // drop one at a page boundary. The tiebreak is ascending in both
        // directions, matching the certificate list, so it is one rule rather
        // than two.
        //
        // ordersCount and lastOrderAt are deliberately absent. Both are
        // correlated subqueries over the order table, and sorting on one
        // evaluates it for every row in the filtered set rather than the
        // twenty five on the page; the activity filter answers those
        // questions instead.
        //
        // An unrecognised key falls through to the default silently rather
        // than erroring, matching CertificateQueryService: a filter that
        // quietly matches everything is a lie, but a sort that quietly uses
        // the default is not.
        var ordered = query.SortBy?.ToLowerInvariant() switch
        {
            "accountid" => query.SortDesc
                ? accounts.OrderByDescending(a => a.AccountId)
                : accounts.OrderBy(a => a.AccountId),
            "status" => query.SortDesc
                ? accounts.OrderByDescending(a => a.Status)
                : accounts.OrderBy(a => a.Status),
            // A left join through the nullable navigation: an unbound account
            // has no credential name, so unbound sorts first ascending and
            // last descending under SQLite, which emits no NULLS FIRST/LAST.
            "credential" => query.SortDesc
                ? accounts.OrderByDescending(a => a.ExternalAccountCredential!.Name)
                : accounts.OrderBy(a => a.ExternalAccountCredential!.Name),
            "createdat" => query.SortDesc
                ? accounts.OrderByDescending(a => a.CreatedAt)
                : accounts.OrderBy(a => a.CreatedAt),
            _ => accounts.OrderByDescending(a => a.CreatedAt), // default: newest first
        };

        var rows = await ordered
            .ThenBy(a => a.Id)
            .Skip(query.Skip)
            .Take(query.Take)
            .Select(a => new
            {
                a.Id,
                a.AccountId,
                a.Status,
                a.ContactJson,
                a.CreatedAt,
                OrdersCount = _db.AcmeOrders.Count(o => o.AccountId == a.Id),
                LastOrderAt = _db.AcmeOrders
                    .Where(o => o.AccountId == a.Id)
                    .Max(o => (DateTime?)o.CreatedAt),
                Credential = a.ExternalAccountCredential == null
                    ? null
                    : new EabCredentialRef(
                        a.ExternalAccountCredential.Id,
                        a.ExternalAccountCredential.KeyId,
                        a.ExternalAccountCredential.Name,
                        a.ExternalAccountCredential.Status),
            })
            .ToListAsync(cancellationToken);

        var items = rows
            .Select(r => new AcmeAccountSummary(
                r.Id,
                r.AccountId,
                r.Status,
                ParseContacts(r.ContactJson),
                r.CreatedAt,
                r.OrdersCount,
                r.LastOrderAt,
                r.Credential))
            .ToList();

        return new PagedResult<AcmeAccountSummary>(items, total, query.Skip, query.Take);
    }

    /// <summary>
    /// The rolling window an activity filter measures, in days, or null for
    /// the two filters that are not a window (Any and NeverOrdered).
    /// </summary>
    private static int? ActivityWindowDays(AcmeAccountActivityFilter activity) => activity switch
    {
        AcmeAccountActivityFilter.ActiveWithin7Days => 7,
        AcmeAccountActivityFilter.IdleFor30Days or
        AcmeAccountActivityFilter.ActiveWithin30Days => 30,
        AcmeAccountActivityFilter.IdleFor90Days => 90,
        AcmeAccountActivityFilter.IdleFor180Days => 180,
        _ => null,
    };

    /// <summary>
    /// Maps a binding filter name to its value, or null when the name is not
    /// one of them. An absent or empty name means no filter.
    /// </summary>
    public static AcmeAccountBindingFilter? ParseBinding(string? binding) =>
        binding?.Trim().ToLowerInvariant() switch
        {
            null or "" or "all" => AcmeAccountBindingFilter.All,
            "bound" => AcmeAccountBindingFilter.Bound,
            "unbound" => AcmeAccountBindingFilter.Unbound,
            "boundtorevoked" => AcmeAccountBindingFilter.BoundToRevoked,
            _ => null,
        };

    /// <summary>
    /// Maps a status filter name to its value, or null when the name is not
    /// one of them. Only valid and deactivated are offered, because those are
    /// the only two values anything writes; see <see cref="AcmeAccount.Status"/>.
    /// </summary>
    public static AcmeAccountStatusFilter? ParseStatus(string? status) =>
        status?.Trim().ToLowerInvariant() switch
        {
            null or "" or "all" => AcmeAccountStatusFilter.All,
            "valid" => AcmeAccountStatusFilter.Valid,
            "deactivated" => AcmeAccountStatusFilter.Deactivated,
            _ => null,
        };

    /// <summary>
    /// Maps an activity filter name to its value, or null when the name is
    /// not one of them. The controller rejects a null, so this list is the
    /// single definition of the vocabulary and the API's idea of it cannot
    /// drift from the query's.
    /// </summary>
    public static AcmeAccountActivityFilter? ParseActivity(string? activity) =>
        activity?.Trim().ToLowerInvariant() switch
        {
            null or "" or "any" => AcmeAccountActivityFilter.Any,
            "never" => AcmeAccountActivityFilter.NeverOrdered,
            "idle30" => AcmeAccountActivityFilter.IdleFor30Days,
            "idle90" => AcmeAccountActivityFilter.IdleFor90Days,
            "idle180" => AcmeAccountActivityFilter.IdleFor180Days,
            "active7" => AcmeAccountActivityFilter.ActiveWithin7Days,
            "active30" => AcmeAccountActivityFilter.ActiveWithin30Days,
            _ => null,
        };

    /// <summary>
    /// How many valid accounts carry no EAB binding. These are the accounts
    /// grandfathered under Required enforcement, so the enforcement card can
    /// say concretely what that mode leaves open. Deactivated accounts are
    /// not counted; they cannot order regardless.
    /// </summary>
    public Task<int> CountUnboundValidAsync(CancellationToken cancellationToken = default)
    {
        return _db.AcmeAccounts.CountAsync(
            a => a.Status == "valid" && a.ExternalAccountCredentialId == null,
            cancellationToken);
    }

    /// <summary>
    /// Deactivates an account from the dashboard and invalidates its open
    /// (pending, ready, or processing) orders in the same SaveChanges, so
    /// the two cannot diverge. The ACME surface needs no extra check: every
    /// kid authenticated request already rejects a non valid account with
    /// 403. Deactivation is terminal (RFC 8555 §7.3.6).
    /// </summary>
    public async Task<AccountDeactivationResult> DeactivateAsync(
        int id,
        CancellationToken cancellationToken = default)
    {
        var account = await _db.AcmeAccounts
            .FirstOrDefaultAsync(a => a.Id == id, cancellationToken);
        if (account == null)
            return new AccountDeactivationResult(
                AccountDeactivationOutcome.NotFound, null, 0);

        if (account.Status != "valid")
            return new AccountDeactivationResult(
                AccountDeactivationOutcome.NotValid, account, 0);

        var openOrders = await _db.AcmeOrders
            .Where(o => o.AccountId == account.Id &&
                (o.Status == "pending" || o.Status == "ready" || o.Status == "processing"))
            .ToListAsync(cancellationToken);
        foreach (var order in openOrders)
            order.Status = "invalid";

        account.Status = "deactivated";
        account.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Deactivated ACME account {AccountId} from the dashboard and invalidated {Count} open order(s)",
            account.AccountId, openOrders.Count);

        return new AccountDeactivationResult(
            AccountDeactivationOutcome.Deactivated, account, openOrders.Count);
    }

    /// <summary>
    /// Parses a stored ContactJson column into the contact list. Shared with
    /// the EAB credential service's bound accounts view so both dashboard
    /// surfaces render the same account's contacts identically.
    /// </summary>
    internal static string[]? ParseContacts(string? contactJson)
    {
        if (string.IsNullOrEmpty(contactJson))
            return null;

        try
        {
            return JsonSerializer.Deserialize<string[]>(contactJson);
        }
        catch (JsonException)
        {
            // The column is written from a parsed request, so this is a hand
            // edit; the dashboard list should survive it rather than 500.
            return null;
        }
    }

    /// <summary>
    /// Builds the ACME account response object, including the orders list URL
    /// and the externalAccountBinding echo (RFC 8555 §7.1.2).
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
            Orders = urlBuilder($"/acme/{template}/acct/{account.AccountId}/orders"),
            ExternalAccountBinding = !string.IsNullOrEmpty(account.EabJwsJson)
                ? JsonSerializer.Deserialize<JsonElement>(account.EabJwsJson)
                : null
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

/// <summary>Binding filter for the dashboard account list.</summary>
public enum AcmeAccountBindingFilter
{
    /// <summary>No binding filter.</summary>
    All,

    /// <summary>Only accounts bound to an EAB credential.</summary>
    Bound,

    /// <summary>Only accounts without a binding (grandfathered under Required).</summary>
    Unbound,

    /// <summary>Only accounts bound to a credential that has since been revoked.</summary>
    BoundToRevoked
}

/// <summary>
/// Account status filter for the dashboard list. An axis of its own, not a
/// continuation of <see cref="AcmeAccountBindingFilter"/>: the two combine
/// with AND, which is what makes "valid and still unbound" askable.
/// </summary>
public enum AcmeAccountStatusFilter
{
    /// <summary>No status filter.</summary>
    All,

    /// <summary>Only accounts that can still order.</summary>
    Valid,

    /// <summary>Only accounts an administrator has deactivated.</summary>
    Deactivated
}

/// <summary>
/// Order activity filter for the dashboard list, measured as a rolling window
/// from the moment the query runs. The idle windows include accounts that
/// have never ordered; <see cref="NeverOrdered"/> isolates only those.
/// </summary>
public enum AcmeAccountActivityFilter
{
    /// <summary>No activity filter.</summary>
    Any,

    /// <summary>Accounts with no orders at all.</summary>
    NeverOrdered,

    /// <summary>No order in the last 30 days.</summary>
    IdleFor30Days,

    /// <summary>No order in the last 90 days.</summary>
    IdleFor90Days,

    /// <summary>No order in the last 180 days.</summary>
    IdleFor180Days,

    /// <summary>At least one order in the last 7 days.</summary>
    ActiveWithin7Days,

    /// <summary>At least one order in the last 30 days.</summary>
    ActiveWithin30Days
}

/// <summary>
/// Parameters of <see cref="AccountService.QueryAsync"/>. The caller clamps
/// paging and rejects unknown filter names. Every member defaults, so callers
/// should pass named arguments; the positional order is not a stable contract.
/// </summary>
public sealed record AcmeAccountQuery(
    string? Search = null,
    AcmeAccountBindingFilter Binding = AcmeAccountBindingFilter.All,
    AcmeAccountStatusFilter Status = AcmeAccountStatusFilter.All,
    int? CredentialId = null,
    AcmeAccountActivityFilter Activity = AcmeAccountActivityFilter.Any,
    DateTime? RegisteredAfter = null,
    DateTime? RegisteredBefore = null,
    DateTime? LastOrderAfter = null,
    DateTime? LastOrderBefore = null,
    string? SortBy = null,
    bool SortDesc = false,
    int Skip = 0,
    int Take = 50);

/// <summary>A dashboard row of the account list.</summary>
public sealed record AcmeAccountSummary(
    int Id,
    string AccountId,
    string Status,
    string[]? Contacts,
    DateTime CreatedAt,
    int OrdersCount,
    DateTime? LastOrderAt,
    EabCredentialRef? Credential);

/// <summary>The bound credential of an account row, or null for an unbound account.</summary>
public sealed record EabCredentialRef(
    int Id,
    string KeyId,
    string Name,
    string Status);

/// <summary>Outcome of <see cref="AccountService.DeactivateAsync"/>.</summary>
public enum AccountDeactivationOutcome
{
    /// <summary>The account was deactivated and its open orders invalidated.</summary>
    Deactivated,

    /// <summary>No account has this id.</summary>
    NotFound,

    /// <summary>The account is already deactivated or revoked; nothing changed.</summary>
    NotValid
}

/// <summary>Result of <see cref="AccountService.DeactivateAsync"/>.</summary>
public sealed record AccountDeactivationResult(
    AccountDeactivationOutcome Outcome,
    AcmeAccount? Account,
    int InvalidatedOrders);
