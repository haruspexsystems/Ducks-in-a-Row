using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>How an erasure request ended.</summary>
public enum AccountErasureOutcome
{
    /// <summary>No account has the id.</summary>
    NotFound,

    /// <summary>
    /// The account is still valid. Erasure needs deactivation first, because a
    /// live account's contacts and identifiers are in use by its own client.
    /// </summary>
    NotDeactivated,

    /// <summary>The personal data is gone; the counts say what was touched.</summary>
    Erased,

    /// <summary>
    /// An earlier request already erased this account. Nothing was changed, and
    /// <see cref="AcmeAccount.ErasedAt"/> says when.
    /// </summary>
    AlreadyErased,
}

/// <summary>What the erasure did, for the endpoint's answer and the log line.</summary>
public sealed record AccountErasureResult(
    AccountErasureOutcome Outcome,
    AcmeAccount? Account,
    int OrdersRedacted,
    int AuthorizationsRedacted,
    int ChallengesRedacted,
    bool CredentialLinkCleared);

/// <summary>
/// Erases one ACME account's personal data at an administrator's request
/// (issue #637, CRA risk R18), keeping the issuance records the CA audit needs.
///
/// <para><b>What goes.</b> The account's contact addresses; the Active Directory
/// principal link (SID, name and type) on the credential the account is bound
/// to; and the identifiers its orders carried: every identifier value in the
/// order's identifier list, the stored CSR, each authorization's identifier
/// value, attested key and attested properties (an Apple device's serial and
/// UDID live there), and each challenge's attestation object.</para>
///
/// <para><b>What stays.</b> The account row itself, with its public key and the
/// instant of erasure; every order row with its id, status, template, CA
/// request id, certificate id and timestamps; and every certificate record,
/// the issued leaf included. The leaf names what it was issued to, as the
/// CA's own copy does, and that is the issuance record: it is also what ARI,
/// <c>replaces</c> and revoke-cert still need while the certificate is live.
/// The identifier list keeps each identifier's type with an empty value, so
/// the record still says a device order was a device order.</para>
///
/// <para><b>The credential link is shared.</b> One EAB credential may bind many
/// accounts, and its principal link names the person the credential was
/// handed to. Clearing it on one account's behalf clears it for every account
/// bound to that credential; the documentation says so.</para>
///
/// <para><b>Deactivation first.</b> A valid account is refused. Its client is
/// still using the contacts and identifiers, and deactivation already
/// invalidates the open orders, so erasure never has to reason about an order
/// in flight.</para>
///
/// <para><b>The record of the erasure.</b> <see cref="AcmeAccount.ErasedAt"/> is
/// written in the same transaction, and the log line is written at Warning so a
/// raised minimum level does not drop it. The administrator audit row (R07,
/// #634) is written by the dashboard's audit filter in the transaction this
/// method joins, see below; a second request reports the first instead of
/// pretending to erase again, and writes no row.
/// <see cref="AcmeAccount.UpdatedAt"/> is deliberately left alone: it is the
/// deactivation instant the retention rule measures from, and an erasure must
/// not restart that clock.</para>
/// </summary>
public sealed class AccountErasureService
{
    /// <summary>Orders rewritten per statement, so one account's history never loads at once.</summary>
    internal const int OrderPageSize = 500;

    private readonly CertusDbContext _db;
    private readonly ILogger<AccountErasureService> _logger;
    private readonly TimeProvider _time;

    public AccountErasureService(
        CertusDbContext db,
        ILogger<AccountErasureService> logger,
        TimeProvider? timeProvider = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Erases the account's personal data. <paramref name="actor"/> is the
    /// administrator's Windows identity, recorded in the log line.
    /// </summary>
    public async Task<AccountErasureResult> EraseAsync(
        int id, string actor, CancellationToken cancellationToken = default)
    {
        var account = await _db.AcmeAccounts
            .FirstOrDefaultAsync(a => a.Id == id, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
            return new AccountErasureResult(AccountErasureOutcome.NotFound, null, 0, 0, 0, false);

        if (account.Status != "deactivated")
            return new AccountErasureResult(AccountErasureOutcome.NotDeactivated, account, 0, 0, 0, false);

        if (account.ErasedAt is not null)
            return new AccountErasureResult(AccountErasureOutcome.AlreadyErased, account, 0, 0, 0, false);

        var now = _time.GetUtcNow().UtcDateTime;

        // Everything in one transaction, so a crash mid way leaves either an
        // account that still reads as not erased, with every datum in place, or
        // one that reads as erased with nothing left. ExecuteUpdate cannot join
        // SaveChanges, and no retrying execution strategy is configured.
        //
        // The dashboard's audit filter opens that transaction before the action
        // runs, so the audit row lands in it too (issue #634); this joins an
        // open one and only opens its own when called with none, as the tests do.
        var ownsTransaction = _db.Database.CurrentTransaction is null;
        await using var tx = ownsTransaction
            ? await _db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false)
            : null;

        var ordersRedacted = await RedactOrderIdentifiersAsync(account.Id, cancellationToken).ConfigureAwait(false);

        var authorizationsRedacted = await _db.AcmeAuthorizations
            .Where(a => a.Order.AccountId == account.Id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(a => a.IdentifierValue, string.Empty)
                .SetProperty(a => a.AttestedSpki, (string?)null)
                .SetProperty(a => a.AttestationFormat, (string?)null)
                .SetProperty(a => a.AttestedPropertiesJson, (string?)null),
                cancellationToken)
            .ConfigureAwait(false);

        var challengesRedacted = await _db.AcmeChallenges
            .Where(c => c.Authorization.Order.AccountId == account.Id && c.AttestationObject != null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(c => c.AttestationObject, (string?)null),
                cancellationToken)
            .ConfigureAwait(false);

        var credentialLinkCleared = false;
        if (account.ExternalAccountCredentialId is int credentialId)
        {
            credentialLinkCleared = await _db.EabCredentials
                .Where(c => c.Id == credentialId
                    && (c.AdPrincipalSid != null || c.AdPrincipalName != null || c.AdPrincipalType != null))
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(c => c.AdPrincipalSid, (string?)null)
                    .SetProperty(c => c.AdPrincipalName, (string?)null)
                    .SetProperty(c => c.AdPrincipalType, (string?)null)
                    .SetProperty(c => c.UpdatedAt, now),
                    cancellationToken)
                .ConfigureAwait(false) > 0;
        }

        account.ContactJson = null;
        account.ErasedAt = now;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        if (tx is not null)
            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);

        _logger.LogWarning(
            "Erased the personal data of ACME account {AccountId} at the request of {Actor}: " +
            "contacts removed, {Orders} order(s), {Authorizations} authorization(s) and {Challenges} challenge(s) " +
            "redacted, credential principal link cleared: {CredentialLinkCleared}.",
            account.AccountId, actor, ordersRedacted, authorizationsRedacted, challengesRedacted,
            credentialLinkCleared);

        return new AccountErasureResult(
            AccountErasureOutcome.Erased, account,
            ordersRedacted, authorizationsRedacted, challengesRedacted, credentialLinkCleared);
    }

    /// <summary>
    /// Blanks every identifier value in the account's orders and drops the
    /// stored CSRs, a page at a time. The identifier list is JSON, so the
    /// rewrite happens in code: each entry keeps its type and loses its value.
    /// A list that does not parse is replaced by an empty one.
    /// </summary>
    private async Task<int> RedactOrderIdentifiersAsync(int accountId, CancellationToken ct)
    {
        var redacted = 0;
        var lastId = 0;
        while (true)
        {
            var page = await _db.AcmeOrders
                .Where(o => o.AccountId == accountId && o.Id > lastId)
                .OrderBy(o => o.Id)
                .Take(OrderPageSize)
                .ToListAsync(ct)
                .ConfigureAwait(false);
            if (page.Count == 0)
                break;

            foreach (var order in page)
            {
                order.IdentifiersJson = RedactIdentifiers(order.IdentifiersJson);
                order.CsrDer = null;
            }

            await _db.SaveChangesAsync(ct).ConfigureAwait(false);
            redacted += page.Count;
            lastId = page[^1].Id;

            if (page.Count < OrderPageSize)
                break;
        }

        return redacted;
    }

    internal static string RedactIdentifiers(string identifiersJson)
    {
        List<AcmeIdentifier>? identifiers;
        try
        {
            identifiers = JsonSerializer.Deserialize<List<AcmeIdentifier>>(identifiersJson);
        }
        catch (JsonException)
        {
            identifiers = null;
        }

        if (identifiers is null)
            return "[]";

        foreach (var identifier in identifiers)
            identifier.Value = string.Empty;

        return JsonSerializer.Serialize(identifiers);
    }
}
