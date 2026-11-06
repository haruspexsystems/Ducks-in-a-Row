using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Web.Audit;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.AcmeAdmin;

/// <summary>
/// ACME account administration for the dashboard tab (issue #129): the
/// account inventory with search, filtering, sorting, and paging, plus the
/// first write path for account status. Deactivation here is the administrative
/// counterpart of the grandfathering rule: unbound accounts keep working
/// under Required enforcement until an administrator deactivates them.
/// </summary>
[ApiController]
[Route("api/acme/accounts")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class AcmeAccountsController : ControllerBase
{
    private readonly AccountService _accountService;
    private readonly AccountErasureService _erasureService;

    public AcmeAccountsController(AccountService accountService, AccountErasureService erasureService)
    {
        _accountService = accountService;
        _erasureService = erasureService;
    }

    /// <summary>
    /// GET /api/acme/accounts: search, filter, sort, and page the account
    /// inventory. Search matches the account id, the contact list, and the
    /// bound credential's name and key id.
    /// </summary>
    /// <remarks>
    /// binding, status, credentialId, and activity are independent axes and
    /// combine with AND, so status=valid&amp;binding=unbound is the set of
    /// accounts grandfathered under Required enforcement.
    ///
    /// The four date parameters are instants, not days: the caller resolves
    /// its own timezone and sends UTC, and <see cref="UtcWallClock.Normalize(DateTime?)"/>
    /// holds them to the UTC wall clock the rows are stored as. The After bounds
    /// are inclusive and the Before bounds are exclusive, so a caller filtering
    /// on a whole local day sends the start of that day and the start of the
    /// next one.
    ///
    /// An unrecognised filter name is a 400, because a filter that silently
    /// matched everything would leave the control showing one thing while the
    /// list showed another. An unrecognised sortBy is not: it falls through to
    /// the default order, matching the certificate inventory.
    /// </remarks>
    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] string? search,
        [FromQuery] string? binding,
        [FromQuery] string? status,
        [FromQuery] int? credentialId,
        [FromQuery] string? activity,
        [FromQuery] DateTime? registeredAfter,
        [FromQuery] DateTime? registeredBefore,
        [FromQuery] DateTime? lastOrderAfter,
        [FromQuery] DateTime? lastOrderBefore,
        [FromQuery] string? sortBy,
        [FromQuery] bool sortDesc = false,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50,
        CancellationToken ct = default)
    {
        if (AccountService.ParseBinding(binding) is not AcmeAccountBindingFilter bindingFilter)
            return BadRequest(new
            {
                error = "binding must be one of: all, bound, unbound, boundToRevoked.",
            });

        if (AccountService.ParseStatus(status) is not AcmeAccountStatusFilter statusFilter)
            return BadRequest(new
            {
                error = "status must be one of: all, valid, deactivated.",
            });

        if (AccountService.ParseActivity(activity) is not AcmeAccountActivityFilter activityFilter)
            return BadRequest(new
            {
                error = "activity must be one of: any, never, idle30, idle90, idle180, active7, active30.",
            });

        take = Math.Clamp(take, 1, 200);
        skip = Math.Max(0, skip);

        var page = await _accountService.QueryAsync(
            new AcmeAccountQuery(
                Search: search,
                Binding: bindingFilter,
                Status: statusFilter,
                CredentialId: credentialId,
                Activity: activityFilter,
                RegisteredAfter: UtcWallClock.Normalize(registeredAfter),
                RegisteredBefore: UtcWallClock.Normalize(registeredBefore),
                LastOrderAfter: UtcWallClock.Normalize(lastOrderAfter),
                LastOrderBefore: UtcWallClock.Normalize(lastOrderBefore),
                SortBy: sortBy,
                SortDesc: sortDesc,
                Skip: skip,
                Take: take),
            ct);
        return Ok(page);
    }

    /// <summary>
    /// POST /api/acme/accounts/{id}/deactivate: terminal (RFC 8555 §7.3.6).
    /// The account's open orders are invalidated in the same change, and
    /// every later ACME request it signs is rejected with 401 by the
    /// existing account status check. The client can also do this itself by
    /// posting {"status":"deactivated"} to its own account URL; both routes
    /// land on the same service method and differ only in the origin they
    /// record.
    /// </summary>
    [HttpPost("{id:int}/deactivate")]
    [AdminAudit("acme.account.deactivated", Transactional = true)]
    public async Task<IActionResult> Deactivate(int id, CancellationToken ct)
    {
        var result = await _accountService.DeactivateAsync(
            id, AccountDeactivationOrigin.Dashboard, ct);
        if (result.Outcome == AccountDeactivationOutcome.Deactivated)
        {
            this.AdminAudit().Describe(
                $"account {result.Account!.AccountId}",
                before: "valid",
                after: $"deactivated, {result.InvalidatedOrders} open order(s) invalidated");
        }

        return result.Outcome switch
        {
            AccountDeactivationOutcome.NotFound =>
                NotFound(new { error = "No account has this id." }),
            AccountDeactivationOutcome.NotValid =>
                Conflict(new { error = $"The account is already {result.Account!.Status}." }),
            _ => Ok(new
            {
                id = result.Account!.Id,
                accountId = result.Account.AccountId,
                status = result.Account.Status,
                invalidatedOrders = result.InvalidatedOrders,
            }),
        };
    }

    /// <summary>
    /// POST /api/acme/accounts/{id}/erase: removes the account's personal data
    /// (issue #637): its contact addresses, the principal link on its
    /// credential, and the identifiers its orders carried, keeping the order
    /// and certificate records the CA audit needs. The account must already be
    /// deactivated, so a live client's data is never pulled out from under it;
    /// a valid account answers 409. A second request for an erased account
    /// answers 200 with the first erasure's instant and changes nothing. The
    /// action is logged at Warning with the caller's identity, and the audit
    /// filter writes its row in the same transaction as the erasure (issue
    /// #634); the repeated request suppresses the row, so the trail never
    /// shows two erasures of one account.
    /// </summary>
    [HttpPost("{id:int}/erase")]
    [AdminAudit("acme.account.erased", Transactional = true)]
    public async Task<IActionResult> Erase(int id, CancellationToken ct)
    {
        var actor = AdminAuditDescription.ActorOf(User);
        var result = await _erasureService.EraseAsync(id, actor, ct);
        if (result.Outcome == AccountErasureOutcome.AlreadyErased)
            this.AdminAudit().Suppress();
        else if (result.Outcome == AccountErasureOutcome.Erased)
        {
            this.AdminAudit().Describe(
                $"account {result.Account!.AccountId}",
                after: $"personal data erased: {result.OrdersRedacted} order(s), " +
                       $"{result.AuthorizationsRedacted} authorization(s), " +
                       $"{result.ChallengesRedacted} challenge(s) redacted, " +
                       $"credential link {(result.CredentialLinkCleared ? "cleared" : "none")}");
        }

        return result.Outcome switch
        {
            AccountErasureOutcome.NotFound =>
                NotFound(new { error = "No account has this id." }),
            AccountErasureOutcome.NotDeactivated =>
                Conflict(new
                {
                    error = "Deactivate the account first. Erasure removes data its client is still using.",
                }),
            _ => Ok(new
            {
                id = result.Account!.Id,
                accountId = result.Account.AccountId,
                erasedAt = result.Account.ErasedAt,
                alreadyErased = result.Outcome == AccountErasureOutcome.AlreadyErased,
                ordersRedacted = result.OrdersRedacted,
                authorizationsRedacted = result.AuthorizationsRedacted,
                challengesRedacted = result.ChallengesRedacted,
                credentialLinkCleared = result.CredentialLinkCleared,
            }),
        };
    }
}
