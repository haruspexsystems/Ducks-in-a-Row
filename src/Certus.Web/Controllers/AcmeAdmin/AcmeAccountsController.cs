using Certus.Core.Acme.Services;
using Certus.Core.Data;
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

    public AcmeAccountsController(AccountService accountService)
    {
        _accountService = accountService;
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
    /// every later ACME request it signs is rejected with 403 by the
    /// existing account status check.
    /// </summary>
    [HttpPost("{id:int}/deactivate")]
    public async Task<IActionResult> Deactivate(int id, CancellationToken ct)
    {
        var result = await _accountService.DeactivateAsync(id, ct);
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
}
