using Certus.Core.Audit;
using Certus.Core.Data;
using Certus.Core.Services;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Certus.Web.Controllers.Dashboard;

/// <summary>
/// Dashboard API: the administrator audit trail (issue #634). Read only, by
/// design: the trail has no write surface but the filter and no delete but
/// the retention job, so nothing an administrator can reach from the
/// dashboard can edit or silence it.
///
/// <para>Two tables. The entries are the actions: who did what, when, to
/// which target, with the value before and after where there is one. The
/// sign in failures are the hourly counts of refused requests per source
/// address that <see cref="Certus.Web.Audit.AdminSignInFailureMiddleware"/>
/// keeps, answered here as one row per source so the page can show who is
/// knocking.</para>
/// </summary>
[ApiController]
[Route("api/audit")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class AuditTrailController : ControllerBase
{
    /// <summary>The widest window the sign in failures answer, in days.</summary>
    public const int MaxSignInFailureDays = 365;

    private readonly CertusDbContext _db;
    private readonly TimeProvider _time;

    public AuditTrailController(CertusDbContext db, TimeProvider? time = null)
    {
        _db = db;
        // Both hosts register TimeProvider.System; the fallback is for a bare test host.
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// GET /api/audit/entries?actor=&amp;skip=&amp;take=: the trail, newest
    /// first, optionally one actor's rows. Paged like the certificate and
    /// account lists so the dashboard reuses its pager.
    /// </summary>
    [HttpGet("entries")]
    public async Task<IActionResult> GetEntries(
        [FromQuery] string? actor,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50,
        CancellationToken ct = default)
    {
        take = Math.Clamp(take, 1, 200);
        skip = Math.Max(0, skip);

        var query = _db.AdminAuditEntries.AsNoTracking();
        var wanted = actor?.Trim();
        if (!string.IsNullOrEmpty(wanted))
            query = query.Where(e => e.Actor == wanted);

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(e => e.OccurredAt)
            .ThenByDescending(e => e.Id)
            .Skip(skip)
            .Take(take)
            .Select(e => new AdminAuditEntryView(
                e.Id, e.OccurredAt, e.Actor, e.Action, e.Target, e.BeforeValue, e.AfterValue))
            .ToListAsync(ct);

        return Ok(new PagedResult<AdminAuditEntryView>(items, total, skip, take));
    }

    /// <summary>GET /api/audit/actors: every identity that has a row, for the filter.</summary>
    [HttpGet("actors")]
    public async Task<IActionResult> GetActors(CancellationToken ct)
    {
        var actors = await _db.AdminAuditEntries.AsNoTracking()
            .Select(e => e.Actor)
            .Distinct()
            .OrderBy(a => a)
            .ToListAsync(ct);
        return Ok(new { actors });
    }

    /// <summary>
    /// GET /api/audit/sign-in-failures?days=30: refused requests per source
    /// address over the window, most recent source first. A 401 is a caller
    /// whose credentials the server refused; a 403 is an authenticated caller
    /// who is not an administrator.
    /// </summary>
    [HttpGet("sign-in-failures")]
    public async Task<IActionResult> GetSignInFailures(
        [FromQuery] int days = 30, CancellationToken ct = default)
    {
        days = Math.Clamp(days, 1, MaxSignInFailureDays);
        var since = _time.GetUtcNow().UtcDateTime.AddDays(-days);

        // An anonymous projection, mapped to the record afterwards: EF Core
        // translates the aggregates into one GROUP BY, but not a record
        // constructor over them.
        var grouped = await _db.AdminSignInFailures.AsNoTracking()
            .Where(f => f.BucketStart >= since)
            .GroupBy(f => f.SourceAddress)
            .Select(g => new
            {
                Source = g.Key,
                Count = g.Sum(f => f.Count),
                Unauthorized = g.Sum(f => f.StatusCode == StatusCodes.Status401Unauthorized ? f.Count : 0),
                Forbidden = g.Sum(f => f.StatusCode == StatusCodes.Status403Forbidden ? f.Count : 0),
                FirstAt = g.Min(f => f.FirstAt),
                LastAt = g.Max(f => f.LastAt),
            })
            .OrderByDescending(s => s.LastAt)
            .ToListAsync(ct);
        var sources = grouped
            .Select(s => new AdminSignInFailureView(s.Source, s.Count, s.Unauthorized, s.Forbidden, s.FirstAt, s.LastAt))
            .ToList();

        return Ok(new
        {
            days,
            since,
            total = sources.Sum(s => s.Count),
            sources,
        });
    }
}

/// <summary>One row of the trail as the dashboard shows it.</summary>
public sealed record AdminAuditEntryView(
    int Id,
    DateTime OccurredAt,
    string Actor,
    string Action,
    string? Target,
    string? Before,
    string? After);

/// <summary>Refused requests from one source address over the window.</summary>
public sealed record AdminSignInFailureView(
    string SourceAddress,
    int Count,
    int Unauthorized,
    int Forbidden,
    DateTime FirstAt,
    DateTime LastAt);
