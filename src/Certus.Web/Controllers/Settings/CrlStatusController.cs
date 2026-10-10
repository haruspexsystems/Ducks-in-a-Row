using Certus.Core.Data;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Certus.Web.Controllers.Settings;

/// <summary>
/// What the CRL monitor can see (issue #447), for the settings page.
///
/// It reads the state the monitor stored and never fetches anything itself.
/// That is deliberate: the distribution points are read on a timer, and an
/// endpoint that read them per page view would turn an administrator refreshing
/// a browser tab into load on the CA and on whatever serves its CRLs.
///
/// Admin only, like the rest of the settings surface. A CRL is public
/// information, but where an estate publishes it, and which copy of it is
/// stale, is a map of the PKI and belongs behind the same door as everything
/// else here.
/// </summary>
[ApiController]
[Route("api/settings/crl-status")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class CrlStatusController : ControllerBase
{
    private readonly CertusDbContext _db;

    public CrlStatusController(CertusDbContext db)
    {
        _db = db;
    }

    /// <summary>
    /// GET /api/settings/crl-status — every CRL being watched, grouped by the
    /// CA that signs it, with one entry per place it is published.
    /// </summary>
    [HttpGet("")]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        var rows = await _db.MonitoredCrls
            .AsNoTracking()
            .OrderBy(r => r.Scope)
            .ThenBy(r => r.IssuerName)
            .ThenBy(r => r.Kind)
            .ToListAsync(ct);

        var groups = rows
            .GroupBy(r => new { r.Scope, r.IssuerKeyId, r.Kind })
            .Select(group => new
            {
                scope = group.Key.Scope,
                kind = group.Key.Kind,
                issuerName = group.First().IssuerName,
                // The group agrees on this unless two copies disagree about
                // whether their issuer publishes on a timer, which cannot
                // happen: it is derived from the CRL's own dates and both
                // copies of one CRL carry the same ones.
                autoPublished = group.First().AutoPublished,
                sources = group
                    .OrderBy(r => r.Source, StringComparer.Ordinal)
                    .Select(r => new
                    {
                        source = r.Source,
                        crlNumber = r.CrlNumber,
                        thisUpdate = r.ThisUpdate,
                        nextUpdate = r.NextUpdate,
                        nextPublish = r.NextPublish,
                        signatureStatus = r.SignatureStatus,
                        publishFlags = r.PublishFlags,
                        lastReadAt = r.LastReadAt,
                        lastCheckedAt = r.LastCheckedAt,
                        lastError = r.LastError,
                    })
                    .ToList(),
            })
            .ToList();

        return Ok(new
        {
            crls = groups,
            lastCheckedAt = rows.Count == 0
                ? (DateTime?)null
                : rows.Max(r => r.LastCheckedAt),
        });
    }
}
