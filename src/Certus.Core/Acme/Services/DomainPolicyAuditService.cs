using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Records orders refused by the allowed domain policy so the dashboard can
/// show them: a refusal never creates an order or certificate row, so
/// without this the only trace would be the log file. The table is kept to
/// a fixed row cap by pruning the oldest rows on insert; refusal volume is
/// already bounded by the new order rate limiter, so the per insert count
/// query is cheap.
///
/// Best effort by design: a failed audit write is logged and swallowed. It
/// must never turn a policy refusal into a server error or change the ACME
/// response the client sees.
/// </summary>
public sealed class DomainPolicyAuditService
{
    /// <summary>Maximum rows kept; the oldest beyond this are pruned on insert.</summary>
    internal const int MaxRows = 1000;

    /// <summary>Matches the column max length configured in CertusDbContext.</summary>
    private const int MaxIdentifiersLength = 2000;

    private readonly CertusDbContext _db;
    private readonly ILogger<DomainPolicyAuditService> _logger;

    public DomainPolicyAuditService(
        CertusDbContext db,
        ILogger<DomainPolicyAuditService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Record one refusal. <paramref name="stage"/> names where the check
    /// ran and which policy refused: "newOrder" or "finalize" for the global
    /// allowed domain list, "newOrder-eab" or "finalize-eab" for an EAB
    /// credential's domain namespace, "newOrder-device", "challenge-device",
    /// or "finalize-device" for the device attestation gate, and
    /// "finalize-guard" for the TLS capability ceiling's leaf check. The
    /// dashboard activity feed keys its label off the "-device", "-eab",
    /// and "-guard" suffixes. The column caps a stage at 20 characters.
    /// </summary>
    public async Task RecordAsync(
        string accountId,
        string templateId,
        IEnumerable<AcmeIdentifier> requested,
        IReadOnlyList<string> rejected,
        string? clientIp,
        string stage,
        CancellationToken ct)
    {
        try
        {
            _db.DomainPolicyRejections.Add(new DomainPolicyRejection
            {
                OccurredAt = DateTime.UtcNow,
                AccountId = accountId,
                TemplateId = templateId,
                RequestedIdentifiers = JoinTruncated(requested.Select(i => i.Value)),
                RejectedIdentifiers = JoinTruncated(rejected),
                ClientIp = clientIp,
                Stage = stage,
            });
            await _db.SaveChangesAsync(ct);

            await PruneAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Could not record a domain policy rejection (account {AccountId}, stage {Stage}); " +
                "the refusal itself is unaffected",
                accountId, stage);
        }
    }

    private async Task PruneAsync(CancellationToken ct)
    {
        // The newest MaxRows survive; everything past them is overflow. Skip
        // yields the overflow ids directly, so no separate count query is
        // needed.
        var overflowIds = await _db.DomainPolicyRejections
            .OrderByDescending(r => r.OccurredAt)
            .Skip(MaxRows)
            .Select(r => r.Id)
            .ToListAsync(ct);

        if (overflowIds.Count == 0)
            return;

        await _db.DomainPolicyRejections
            .Where(r => overflowIds.Contains(r.Id))
            .ExecuteDeleteAsync(ct);
    }

    private static string JoinTruncated(IEnumerable<string> values)
    {
        var joined = string.Join(", ", values);
        return joined.Length <= MaxIdentifiersLength
            ? joined
            : joined[..MaxIdentifiersLength];
    }
}
