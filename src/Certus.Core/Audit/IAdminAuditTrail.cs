using Certus.Core.Data.Entities;

namespace Certus.Core.Audit;

/// <summary>
/// One administrator action to record (issue #634). <paramref name="Actor"/> is
/// the Windows identity the request authenticated as; <paramref name="Action"/>
/// a stable dotted name; the rest optional words, never a secret.
/// </summary>
public sealed record AdminAuditEvent(
    string Actor,
    string Action,
    string? Target = null,
    string? Before = null,
    string? After = null);

/// <summary>
/// Writes the administrator audit trail (issue #634, CRA risk R07). Scoped, on
/// the request's <c>CertusDbContext</c>: a row recorded while a transaction is
/// open on that context lands inside it, which is how a change and its record
/// commit or roll back together. Every record also writes one log line at
/// Warning, so neither a raised minimum level nor any configuration key can
/// silence the trail.
/// </summary>
public interface IAdminAuditTrail
{
    /// <summary>How many rows this scope has recorded. The web filter reads it to know whether an action already wrote its own row.</summary>
    int Recorded { get; }

    /// <summary>Appends one row and writes the Warning log line. Saves at once; an open transaction on the context decides when it commits.</summary>
    Task<AdminAuditEntry> RecordAsync(AdminAuditEvent auditEvent, CancellationToken cancellationToken = default);
}
