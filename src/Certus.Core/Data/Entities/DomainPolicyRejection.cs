namespace Certus.Core.Data.Entities;

/// <summary>
/// One order refused by the allowed domain policy: who asked, for which
/// names, and at which stage. A refusal never creates an order or a
/// certificate row, so without this table the only trace would be the log
/// file. Written by DomainPolicyAuditService and pruned to a fixed cap so a
/// chatty client cannot grow the table without bound. Deliberately no
/// foreign key to the ACME account: the audit row must outlive account
/// cleanup.
/// </summary>
public class DomainPolicyRejection
{
    /// <summary>Internal database ID.</summary>
    public int Id { get; set; }

    /// <summary>When the order was refused (UTC).</summary>
    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;

    /// <summary>The public ACME account id string of the requester.</summary>
    public string AccountId { get; set; } = string.Empty;

    /// <summary>The certificate template the order named.</summary>
    public string TemplateId { get; set; } = string.Empty;

    /// <summary>All identifiers the order asked for, comma separated.</summary>
    public string RequestedIdentifiers { get; set; } = string.Empty;

    /// <summary>The subset the policy refused, comma separated.</summary>
    public string RejectedIdentifiers { get; set; } = string.Empty;

    /// <summary>The client address the request came from, when known.</summary>
    public string? ClientIp { get; set; }

    /// <summary>Where the refusal happened: "newOrder" or "finalize".</summary>
    public string Stage { get; set; } = string.Empty;
}
