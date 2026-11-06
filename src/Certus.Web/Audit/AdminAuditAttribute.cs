using Microsoft.AspNetCore.Mvc.Filters;

namespace Certus.Web.Audit;

/// <summary>
/// Marks a mutating dashboard API action as an administrator action the audit
/// trail records (issue #634, CRA risk R07). <see cref="AdminAuditFilter"/>
/// reads it: when the action answers 2xx a row is appended under the stable
/// name given here, with whatever the action put in
/// <see cref="AdminAuditDescription"/>, and a line is logged at Warning.
///
/// <para><see cref="Transactional"/> is for actions whose change is a database
/// write through the request's scoped <c>CertusDbContext</c>: the filter then
/// opens a transaction before the action and commits it after the row, so the
/// change and its record land together or not at all. Leave it false for an
/// action that writes a settings file, calls the CA or restarts the service;
/// a file write records its row first with
/// <see cref="AdminAuditDescription.RecordBeforeFileWriteAsync"/>.</para>
///
/// <para>Every mutating action on an admin controller carries this or
/// <see cref="AdminAuditExemptAttribute"/>; <c>AdminAuditCoverageTests</c>
/// walks the route table and fails on one that has neither.</para>
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class AdminAuditAttribute : Attribute, IFilterMetadata
{
    public AdminAuditAttribute(string action)
    {
        if (string.IsNullOrWhiteSpace(action))
            throw new ArgumentException("An audited action needs a stable name.", nameof(action));
        Action = action;
    }

    /// <summary>The stable dotted action name, for example <c>settings.allowed-domains.changed</c>.</summary>
    public string Action { get; }

    /// <summary>Whether the filter wraps the action and its audit row in one database transaction.</summary>
    public bool Transactional { get; init; }
}

/// <summary>
/// Marks a mutating dashboard API action that changes nothing an audit trail
/// should record: a connectivity probe, a template listing, a licence
/// preview. The reason is required so the exemption is a decision someone
/// wrote down, and <c>AdminAuditCoverageTests</c> fails on an empty one.
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class AdminAuditExemptAttribute : Attribute, IFilterMetadata
{
    public AdminAuditExemptAttribute(string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("An exemption needs its reason.", nameof(reason));
        Reason = reason;
    }

    /// <summary>Why this mutating action writes no audit row.</summary>
    public string Reason { get; }
}
