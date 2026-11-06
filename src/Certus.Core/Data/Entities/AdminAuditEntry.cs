namespace Certus.Core.Data.Entities;

/// <summary>
/// One administrator action taken through the dashboard API (issue #634, CRA
/// risk R07): who did what to which target, and for a setting the value before
/// and after. Written by <c>AdminAuditTrail</c> in the same transaction as the
/// change when the change is a database write, and immediately before the file
/// write when it is a settings file, so a crash in between cannot lose the
/// record. No configuration key turns the writes off, and the matching log
/// line is written at Warning so a raised minimum level does not drop it.
///
/// <para>Never holds a secret. A regenerated binding secret is recorded as
/// "secret regenerated", a saved SMTP password as "set" or "cleared". The
/// controllers decide the wording; this row stores what they hand over,
/// bounded to the declared widths in code because SQLite enforces none of
/// them.</para>
///
/// <para>Deliberately no foreign key to anything: the row must outlive the
/// credential, account or profile it names.</para>
/// </summary>
public class AdminAuditEntry
{
    /// <summary>Internal database ID. Ascending with time, so it breaks ties in the newest first order.</summary>
    public int Id { get; set; }

    /// <summary>When the action happened (UTC).</summary>
    public DateTime OccurredAt { get; set; }

    /// <summary>
    /// The administrator's Windows identity (DOMAIN\name), or "(anonymous)" on
    /// a development host running with authentication disabled.
    /// </summary>
    public string Actor { get; set; } = string.Empty;

    /// <summary>
    /// A stable, dotted action name such as <c>settings.allowed-domains.changed</c>.
    /// Stable so a filter or an export written against one release still
    /// matches the next; the dashboard turns it into words.
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>What was acted on: a credential key id, an account id, a template, a setting name. Null when the action has no single target.</summary>
    public string? Target { get; set; }

    /// <summary>The value before a settings change, in words. Null when the action is not a settings change or the old value is unknown.</summary>
    public string? BeforeValue { get; set; }

    /// <summary>The value after the change, or what the action did, in words. Never a secret.</summary>
    public string? AfterValue { get; set; }
}
