using System.Security.Claims;
using Certus.Core.Audit;

namespace Certus.Web.Audit;

/// <summary>
/// What one audited request has to say about itself (issue #634): the
/// target, and for a settings change the value before and after. Scoped per
/// request; a controller action fills it in and <see cref="AdminAuditFilter"/>
/// turns it into the row once the action has answered 2xx. The action name
/// and the actor come from the attribute and the request's identity, so the
/// action cannot misname itself.
///
/// <para>Three things an action can do here. <see cref="Describe"/> for the
/// ordinary case, the row written after the action. <see cref="Suppress"/> for
/// a 2xx that changed nothing, such as a repeated erasure answering
/// "already erased", so the trail never shows two erasures of one account.
/// <see cref="RecordBeforeFileWriteAsync"/> for a settings file write: the row
/// is committed before the file is touched, as the acceptance criteria ask, so
/// a crash between the two cannot lose the record; if the write is then
/// refused, the filter appends a second row saying so.</para>
/// </summary>
public sealed class AdminAuditDescription
{
    private readonly IAdminAuditTrail _trail;

    public AdminAuditDescription(IAdminAuditTrail trail)
    {
        _trail = trail ?? throw new ArgumentNullException(nameof(trail));
    }

    /// <summary>The stable action name, set by the filter from the attribute before the action runs.</summary>
    public string? Action { get; private set; }

    /// <summary>The Windows identity of the caller, set by the filter.</summary>
    public string Actor { get; private set; } = AdminAuditTrail.AnonymousActor;

    /// <summary>What was acted on.</summary>
    public string? Target { get; private set; }

    /// <summary>The value before a settings change.</summary>
    public string? Before { get; private set; }

    /// <summary>The value after, or what the action did.</summary>
    public string? After { get; private set; }

    /// <summary>True once the action said its 2xx changed nothing.</summary>
    public bool Suppressed { get; private set; }

    /// <summary>True once <see cref="RecordBeforeFileWriteAsync"/> wrote the row for this request.</summary>
    public bool RecordedBeforeWrite { get; private set; }

    /// <summary>Called by the filter, once, before the action runs.</summary>
    internal void Begin(string action, ClaimsPrincipal user)
    {
        Action = action;
        Actor = ActorOf(user);
    }

    /// <summary>Sets what the row will say. Later calls replace earlier ones.</summary>
    public void Describe(string? target, string? before = null, string? after = null)
    {
        Target = target;
        Before = before;
        After = after;
    }

    /// <summary>The 2xx about to be returned changed nothing, so no row is due.</summary>
    public void Suppress() => Suppressed = true;

    /// <summary>
    /// Writes the row now, before the caller touches a settings file. Meant
    /// for an audited, non transactional action. With no action name (the
    /// filter did not run, which happens only for a controller built by hand
    /// in a unit test) it keeps the words and records nothing; the coverage
    /// test is what guarantees every file writing action carries the
    /// attribute in the real host.
    /// </summary>
    public async Task RecordBeforeFileWriteAsync(
        string? target, string? before, string? after, CancellationToken cancellationToken = default)
    {
        Describe(target, before, after);
        if (Action is null)
            return;

        await _trail.RecordAsync(new AdminAuditEvent(Actor, Action, Target, Before, After), cancellationToken);
        RecordedBeforeWrite = true;
    }

    /// <summary>
    /// The identity to attribute an action to. Negotiate always yields a name
    /// for an authorized admin; the fallback covers the Development only
    /// Auth:Mode=Disabled escape hatch, where there is no identity at all.
    /// </summary>
    public static string ActorOf(ClaimsPrincipal? user) =>
        string.IsNullOrWhiteSpace(user?.Identity?.Name) ? AdminAuditTrail.AnonymousActor : user.Identity.Name;
}
