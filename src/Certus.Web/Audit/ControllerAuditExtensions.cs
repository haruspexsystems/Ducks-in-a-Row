using Certus.Core.Audit;
using Certus.Core.Data.Entities;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Audit;

/// <summary>
/// How a controller action reaches its request's <see cref="AdminAuditDescription"/>
/// (issue #634) without every controller taking one more constructor
/// parameter: through the request's services, where <c>AddAdminAudit</c>
/// registered it scoped. A controller built by hand in a unit test, with a
/// bare <c>DefaultHttpContext</c> and no services, gets a detached description
/// that accepts the words and records nothing; the trail is proven through
/// the real host in the integration tests.
/// </summary>
public static class ControllerAuditExtensions
{
    public static AdminAuditDescription AdminAudit(this ControllerBase controller)
    {
        ArgumentNullException.ThrowIfNull(controller);
        return controller.HttpContext?.RequestServices?.GetService<AdminAuditDescription>()
            ?? new AdminAuditDescription(DetachedTrail.Instance);
    }

    /// <summary>A trail that keeps nothing, for a controller running outside the host.</summary>
    private sealed class DetachedTrail : IAdminAuditTrail
    {
        public static readonly DetachedTrail Instance = new();

        public int Recorded => 0;

        public Task<AdminAuditEntry> RecordAsync(AdminAuditEvent auditEvent, CancellationToken cancellationToken = default) =>
            Task.FromResult(new AdminAuditEntry { Action = auditEvent.Action, Actor = auditEvent.Actor });
    }
}
