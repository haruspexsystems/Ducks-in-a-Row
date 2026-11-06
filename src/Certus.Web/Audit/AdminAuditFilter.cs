using Certus.Core.Audit;
using Certus.Core.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;

namespace Certus.Web.Audit;

/// <summary>
/// Turns an <see cref="AdminAuditAttribute"/> into an audit row (issue #634,
/// CRA risk R07). Registered globally; it does nothing for an action without
/// the attribute, so the read side and the ACME protocol pay nothing.
///
/// <para>The rule it applies: a row is written when the action answered 2xx
/// and did not say the answer changed nothing. A refusal (400, 404, 409, 503)
/// writes no row, because nothing happened; the controller's own log line
/// says why. An exception writes no row and is not swallowed.</para>
///
/// <para>For a transactional action the filter opens the transaction on the
/// request's scoped <c>CertusDbContext</c> before the action, so every write
/// the action's services make through that context, and the audit row, commit
/// together. A non 2xx answer rolls the transaction back, which is harmless
/// (the services write nothing before they refuse) and keeps a half applied
/// change from ever committing without its record.</para>
///
/// <para>An action that recorded its row before a file write
/// (<see cref="AdminAuditDescription.RecordBeforeFileWriteAsync"/>) gets no
/// second row on success. If that write was then refused, a row is appended
/// saying the change was not applied, so the trail never claims a change the
/// file does not hold.</para>
/// </summary>
public sealed class AdminAuditFilter : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var audit = context.ActionDescriptor.EndpointMetadata.OfType<AdminAuditAttribute>().FirstOrDefault();
        if (audit is null)
        {
            await next();
            return;
        }

        var services = context.HttpContext.RequestServices;
        var description = services.GetRequiredService<AdminAuditDescription>();
        var trail = services.GetRequiredService<IAdminAuditTrail>();
        description.Begin(audit.Action, context.HttpContext.User);

        if (!audit.Transactional)
        {
            var executed = await next();
            await RecordAsync(executed, audit, description, trail);
            return;
        }

        // The request's token opens the transaction and runs the action, and
        // is not used past that: once the action has made its change, the row
        // and the commit must land whether or not the client is still
        // listening. A commit cancelled by a closed tab would roll back a
        // change the Warning line had already announced.
        var db = services.GetRequiredService<CertusDbContext>();
        await using var tx = await db.Database.BeginTransactionAsync(context.HttpContext.RequestAborted);
        var executedInTx = await next();
        if (!Succeeded(executedInTx))
            return; // disposing the transaction rolls it back

        await RecordAsync(executedInTx, audit, description, trail);
        await tx.CommitAsync(CancellationToken.None);
    }

    private static async Task RecordAsync(
        ActionExecutedContext executed,
        AdminAuditAttribute audit,
        AdminAuditDescription description,
        IAdminAuditTrail trail)
    {
        // The row is written whether or not the client is still listening:
        // the change is made, and a record of it is the point of this class.
        var recordToken = CancellationToken.None;

        if (!Succeeded(executed))
        {
            if (description.RecordedBeforeWrite)
            {
                await trail.RecordAsync(new AdminAuditEvent(
                    description.Actor, audit.Action, description.Target,
                    Before: null,
                    After: $"not applied: the request was refused with status {StatusOf(executed)}"),
                    recordToken);
            }
            return;
        }

        if (description.Suppressed || description.RecordedBeforeWrite)
            return;

        await trail.RecordAsync(new AdminAuditEvent(
            description.Actor, audit.Action, description.Target, description.Before, description.After),
            recordToken);
    }

    private static bool Succeeded(ActionExecutedContext executed)
    {
        if (executed.Exception is not null && !executed.ExceptionHandled)
            return false;
        var status = StatusOf(executed);
        return status is >= 200 and < 300;
    }

    /// <summary>
    /// The status the result will carry once executed. An ObjectResult with no
    /// explicit code is a 200; a result that is not a status code result (a
    /// file or a redirect) does not occur on the admin API, and reads as 200.
    /// </summary>
    private static int StatusOf(ActionExecutedContext executed) =>
        executed.Exception is not null && !executed.ExceptionHandled
            ? StatusCodes.Status500InternalServerError
            : (executed.Result as IStatusCodeActionResult)?.StatusCode ?? StatusCodes.Status200OK;
}
