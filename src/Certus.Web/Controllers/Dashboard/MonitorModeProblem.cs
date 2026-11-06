using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.Dashboard;

/// <summary>
/// The one problem document every monitor mode refusal on the dashboard API carries
/// (issue #470), so the endpoints that refuse and the request gate cannot word it two
/// ways. The type resolves to https://ducksinarow.dev/problems/monitor-mode, the same
/// page the dashboard's monitor mode badge links to.
///
/// The endpoints refuse with 403, matching the other policy refusals on the revoke
/// endpoint (the TLS guardrail, the revocation scope): the server understood the
/// request and this instance will not carry it out, which no retry changes. The
/// administration API gate answers 404 instead, because there the resource itself does
/// not exist in this mode.
/// </summary>
public static class MonitorModeProblem
{
    /// <summary>The problem title.</summary>
    public const string Title = "Not available in monitor mode";

    /// <summary>A problem document for a caller outside a controller action.</summary>
    public static ProblemDetails Create(int statusCode, string detail) => new()
    {
        Type = DashboardProblemType.MonitorMode,
        Title = Title,
        Status = statusCode,
        Detail = detail,
    };

    /// <summary>The 403 refusal an endpoint that would write to the CA answers with.</summary>
    public static ObjectResult Refuse(ControllerBase controller, string detail)
    {
        ArgumentNullException.ThrowIfNull(controller);
        return controller.Problem(
            type: DashboardProblemType.MonitorMode,
            title: Title,
            detail: detail,
            statusCode: StatusCodes.Status403Forbidden);
    }
}
