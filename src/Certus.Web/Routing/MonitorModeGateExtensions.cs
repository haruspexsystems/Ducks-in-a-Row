using Certus.Core.Acme.Models;
using Certus.Core.Configuration;
using Certus.Web.Controllers.Dashboard;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Routing;

/// <summary>
/// Monitor mode's two request gates (issue #470), shared by both hosts for the reason
/// <see cref="ProtocolFallbackExtensions"/> is: the two Program.cs pipelines are near
/// duplicates, and wiring that lives in one host only is wiring nobody checks. In full
/// mode neither adds anything to the pipeline, so full mode is unchanged.
///
/// They gate on the path rather than on the controllers, so the protocol fallback and any
/// route added later under the same prefix are closed too, with nothing to remember.
/// </summary>
public static class MonitorModeGateExtensions
{
    /// <summary>
    /// Every ACME protocol URL (<c>/acme/{template}/...</c>) answers 404 in monitor mode.
    /// Bare <c>/acme</c> is the dashboard's own ACME tab and is not a protocol path, so it
    /// still reaches the SPA shell, which hides the tab in this mode.
    ///
    /// Insert it immediately after the request logger and before <c>UseRouting</c>.
    /// Earlier than that would skip the request log. It short circuits, so nothing
    /// later in the pipeline runs for a refused request: <c>AcmeNonceMiddleware</c>,
    /// which sits after the rate limiter since issue #632, never sees it and stores
    /// no nonce for it.
    /// </summary>
    public static WebApplication UseMonitorModeAcmeGate(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (!app.Services.GetRequiredService<CertusInstanceMode>().IsMonitor)
            return app;

        app.Use((context, next) =>
        {
            if (!ProtocolPaths.IsAcmeProtocolPath(context.Request.Path))
                return next(context);

            // Saying why is worth more to an operator debugging a client than it is to
            // anyone else: a server that cannot issue has nothing to hide about it.
            return AcmeProblemResults.WriteProblemAsync(
                context,
                StatusCodes.Status404NotFound,
                AcmeErrorType.Malformed,
                "This server runs in monitor mode: it watches its certification authority " +
                "and never issues or revokes, so it offers no ACME service.",
                context.RequestAborted);
        });

        return app;
    }

    /// <summary>
    /// The ACME administration API (<c>/api/acme</c> and below: accounts, external account
    /// binding, device attestation) answers 404 in monitor mode, with the monitor mode
    /// problem type.
    ///
    /// Insert it immediately after <c>UseCertusAuth</c>. Authorization has then already
    /// answered an anonymous caller 401 and a non admin 403, exactly as for every other
    /// /api path, so the gate tells nobody outside the admin group which routes exist.
    /// </summary>
    public static WebApplication UseMonitorModeAdminApiGate(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (!app.Services.GetRequiredService<CertusInstanceMode>().IsMonitor)
            return app;

        app.Use((context, next) =>
        {
            if (!context.Request.Path.StartsWithSegments("/" + ProtocolPaths.ApiSegment + "/" + ProtocolPaths.AcmeSegment))
                return next(context);

            var problem = MonitorModeProblem.Create(
                StatusCodes.Status404NotFound,
                "The ACME administration API is not available in monitor mode, because this " +
                "server never issues certificates.");
            context.Response.StatusCode = problem.Status!.Value;
            return context.Response.WriteAsJsonAsync(
                problem, options: null, contentType: "application/problem+json", context.RequestAborted);
        });

        return app;
    }
}
