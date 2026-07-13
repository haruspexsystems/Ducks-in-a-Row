using Certus.Core.Services;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.Dashboard;

/// <summary>
/// Dashboard API: aggregate metrics that back the dashboard widgets
/// (fleet health, validation-method mix, recent activity, daily issuance).
/// Certificate counts come from <c>/api/certificates/stats</c>; these
/// endpoints serve the remaining charts.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class DashboardController : ControllerBase
{
    private readonly DashboardMetricsService _metrics;

    public DashboardController(DashboardMetricsService metrics)
    {
        _metrics = metrics;
    }

    /// <summary>GET /api/dashboard/health — fleet health score and segments.</summary>
    [HttpGet("health")]
    public async Task<IActionResult> GetHealth(CancellationToken ct)
        => Ok(await _metrics.GetFleetHealthAsync(ct));

    /// <summary>GET /api/dashboard/validation — successful validations by challenge type.</summary>
    [HttpGet("validation")]
    public async Task<IActionResult> GetValidation(CancellationToken ct)
        => Ok(await _metrics.GetValidationMethodsAsync(ct));

    /// <summary>GET /api/dashboard/activity — recent activity feed (synthesized).</summary>
    [HttpGet("activity")]
    public async Task<IActionResult> GetActivity([FromQuery] int take = 20, CancellationToken ct = default)
    {
        take = Math.Clamp(take, 1, 100);
        return Ok(await _metrics.GetActivityAsync(take, ct));
    }

    /// <summary>GET /api/dashboard/registrations — daily issuance over the last N days.</summary>
    [HttpGet("registrations")]
    public async Task<IActionResult> GetRegistrations([FromQuery] int days = 30, CancellationToken ct = default)
    {
        days = Math.Clamp(days, 1, 90);
        return Ok(await _metrics.GetRegistrationsAsync(days, ct));
    }
}
