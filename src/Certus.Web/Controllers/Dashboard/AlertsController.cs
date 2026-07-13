using Certus.Core.Alerts;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Certus.Web.Controllers.Dashboard;

/// <summary>
/// Dashboard API: alert configuration and history.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class AlertsController : ControllerBase
{
    private readonly AlertQueryService _alertQueryService;
    private readonly IOptionsMonitor<AlertOptions> _alertOptions;

    public AlertsController(
        AlertQueryService alertQueryService,
        IOptionsMonitor<AlertOptions> alertOptions)
    {
        _alertQueryService = alertQueryService;
        _alertOptions = alertOptions;
    }

    /// <summary>
    /// GET /api/alerts/history — paginated alert notification history.
    /// </summary>
    [HttpGet("history")]
    public async Task<IActionResult> GetHistory(
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50,
        CancellationToken ct = default)
    {
        take = Math.Clamp(take, 1, 200);
        skip = Math.Max(0, skip);

        var result = await _alertQueryService.GetHistoryAsync(skip, take, ct);
        return Ok(result);
    }

    /// <summary>
    /// GET /api/alerts/summary — alert statistics summary.
    /// </summary>
    [HttpGet("summary")]
    public async Task<IActionResult> GetSummary(CancellationToken ct)
    {
        var summary = await _alertQueryService.GetSummaryAsync(ct);
        return Ok(summary);
    }

    /// <summary>
    /// GET /api/alerts/config — current alert configuration (sanitized, no passwords).
    /// </summary>
    [HttpGet("config")]
    public IActionResult GetConfig()
    {
        var options = _alertOptions.CurrentValue;
        return Ok(new
        {
            enabled = options.Enabled,
            checkIntervalMinutes = options.CheckIntervalMinutes,
            thresholdDays = options.ThresholdDays,
            smtp = options.Smtp == null ? null : new
            {
                host = options.Smtp.Host,
                port = options.Smtp.Port,
                useSsl = options.Smtp.UseSsl,
                fromAddress = options.Smtp.FromAddress,
                fromName = options.Smtp.FromName,
                recipients = options.Smtp.Recipients,
                hasCredentials = !string.IsNullOrEmpty(options.Smtp.Username),
            },
            webhook = options.Webhook == null ? null : new
            {
                url = options.Webhook.Url,
                hasSecret = !string.IsNullOrEmpty(options.Webhook.Secret),
                headers = options.Webhook.Headers.Keys.ToArray(),
            },
        });
    }
}
