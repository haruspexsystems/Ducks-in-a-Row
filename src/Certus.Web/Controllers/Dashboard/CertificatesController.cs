using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Services;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Certus.Web.Controllers.Dashboard;

/// <summary>
/// Dashboard API: certificate inventory, search, and statistics.
/// These endpoints serve the React dashboard frontend.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class CertificatesController : ControllerBase
{
    private readonly CertificateQueryService _queryService;
    private readonly TemplateService _templateService;
    private readonly CertificateSyncService _syncService;
    private readonly ILogger<CertificatesController> _logger;

    public CertificatesController(
        CertificateQueryService queryService,
        TemplateService templateService,
        CertificateSyncService syncService,
        ILogger<CertificatesController> logger)
    {
        _queryService = queryService;
        _templateService = templateService;
        _syncService = syncService;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/certificates — search and paginate the certificate inventory.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ListCertificates(
        [FromQuery] string? search,
        [FromQuery] string? template,
        [FromQuery] string? status,
        [FromQuery] DateTime? expiringBefore,
        [FromQuery] DateTime? expiringAfter,
        [FromQuery] string? sortBy,
        [FromQuery] bool sortDesc = false,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50,
        CancellationToken ct = default)
    {
        // Clamp take to reasonable limits
        take = Math.Clamp(take, 1, 200);
        skip = Math.Max(0, skip);

        var query = new CertificateSearchQuery(
            Search: search,
            TemplateName: template,
            Status: status,
            ExpiringBefore: expiringBefore,
            ExpiringAfter: expiringAfter,
            SortBy: sortBy,
            SortDesc: sortDesc,
            Skip: skip,
            Take: take);

        var result = await _queryService.QueryAsync(query, ct);
        return Ok(result);
    }

    /// <summary>
    /// GET /api/certificates/{id} — get a single certificate by ID.
    /// </summary>
    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetCertificate(int id, CancellationToken ct)
    {
        var cert = await _queryService.GetDetailByIdAsync(id, ct);
        if (cert == null)
            return NotFound();

        return Ok(cert);
    }

    /// <summary>
    /// GET /api/certificates/stats — dashboard summary statistics.
    /// </summary>
    [HttpGet("stats")]
    public async Task<IActionResult> GetStats(CancellationToken ct)
    {
        var stats = await _queryService.GetStatsAsync(ct);
        return Ok(stats);
    }

    /// <summary>
    /// POST /api/certificates/sync — pull the inventory from the CA now.
    /// Runs a full sync and returns its counts, so the dashboard Refresh
    /// button reflects the CA immediately instead of waiting for the next
    /// interval tick. Concurrent requests serialize on the sync gate inside
    /// CertificateSyncService.
    /// </summary>
    [HttpPost("sync")]
    public async Task<IActionResult> TriggerSync(CancellationToken ct)
    {
        try
        {
            var result = await _syncService.SyncCertificatesAsync(ct);
            return Ok(result);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "Manual sync: CA is unavailable");
            return Problem(
                type: "https://ducksinarow.app/problems/ca-unavailable",
                title: "Certificate Authority is unavailable",
                detail: "The ADCS Certificate Authority cannot be reached. Try again shortly.",
                statusCode: 503);
        }
        catch (CaAccessDeniedException ex)
        {
            _logger.LogWarning(ex, "Manual sync: CA view access denied");
            return Problem(
                type: "https://ducksinarow.app/problems/ca-access-denied",
                title: "CA view access denied",
                detail: ex.Message,
                statusCode: 503);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Manual sync failed");
            return Problem(
                type: "https://ducksinarow.app/problems/ca-error",
                title: "Certificate Authority error",
                detail: "An unexpected error occurred while syncing from the certificate authority.",
                statusCode: 503);
        }
    }

    /// <summary>
    /// GET /api/templates — list available ADCS certificate templates.
    /// </summary>
    [HttpGet("/api/templates")]
    public async Task<IActionResult> ListTemplates(CancellationToken ct)
    {
        try
        {
            var templates = await _templateService.GetTemplatesAsync(ct);
            return Ok(templates);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "Templates endpoint: CA is unavailable");
            return Problem(
                type: "https://ducksinarow.app/problems/ca-unavailable",
                title: "Certificate Authority is unavailable",
                detail: "The ADCS Certificate Authority cannot be reached. Try again shortly.",
                statusCode: 503);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve templates from CA");
            return Problem(
                type: "https://ducksinarow.app/problems/ca-error",
                title: "Certificate Authority error",
                detail: "An unexpected error occurred while contacting the certificate authority.",
                statusCode: 503);
        }
    }
}
