using Certus.Core.Configuration;
using Certus.Core.ServiceRights;
using Certus.Core.Setup;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Certus.Web.Controllers.Settings;

/// <summary>
/// The service rights check for the configured CA and the templates enabled for
/// ACME, for the Settings page (issue #440). The wizard proves rights before
/// first use, but it never reopens once setup is done, and rights change: a CA
/// administrator tidies a security tab, a template is re-permissioned. This is
/// where an administrator looks again.
///
/// Both routes take the CA and the templates from the configuration, never from
/// the request, so nothing here can be pointed at a CA the service is not
/// configured for. The GET serves the kept report while it is fresh, because
/// every check reads from the CA and the directory; the POST always runs one.
/// </summary>
[ApiController]
[Route("api/settings/service-rights")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class ServiceRightsController : ControllerBase
{
    /// <summary>
    /// What the mock CA is checked as on the dev host, where no connection string
    /// is configured. The mock client factory ignores the value.
    /// </summary>
    private const string MockCaConnectionString = @"ca-server.corp.example.com\Example Issuing CA";

    private readonly ServiceRightsCheck _check;
    private readonly ServiceRightsReportCache _cache;
    private readonly SetupService _setupService;
    private readonly CertusOptions _options;

    public ServiceRightsController(
        ServiceRightsCheck check,
        ServiceRightsReportCache cache,
        SetupService setupService,
        IOptions<CertusOptions> options)
    {
        _check = check;
        _cache = cache;
        _setupService = setupService;
        _options = options.Value;
    }

    /// <summary>GET /api/settings/service-rights: the kept report, or a fresh one when it has aged.</summary>
    [HttpGet("")]
    public Task<IActionResult> Get(CancellationToken ct) => RunAsync(force: false, ct);

    /// <summary>POST /api/settings/service-rights/check: always a fresh check.</summary>
    [HttpPost("check")]
    public Task<IActionResult> Check(CancellationToken ct) => RunAsync(force: true, ct);

    private async Task<IActionResult> RunAsync(bool force, CancellationToken ct)
    {
        var ca = _options.UseMockCa
            ? MockCaConnectionString
            : _options.CaConnectionString;
        if (string.IsNullOrWhiteSpace(ca))
            return Conflict(new { error = "No CA is configured yet. Complete the setup wizard first." });

        var templates = _setupService.GetStatus().EnabledTemplates
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(ServiceRightsCheck.MaxTemplates)
            .ToList();

        var key = ca + "|" + string.Join("|", templates.Order(StringComparer.OrdinalIgnoreCase));
        var report = await _cache.GetOrRunAsync(key, token => _check.RunAsync(ca, templates, token), force, ct);
        return Ok(report.ToWire());
    }
}
