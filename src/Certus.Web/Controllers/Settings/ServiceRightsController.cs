using Certus.Core.Configuration;
using Certus.Core.ServiceRights;
using Certus.Core.Setup;
using Certus.Web.Audit;
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
    private readonly CertusInstanceMode _instanceMode;

    public ServiceRightsController(
        ServiceRightsCheck check,
        ServiceRightsReportCache cache,
        SetupService setupService,
        IOptions<CertusOptions> options,
        CertusInstanceMode instanceMode)
    {
        _check = check;
        _cache = cache;
        _setupService = setupService;
        _options = options.Value;
        _instanceMode = instanceMode;
    }

    /// <summary>GET /api/settings/service-rights: the kept report, or a fresh one when it has aged.</summary>
    [HttpGet("")]
    public Task<IActionResult> Get(CancellationToken ct) => RunAsync(force: false, ct);

    /// <summary>POST /api/settings/service-rights/check: always a fresh check.</summary>
    [HttpPost("check")]
    [AdminAuditExempt("reads the service account's rights at the CA and changes nothing")]
    public Task<IActionResult> Check(CancellationToken ct) => RunAsync(force: true, ct);

    private async Task<IActionResult> RunAsync(bool force, CancellationToken ct)
    {
        var ca = _options.UseMockCa
            ? MockCaConnectionString
            : _options.CaConnectionString;
        if (string.IsNullOrWhiteSpace(ca))
            return Conflict(new { error = "No CA is configured yet. Complete the setup wizard first." });

        var enabled = _setupService.GetStatus().EnabledTemplates
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var templates = enabled.Take(ServiceRightsCheck.MaxTemplates).ToList();

        // The names past the cap have no rows, and the page has to say so, or an
        // estate with more templates than one check reads sees the first ones and
        // takes the rest for a clean answer (issue #478). The count is of names as
        // the status file records them, before the check resolves a display name
        // to the programmatic one, so a template recorded under both of its names
        // (the dual form of issue #17) with one of them past the cap is counted
        // although its row is there. That errs towards sending an operator to
        // look, never away from it: a template with no row has at least one name
        // past the cap, so zero still means every enabled template was checked.
        var notChecked = enabled.Count - templates.Count;

        var key = ca + "|" + string.Join("|", templates.Order(StringComparer.OrdinalIgnoreCase));
        var report = await _cache.GetOrRunAsync(key, token => _check.RunAsync(ca, templates, token), force, ct);

        // Added to the answer rather than kept with the report: the kept report is
        // keyed on what was checked, which one more name past the cap leaves alone,
        // so a count stored with it would go stale while the report stayed fresh.
        return Ok(report.ToWire(_instanceMode) with { TemplatesNotChecked = notChecked });
    }
}
