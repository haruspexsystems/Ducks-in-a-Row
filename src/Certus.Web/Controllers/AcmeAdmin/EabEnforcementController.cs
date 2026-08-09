using Certus.Core.Acme.Services;
using Certus.Core.Setup;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.AcmeAdmin;

/// <summary>
/// EAB enforcement mode API for the ACME dashboard tab (issue #129). The mode
/// lives in the wizard status file, which EabEnforcementPolicy hot reads, so a
/// change here applies to the next directory fetch and new-account without a
/// restart. Admin only with no anonymous carve outs, like the settings API.
/// </summary>
[ApiController]
[Route("api/acme/eab")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class EabEnforcementController : ControllerBase
{
    private readonly EabEnforcementPolicy _eabPolicy;
    private readonly SetupService _setupService;
    private readonly AccountService _accountService;
    private readonly ILogger<EabEnforcementController> _logger;

    public EabEnforcementController(
        EabEnforcementPolicy eabPolicy,
        SetupService setupService,
        AccountService accountService,
        ILogger<EabEnforcementController> logger)
    {
        _eabPolicy = eabPolicy;
        _setupService = setupService;
        _accountService = accountService;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/acme/eab/enforcement: the mode in force right now (the same
    /// hot read the ACME surface uses) plus the number of valid accounts
    /// without a binding, so the Required option can say concretely how many
    /// grandfathered accounts it would leave working.
    /// </summary>
    [HttpGet("enforcement")]
    public async Task<IActionResult> GetEnforcement(CancellationToken ct)
    {
        return Ok(new
        {
            mode = EabEnforcementPolicy.ModeName(_eabPolicy.Mode),
            unboundAccounts = await _accountService.CountUnboundValidAsync(ct),
        });
    }

    /// <summary>
    /// PUT /api/acme/eab/enforcement: change the mode after setup. The parse
    /// is strict (a typo is a 400, never a silent off), and the same setup
    /// completion guard as the allowed domains endpoint applies: the wizard
    /// status file is the store itself, and writing over an incomplete one
    /// would wipe the wizard state.
    /// </summary>
    [HttpPut("enforcement")]
    public IActionResult UpdateEnforcement([FromBody] UpdateEabEnforcementRequest request)
    {
        if (!EabEnforcementPolicy.TryParseMode(request.Mode, out var mode))
            return BadRequest(new
            {
                error = "Mode must be one of: off, optional, required.",
            });

        var status = _setupService.GetStatus();
        if (!status.SetupCompleted || !_setupService.IsCaEffectivelyConfigured)
            return Conflict(new { error = "Setup has not been completed. Finish the setup wizard first." });

        if (!_setupService.UpdateEabEnforcement(mode))
            return Conflict(new
            {
                error = "The wizard status file could not be read back as completed, " +
                        "so nothing was changed. Check the service log for the file path.",
            });

        _logger.LogInformation("EAB enforcement mode set from the dashboard: {Mode}",
            EabEnforcementPolicy.ModeName(mode));

        return Ok(new
        {
            mode = EabEnforcementPolicy.ModeName(mode),
            message = "Saved. The mode applies to new ACME requests immediately.",
        });
    }
}

/// <summary>Request body for changing the EAB enforcement mode.</summary>
public sealed record UpdateEabEnforcementRequest(string? Mode);
