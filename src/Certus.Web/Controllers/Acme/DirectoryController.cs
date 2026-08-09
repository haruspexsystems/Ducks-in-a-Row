using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME directory endpoint — the entry point for ACME clients.
/// RFC 8555 §7.1.1
/// Each ADCS template gets its own directory: GET /acme/{template}/directory
/// </summary>
[ApiController]
[EnableRateLimiting("acme-general")]
public sealed class DirectoryController : AcmeControllerBase
{
    private readonly TemplateService _templateService;
    private readonly EabEnforcementPolicy _eabPolicy;

    public DirectoryController(TemplateService templateService, EabEnforcementPolicy eabPolicy)
    {
        _templateService = templateService;
        _eabPolicy = eabPolicy;
    }

    // HEAD is answered by the same action. ASP.NET normally serves HEAD from a
    // GET endpoint on its own, but only when no candidate accepts the method,
    // and the ACME protocol fallback is an unconstrained catch all that always
    // does. Without the explicit attribute a HEAD on a live directory reaches
    // the fallback and is reported as a missing resource (issue #147).
    [HttpGet("/acme/{template}/directory")]
    [HttpHead("/acme/{template}/directory")]
    public async Task<IActionResult> GetDirectory(string template, CancellationToken cancellationToken)
    {
        var (_, error) = await ResolveTemplateAsync(_templateService, template, cancellationToken);
        if (error != null)
            return error;

        var directory = new AcmeDirectory
        {
            NewNonce = AcmeUrl($"/acme/{template}/new-nonce"),
            NewAccount = AcmeUrl($"/acme/{template}/new-account"),
            NewOrder = AcmeUrl($"/acme/{template}/new-order"),
            RevokeCert = AcmeUrl($"/acme/{template}/revoke-cert"),
            KeyChange = AcmeUrl($"/acme/{template}/key-change"),
            Meta = new AcmeDirectoryMeta
            {
                Website = "https://github.com/haruspexsystems/Ducks-in-a-Row",
                // Hot read: flipping the enforcement mode changes the very
                // next directory fetch (RFC 8555 §7.1.1), no restart needed.
                ExternalAccountRequired = _eabPolicy.Mode == EabEnforcementMode.Required
            }
        };

        return Ok(directory);
    }
}
