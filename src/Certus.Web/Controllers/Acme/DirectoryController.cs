using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
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

    public DirectoryController(TemplateService templateService)
    {
        _templateService = templateService;
    }

    [HttpGet("/acme/{template}/directory")]
    public async Task<IActionResult> GetDirectory(string template, CancellationToken cancellationToken)
    {
        TemplateResolution resolution;
        try
        {
            resolution = await _templateService.ResolveAsync(template, cancellationToken);
        }
        catch (CaUnavailableException)
        {
            return AcmeError(503, AcmeErrorType.ServiceUnavailable,
                "The ADCS Certificate Authority is unavailable. Try again shortly.");
        }

        var error = TemplateAccessError(resolution, template);
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
                Website = "https://github.com/haruspexsystems/Ducks-in-a-Row"
            }
        };

        return Ok(directory);
    }
}
