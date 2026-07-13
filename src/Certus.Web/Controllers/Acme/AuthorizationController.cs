using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME authorization endpoint: fetch authorization status and challenges.
/// RFC 8555 §7.5
/// </summary>
[ApiController]
[EnableRateLimiting("acme-general")]
public sealed class AuthorizationController : AcmeControllerBase
{
    private readonly OrderService _orderService;
    private readonly AccountService _accountService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;

    public AuthorizationController(
        OrderService orderService,
        AccountService accountService,
        NonceService nonceService,
        JwsService jwsService)
    {
        _orderService = orderService;
        _accountService = accountService;
        _nonceService = nonceService;
        _jwsService = jwsService;
    }

    /// <summary>
    /// POST /acme/{template}/authz/{authzId} — get authorization (POST-as-GET).
    /// RFC 8555 §7.5
    /// </summary>
    [HttpPost("/acme/{template}/authz/{authzId}")]
    [Consumes("application/jose+json")]
    public async Task<IActionResult> GetAuthorization(
        string template, string authzId, CancellationToken ct)
    {
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        var authz = await _orderService.GetAuthorizationAsync(authzId, ct);
        if (authz == null)
            return AcmeError(404, AcmeErrorType.Malformed, "Authorization not found.");

        // Verify the authorization belongs to this account
        if (authz.Order.AccountId != auth.Account!.Id)
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "Authorization does not belong to this account.");

        var response = OrderService.ToAuthorizationResponse(authz, template, AcmeUrl);
        return Ok(response);
    }
}
