using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME challenge endpoint: respond to challenges to prove domain control.
/// RFC 8555 §7.5.1
/// </summary>
[ApiController]
[EnableRateLimiting("acme-general")]
public sealed class ChallengeController : AcmeControllerBase
{
    private readonly OrderService _orderService;
    private readonly AccountService _accountService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;

    public ChallengeController(
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
    /// POST /acme/{template}/chall/{challengeId} — respond to a challenge.
    /// The client POSTs an empty JSON object {} to indicate it has provisioned
    /// the challenge response and is ready for validation.
    /// RFC 8555 §7.5.1
    /// </summary>
    [HttpPost("/acme/{template}/chall/{challengeId}")]
    [Consumes("application/jose+json")]
    public async Task<IActionResult> RespondToChallenge(
        string template, string challengeId, CancellationToken ct)
    {
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        // Look up the challenge
        var challenge = await _orderService.GetChallengeAsync(challengeId, ct);
        if (challenge == null)
            return AcmeError(404, AcmeErrorType.Malformed, "Challenge not found.");

        // Verify the challenge belongs to this account
        if (challenge.Authorization.Order.AccountId != auth.Account!.Id)
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "Challenge does not belong to this account.");

        // If challenge is already processing or beyond, return current state
        if (challenge.Status != "pending")
        {
            var currentResponse = OrderService.ToChallengeResponse(challenge, template, AcmeUrl);
            return Ok(currentResponse);
        }

        // Transition to "processing" — the background validation service will pick it up
        var moved = await _orderService.RespondToChallengeAsync(challengeId, ct);
        if (!moved)
            return AcmeError(400, AcmeErrorType.Malformed,
                "Challenge cannot be responded to in its current state.");

        // Re-fetch to get updated status
        challenge = await _orderService.GetChallengeAsync(challengeId, ct);
        if (challenge == null)
            return AcmeError(500, AcmeErrorType.ServerInternal,
                "Challenge could not be reloaded after the state transition.");
        var response = OrderService.ToChallengeResponse(challenge, template, AcmeUrl);

        // Return the challenge URL in the Link header as required by RFC 8555
        var authzUrl = AcmeUrl(
            $"/acme/{template}/authz/{challenge.Authorization.AuthorizationId}");
        Response.Headers.Append("Link", $"<{authzUrl}>;rel=\"up\"");

        return Ok(response);
    }
}
