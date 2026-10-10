using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME challenge endpoint: respond to challenges to prove domain control.
/// RFC 8555 §7.5.1
/// </summary>
[ApiController]
[EnableRateLimiting(AcmeRateLimitPolicies.General)]
public sealed class ChallengeController : AcmeControllerBase
{
    /// <summary>
    /// Cap on the whole challenge POST body. Network challenges post an
    /// empty object; only a device attestation carries bulk, and a real
    /// Apple attestation object is a few kilobytes, so a quarter megabyte
    /// of JWS envelope is generous for any honest client.
    /// </summary>
    private const int MaxChallengeRequestBytes = 262_144;

    /// <summary>Cap on the base64url attObj string inside the payload.</summary>
    private const int MaxAttestationObjectChars = 96_000;

    /// <summary>Cap on the decoded attestation object.</summary>
    private const int MaxAttestationObjectBytes = 65_536;

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
    /// For the network challenge types the client POSTs an empty JSON object
    /// {} to indicate it has provisioned the challenge response and is ready
    /// for validation (RFC 8555 §7.5.1). For device-attest-01 the response
    /// carries the attestation itself as {"attObj": base64url}
    /// (draft-ietf-acme-device-attest-08 section 5.1).
    /// </summary>
    [HttpPost("/acme/{template}/chall/{challengeId}")]
    [Consumes("application/jose+json")]
    [RequestSizeLimit(MaxChallengeRequestBytes)]
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

        // If challenge is already processing or beyond, return current state.
        // For device-attest-01 this is the single shot contract: the first
        // accepted attObj is the one that gets validated, and a re-POST
        // cannot replace it.
        if (challenge.Status != "pending")
        {
            var currentResponse = OrderService.ToChallengeResponse(challenge, template, AcmeUrl);
            return Ok(currentResponse);
        }

        string? attestationObject = null;
        if (challenge.Type == DeviceAttest01ChallengeValidator.TypeName)
        {
            // POST-as-GET (empty payload) fetches the resource without
            // answering it, so a client can poll a pending device challenge
            // without spending its attestation.
            if (auth.PayloadBytes is not { Length: > 0 })
                return Ok(OrderService.ToChallengeResponse(challenge, template, AcmeUrl));

            var intakeError = TryReadAttestationObject(auth.PayloadBytes, out attestationObject);
            if (intakeError != null)
                return intakeError;
        }

        // RFC 8555 §7.5.2: the client has said it no longer holds this authorization,
        // so it may not put the authorization's challenges back to work. Without this
        // a client could deactivate an authorization and then still drive its pending
        // challenge to "processing", where the background validator would set the
        // authorization back to "valid" and undo the deactivation.
        //
        // Placed here rather than beside the ownership check on purpose: reading a
        // challenge under a deactivated authorization stays a 200, matching how the
        // authorization resource itself still reads back. Only the state change is
        // refused. GetChallengeAsync already includes the authorization, so this is free.
        if (string.Equals(challenge.Authorization.Status, "deactivated", StringComparison.Ordinal))
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "The authorization for this challenge has been deactivated.");

        // Transition to "processing" — the background validation service will pick it up
        var moved = await _orderService.RespondToChallengeAsync(challengeId, attestationObject, ct);
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

    /// <summary>
    /// Reads {"attObj": base64url} from a device-attest-01 challenge
    /// response payload. Intake checks shape and size only; the CBOR inside
    /// is the background validator's business, and the string is kept as
    /// received so what gets validated is exactly what the client signed
    /// over. The challenge stays pending on every refusal here, so the
    /// client can re-POST a corrected response. Returns the error result,
    /// or null with the attObj set.
    /// </summary>
    private IActionResult? TryReadAttestationObject(byte[] payloadBytes, out string? attObj)
    {
        attObj = null;

        DeviceAttestChallengePayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<DeviceAttestChallengePayload>(payloadBytes);
        }
        catch (JsonException)
        {
            return AcmeError(400, AcmeErrorType.Malformed,
                "Invalid device-attest-01 challenge response payload.");
        }

        if (string.IsNullOrEmpty(payload?.AttObj))
            return AcmeError(400, AcmeErrorType.Malformed,
                "A device-attest-01 challenge response must carry a non-empty attObj.");

        if (payload.AttObj.Length > MaxAttestationObjectChars)
            return AcmeError(400, AcmeErrorType.Malformed,
                "The attestation object is too large.");

        byte[] decoded;
        try
        {
            decoded = JwsService.Base64UrlDecode(payload.AttObj);
        }
        catch (FormatException)
        {
            return AcmeError(400, AcmeErrorType.Malformed,
                "attObj is not valid base64url.");
        }

        if (decoded.Length > MaxAttestationObjectBytes)
            return AcmeError(400, AcmeErrorType.Malformed,
                "The attestation object is too large.");

        attObj = payload.AttObj;
        return null;
    }
}
