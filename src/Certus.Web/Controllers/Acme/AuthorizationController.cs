using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data.Entities;
using Certus.Core.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME authorization endpoint: fetch authorization status and challenges.
/// RFC 8555 §7.5
///
/// Rate limited as polling, not as general traffic. This is a POST-as-GET read a
/// client repeats for as long as validation takes, so its request count is set by
/// the validation worker's sweep interval rather than by how many certificates
/// were asked for. Leaving it in the general bucket, while the order poll beside
/// it was exempt entirely, meant a correctly behaving client could exhaust the
/// general limit part way through a single issuance (issue #263).
/// </summary>
[ApiController]
[EnableRateLimiting(AcmeRateLimitPolicies.Poll)]
public sealed class AuthorizationController : AcmeControllerBase
{
    private readonly OrderService _orderService;
    private readonly AccountService _accountService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        OrderService orderService,
        AccountService accountService,
        NonceService nonceService,
        JwsService jwsService,
        ILogger<AuthorizationController> logger)
    {
        _orderService = orderService;
        _accountService = accountService;
        _nonceService = nonceService;
        _jwsService = jwsService;
        _logger = logger;
    }

    /// <summary>
    /// POST /acme/{template}/authz/{authzId} — read an authorization
    /// (POST-as-GET, RFC 8555 §7.5) or deactivate it (§7.5.2).
    ///
    /// One URL, two operations, told apart by the payload, exactly as the account
    /// URL is. An empty payload reads; {"status":"deactivated"} writes. Anything
    /// else is refused, and that is a deliberate divergence from the account
    /// handler; see ApplyAuthorizationUpdateAsync.
    /// </summary>
    [HttpPost("/acme/{template}/authz/{authzId}")]
    [Consumes("application/jose+json")]
    public async Task<IActionResult> GetOrDeactivateAuthorization(
        string template, string authzId, CancellationToken ct)
    {
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        var authz = await _orderService.GetAuthorizationAsync(authzId, ct);
        if (authz == null)
            return AcmeError(404, AcmeErrorType.Malformed, "Authorization not found.");

        // Verify the authorization belongs to this account. Strictly before the
        // payload branch: a payload must never reach the write path for an
        // authorization this account does not own.
        if (authz.Order.AccountId != auth.Account!.Id)
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "Authorization does not belong to this account.");

        // An empty payload is POST-as-GET: read the authorization and change
        // nothing. JwsService decodes an absent payload to an empty array, never
        // null, so length is the whole test.
        if (auth.PayloadBytes is { Length: > 0 })
        {
            var updateResult = await ApplyAuthorizationUpdateAsync(authz, auth.PayloadBytes, ct);
            if (updateResult.Error != null)
                return updateResult.Error;

            authz = updateResult.Authorization!;
        }

        // Built after the write, so a deactivating request reports "deactivated"
        // in the very response that performed it (§7.5.2).
        var response = OrderService.ToAuthorizationResponse(authz, template, AcmeUrl);
        return Ok(response);
    }

    /// <summary>
    /// Applies a §7.5.2 deactivation payload. Returns the authorization to build
    /// the response from, or the error to return instead.
    /// </summary>
    private async Task<(AcmeAuthorization? Authorization, IActionResult? Error)>
        ApplyAuthorizationUpdateAsync(
            AcmeAuthorization authz,
            byte[] payloadBytes,
            CancellationToken cancellationToken)
    {
        AuthorizationUpdateRequest? update;
        try
        {
            update = JsonSerializer.Deserialize<AuthorizationUpdateRequest>(payloadBytes);
        }
        catch (JsonException)
        {
            return (null, AcmeError(400, AcmeErrorType.Malformed,
                "Invalid authorization update payload."));
        }

        // A payload of the literal "null" lands here. §7.1.2 defines POST-as-GET as
        // an empty payload, not a null one, so this is malformed rather than a read.
        if (update == null)
            return (null, AcmeError(400, AcmeErrorType.Malformed,
                "Invalid authorization update payload."));

        // No status member at all, so nothing is being asked for. Read it instead of
        // refusing: clients do poll with a bare {} and other ACME servers accept it
        // as POST-as-GET. This test must come before the deactivation test, because
        // IsDeactivation is also false for null.
        if (update.Status == null)
            return (authz, null);

        // A status this server does not act on is REFUSED, where the account handler
        // ignores the same shape. The divergence is deliberate: §7.3.2 tells the
        // server to ignore an unrecognised status on an account, and §7.5.2 gives no
        // such instruction here. Answering 200 with the unchanged object would tell a
        // client that asked for something the server did not do that it succeeded,
        // which is the false success issue #268 exists to remove.
        //
        // The value is not echoed. It is client supplied, and #232/#234 record that
        // the character guards still pass U+2028 and U+2029, so a log or error reader
        // could see one line as two.
        if (!update.IsDeactivation)
            return (null, AcmeError(400, AcmeErrorType.Malformed,
                "Only \"deactivated\" may be requested for an authorization (RFC 8555 section 7.5.2)."));

        var result = await _orderService.DeactivateAuthorizationAsync(authz, cancellationToken);

        switch (result.Outcome)
        {
            case AuthorizationDeactivationOutcome.Deactivated:
                return (result.Authorization, null);

            case AuthorizationDeactivationOutcome.AlreadyDeactivated:
                // Idempotent. The requested state holds, so this is a success on the
                // state, not a no-op dressed as one.
                _logger.LogDebug(
                    "Authorization {AuthorizationId} was already deactivated",
                    authz.AuthorizationId);
                return (result.Authorization, null);

            default:
                // Terminal and not deactivatable. Naming the current status is safe:
                // it is a server written value from a fixed vocabulary, never client
                // text.
                return (null, AcmeError(400, AcmeErrorType.Malformed,
                    $"An authorization that is {result.Authorization.Status} cannot be deactivated."));
        }
    }
}
