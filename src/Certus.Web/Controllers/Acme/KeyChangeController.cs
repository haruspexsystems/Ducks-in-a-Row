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
/// ACME account key rollover endpoint. Swaps the key pair bound to an account without losing
/// account state. The request is a nested JWS: the outer JWS is signed by the current (old)
/// account key (kid) and its payload is an inner JWS signed by the new key (jwk), which proves
/// possession of the new key. RFC 8555 §7.3.5
/// </summary>
[ApiController]
[EnableRateLimiting(AcmeRateLimitPolicies.General)]
public sealed class KeyChangeController : AcmeControllerBase
{
    private readonly AccountService _accountService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;

    public KeyChangeController(
        AccountService accountService,
        NonceService nonceService,
        JwsService jwsService)
    {
        _accountService = accountService;
        _nonceService = nonceService;
        _jwsService = jwsService;
    }

    /// <summary>
    /// POST /acme/{template}/key-change — roll the account key over to a new key.
    /// RFC 8555 §7.3.5
    /// </summary>
    [HttpPost("/acme/{template}/key-change")]
    [Consumes("application/jose+json")]
    public async Task<IActionResult> KeyChange(string template, CancellationToken ct)
    {
        // 1. Authenticate the OUTER JWS: signed by the current (old) account key via kid. This
        //    verifies the nonce, the url, and the outer signature against the stored account key.
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        var account = auth.Account!;

        // 2. The outer payload is the INNER JWS (RFC 8555 §7.3.5), signed by the new key.
        JwsFlattenedRequest? innerJws;
        try
        {
            innerJws = JsonSerializer.Deserialize<JwsFlattenedRequest>(
                auth.PayloadBytes ?? Array.Empty<byte>());
        }
        catch (JsonException)
        {
            return AcmeError(400, AcmeErrorType.Malformed, "Invalid inner JWS JSON.");
        }

        if (innerJws == null)
            return AcmeError(400, AcmeErrorType.Malformed,
                "The key-change payload must be an inner JWS.");

        // 3. Validate the inner JWS. It must carry the new key as an embedded jwk, and that key
        //    must verify the inner signature (proof of possession of the new key). A kid inner
        //    JWS is not verified here (NeedsKeyLookup, not Verified) and is rejected.
        var inner = _jwsService.Validate(innerJws);
        if (!inner.IsVerified || inner.JwkJson == null)
            return AcmeError(400, AcmeErrorType.Malformed,
                inner.ErrorMessage ?? "The inner JWS must be signed by the new key (jwk).");

        var newKeyJson = inner.JwkJson;

        // 4. Reject a weak new key with badPublicKey (RFC 8555 §6.7), same policy as new-account.
        if (!JwsService.ValidatePublicKeyStrength(newKeyJson, out var keyStrengthError))
            return AcmeError(400, AcmeErrorType.BadPublicKey, keyStrengthError!);

        // 5. The inner JWS url must match the request url (RFC 8555 §7.3.5).
        var expectedUrl = AcmeUrl(Request.Path.Value ?? string.Empty);
        if (NormalizeAcmeUrl(inner.Header?.Url) != NormalizeAcmeUrl(expectedUrl))
            return AcmeError(400, AcmeErrorType.Malformed,
                "Inner JWS 'url' does not match the request URL.");

        // 6. Parse the inner payload: { "account": "<url>", "oldKey": <JWK> }.
        KeyChangeInnerPayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<KeyChangeInnerPayload>(
                inner.PayloadBytes ?? Array.Empty<byte>());
        }
        catch (JsonException)
        {
            return AcmeError(400, AcmeErrorType.Malformed, "Invalid key-change inner payload JSON.");
        }

        if (payload == null)
            return AcmeError(400, AcmeErrorType.Malformed, "The inner payload is required.");

        // 7. The inner 'account' must be the outer kid: RFC 8555 §7.3.5 asks for "the URL for the
        //    account matching the old key (i.e., the 'kid' field in the outer JWS)". Compare with
        //    the kid itself, not a URL rebuilt from this request's template, because a client may
        //    hold a kid under one template name and post key-change under another (issue #607).
        //    A missing kid fails closed, because NormalizeAcmeUrl(null) would match an empty
        //    account. The id in the kid already resolved to the account that signed the outer JWS.
        if (auth.Kid == null || NormalizeAcmeUrl(payload.Account) != NormalizeAcmeUrl(auth.Kid))
            return AcmeError(400, AcmeErrorType.Malformed,
                "Inner payload 'account' does not match the 'kid' of the outer JWS.");

        // 8. The inner 'oldKey' must be the account's current key. Compare by canonical thumbprint
        //    (RFC 7638) so member order in the supplied JWK does not matter.
        string oldKeyThumbprint;
        try
        {
            oldKeyThumbprint = JwsService.ComputeThumbprint(payload.OldKey.GetRawText());
        }
        catch (Exception)
        {
            return AcmeError(400, AcmeErrorType.Malformed,
                "Inner payload 'oldKey' is not a valid JWK.");
        }

        if (oldKeyThumbprint != account.JwkThumbprint)
            return AcmeError(400, AcmeErrorType.Malformed,
                "Inner payload 'oldKey' does not match the account's current key.");

        // 9. The new key must not already be registered to an account. RFC 8555 §7.3.5 requires a
        //    409 with a Location header pointing to the account that already holds the key. This
        //    also rejects rolling over to the same key (it resolves to this same account).
        var existing = await _accountService.FindByThumbprintAsync(newKeyJson, ct);
        if (existing != null)
            return KeyAlreadyInUse(template, existing);

        // 10. Swap the key. A lost race on the unique key index is reported as a conflict, and
        //     it owes the client the same Location as the pre-check above (issue #127).
        var result = await _accountService.ChangeKeyAsync(account, newKeyJson, ct);
        if (result.Outcome == KeyChangeOutcome.Conflict)
            return KeyAlreadyInUse(template, result.KeyHolder!);

        // RFC 8555 §7.3.5: a successful rollover returns the account object.
        Response.Headers["Location"] = AcmeUrl($"/acme/{template}/acct/{account.AccountId}");
        return Ok(AccountService.ToResponse(account, AcmeUrl, template));
    }

    /// <summary>
    /// The 409 for a new key that another account already holds. RFC 8555 §7.3.5 requires the
    /// Location header to name that account. Both refusals go through here, the pre-check and
    /// the race the unique index catches at save, so the two cannot drift apart again.
    /// </summary>
    private IActionResult KeyAlreadyInUse(string template, AcmeAccount holder)
    {
        Response.Headers["Location"] = AcmeUrl($"/acme/{template}/acct/{holder.AccountId}");
        return AcmeError(409, AcmeErrorType.Malformed,
            "The new key is already in use by another account.");
    }
}
