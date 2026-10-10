using System.Text.Json;
using System.Threading.RateLimiting;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data.Entities;
using Certus.Core.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// ACME account management endpoints.
/// RFC 8555 §7.3
/// </summary>
[ApiController]
public sealed class AccountController : AcmeControllerBase
{
    private readonly AccountService _accountService;
    private readonly OrderService _orderService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;
    private readonly TemplateService _templateService;
    private readonly EabEnforcementPolicy _eabPolicy;
    private readonly EabCredentialService _eabCredentials;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        AccountService accountService,
        OrderService orderService,
        NonceService nonceService,
        JwsService jwsService,
        TemplateService templateService,
        EabEnforcementPolicy eabPolicy,
        EabCredentialService eabCredentials,
        ILogger<AccountController> logger)
    {
        _accountService = accountService;
        _orderService = orderService;
        _nonceService = nonceService;
        _jwsService = jwsService;
        _templateService = templateService;
        _eabPolicy = eabPolicy;
        _eabCredentials = eabCredentials;
        _logger = logger;
    }

    /// <summary>
    /// POST /acme/{template}/new-account — create a new account or find existing.
    /// RFC 8555 §7.3
    /// </summary>
    [HttpPost("/acme/{template}/new-account")]
    [Consumes("application/jose+json")]
    [EnableRateLimiting(AcmeRateLimitPolicies.NewAccount)]
    public async Task<IActionResult> NewAccount(
        string template,
        CancellationToken cancellationToken)
    {
        // 1. Validate template: it must exist and be enabled for ACME (issue #85).
        var (_, templateError) = await ResolveTemplateAsync(
            _templateService, template, cancellationToken);
        if (templateError != null)
            return templateError;

        // 2. Read and parse JWS body
        var body = await new StreamReader(Request.Body).ReadToEndAsync(cancellationToken);
        JwsFlattenedRequest? jws;
        try
        {
            jws = JsonSerializer.Deserialize<JwsFlattenedRequest>(body);
        }
        catch (JsonException)
        {
            return AcmeError(400, AcmeErrorType.Malformed, "Invalid JWS JSON.");
        }

        if (jws == null)
            return AcmeError(400, AcmeErrorType.Malformed, "Empty JWS body.");

        // 3. Validate JWS structure and signature
        var validation = _jwsService.Validate(jws);
        if (validation.Status == JwsValidationStatus.Malformed)
        {
            return AcmeError(400, AcmeErrorType.Malformed,
                validation.ErrorMessage ?? "JWS validation failed.");
        }

        // 4. new-account MUST use jwk (not kid) — RFC 8555 §7.3
        if (validation.Header?.Jwk == null || !validation.Header.Jwk.HasValue)
        {
            return AcmeError(400, AcmeErrorType.Malformed,
                "new-account requests must use JWK in the protected header, not kid.");
        }

        // 4b. Reject weak public keys with badPublicKey (RFC 8555 §6.7).
        if (!JwsService.ValidatePublicKeyStrength(validation.JwkJson!, out var keyStrengthError))
        {
            return AcmeError(400, AcmeErrorType.BadPublicKey, keyStrengthError!);
        }

        // 5. Validate nonce
        if (string.IsNullOrEmpty(validation.Header.Nonce) ||
            !_nonceService.ValidateAndConsume(validation.Header.Nonce))
        {
            return AcmeError(400, AcmeErrorType.BadNonce,
                "Invalid or expired nonce. Retry with a fresh nonce from the Replay-Nonce header.");
        }

        // 6. Validate URL matches the request URL.
        // Compare via NormalizeAcmeUrl so a client that decodes the URL before
        // including it in the JWS url header still matches (see helper docs).
        var expectedUrl = AcmeUrl($"/acme/{template}/new-account");
        if (NormalizeAcmeUrl(validation.Header.Url) != NormalizeAcmeUrl(expectedUrl))
        {
            return AcmeError(400, AcmeErrorType.Malformed,
                $"JWS header 'url' does not match the request URL.");
        }

        // 7. Parse the account request payload
        NewAccountRequest? request;
        try
        {
            if (validation.PayloadBytes == null || validation.PayloadBytes.Length == 0)
            {
                // POST-as-GET (empty payload) — account lookup
                request = new NewAccountRequest { OnlyReturnExisting = true };
            }
            else
            {
                request = JsonSerializer.Deserialize<NewAccountRequest>(validation.PayloadBytes);
            }
        }
        catch (JsonException)
        {
            return AcmeError(400, AcmeErrorType.Malformed, "Invalid account request payload.");
        }

        if (request == null)
            return AcmeError(400, AcmeErrorType.Malformed, "Invalid account request payload.");

        // 7b. Bound the contact list, with the same limits the update endpoint applies
        // (RFC 8555 §7.3.2). One shared guard so a list this server would refuse to
        // update cannot be smuggled in at registration instead.
        if (!AccountService.ValidateContacts(request.Contact, out var contactError))
            return AcmeError(400, AcmeErrorType.InvalidContact, contactError!);

        // 8. Handle onlyReturnExisting
        if (request.OnlyReturnExisting)
        {
            var existing = await _accountService.FindByThumbprintAsync(
                validation.JwkJson!, cancellationToken);

            if (existing == null)
            {
                return AcmeError(400, AcmeErrorType.AccountDoesNotExist,
                    "No account exists for this key.");
            }

            if (DeactivatedAccountError(existing) is IActionResult lookupRefusal)
                return lookupRefusal;

            var accountUrl = AcmeUrl($"/acme/{template}/acct/{existing.AccountId}");
            Response.Headers["Location"] = accountUrl;
            return Ok(AccountService.ToResponse(existing, AcmeUrl, template));
        }

        // 8b. External account binding (RFC 8555 §7.3.4). Only requests that
        // could register or bind are checked: the onlyReturnExisting path
        // above is the read path and keeps working for existing clients in
        // every mode; that is the grandfathering contract.
        var eabMode = _eabPolicy.Mode;
        EabCredential? eabCredential = null;
        string? eabJwsJson = null;

        // An explicit JSON null reads as absent, so a client library that
        // always emits the member does not get treated as presenting one.
        var providedEab = request.ExternalAccountBinding;
        if (providedEab.HasValue &&
            (providedEab.Value.ValueKind == JsonValueKind.Null
             || providedEab.Value.ValueKind == JsonValueKind.Undefined))
        {
            providedEab = null;
        }

        if (providedEab == null)
        {
            // Required applies to registration, not to a re-POST from a key
            // that already has an account: RFC 8555 §7.3 returns the existing
            // account for a known key, and clients like certbot and
            // cert-manager re-run plain registration routinely. Refusing
            // those would cut grandfathered accounts off from their own
            // account URL, breaking the grandfathering contract.
            if (eabMode == EabEnforcementMode.Required &&
                await _accountService.FindByThumbprintAsync(
                    validation.JwkJson!, cancellationToken) == null)
            {
                return AcmeError(400, AcmeErrorType.ExternalAccountRequired,
                    "This server requires external account binding. Register with the " +
                    "key identifier and MAC key issued by your administrator.");
            }
        }
        else if (eabMode == EabEnforcementMode.Off)
        {
            // The machinery is off: ignore a stale binding rather than fail
            // clients still configured with one after the server stopped
            // requiring it.
            _logger.LogDebug(
                "Ignoring externalAccountBinding on new-account while EAB enforcement is off");
        }
        else
        {
            // Optional or Required: a presented binding is always verified,
            // and an invalid one always fails the request. Falling through to
            // an unbound registration would silently drop the attribution the
            // client asked for.
            var eabElement = providedEab.Value;
            var verification = await _eabCredentials.VerifyBindingAsync(
                validation.JwkJson!, expectedUrl, eabElement, cancellationToken);

            switch (verification.Outcome)
            {
                case EabVerificationOutcome.Verified:
                    eabCredential = verification.Credential;
                    eabJwsJson = eabElement.GetRawText();
                    break;

                case EabVerificationOutcome.UnsupportedAlgorithm:
                    // RFC 8555 §6.2: badSignatureAlgorithm problems SHOULD
                    // list the algorithms the server accepts.
                    return AcmeError(400, AcmeErrorType.BadSignatureAlgorithm,
                        verification.Detail ?? "Unsupported externalAccountBinding algorithm.",
                        JwsService.SupportedMacAlgorithms);

                case EabVerificationOutcome.Unauthorized:
                    return AcmeError(403, AcmeErrorType.Unauthorized,
                        verification.Detail ?? "External account binding verification failed.");

                default:
                    return AcmeError(400, AcmeErrorType.Malformed,
                        verification.Detail ?? "Invalid externalAccountBinding.");
            }
        }

        // 9. Create (or find existing) account
        var (account, alreadyExists) = await _accountService.CreateAccountAsync(
            validation.JwkJson!, request, eabCredential?.Id, eabJwsJson, cancellationToken);

        if (account == null)
            return AcmeError(500, AcmeErrorType.ServerInternal, "Failed to create account.");

        // 9a. Deactivation is terminal (RFC 8555 §7.3.6), and this is the one route back
        // to an account that does not authenticate with kid, so the status check the kid
        // helper performs has to be repeated here. Refused before the binding rules below
        // run: a dead account must not adopt a credential and re-emerge looking like a
        // working bound account. A freshly created account is always valid, so this can
        // only fire for an existing one.
        if (DeactivatedAccountError(account) is IActionResult registrationRefusal)
            return registrationRefusal;

        // 9b. The bind and rebind rules when the account already existed
        // (RFC 8555 §7.3 returns the existing account for a known key): an
        // unbound account with a verified binding adopts it, the deliberate
        // migration path for grandfathered accounts; the same credential
        // again is an idempotent retry; a different credential never silently
        // swaps the stored binding, because that would rewrite the account's
        // attribution. Only valid accounts reach here; 9a refused the rest.
        if (alreadyExists && eabCredential != null)
        {
            if (account.ExternalAccountCredentialId == null)
            {
                await _accountService.BindAsync(
                    account, eabCredential.Id, eabJwsJson!, cancellationToken);
            }
            else if (account.ExternalAccountCredentialId != eabCredential.Id)
            {
                _logger.LogWarning(
                    "new-account for existing account {AccountId} presented EAB credential " +
                    "{KeyId}, but the account is bound to a different credential; keeping " +
                    "the original binding",
                    account.AccountId, eabCredential.KeyId);
            }
        }

        var location = AcmeUrl($"/acme/{template}/acct/{account.AccountId}");
        Response.Headers["Location"] = location;

        var response = AccountService.ToResponse(account, AcmeUrl, template);

        if (alreadyExists)
        {
            // RFC 8555 §7.3: existing account → 200
            return Ok(response);
        }
        else
        {
            // RFC 8555 §7.3: new account → 201
            return StatusCode(201, response);
        }
    }

    /// <summary>
    /// The refusal for a new-account request signed by the key of an account that is no
    /// longer valid, or null when the account may proceed.
    ///
    /// new-account authenticates with an embedded jwk rather than a kid, so it is the one
    /// ACME route that does not pass through the kid helper's status check. Without this
    /// the same key that RFC 8555 §7.3.6 says must be refused everywhere would still get
    /// 200 and its account object back from this endpoint. It could do nothing with it,
    /// because the unique thumbprint index means a deactivated key can never register
    /// afresh and every other endpoint refuses it, but "deactivated" should not have an
    /// exception a reader has to know about.
    /// </summary>
    private IActionResult? DeactivatedAccountError(AcmeAccount account)
    {
        if (account.Status == "valid")
            return null;

        _logger.LogInformation(
            "Refused a new-account request signed by the key of {Status} account {AccountId}",
            account.Status, account.AccountId);

        // 401 for the same reason the kid helper answers 401: RFC 8555 §7.3.6 names that
        // status for a request from a deactivated account.
        return AcmeError(401, AcmeErrorType.Unauthorized,
            $"The account registered to this key is {account.Status} and can no longer " +
            "be used. Deactivation is permanent; register with a new key to continue.");
    }

    /// <summary>
    /// POST /acme/{template}/acct/{accountId} — the account resource. Three operations
    /// share this URL, told apart by the payload: an empty payload is a lookup
    /// (POST-as-GET, RFC 8555 §7.1.2), a payload carrying status "deactivated" is a
    /// deactivation (§7.3.6), and anything else is an account update (§7.3.2).
    ///
    /// Authenticated with kid through the shared helper, which also verifies the nonce,
    /// the JWS url header (§6.4), and the signature against the stored account key, and
    /// refuses an account that is already deactivated. This method then confirms the
    /// authenticated account matches the account named in the path.
    ///
    /// Every path answers 200 with the account object, per §7.3.2: "If the server
    /// accepts the update, it MUST return a response with a 200 (OK) status code and the
    /// resulting account object." Resulting: the response is built after the write, so a
    /// deactivation reports "deactivated" in the very response that performed it.
    /// </summary>
    [HttpPost("/acme/{template}/acct/{accountId}")]
    [Consumes("application/jose+json")]
    [EnableRateLimiting(AcmeRateLimitPolicies.General)]
    public async Task<IActionResult> GetOrUpdateAccount(
        string template,
        string accountId,
        CancellationToken cancellationToken)
    {
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, cancellationToken);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        // The authenticated account must match the account named in the path.
        if (auth.Account!.AccountId != accountId)
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "Account URL does not match the authenticated account.");

        var account = auth.Account;

        // An empty payload is POST-as-GET: read the account and change nothing.
        // JwsService decodes an absent payload to an empty array, never null, so
        // length is the whole test.
        if (auth.PayloadBytes is { Length: > 0 })
        {
            var updateResult = await ApplyAccountUpdateAsync(
                account, auth.PayloadBytes, cancellationToken);
            if (updateResult.Error != null)
                return updateResult.Error;

            account = updateResult.Account!;
        }

        Response.Headers["Location"] = AcmeUrl($"/acme/{template}/acct/{account.AccountId}");
        return Ok(AccountService.ToResponse(account, AcmeUrl, template));
    }

    /// <summary>
    /// Applies a non empty account payload: a deactivation (RFC 8555 §7.3.6) or a
    /// contact change (§7.3.2). Returns the account to report back, or the problem
    /// response that refused the request.
    /// </summary>
    private async Task<(AcmeAccount? Account, IActionResult? Error)> ApplyAccountUpdateAsync(
        AcmeAccount account,
        byte[] payloadBytes,
        CancellationToken cancellationToken)
    {
        AccountUpdateRequest? update;
        try
        {
            update = JsonSerializer.Deserialize<AccountUpdateRequest>(payloadBytes);
        }
        catch (JsonException)
        {
            return (null, AcmeError(400, AcmeErrorType.Malformed,
                "Invalid account update payload."));
        }

        if (update == null)
            return (null, AcmeError(400, AcmeErrorType.Malformed,
                "Invalid account update payload."));

        // Deactivation wins over a contact change in the same payload. The account is
        // about to stop being usable, so persisting a contact onto it first would be
        // writing to something nobody can read back.
        if (update.IsDeactivation)
        {
            var result = await _accountService.DeactivateAsync(
                account.Id, AccountDeactivationOrigin.AcmeClient, cancellationToken);

            // The account authenticated as valid a moment ago, so neither of the other
            // outcomes is anything the client did. They are not equivalent, though, and
            // must not collapse into one "report the current state" arm.
            if (result.Account == null)
            {
                // The row went away between authentication and the write. Nothing
                // deactivates it now, so answering 200 here would hand back the stale
                // entity still reporting "valid" to a client that asked for
                // deactivation: exactly the false success this endpoint was fixed to
                // stop telling. Refuse instead, matching how the kid helper answers an
                // account it cannot resolve.
                _logger.LogWarning(
                    "ACME deactivation of account {AccountId} found no account row; " +
                    "it was removed between authentication and the write",
                    account.AccountId);
                return (null, AcmeError(401, AcmeErrorType.AccountDoesNotExist,
                    "Account not found."));
            }

            if (result.Outcome != AccountDeactivationOutcome.Deactivated)
            {
                // Raced a dashboard deactivation. The account is already where the
                // client wanted it, so this reports success on the state, not the write.
                _logger.LogInformation(
                    "ACME deactivation of account {AccountId} raced another change; " +
                    "the account is already {Status}",
                    account.AccountId, result.Account.Status);
            }

            return (result.Account, null);
        }

        // RFC 8555 §7.3.2: the server "MUST ignore any updates to the 'orders' field,
        // 'termsOfServiceAgreed' field, the 'status' field (except as allowed by Section
        // 7.3.6), or any other fields it does not recognize". So a status of "valid" or
        // "revoked" is ignored rather than refused, and the fields this server does not
        // act on never reach here: AccountUpdateRequest does not declare them.
        if (update.Status != null)
        {
            // The value itself is deliberately not echoed. It is client supplied,
            // and nothing validates it before this point: RFC 8555 says to ignore
            // an unrecognized status rather than refuse it, so it never passes a
            // guard on its way here. That the field was present and ignored is the
            // whole diagnostic, and the account id is what a reader needs to act on.
            _logger.LogDebug(
                "Ignoring a non actionable status in an update to account {AccountId}; " +
                "only 'deactivated' is actionable (RFC 8555 §7.3.2)",
                account.AccountId);
        }

        if (update.Contact != null)
        {
            if (!AccountService.ValidateContacts(update.Contact, out var contactError))
                return (null, AcmeError(400, AcmeErrorType.InvalidContact, contactError!));

            await _accountService.UpdateContactAsync(account, update.Contact, cancellationToken);
        }

        return (account, null);
    }

    /// <summary>
    /// POST /acme/{template}/acct/{accountId}/orders — list the account's orders (POST-as-GET).
    /// RFC 8555 §7.1.2.1
    /// </summary>
    [HttpPost("/acme/{template}/acct/{accountId}/orders")]
    [Consumes("application/jose+json")]
    [EnableRateLimiting(AcmeRateLimitPolicies.General)]
    public async Task<IActionResult> GetAccountOrders(
        string template,
        string accountId,
        CancellationToken cancellationToken)
    {
        // Authenticate with kid (fail closed on an unverified signature, like every other
        // account-scoped endpoint).
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, cancellationToken);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        // The authenticated account must match the account named in the path.
        if (auth.Account!.AccountId != accountId)
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "Orders list does not belong to this account.");

        var orders = await _orderService.GetOrderUrlsForAccountAsync(
            auth.Account.Id, AcmeUrl, cancellationToken);

        return Ok(new OrdersListResponse { Orders = orders });
    }
}
