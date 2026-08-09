using System.Text.Json;
using System.Threading.RateLimiting;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data.Entities;
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
    [EnableRateLimiting("acme-new-account")]
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

        // 9b. The bind and rebind rules when the account already existed
        // (RFC 8555 §7.3 returns the existing account for a known key): an
        // unbound account with a verified binding adopts it, the deliberate
        // migration path for grandfathered accounts; the same credential
        // again is an idempotent retry; a different credential never silently
        // swaps the stored binding, because that would rewrite the account's
        // attribution. A non valid account is never mutated: deactivation is
        // terminal (RFC 8555 §7.3.6), so a re-registration must not bind it
        // to a credential and surface it as a working bound account.
        if (alreadyExists && eabCredential != null)
        {
            if (account.Status != "valid")
            {
                _logger.LogWarning(
                    "new-account for existing account {AccountId} presented EAB credential " +
                    "{KeyId}, but the account is {Status}; not binding",
                    account.AccountId, eabCredential.KeyId, account.Status);
            }
            else if (account.ExternalAccountCredentialId == null)
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
    /// POST /acme/{template}/acct/{accountId} — account lookup (POST-as-GET).
    /// RFC 8555 §7.3.2. Authenticated with kid through the shared helper, which also
    /// verifies the nonce, the JWS url header (RFC 8555 §6.4), and the signature against
    /// the stored account key, then confirms the authenticated account matches the
    /// account named in the path.
    /// </summary>
    [HttpPost("/acme/{template}/acct/{accountId}")]
    [Consumes("application/jose+json")]
    [EnableRateLimiting("acme-general")]
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

        Response.Headers["Location"] = AcmeUrl($"/acme/{template}/acct/{auth.Account.AccountId}");
        return Ok(AccountService.ToResponse(auth.Account, AcmeUrl, template));
    }

    /// <summary>
    /// POST /acme/{template}/acct/{accountId}/orders — list the account's orders (POST-as-GET).
    /// RFC 8555 §7.1.2.1
    /// </summary>
    [HttpPost("/acme/{template}/acct/{accountId}/orders")]
    [Consumes("application/jose+json")]
    [EnableRateLimiting("acme-general")]
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
