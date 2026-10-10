using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Data.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Certus.Web.Controllers.Acme;

/// <summary>
/// Base class for ACME controllers. Provides helper methods for ACME-compliant responses.
/// The whole /acme/ surface is exempt from the global authorization fallback
/// policy: ACME clients authenticate with JWS signatures (RFC 8555 §6.2), not
/// HTTP authentication. The attribute is inherited by every derived controller.
/// </summary>
[AllowAnonymous]
public abstract class AcmeControllerBase : ControllerBase
{
    /// <summary>
    /// Returns an ACME error response with application/problem+json content type.
    /// RFC 8555 §6.7
    /// </summary>
    protected IActionResult AcmeError(int statusCode, string errorType, string detail)
    {
        var error = new AcmeError
        {
            Type = errorType,
            Detail = detail,
            Status = statusCode
        };

        return new ObjectResult(error)
        {
            StatusCode = statusCode,
            ContentTypes = { "application/problem+json" }
        };
    }

    /// <summary>
    /// Returns an ACME error response carrying per identifier subproblems
    /// (RFC 8555 §6.7.1), so a client can report exactly which identifiers
    /// were refused and why instead of one opaque failure.
    /// </summary>
    protected IActionResult AcmeError(
        int statusCode, string errorType, string detail, AcmeError[] subproblems)
    {
        var error = new AcmeError
        {
            Type = errorType,
            Detail = detail,
            Status = statusCode,
            Subproblems = subproblems
        };

        return new ObjectResult(error)
        {
            StatusCode = statusCode,
            ContentTypes = { "application/problem+json" }
        };
    }

    /// <summary>
    /// Returns a problem that also names the algorithms the server accepts,
    /// for badSignatureAlgorithm responses (RFC 8555 §6.2: the problem
    /// document SHOULD include an "algorithms" field). Kept on the base so
    /// the problem+json envelope stays in one place.
    /// </summary>
    protected IActionResult AcmeError(
        int statusCode, string errorType, string detail, string[] algorithms)
    {
        var error = new AcmeError
        {
            Type = errorType,
            Detail = detail,
            Status = statusCode,
            Algorithms = algorithms
        };

        return new ObjectResult(error)
        {
            StatusCode = statusCode,
            ContentTypes = { "application/problem+json" }
        };
    }

    /// <summary>
    /// Maps a template resolution to its ACME problem response, or null when
    /// the template is enabled and the endpoint may proceed. Unknown keeps the
    /// historical 404; Disabled is the issue #85 policy response for templates
    /// the CA publishes but the administrator did not enable for ACME. Enabled
    /// is the only state that passes: this is an authorization gate, so any
    /// access state added later fails closed until this mapping names it.
    /// </summary>
    protected IActionResult? TemplateAccessError(TemplateResolution resolution, string template)
    {
        return resolution.Access switch
        {
            TemplateAccess.Enabled => null,
            TemplateAccess.Unknown => AcmeError(404, AcmeErrorType.Malformed,
                $"Unknown certificate template: '{template}'."),
            TemplateAccess.BlockedByCeiling => AcmeError(403, AcmeErrorType.Unauthorized,
                $"Certificate template '{template}' cannot issue TLS server or client " +
                "certificates, so this ACME server will not serve it."),
            _ => AcmeError(403, AcmeErrorType.Unauthorized,
                $"Certificate template '{template}' is not enabled for ACME on this server."),
        };
    }

    /// <summary>
    /// Resolves the template named in the URL and maps every refusal to its ACME problem
    /// response, so a caller only has to check whether Error is null. Resolution reaches the
    /// CA, which can be down: without the guard the exception escapes the action and faults to
    /// a bare 500 with no problem document and no nonce, which is what new-account and
    /// new-order did until issue #147. Keeping the guard on the base means an endpoint added
    /// later inherits it rather than repeating the omission.
    /// </summary>
    protected async Task<(TemplateResolution Resolution, IActionResult? Error)> ResolveTemplateAsync(
        TemplateService templateService,
        string template,
        CancellationToken cancellationToken)
    {
        TemplateResolution resolution;
        try
        {
            resolution = await templateService.ResolveAsync(template, cancellationToken);
        }
        catch (CaUnavailableException)
        {
            return (default!, AcmeError(503, AcmeErrorType.ServiceUnavailable,
                "The ADCS Certificate Authority is unavailable. Try again shortly."));
        }

        return (resolution, TemplateAccessError(resolution, template));
    }

    /// <summary>
    /// Builds a full URL for an ACME resource. When Certus:ExternalUrl is configured it is
    /// the authoritative origin (scheme, host, and port) for every ACME URL, matching what
    /// ACME clients are pointed at. When it is not configured the origin comes from the
    /// request: request.Scheme and request.Host already reflect X-Forwarded-Proto and
    /// X-Forwarded-Host only when those arrive from a configured trusted proxy (see
    /// CertusAuthExtensions.BuildForwardedHeadersOptions), so an untrusted caller cannot
    /// inject the host. The path is percent encoded so a template name with reserved
    /// characters still matches during JWS url validation. Pass a decoded path; this method
    /// encodes it.
    /// </summary>
    protected string AcmeUrl(string path)
    {
        var encodedPath = new PathString(path).ToUriComponent();

        var externalUrl = HttpContext.RequestServices
            .GetRequiredService<IOptions<CertusOptions>>().Value.ExternalUrl;
        if (!string.IsNullOrEmpty(externalUrl) &&
            Uri.TryCreate(externalUrl, UriKind.Absolute, out var configured))
        {
            return $"{configured.GetLeftPart(UriPartial.Authority)}{encodedPath}";
        }

        var request = HttpContext.Request;
        return $"{request.Scheme}://{request.Host}{encodedPath}";
    }

    /// <summary>
    /// Normalizes an ACME URL for resource-equivalence comparison. RFC 8555 6.4
    /// prescribes percent encoded form in the JWS url header, but real ACME
    /// clients diverge: Posh-ACME and certbot preserve the encoded form, while
    /// win-acme decodes the URL from the new-order response before signing.
    /// We treat the URL as a resource identifier and compare by decoded form so
    /// any compliant or near-compliant client interoperates.
    /// </summary>
    protected static string NormalizeAcmeUrl(string? value)
    {
        return Uri.UnescapeDataString(value ?? string.Empty);
    }

    /// <summary>
    /// Result of kid-based JWS authentication.
    /// </summary>
    protected sealed record KidAuthResult(
        bool IsAuthenticated,
        AcmeAccount? Account = null,
        byte[]? PayloadBytes = null,
        IActionResult? ErrorResult = null);

    /// <summary>
    /// Authenticates a JWS request using kid (account URL) in the protected header.
    /// Used by all ACME endpoints except new-account.
    /// RFC 8555 §6.2
    /// </summary>
    protected async Task<KidAuthResult> AuthenticateKidJwsAsync(
        JwsService jwsService,
        NonceService nonceService,
        AccountService accountService,
        string template,
        CancellationToken cancellationToken)
    {
        // 1. Read and parse JWS body
        var body = await new StreamReader(Request.Body).ReadToEndAsync(cancellationToken);
        JwsFlattenedRequest? jws;
        try
        {
            jws = JsonSerializer.Deserialize<JwsFlattenedRequest>(body);
        }
        catch (JsonException)
        {
            return new KidAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed, "Invalid JWS JSON."));
        }

        if (jws == null)
            return new KidAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed, "Empty JWS body."));

        // 2. Validate JWS structure and decode header
        var validation = jwsService.Validate(jws);
        if (validation.Status == JwsValidationStatus.Malformed)
            return new KidAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed,
                    validation.ErrorMessage ?? "JWS validation failed."));

        // 3. Must use kid (not jwk)
        if (validation.Header?.Kid == null)
            return new KidAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed,
                    "Request must use 'kid' in the JWS protected header."));

        // 4. Validate nonce
        if (string.IsNullOrEmpty(validation.Header.Nonce) ||
            !nonceService.ValidateAndConsume(validation.Header.Nonce))
            return new KidAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.BadNonce,
                    "Invalid or expired nonce. Retry with a fresh nonce from the Replay-Nonce header."));

        // 5. Validate URL matches the request URL.
        // AcmeUrl encodes the path; feed it the decoded form so we do not double encode.
        // Compare via NormalizeAcmeUrl so a client that decodes the URL before
        // including it in the JWS url header still matches (see helper docs).
        var expectedUrl = AcmeUrl(Request.Path.Value ?? string.Empty);
        if (NormalizeAcmeUrl(validation.Header.Url) != NormalizeAcmeUrl(expectedUrl))
            return new KidAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed,
                    "JWS header 'url' does not match the request URL."));

        // 6-8. Resolve the account named by the kid URL and verify the signature against its
        // stored key. Shared with the revoke-cert kid path via ResolveAndVerifyKidAsync.
        var (account, kidError) = await ResolveAndVerifyKidAsync(
            jwsService, accountService, validation, cancellationToken);
        if (kidError != null)
            return new KidAuthResult(false, ErrorResult: kidError);

        return new KidAuthResult(true, account, validation.PayloadBytes);
    }

    /// <summary>
    /// Result of revoke-cert JWS authentication (RFC 8555 §7.6), which accepts either the
    /// owning account key (kid) or the certificate's own key pair (jwk). Exactly one of
    /// <see cref="Account"/> (kid) or <see cref="JwkJson"/> (jwk) is set on success.
    /// </summary>
    protected sealed record RevocationAuthResult(
        bool IsAuthenticated,
        AcmeAccount? Account = null,
        string? JwkJson = null,
        byte[]? PayloadBytes = null,
        IActionResult? ErrorResult = null);

    /// <summary>
    /// Authenticates a revoke-cert JWS request. RFC 8555 §7.6 permits two signer identities:
    /// the account key (kid) of the account that owns the certificate, or the certificate's own
    /// key pair (jwk). For kid the account key is looked up and the signature verified here; for
    /// jwk the embedded key already verified the signature in <see cref="JwsService.Validate"/>,
    /// and the caller must still confirm the key belongs to the certificate being revoked.
    /// </summary>
    protected async Task<RevocationAuthResult> AuthenticateRevocationJwsAsync(
        JwsService jwsService,
        NonceService nonceService,
        AccountService accountService,
        CancellationToken cancellationToken)
    {
        // 1. Read and parse JWS body
        var body = await new StreamReader(Request.Body).ReadToEndAsync(cancellationToken);
        JwsFlattenedRequest? jws;
        try
        {
            jws = JsonSerializer.Deserialize<JwsFlattenedRequest>(body);
        }
        catch (JsonException)
        {
            return new RevocationAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed, "Invalid JWS JSON."));
        }

        if (jws == null)
            return new RevocationAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed, "Empty JWS body."));

        // 2. Validate JWS structure and decode header
        var validation = jwsService.Validate(jws);
        if (validation.Status == JwsValidationStatus.Malformed || validation.Header == null)
            return new RevocationAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed,
                    validation.ErrorMessage ?? "JWS validation failed."));

        // 3. Validate nonce
        if (string.IsNullOrEmpty(validation.Header.Nonce) ||
            !nonceService.ValidateAndConsume(validation.Header.Nonce))
            return new RevocationAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.BadNonce,
                    "Invalid or expired nonce. Retry with a fresh nonce from the Replay-Nonce header."));

        // 4. Validate URL matches the request URL
        var expectedUrl = AcmeUrl(Request.Path.Value ?? string.Empty);
        if (NormalizeAcmeUrl(validation.Header.Url) != NormalizeAcmeUrl(expectedUrl))
            return new RevocationAuthResult(false,
                ErrorResult: AcmeError(400, AcmeErrorType.Malformed,
                    "JWS header 'url' does not match the request URL."));

        // 5. Branch on signer identity (RFC 8555 §7.6)
        if (validation.RequiresKeyLookup)
        {
            // kid — account key. Resolve and verify against the stored account key.
            var (account, kidError) = await ResolveAndVerifyKidAsync(
                jwsService, accountService, validation, cancellationToken);
            if (kidError != null)
                return new RevocationAuthResult(false, ErrorResult: kidError);

            return new RevocationAuthResult(true, Account: account, PayloadBytes: validation.PayloadBytes);
        }

        // jwk — the certificate's own key. Validate already verified the signature against the
        // embedded key; the controller confirms the key matches the certificate being revoked.
        return new RevocationAuthResult(true, JwkJson: validation.JwkJson, PayloadBytes: validation.PayloadBytes);
    }

    /// <summary>
    /// Resolves the account named by a kid JWS and verifies the request signature against the
    /// account's stored key. Fails closed: a kid result missing the material needed to verify is
    /// rejected rather than treated as authenticated. Shared by the endpoints that authenticate
    /// with kid and by the revoke-cert kid path.
    /// </summary>
    private async Task<(AcmeAccount? Account, IActionResult? Error)> ResolveAndVerifyKidAsync(
        JwsService jwsService,
        AccountService accountService,
        JwsValidationResult validation,
        CancellationToken cancellationToken)
    {
        if (validation.Header?.Kid == null)
            return (null, AcmeError(400, AcmeErrorType.Malformed,
                "Request must use 'kid' in the JWS protected header."));

        // Extract accountId from kid URL: https://host/acme/{template}/acct/{accountId}
        string accountId;
        try
        {
            var kidUri = new Uri(validation.Header.Kid);
            var segments = kidUri.AbsolutePath.Split('/');
            var acctIndex = Array.IndexOf(segments, "acct");
            if (acctIndex < 0 || acctIndex + 1 >= segments.Length)
                throw new FormatException("No 'acct' segment found");
            accountId = segments[acctIndex + 1];
        }
        catch
        {
            return (null, AcmeError(400, AcmeErrorType.Malformed, "Invalid kid URL format."));
        }

        var account = await accountService.FindByAccountIdAsync(accountId, cancellationToken);
        if (account == null)
            return (null, AcmeError(401, AcmeErrorType.AccountDoesNotExist, "Account not found."));

        // RFC 8555 §7.3.6 names this status exactly: "If a server receives a POST or
        // POST-as-GET from a deactivated account, it MUST return an error response with
        // status code 401 (Unauthorized)". 401, not the 403 the signature failure below
        // returns: that one is §6.2 territory, a key that does not match the account,
        // and the two must stay distinguishable to a client reading the status alone.
        if (account.Status != "valid")
            return (null, AcmeError(401, AcmeErrorType.Unauthorized,
                $"The account is {account.Status} and can no longer be used. " +
                "Deactivation is permanent; register a new account to continue."));

        // Verify signature against stored key. Mandatory for kid requests and must fail closed:
        // JwsService.Validate returns a kid result WITHOUT checking the signature (it cannot — the
        // key is looked up here), so a result missing the material needed to verify is rejected
        // rather than allowed to fall through to an authenticated result.
        if (!validation.RequiresKeyLookup ||
            validation.SigningInput == null ||
            validation.SignatureBytes == null)
            return (null, AcmeError(400, AcmeErrorType.Malformed,
                "kid request did not provide a verifiable signature."));

        var verified = jwsService.VerifyWithStoredKey(
            validation.Header.Alg,
            account.JwkJson,
            validation.SigningInput,
            validation.SignatureBytes);

        if (!verified)
            return (null, AcmeError(403, AcmeErrorType.Unauthorized,
                "JWS signature verification failed."));

        return (account, null);
    }
}
