using Certus.Core.Acme.Services;
using Certus.Core.ActiveDirectory;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.AcmeAdmin;

/// <summary>
/// EAB credential administration for the ACME dashboard tab (issue #129).
/// The MAC secret appears in exactly two responses, create and regenerate,
/// and is never stored or served in plaintext anywhere else: the list
/// projection does not include the protected column, and there is no GET
/// that returns a stored secret. Revocation is terminal; the recovery for a
/// lost secret is regenerate (same key id), the recovery for a compromised
/// credential is revoke and create a new one. This controller also carries
/// the directory principal search for the owner picker (issue #132), so the
/// AdminOnly policy on this class is what gates Active Directory
/// enumeration.
/// </summary>
[ApiController]
[Route("api/acme/credentials")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class EabCredentialsController : ControllerBase
{
    private readonly EabCredentialService _credentialService;
    private readonly IAdPrincipalLookup _principalLookup;

    public EabCredentialsController(
        EabCredentialService credentialService,
        IAdPrincipalLookup principalLookup)
    {
        _credentialService = credentialService;
        _principalLookup = principalLookup;
    }

    /// <summary>
    /// GET /api/acme/credentials: every credential, newest first, with its
    /// bound account count. Never carries a secret.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        return Ok(new { credentials = await _credentialService.ListAsync(ct) });
    }

    /// <summary>
    /// POST /api/acme/credentials: create a credential. The response is the
    /// only time this secret is ever available; the dashboard shows it once
    /// and the API never returns it again. Domains, when given, become the
    /// credential's namespace: its accounts may only order inside those
    /// domains (each entry covering itself and its subdomains), across every
    /// template. An empty list adds no restriction.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> Create(
        [FromBody] CreateEabCredentialRequest request, CancellationToken ct)
    {
        var error = ValidateCredentialFields(
            request.Name, request.ExpiresAt, request.Domains ?? [],
            out var name, out var expiresAt, out var namespaces);
        if (error != null)
            return error;

        var (credential, secret) = await _credentialService.CreateAsync(
            name, expiresAt, namespaces, ct);

        // 201 with no Location header: there is no GET for a single
        // credential (the list is the read surface), so advertising a URL
        // that answers 404 would only mislead.
        return StatusCode(201, CredentialWithSecret(credential, secret));
    }

    /// <summary>
    /// PUT /api/acme/credentials/{id}: replace the name, expiry, and domain
    /// namespace. The key id and secret stay, and the change applies to the
    /// next ACME request immediately. Moving the expiry forward, or clearing
    /// it, puts an expired credential back in use by design; a revoked
    /// credential can no longer be changed.
    /// </summary>
    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(
        int id, [FromBody] UpdateEabCredentialRequest request, CancellationToken ct)
    {
        // The update is a full replacement, so an omitted domains field
        // would silently clear the namespace, a security widening a caller
        // who only meant to rename must not trip into. Removing the
        // namespace requires saying so with an explicit empty list.
        if (request.Domains == null)
            return BadRequest(new
            {
                error = "Include domains: send the full namespace list, " +
                        "or an empty list to remove the namespace.",
            });

        var error = ValidateCredentialFields(
            request.Name, request.ExpiresAt, request.Domains,
            out var name, out var expiresAt, out var namespaces);
        if (error != null)
            return error;

        var result = await _credentialService.UpdateAsync(id, name, expiresAt, namespaces, ct);
        return result.Outcome switch
        {
            EabUpdateOutcome.NotFound =>
                NotFound(new { error = "No credential has this id." }),
            EabUpdateOutcome.Revoked =>
                Conflict(new { error = "The credential is revoked and can no longer be changed." }),
            _ => Ok(new
            {
                id = result.Credential!.Id,
                keyId = result.Credential.KeyId,
                name = result.Credential.Name,
                status = result.Credential.Status,
                expiresAt = result.Credential.ExpiresAt,
                namespaces,
                updatedAt = result.Credential.UpdatedAt,
                message = "Saved. New ACME requests use the updated credential immediately.",
            }),
        };
    }

    /// <summary>
    /// POST /api/acme/credentials/{id}/regenerate: rotate the secret on the
    /// same key id. Every handed out copy of the old secret stops verifying;
    /// the response is the only time the new secret is available. A revoked
    /// or expired credential is refused: revocation is terminal, and a fresh
    /// secret on an expired credential could never verify.
    /// </summary>
    [HttpPost("{id:int}/regenerate")]
    public async Task<IActionResult> Regenerate(int id, CancellationToken ct)
    {
        var result = await _credentialService.RegenerateSecretAsync(id, ct);
        return result.Outcome switch
        {
            EabRegenerateOutcome.NotFound =>
                NotFound(new { error = "No credential has this id." }),
            EabRegenerateOutcome.Revoked =>
                Conflict(new { error = "The credential is revoked. Create a new credential instead." }),
            EabRegenerateOutcome.Expired =>
                Conflict(new { error = "The credential has expired, so a new secret could not verify. Create a new credential instead." }),
            _ => Ok(CredentialWithSecret(result.Credential!, result.Secret!)),
        };
    }

    /// <summary>
    /// POST /api/acme/credentials/{id}/revoke: terminal. New registrations
    /// with this credential are rejected and new orders from its bound
    /// accounts are suspended from the next request on. Idempotent.
    /// </summary>
    [HttpPost("{id:int}/revoke")]
    public async Task<IActionResult> Revoke(int id, CancellationToken ct)
    {
        var credential = await _credentialService.RevokeAsync(id, ct);
        if (credential == null)
            return NotFound(new { error = "No credential has this id." });

        return Ok(new
        {
            id = credential.Id,
            keyId = credential.KeyId,
            status = credential.Status,
            revokedAt = credential.RevokedAt,
        });
    }

    /// <summary>
    /// GET /api/acme/credentials/{id}/accounts: the accounts bound to this
    /// credential, for the dashboard row expander.
    /// </summary>
    [HttpGet("{id:int}/accounts")]
    public async Task<IActionResult> BoundAccounts(int id, CancellationToken ct)
    {
        var accounts = await _credentialService.GetBoundAccountsAsync(id, ct);
        if (accounts == null)
            return NotFound(new { error = "No credential has this id." });

        return Ok(new { accounts });
    }

    /// <summary>
    /// GET /api/acme/directory-principals?query=: users, computers, and
    /// groups whose account name or common name starts with the query, for
    /// the credential owner picker. Best effort by contract: a host that is
    /// not domain joined or cannot reach the directory answers with an empty
    /// list, never an error, because the owner link is display and audit
    /// only. The leading slash makes the route absolute; the picker searches
    /// the directory, not a credential.
    /// </summary>
    [HttpGet("/api/acme/directory-principals")]
    public async Task<IActionResult> SearchDirectoryPrincipals(
        [FromQuery] string? query, CancellationToken ct)
    {
        var trimmed = query?.Trim() ?? string.Empty;
        var principals = trimmed.Length == 0
            ? Array.Empty<AdPrincipal>()
            : await _principalLookup.SearchAsync(trimmed, ct);

        return Ok(new
        {
            principals = principals.Select(p => new
            {
                sid = p.Sid,
                name = p.Name,
                type = p.Type,
                distinguishedName = p.DistinguishedName,
            }).ToList(),
        });
    }

    /// <summary>
    /// PUT /api/acme/credentials/{id}/principal: link an AD principal to the
    /// credential as its owner, for display and audit only. The server
    /// re-resolves the posted SID before storing, so the recorded name and
    /// type are the directory's answer at link time, not the client's claim;
    /// a SID the directory cannot resolve is refused.
    /// </summary>
    [HttpPut("{id:int}/principal")]
    public async Task<IActionResult> SetPrincipal(
        int id, [FromBody] SetEabPrincipalRequest request, CancellationToken ct)
    {
        var sid = request.Sid?.Trim();
        if (string.IsNullOrEmpty(sid))
            return BadRequest(new { error = "A principal SID is required." });

        var principal = await _principalLookup.ResolveSidAsync(sid, ct);
        if (principal == null)
            return BadRequest(new
            {
                error = "The SID does not resolve to a directory principal. " +
                        "The principal may have been deleted, or the directory " +
                        "may be unreachable from this server.",
            });

        var result = await _credentialService.SetPrincipalAsync(id, principal, ct);
        return PrincipalChangeResult(result, principal);
    }

    /// <summary>
    /// DELETE /api/acme/credentials/{id}/principal: remove the owner link.
    /// Idempotent on a credential that has none.
    /// </summary>
    [HttpDelete("{id:int}/principal")]
    public async Task<IActionResult> ClearPrincipal(int id, CancellationToken ct)
    {
        var result = await _credentialService.ClearPrincipalAsync(id, ct);
        return PrincipalChangeResult(result, null);
    }

    /// <summary>
    /// The shared response mapping of the two owner endpoints, so the not
    /// found and revoked bodies are stated once. A null principal is the
    /// cleared state.
    /// </summary>
    private IActionResult PrincipalChangeResult(EabUpdateResult result, AdPrincipal? principal)
    {
        return result.Outcome switch
        {
            EabUpdateOutcome.NotFound =>
                NotFound(new { error = "No credential has this id." }),
            EabUpdateOutcome.Revoked =>
                Conflict(new { error = "The credential is revoked and can no longer be changed." }),
            _ => Ok(new
            {
                id = result.Credential!.Id,
                keyId = result.Credential.KeyId,
                adPrincipal = principal == null
                    ? null
                    : (object)new
                    {
                        sid = principal.Sid,
                        name = principal.Name,
                        type = principal.Type,
                    },
                updatedAt = result.Credential.UpdatedAt,
            }),
        };
    }

    /// <summary>
    /// The create and regenerate response shape, the only two places a
    /// plaintext secret ever appears.
    /// </summary>
    private static object CredentialWithSecret(EabCredential credential, string secret)
    {
        return new
        {
            id = credential.Id,
            keyId = credential.KeyId,
            name = credential.Name,
            status = credential.Status,
            expiresAt = credential.ExpiresAt,
            createdAt = credential.CreatedAt,
            secretRegeneratedAt = credential.SecretRegeneratedAt,
            secret,
        };
    }

    /// <summary>
    /// The field validation shared by create and update, so the two cannot
    /// drift on what a valid credential looks like. Returns the 400 result
    /// to send, or null when the fields are usable (then the out parameters
    /// carry the trimmed name, normalized expiry, and normalized namespace).
    /// </summary>
    private IActionResult? ValidateCredentialFields(
        string? rawName,
        DateTime? rawExpiresAt,
        List<string> domains,
        out string name,
        out DateTime? expiresAt,
        out List<string> namespaces)
    {
        name = rawName?.Trim() ?? string.Empty;
        expiresAt = null;
        namespaces = [];

        if (name.Length == 0)
            return BadRequest(new { error = "A credential name is required." });
        if (name.Length > 200)
            return BadRequest(new { error = "The name must be 200 characters or fewer." });

        expiresAt = UtcWallClock.Normalize(rawExpiresAt);
        if (expiresAt is { } expiry && expiry <= DateTime.UtcNow)
            return BadRequest(new { error = "The expiry must be in the future." });

        var (normalized, invalid) = AllowedDomainsPolicy.ValidateAndNormalize(domains);
        if (invalid.Count > 0)
            return BadRequest(InvalidEntriesBody(invalid));

        namespaces = normalized;
        return null;
    }

    /// <summary>
    /// The 400 body for unusable namespace entries: the same
    /// { error, invalidEntries } shape as the settings allowed domains
    /// endpoint, so the frontend renders both with one idiom.
    /// </summary>
    private static object InvalidEntriesBody(
        IReadOnlyList<(string Entry, string Reason)> invalid)
    {
        return new
        {
            error = "Some entries are not usable domain names.",
            invalidEntries = invalid
                .Select(i => new { entry = i.Entry, reason = i.Reason })
                .ToList(),
        };
    }
}

/// <summary>
/// Request body for creating a credential. ExpiresAt is optional; a value
/// without an offset is taken as UTC. Domains is the optional namespace;
/// entries follow the allowed domain list rules (bare names, no wildcards).
/// </summary>
public sealed record CreateEabCredentialRequest(
    string? Name,
    DateTime? ExpiresAt = null,
    List<string>? Domains = null);

/// <summary>
/// Request body for updating a credential: a full replacement of the name,
/// expiry, and namespace. An omitted or null ExpiresAt clears the expiry;
/// Domains must be sent explicitly (an empty list removes the namespace),
/// so omitting it cannot silently widen what the credential may order.
/// </summary>
public sealed record UpdateEabCredentialRequest(
    string? Name,
    DateTime? ExpiresAt = null,
    List<string>? Domains = null);

/// <summary>
/// Request body for linking an owner principal: only the SID travels. The
/// server resolves the name and type itself before storing anything.
/// </summary>
public sealed record SetEabPrincipalRequest(string? Sid);
