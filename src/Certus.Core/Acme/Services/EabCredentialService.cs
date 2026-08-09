using System.Security.Cryptography;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.ActiveDirectory;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Manages external account binding credentials (RFC 8555 §7.3.4): creation,
/// secret regeneration, revocation, and the two enforcement checks the ACME
/// surface needs, binding verification at new-account and the order time gate
/// for accounts bound to a revoked or expired credential. The MAC secret is
/// stored only in protected form (<see cref="ISecretProtector"/>); the
/// plaintext exists solely in the create and regenerate return values.
/// </summary>
public sealed class EabCredentialService
{
    private readonly CertusDbContext _db;
    private readonly ISecretProtector _protector;
    private readonly ILogger<EabCredentialService> _logger;

    public EabCredentialService(
        CertusDbContext db,
        ISecretProtector protector,
        ILogger<EabCredentialService> logger)
    {
        _db = db;
        _protector = protector;
        _logger = logger;
    }

    /// <summary>
    /// Creates a credential and returns it together with the plaintext secret,
    /// the only time the secret is ever available. Namespaces, when given,
    /// must already be normalized (AllowedDomainsPolicy.ValidateAndNormalize).
    /// </summary>
    public async Task<(EabCredential Credential, string Secret)> CreateAsync(
        string name,
        DateTime? expiresAt = null,
        IReadOnlyList<string>? normalizedNamespaces = null,
        CancellationToken cancellationToken = default)
    {
        var trimmed = name.Trim();
        if (trimmed.Length == 0)
            throw new ArgumentException("Credential name must not be empty.", nameof(name));

        var secret = GenerateSecret();
        var credential = new EabCredential
        {
            Name = trimmed,
            SecretProtected = _protector.Protect(secret),
            ExpiresAt = UtcWallClock.Normalize(expiresAt),
            NamespacesJson = JsonSerializer.Serialize(
                normalizedNamespaces ?? Array.Empty<string>()),
            CreatedAt = DateTime.UtcNow,
        };

        // Two attempts on the practically impossible 128 bit kid collision:
        // the unique index is the arbiter, the same pattern as the account id.
        for (var attempt = 0; ; attempt++)
        {
            credential.KeyId = GenerateKeyId();
            _db.EabCredentials.Add(credential);
            try
            {
                await _db.SaveChangesAsync(cancellationToken);
                break;
            }
            catch (DbUpdateException) when (attempt == 0)
            {
                _db.Entry(credential).State = EntityState.Detached;
            }
        }

        _logger.LogInformation(
            "Created EAB credential '{Name}' with key id {KeyId}{Expiry}",
            credential.Name, credential.KeyId,
            credential.ExpiresAt is { } exp ? $", expires {exp:u}" : "");

        return (credential, secret);
    }

    /// <summary>
    /// Replaces a credential's name, expiry, and domain namespace. The key id
    /// and secret stay, and the change is in force for the next ACME request,
    /// because the order gate reads the row per request. Moving the expiry
    /// forward (or clearing it) revives an expired credential by design; a
    /// revoked credential is refused, revocation is terminal. Namespaces
    /// must already be normalized (AllowedDomainsPolicy.ValidateAndNormalize).
    /// </summary>
    public async Task<EabUpdateResult> UpdateAsync(
        int id,
        string name,
        DateTime? expiresAt,
        IReadOnlyList<string> normalizedNamespaces,
        CancellationToken cancellationToken = default)
    {
        var trimmed = name.Trim();
        if (trimmed.Length == 0)
            throw new ArgumentException("Credential name must not be empty.", nameof(name));

        var credential = await _db.EabCredentials
            .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        if (credential == null)
            return new EabUpdateResult(EabUpdateOutcome.NotFound, null);

        if (credential.Status != "active")
        {
            _logger.LogWarning(
                "Refused to update revoked EAB credential {KeyId}; revocation is terminal",
                credential.KeyId);
            return new EabUpdateResult(EabUpdateOutcome.Revoked, credential);
        }

        credential.Name = trimmed;
        credential.ExpiresAt = UtcWallClock.Normalize(expiresAt);
        credential.NamespacesJson = JsonSerializer.Serialize(normalizedNamespaces);
        credential.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Updated EAB credential '{Name}' ({KeyId}): expiry {Expiry}, namespace [{Namespaces}]",
            credential.Name, credential.KeyId,
            credential.ExpiresAt is { } exp ? exp.ToString("u") : "none",
            string.Join(", ", normalizedNamespaces));

        return new EabUpdateResult(EabUpdateOutcome.Updated, credential);
    }

    /// <summary>
    /// Links an Active Directory principal to a credential as its owner, for
    /// display and audit only: nothing enforces against the link. The caller
    /// resolves the principal first (the admin endpoint re-resolves the SID
    /// it was sent), so the stored name and type are the directory's answer,
    /// not the client's claim. A revoked credential is refused; revocation
    /// is terminal.
    /// </summary>
    public Task<EabUpdateResult> SetPrincipalAsync(
        int id,
        AdPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        return ChangePrincipalAsync(id, principal, cancellationToken);
    }

    /// <summary>
    /// Removes a credential's owner link. Idempotent on an unlinked
    /// credential; a revoked one is refused like every other change.
    /// </summary>
    public Task<EabUpdateResult> ClearPrincipalAsync(
        int id,
        CancellationToken cancellationToken = default)
    {
        return ChangePrincipalAsync(id, null, cancellationToken);
    }

    /// <summary>
    /// The shared body of the two owner operations, so the not found and
    /// terminal revocation rules are stated once. Null clears the link.
    /// </summary>
    private async Task<EabUpdateResult> ChangePrincipalAsync(
        int id,
        AdPrincipal? principal,
        CancellationToken cancellationToken)
    {
        var credential = await _db.EabCredentials
            .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        if (credential == null)
            return new EabUpdateResult(EabUpdateOutcome.NotFound, null);

        if (credential.Status != "active")
        {
            _logger.LogWarning(
                "Refused to change the owner of revoked EAB credential {KeyId}; revocation is terminal",
                credential.KeyId);
            return new EabUpdateResult(EabUpdateOutcome.Revoked, credential);
        }

        // Clearing an already unlinked credential is a harmless no op; skip
        // the write so UpdatedAt does not move for a change that is none.
        if (principal == null && credential.AdPrincipalSid == null)
            return new EabUpdateResult(EabUpdateOutcome.Updated, credential);

        if (principal == null)
        {
            _logger.LogInformation(
                "Unlinked EAB credential '{Name}' ({KeyId}) from {Type} '{Principal}'",
                credential.Name, credential.KeyId,
                credential.AdPrincipalType, credential.AdPrincipalName);
        }
        else
        {
            _logger.LogInformation(
                "Linked EAB credential '{Name}' ({KeyId}) to {Type} '{Principal}' ({Sid})",
                credential.Name, credential.KeyId,
                principal.Type, principal.Name, principal.Sid);
        }

        credential.AdPrincipalSid = principal?.Sid;
        credential.AdPrincipalName = principal?.Name;
        credential.AdPrincipalType = principal?.Type;
        credential.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);

        return new EabUpdateResult(EabUpdateOutcome.Updated, credential);
    }

    /// <summary>
    /// Rotates the secret on an existing credential. The key id and the
    /// configuration stay; every copy of the old secret stops verifying.
    /// A revoked or expired credential is refused: revocation is terminal,
    /// and a fresh secret on an expired credential could never verify, so
    /// handing one out would only mislead. The outcome names each case so
    /// the admin API can map it to a status code without inspecting nulls.
    /// </summary>
    public async Task<EabRegenerateResult> RegenerateSecretAsync(
        int id,
        CancellationToken cancellationToken = default)
    {
        var credential = await _db.EabCredentials
            .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        if (credential == null)
            return new EabRegenerateResult(EabRegenerateOutcome.NotFound, null, null);

        if (credential.Status != "active")
        {
            _logger.LogWarning(
                "Refused to regenerate the secret of revoked EAB credential {KeyId}",
                credential.KeyId);
            return new EabRegenerateResult(EabRegenerateOutcome.Revoked, credential, null);
        }

        if (credential.ExpiresAt is { } expiry && expiry <= DateTime.UtcNow)
        {
            _logger.LogWarning(
                "Refused to regenerate the secret of expired EAB credential {KeyId}; " +
                "the new secret could never verify",
                credential.KeyId);
            return new EabRegenerateResult(EabRegenerateOutcome.Expired, credential, null);
        }

        var secret = GenerateSecret();
        credential.SecretProtected = _protector.Protect(secret);
        credential.SecretRegeneratedAt = DateTime.UtcNow;
        credential.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Regenerated the secret of EAB credential '{Name}' ({KeyId}); the previous secret no longer verifies",
            credential.Name, credential.KeyId);

        return new EabRegenerateResult(EabRegenerateOutcome.Regenerated, credential, secret);
    }

    /// <summary>
    /// Revokes a credential: new registrations with it are rejected and new
    /// orders from accounts bound to it are suspended. Idempotent; returns
    /// the credential in its revoked state, or null for an unknown id.
    /// </summary>
    public async Task<EabCredential?> RevokeAsync(
        int id, CancellationToken cancellationToken = default)
    {
        var credential = await _db.EabCredentials
            .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        if (credential == null)
            return null;

        if (credential.Status != "revoked")
        {
            credential.Status = "revoked";
            credential.RevokedAt = DateTime.UtcNow;
            credential.UpdatedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync(cancellationToken);

            _logger.LogInformation(
                "Revoked EAB credential '{Name}' ({KeyId}); new registrations and orders from its accounts are suspended",
                credential.Name, credential.KeyId);
        }

        return credential;
    }

    /// <summary>Finds a credential by its key identifier.</summary>
    public Task<EabCredential?> FindByKeyIdAsync(
        string keyId,
        CancellationToken cancellationToken = default)
    {
        return _db.EabCredentials
            .FirstOrDefaultAsync(c => c.KeyId == keyId, cancellationToken);
    }

    /// <summary>
    /// The dashboard credential list, newest first, each row carrying how many
    /// accounts are bound to it. The stored secret is not part of the
    /// projection, so it cannot leak into a list response by accident.
    /// </summary>
    public async Task<IReadOnlyList<EabCredentialSummary>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        var rows = await _db.EabCredentials
            .AsNoTracking()
            .OrderByDescending(c => c.CreatedAt)
            .ThenByDescending(c => c.Id)
            .Select(c => new
            {
                c.Id,
                c.KeyId,
                c.Name,
                c.Status,
                c.ExpiresAt,
                c.NamespacesJson,
                c.AdPrincipalSid,
                c.AdPrincipalName,
                c.AdPrincipalType,
                c.CreatedAt,
                c.UpdatedAt,
                c.RevokedAt,
                c.SecretRegeneratedAt,
                BoundAccountCount =
                    _db.AcmeAccounts.Count(a => a.ExternalAccountCredentialId == c.Id),
            })
            .ToListAsync(cancellationToken);

        return rows
            .Select(r => new EabCredentialSummary(
                r.Id,
                r.KeyId,
                r.Name,
                r.Status,
                r.ExpiresAt,
                ParseNamespaces(r.NamespacesJson, r.KeyId),
                r.AdPrincipalSid == null
                    ? null
                    : new EabCredentialPrincipal(
                        r.AdPrincipalSid,
                        r.AdPrincipalName ?? string.Empty,
                        r.AdPrincipalType ?? string.Empty),
                r.CreatedAt,
                r.UpdatedAt,
                r.RevokedAt,
                r.SecretRegeneratedAt,
                r.BoundAccountCount))
            .ToList();
    }

    /// <summary>
    /// The accounts bound to one credential, newest first, for the dashboard
    /// row expander. Returns null when no credential has this id, so the API
    /// can tell "unknown credential" from "no accounts yet".
    /// </summary>
    public async Task<IReadOnlyList<EabBoundAccountSummary>?> GetBoundAccountsAsync(
        int credentialId,
        CancellationToken cancellationToken = default)
    {
        var exists = await _db.EabCredentials
            .AnyAsync(c => c.Id == credentialId, cancellationToken);
        if (!exists)
            return null;

        var rows = await _db.AcmeAccounts
            .AsNoTracking()
            .Where(a => a.ExternalAccountCredentialId == credentialId)
            .OrderByDescending(a => a.CreatedAt)
            .ThenByDescending(a => a.Id)
            .Select(a => new { a.Id, a.AccountId, a.Status, a.ContactJson, a.CreatedAt })
            .ToListAsync(cancellationToken);

        return rows
            .Select(r => new EabBoundAccountSummary(
                r.Id, r.AccountId, r.Status,
                AccountService.ParseContacts(r.ContactJson), r.CreatedAt))
            .ToList();
    }

    /// <summary>
    /// Runs the full RFC 8555 §7.3.4 verification of an externalAccountBinding
    /// against the stored credentials. <paramref name="outerJwkJson"/> is the
    /// account key that signed the outer JWS; <paramref name="expectedUrl"/>
    /// is the outer JWS url the endpoint already validated.
    /// </summary>
    public async Task<EabVerificationResult> VerifyBindingAsync(
        string outerJwkJson,
        string expectedUrl,
        JsonElement eab,
        CancellationToken cancellationToken = default)
    {
        var parse = EabJwsVerifier.Parse(eab, expectedUrl);
        if (parse.Parsed == null)
        {
            var outcome = parse.Failure == EabJwsVerifier.EabParseFailure.UnsupportedAlgorithm
                ? EabVerificationOutcome.UnsupportedAlgorithm
                : EabVerificationOutcome.Malformed;
            return new EabVerificationResult(outcome, null, parse.Error);
        }

        var parsed = parse.Parsed;
        var credential = await FindByKeyIdAsync(parsed.KeyId, cancellationToken);
        if (credential == null)
        {
            return Unauthorized(null,
                "Unknown external account key identifier.");
        }

        if (credential.Status != "active")
        {
            return Unauthorized(credential,
                "The external account credential has been revoked. Contact your administrator.");
        }

        if (credential.ExpiresAt is { } expiresAt && expiresAt <= DateTime.UtcNow)
        {
            return Unauthorized(credential,
                $"The external account credential expired on {expiresAt:u}. Contact your administrator.");
        }

        var secret = _protector.TryUnprotect(credential.SecretProtected);
        if (secret == null)
        {
            // Fail closed. The usual cause is a data directory restored onto
            // a different machine, which the keyring cannot follow.
            _logger.LogError(
                "The stored secret of EAB credential '{Name}' ({KeyId}) could not be decrypted; " +
                "regenerate the credential secret from the dashboard",
                credential.Name, credential.KeyId);
            return Unauthorized(credential,
                "The external account credential is unusable on this server. Contact your administrator.");
        }

        byte[] key;
        try
        {
            key = JwsService.Base64UrlDecode(secret);
        }
        catch (FormatException)
        {
            _logger.LogError(
                "The stored secret of EAB credential '{Name}' ({KeyId}) is not valid base64url; " +
                "regenerate the credential secret from the dashboard",
                credential.Name, credential.KeyId);
            return Unauthorized(credential,
                "The external account credential is unusable on this server. Contact your administrator.");
        }

        if (!JwsService.VerifyMac(parsed.Alg, key, parsed.SigningInput, parsed.SignatureBytes))
        {
            return Unauthorized(credential,
                "External account binding signature verification failed.");
        }

        if (!EabJwsVerifier.PayloadKeyMatchesOuterKey(parsed.PayloadBytes, outerJwkJson))
        {
            return new EabVerificationResult(EabVerificationOutcome.Malformed, null,
                "The externalAccountBinding payload key does not match the account key.");
        }

        return new EabVerificationResult(EabVerificationOutcome.Verified, credential, null);
    }

    /// <summary>
    /// The order time gate for a bound account: one indexed primary key query
    /// answering whether the credential still permits orders, and inside what
    /// domain namespace. Runs only for accounts that carry a binding, so
    /// unbound (grandfathered) accounts pay nothing. The namespace rides the
    /// same query so the order path never needs a second credential lookup.
    /// </summary>
    public async Task<EabBindingGate> GetBindingGateAsync(
        int credentialId,
        CancellationToken cancellationToken = default)
    {
        var credential = await _db.EabCredentials
            .Where(c => c.Id == credentialId)
            .Select(c => new { c.Name, c.Status, c.ExpiresAt, c.NamespacesJson })
            .FirstOrDefaultAsync(cancellationToken);

        if (credential == null)
            return new EabBindingGate(
                EabBindingGateStatus.Missing, string.Empty, null, Array.Empty<string>());

        if (credential.Status != "active")
            return new EabBindingGate(
                EabBindingGateStatus.Revoked, credential.Name, null, Array.Empty<string>());

        if (credential.ExpiresAt is { } expiresAt && expiresAt <= DateTime.UtcNow)
            return new EabBindingGate(
                EabBindingGateStatus.Expired, credential.Name, expiresAt, Array.Empty<string>());

        return new EabBindingGate(
            EabBindingGateStatus.Allowed, credential.Name, credential.ExpiresAt,
            ParseNamespaces(credential.NamespacesJson, credential.Name));
    }

    /// <summary>
    /// Parses a stored namespace column. The column is only ever written by
    /// this service from a normalized list, so an unparseable value means the
    /// database was edited by hand; treat it as no extra restriction and say
    /// so loudly, the fail open stance AllowedDomainsPolicy takes for
    /// unusable hand edited state.
    /// </summary>
    private IReadOnlyList<string> ParseNamespaces(string namespacesJson, string credentialLabel)
    {
        try
        {
            return JsonSerializer.Deserialize<string[]>(namespacesJson) ?? Array.Empty<string>();
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex,
                "The stored namespace of EAB credential '{Credential}' is not a JSON string " +
                "array; treating it as unrestricted until the row is fixed",
                credentialLabel);
            return Array.Empty<string>();
        }
    }

    private static EabVerificationResult Unauthorized(EabCredential? credential, string detail)
    {
        return new EabVerificationResult(EabVerificationOutcome.Unauthorized, credential, detail);
    }

    private static string GenerateKeyId()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string GenerateSecret()
    {
        // 32 bytes: sized for HS256, the algorithm every mainstream ACME
        // client signs EAB with. Handed out base64url (43 characters), the
        // form certbot, win-acme, acme.sh, and cert-manager expect.
        return JwsService.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    }
}

/// <summary>
/// A dashboard row of the credential list. EffectiveStatus is the display
/// state: "revoked" is terminal and wins, then "expired", then "active", so
/// every consumer renders the same triage color for the same row.
/// </summary>
public sealed record EabCredentialSummary(
    int Id,
    string KeyId,
    string Name,
    string Status,
    DateTime? ExpiresAt,
    IReadOnlyList<string> Namespaces,
    EabCredentialPrincipal? AdPrincipal,
    DateTime CreatedAt,
    DateTime? UpdatedAt,
    DateTime? RevokedAt,
    DateTime? SecretRegeneratedAt,
    int BoundAccountCount)
{
    /// <summary>"revoked", "expired", or "active", in that precedence.</summary>
    public string EffectiveStatus =>
        Status == "revoked" ? "revoked"
        : ExpiresAt is { } expiresAt && expiresAt <= DateTime.UtcNow ? "expired"
        : "active";
}

/// <summary>
/// The linked AD owner of a credential row, display and audit only. The name
/// and type were resolved when the link was made; the SID is the identity.
/// </summary>
public sealed record EabCredentialPrincipal(
    string Sid,
    string Name,
    string Type);

/// <summary>An account bound to a credential, for the dashboard row expander.</summary>
public sealed record EabBoundAccountSummary(
    int Id,
    string AccountId,
    string Status,
    string[]? Contacts,
    DateTime CreatedAt);

/// <summary>
/// How a credential change request ended. Shared by the field replacement
/// (<see cref="EabCredentialService.UpdateAsync"/>) and the owner link
/// operations, which all obey the same not found and terminal revocation
/// rules.
/// </summary>
public enum EabUpdateOutcome
{
    /// <summary>The requested change was applied.</summary>
    Updated,

    /// <summary>No credential has this id.</summary>
    NotFound,

    /// <summary>The credential is revoked; revocation is terminal.</summary>
    Revoked
}

/// <summary>Result of a credential change (update, set owner, clear owner).</summary>
public sealed record EabUpdateResult(
    EabUpdateOutcome Outcome,
    EabCredential? Credential);

/// <summary>How a secret regeneration request ended.</summary>
public enum EabRegenerateOutcome
{
    /// <summary>The secret was rotated; the result carries the new plaintext.</summary>
    Regenerated,

    /// <summary>No credential has this id.</summary>
    NotFound,

    /// <summary>The credential is revoked; revocation is terminal.</summary>
    Revoked,

    /// <summary>
    /// The credential is past its expiry; a new secret could never verify.
    /// </summary>
    Expired
}

/// <summary>
/// Result of <see cref="EabCredentialService.RegenerateSecretAsync"/>.
/// <see cref="Secret"/> is the new plaintext, present only on
/// <see cref="EabRegenerateOutcome.Regenerated"/> and never stored.
/// </summary>
public sealed record EabRegenerateResult(
    EabRegenerateOutcome Outcome,
    EabCredential? Credential,
    string? Secret);

/// <summary>How an externalAccountBinding verification ended.</summary>
public enum EabVerificationOutcome
{
    /// <summary>The binding verified; the account may be bound to the credential.</summary>
    Verified,

    /// <summary>Structurally invalid: respond 400 malformed.</summary>
    Malformed,

    /// <summary>MAC algorithm not accepted: respond 400 badSignatureAlgorithm.</summary>
    UnsupportedAlgorithm,

    /// <summary>
    /// Unknown key id, revoked or expired credential, unreadable stored
    /// secret, or MAC mismatch: respond 403 unauthorized.
    /// </summary>
    Unauthorized
}

/// <summary>Result of <see cref="EabCredentialService.VerifyBindingAsync"/>.</summary>
public sealed record EabVerificationResult(
    EabVerificationOutcome Outcome,
    EabCredential? Credential,
    string? Detail);

/// <summary>Answer of the order time gate for a bound account.</summary>
public enum EabBindingGateStatus
{
    /// <summary>The credential is active; orders proceed.</summary>
    Allowed,

    /// <summary>The credential was revoked; orders are suspended.</summary>
    Revoked,

    /// <summary>The credential is past its expiry; orders are suspended.</summary>
    Expired,

    /// <summary>
    /// The credential row is gone. Should be unreachable (the foreign key
    /// restricts deletes), so it fails closed like Revoked.
    /// </summary>
    Missing
}

/// <summary>
/// Result of <see cref="EabCredentialService.GetBindingGateAsync"/>.
/// Namespaces is the credential's normalized domain namespace, empty when
/// the credential adds no restriction; it is only populated on
/// <see cref="EabBindingGateStatus.Allowed"/>, the one state that orders.
/// </summary>
public sealed record EabBindingGate(
    EabBindingGateStatus Status,
    string Name,
    DateTime? ExpiresAt,
    IReadOnlyList<string> Namespaces);
