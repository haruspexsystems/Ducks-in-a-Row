using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Manages the ACME order lifecycle: creation, authorization, finalization, and certificate issuance.
/// RFC 8555 §7.4
/// </summary>
public sealed class OrderService
{
    private readonly CertusDbContext _db;
    private readonly IAdcsClient _adcsClient;
    private readonly CertificateSyncTrigger _syncTrigger;
    private readonly ILogger<OrderService> _logger;

    /// <summary>Order expiration: 7 days from creation.</summary>
    private static readonly TimeSpan OrderLifetime = TimeSpan.FromDays(7);

    /// <summary>
    /// Delay before the post issuance inventory sync. Long enough to coalesce
    /// a burst of issuances into one CA pull, short enough that a new
    /// certificate shows up on the dashboard while the operator is looking.
    /// </summary>
    private static readonly TimeSpan PostIssuanceSyncDelay = TimeSpan.FromSeconds(10);

    public OrderService(
        CertusDbContext db,
        IAdcsClient adcsClient,
        CertificateSyncTrigger syncTrigger,
        ILogger<OrderService> logger)
    {
        _db = db;
        _adcsClient = adcsClient;
        _syncTrigger = syncTrigger;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new order with authorizations and challenges.
    /// RFC 8555 §7.4
    /// </summary>
    public async Task<AcmeOrder> CreateOrderAsync(
        AcmeAccount account,
        string template,
        AcmeIdentifier[] identifiers,
        DateTime? notBefore,
        DateTime? notAfter,
        CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var expires = now.Add(OrderLifetime);

        var order = new AcmeOrder
        {
            OrderId = GenerateId(),
            AccountId = account.Id,
            Status = "pending",
            TemplateId = template,
            IdentifiersJson = JsonSerializer.Serialize(identifiers),
            NotBefore = notBefore,
            NotAfter = notAfter,
            CreatedAt = now,
            ExpiresAt = expires
        };

        // Create one authorization per identifier
        foreach (var identifier in identifiers)
        {
            var isWildcard = identifier.Value.StartsWith("*.", StringComparison.Ordinal);
            var authz = new AcmeAuthorization
            {
                AuthorizationId = GenerateId(),
                IdentifierType = identifier.Type,
                IdentifierValue = identifier.Value,
                Status = "pending",
                Wildcard = isWildcard,
                CreatedAt = now,
                ExpiresAt = expires
            };

            // Per RFC 8555 §7.4.2, each authorization offers challenge types:
            // - Wildcards: only DNS-01 (HTTP-01 and TLS-ALPN-01 cannot validate wildcards)
            // - Non-wildcards: HTTP-01, DNS-01, and TLS-ALPN-01
            // The client chooses which challenge to complete. RFC 8555 §8.1 models the
            // token as per challenge, so each challenge gets its own fresh token.
            if (!isWildcard)
            {
                authz.Challenges.Add(new AcmeChallenge
                {
                    ChallengeId = GenerateId(),
                    Type = "http-01",
                    Token = GenerateToken(),
                    Status = "pending"
                });

                authz.Challenges.Add(new AcmeChallenge
                {
                    ChallengeId = GenerateId(),
                    Type = "tls-alpn-01",
                    Token = GenerateToken(),
                    Status = "pending"
                });
            }

            // DNS-01 is always available (required for wildcards, optional for non-wildcards)
            authz.Challenges.Add(new AcmeChallenge
            {
                ChallengeId = GenerateId(),
                Type = "dns-01",
                Token = GenerateToken(),
                Status = "pending"
            });

            order.Authorizations.Add(authz);
        }

        _db.AcmeOrders.Add(order);
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Created ACME order {OrderId} for account {AccountId} with {Count} identifiers on template {Template}",
            order.OrderId, account.AccountId, identifiers.Length, template);

        return order;
    }

    /// <summary>
    /// Gets an order by its public order ID, including all navigation properties.
    /// </summary>
    public async Task<AcmeOrder?> GetOrderAsync(
        string orderId,
        CancellationToken cancellationToken = default)
    {
        return await _db.AcmeOrders
            .Include(o => o.Account)
            .Include(o => o.Authorizations)
                .ThenInclude(a => a.Challenges)
            .FirstOrDefaultAsync(o => o.OrderId == orderId, cancellationToken);
    }

    /// <summary>
    /// Gets an authorization by its public ID, including challenges and parent order.
    /// </summary>
    public async Task<AcmeAuthorization?> GetAuthorizationAsync(
        string authorizationId,
        CancellationToken cancellationToken = default)
    {
        return await _db.AcmeAuthorizations
            .Include(a => a.Challenges)
            .Include(a => a.Order)
                .ThenInclude(o => o.Account)
            .FirstOrDefaultAsync(a => a.AuthorizationId == authorizationId, cancellationToken);
    }

    /// <summary>
    /// Gets a challenge by its public ID, including parent authorization and order.
    /// </summary>
    public async Task<AcmeChallenge?> GetChallengeAsync(
        string challengeId,
        CancellationToken cancellationToken = default)
    {
        return await _db.AcmeChallenges
            .Include(c => c.Authorization)
                .ThenInclude(a => a.Order)
                    .ThenInclude(o => o.Account)
            .Include(c => c.Authorization)
                .ThenInclude(a => a.Challenges)
            .FirstOrDefaultAsync(c => c.ChallengeId == challengeId, cancellationToken);
    }

    /// <summary>
    /// Marks a challenge as ready for validation (client has provisioned the response).
    /// Transitions the challenge from "pending" to "processing".
    /// RFC 8555 §7.5.1
    /// </summary>
    public async Task<bool> RespondToChallengeAsync(
        string challengeId,
        CancellationToken cancellationToken = default)
    {
        var challenge = await _db.AcmeChallenges
            .FirstOrDefaultAsync(c => c.ChallengeId == challengeId, cancellationToken);

        if (challenge == null || challenge.Status != "pending")
            return false;

        challenge.Status = "processing";
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Challenge {ChallengeId} ({Type}) moved to processing",
            challengeId, challenge.Type);

        return true;
    }

    /// <summary>
    /// Finalizes an order by submitting the CSR to ADCS.
    /// The order must be in "ready" status (all authorizations valid).
    /// RFC 8555 §7.4
    /// </summary>
    public async Task<(bool Success, string? ErrorMessage)> FinalizeOrderAsync(
        string orderId,
        byte[] csrDer,
        CancellationToken cancellationToken = default)
    {
        var order = await GetOrderAsync(orderId, cancellationToken);
        if (order == null)
            return (false, "Order not found.");

        if (order.Status != "ready")
            return (false, $"Order is not ready for finalization (current status: {order.Status}).");

        // RFC 8555 §7.1.3: a ready order that has passed its expiry can no longer be
        // finalized. Mark it invalid so a later poll reflects the terminal state.
        if (DateTime.UtcNow > order.ExpiresAt)
        {
            order.Status = "invalid";
            order.ErrorJson = JsonSerializer.Serialize(new AcmeError
            {
                Type = AcmeErrorType.Malformed,
                Detail = "Order has expired."
            });
            await _db.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("Order {OrderId} rejected for finalization: expired", orderId);
            return (false, "Order has expired.");
        }

        // Validate CSR SANs match order identifiers.
        // Compare the full identifier strings, wildcard marker included. Normalize only case
        // and surrounding whitespace. Do not strip "*." — apex and wildcard are distinct
        // identifiers and each must be validated on its own (RFC 8555 §7.4, §8). Stripping the
        // marker would let a non-wildcard authorization finalize a wildcard CSR, and the reverse.
        var csrSans = CsrHelper.ExtractSansFromCsr(csrDer);
        var orderIdentifiers = JsonSerializer.Deserialize<AcmeIdentifier[]>(order.IdentifiersJson)
            ?? Array.Empty<AcmeIdentifier>();
        var orderDomains = orderIdentifiers
            .Where(i => i.Type == "dns")
            .Select(i => i.Value.Trim().ToLowerInvariant())
            .ToHashSet();
        var csrDomains = csrSans
            .Select(s => s.Trim().ToLowerInvariant())
            .ToHashSet();

        if (!orderDomains.SetEquals(csrDomains))
        {
            _logger.LogWarning(
                "CSR SAN mismatch for order {OrderId}. Order: [{OrderDomains}], CSR: [{CsrDomains}]",
                orderId, string.Join(", ", orderDomains), string.Join(", ", csrDomains));
            return (false, "CSR SANs do not match order identifiers.");
        }

        // Submit to ADCS
        order.Status = "processing";
        order.CsrDer = JwsService.Base64UrlEncode(csrDer);
        await _db.SaveChangesAsync(cancellationToken);

        try
        {
            var result = await _adcsClient.SubmitCertificateRequestAsync(
                order.TemplateId, csrDer, cancellationToken);

            order.AdcsRequestId = result.RequestId;

            if (result.Status == SubmitStatus.Issued)
            {
                // Certificate issued immediately — fetch and store it
                await IssueCertificateAsync(order, result.RequestId, cancellationToken);
            }
            else if (result.Status == SubmitStatus.Pending)
            {
                // Pending CA approval — stay in "processing"
                _logger.LogInformation(
                    "Order {OrderId} submitted to ADCS (request {RequestId}), pending approval",
                    orderId, result.RequestId);
                await _db.SaveChangesAsync(cancellationToken);
            }
            else
            {
                // Denied or error
                order.Status = "invalid";
                order.ErrorJson = JsonSerializer.Serialize(new AcmeError
                {
                    Type = AcmeErrorType.ServerInternal,
                    Detail = result.Message ?? "Certificate request was denied by the CA."
                });
                await _db.SaveChangesAsync(cancellationToken);
                return (false, result.Message ?? "CA denied the certificate request.");
            }

            return (true, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to submit CSR to ADCS for order {OrderId}", orderId);
            order.Status = "invalid";
            order.ErrorJson = JsonSerializer.Serialize(new AcmeError
            {
                Type = AcmeErrorType.ServerInternal,
                Detail = "Failed to submit certificate request to the CA."
            });
            await _db.SaveChangesAsync(cancellationToken);
            return (false, "Failed to submit to CA.");
        }
    }

    /// <summary>
    /// Retrieves a stored certificate by its certificate ID.
    /// </summary>
    public async Task<AcmeCertificate?> GetCertificateAsync(
        string certificateId,
        CancellationToken cancellationToken = default)
    {
        return await _db.AcmeCertificates
            .Include(c => c.Order)
            .FirstOrDefaultAsync(c => c.CertificateId == certificateId, cancellationToken);
    }

    /// <summary>
    /// Finds a stored certificate by its leaf serial number (hex, uppercase), including its
    /// order and account for the revocation ownership check. A revoke-cert request carries the
    /// certificate itself (RFC 8555 §7.6), so the row is located by serial, not certificate ID.
    /// </summary>
    public async Task<AcmeCertificate?> FindCertificateBySerialAsync(
        string serialNumber,
        CancellationToken cancellationToken = default)
    {
        // Never match on an empty serial. A certificate row could carry an empty serial only if
        // it was stored without a parseable DER, and an empty match would return an arbitrary
        // such row rather than the intended certificate.
        if (string.IsNullOrEmpty(serialNumber))
            return null;

        return await _db.AcmeCertificates
            .Include(c => c.Order)
                .ThenInclude(o => o.Account)
            .FirstOrDefaultAsync(c => c.SerialNumber == serialNumber, cancellationToken);
    }

    /// <summary>
    /// Revokes a stored certificate at the CA and records the revocation on the row.
    /// Returns <see cref="RevokeOutcome.AlreadyRevoked"/> without calling the CA when the
    /// certificate is already revoked (RFC 8555 §7.6). A
    /// <see cref="Certus.Core.Adcs.CaUnavailableException"/> from the CA propagates so the
    /// endpoint can map it to a 503.
    /// </summary>
    public async Task<RevokeOutcome> RevokeCertificateAsync(
        AcmeCertificate certificate,
        int reason,
        CancellationToken cancellationToken = default)
    {
        if (certificate.RevokedAt != null)
            return RevokeOutcome.AlreadyRevoked;

        await _adcsClient.RevokeCertificateAsync(certificate.SerialNumber, reason, cancellationToken);

        certificate.RevokedAt = DateTime.UtcNow;
        certificate.RevokedReason = reason;
        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Revoked certificate {CertId} (serial {Serial}) with reason {Reason}",
            certificate.CertificateId, certificate.SerialNumber, reason);

        // Wake the inventory sync so the revocation reaches the dashboard without
        // waiting for the next timer tick. Immediate rather than debounced:
        // revocations arrive at operator speed, not in issuance style bursts, and
        // the trigger channel already coalesces fires during a running sync.
        _syncTrigger.Fire();

        return RevokeOutcome.Revoked;
    }

    /// <summary>
    /// Builds the list of order URLs for an account, newest first. RFC 8555 §7.1.2.1.
    /// Each URL uses the order's own template, matching how the order resource is routed.
    /// </summary>
    public async Task<string[]> GetOrderUrlsForAccountAsync(
        int accountId,
        Func<string, string> urlBuilder,
        CancellationToken cancellationToken = default)
    {
        var orders = await _db.AcmeOrders
            .Where(o => o.AccountId == accountId)
            .OrderByDescending(o => o.CreatedAt)
            .Select(o => new { o.TemplateId, o.OrderId })
            .ToListAsync(cancellationToken);

        return orders
            .Select(o => urlBuilder($"/acme/{o.TemplateId}/order/{o.OrderId}"))
            .ToArray();
    }

    /// <summary>
    /// Recalculates the order status based on its authorizations.
    /// Called after challenge validation completes.
    /// </summary>
    public async Task RecalculateOrderStatusAsync(
        int orderId,
        CancellationToken cancellationToken = default)
    {
        var order = await _db.AcmeOrders
            .Include(o => o.Authorizations)
            .FirstOrDefaultAsync(o => o.Id == orderId, cancellationToken);

        if (order == null || order.Status is "valid" or "invalid")
            return;

        // Check if any authorization is invalid → order invalid
        if (order.Authorizations.Any(a => a.Status == "invalid"))
        {
            order.Status = "invalid";
            _logger.LogInformation("Order {OrderId} is now invalid (authorization failed)", order.OrderId);
        }
        // Check if all authorizations are valid → order ready
        else if (order.Authorizations.All(a => a.Status == "valid"))
        {
            order.Status = "ready";
            _logger.LogInformation("Order {OrderId} is now ready for finalization", order.OrderId);
        }
        // Otherwise: still pending

        await _db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Fetches the certificate from ADCS and stores it. Transitions order to "valid".
    /// </summary>
    private async Task IssueCertificateAsync(
        AcmeOrder order,
        int requestId,
        CancellationToken cancellationToken)
    {
        var certResult = await _adcsClient.GetCertificateAsync(requestId, cancellationToken);

        if (certResult.Status != CertificateStatus.Issued || certResult.CertificatePem == null)
        {
            order.Status = "invalid";
            order.ErrorJson = JsonSerializer.Serialize(new AcmeError
            {
                Type = AcmeErrorType.ServerInternal,
                Detail = "Failed to retrieve issued certificate from CA."
            });
            await _db.SaveChangesAsync(cancellationToken);
            return;
        }

        // Record the leaf serial so a later revoke-cert request (RFC 8555 §7.6), which
        // carries the certificate itself, can locate this row. Use the same X509Certificate2
        // representation the revoke path parses with, so the two serials compare equal.
        var serialNumber = string.Empty;
        if (certResult.CertificateDer != null)
        {
            using var leaf = new X509Certificate2(certResult.CertificateDer);
            serialNumber = leaf.SerialNumber;
        }

        var cert = new AcmeCertificate
        {
            CertificateId = GenerateId(),
            OrderId = order.Id,
            CertificatePem = certResult.CertificatePem,
            AdcsRequestId = requestId,
            SerialNumber = serialNumber,
            IssuedAt = DateTime.UtcNow
        };

        _db.AcmeCertificates.Add(cert);
        order.CertificateId = cert.CertificateId;
        order.Status = "valid";

        await _db.SaveChangesAsync(cancellationToken);

        _logger.LogInformation(
            "Certificate issued for order {OrderId}, cert ID {CertId}",
            order.OrderId, cert.CertificateId);

        // Nudge the inventory sync so the new certificate reaches the
        // dashboard without waiting for the next timer tick. Debounced so a
        // burst of issuances collapses into one CA pull.
        _syncTrigger.FireDebounced(PostIssuanceSyncDelay);
    }

    /// <summary>
    /// Builds the order response DTO with fully qualified URLs.
    /// </summary>
    public static OrderResponse ToResponse(AcmeOrder order, Func<string, string> urlBuilder)
    {
        var identifiers = JsonSerializer.Deserialize<AcmeIdentifier[]>(order.IdentifiersJson)
            ?? Array.Empty<AcmeIdentifier>();

        var response = new OrderResponse
        {
            Status = order.Status,
            Expires = order.ExpiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Identifiers = identifiers,
            NotBefore = order.NotBefore?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            NotAfter = order.NotAfter?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Authorizations = order.Authorizations
                .Select(a => urlBuilder($"/acme/{order.TemplateId}/authz/{a.AuthorizationId}"))
                .ToArray(),
            Finalize = urlBuilder($"/acme/{order.TemplateId}/order/{order.OrderId}/finalize")
        };

        if (order.CertificateId != null)
        {
            response.Certificate = urlBuilder($"/acme/{order.TemplateId}/cert/{order.CertificateId}");
        }

        return response;
    }

    /// <summary>
    /// Builds the authorization response DTO.
    /// </summary>
    public static AuthorizationResponse ToAuthorizationResponse(
        AcmeAuthorization authz, string template, Func<string, string> urlBuilder)
    {
        return new AuthorizationResponse
        {
            Identifier = new AcmeIdentifier
            {
                Type = authz.IdentifierType,
                // RFC 8555 §7.1.4: a wildcard authorization carries the base domain in
                // identifier.value and signals the wildcard via the wildcard field. The
                // stored value keeps the "*." prefix (it matches the order identifier),
                // so strip it here at the response layer only.
                Value = authz.Wildcard ? authz.IdentifierValue[2..] : authz.IdentifierValue
            },
            Status = authz.Status,
            Expires = authz.ExpiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Wildcard = authz.Wildcard,
            Challenges = authz.Challenges.Select(c => ToChallengeResponse(c, template, urlBuilder)).ToArray()
        };
    }

    /// <summary>
    /// Builds the challenge response DTO.
    /// </summary>
    public static ChallengeResponse ToChallengeResponse(
        AcmeChallenge challenge, string template, Func<string, string> urlBuilder)
    {
        var response = new ChallengeResponse
        {
            Type = challenge.Type,
            Url = urlBuilder($"/acme/{template}/chall/{challenge.ChallengeId}"),
            Token = challenge.Token,
            Status = challenge.Status,
            Validated = challenge.ValidatedAt?.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };

        if (challenge.ErrorJson != null)
        {
            response.Error = JsonSerializer.Deserialize<AcmeError>(challenge.ErrorJson);
        }

        return response;
    }

    private static string GenerateId()
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
    }

    private static string GenerateToken()
    {
        // Token must be URL safe — base64url encode 32 random bytes
        return JwsService.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    }
}

/// <summary>
/// Outcome of <see cref="OrderService.RevokeCertificateAsync"/>.
/// </summary>
public enum RevokeOutcome
{
    /// <summary>The certificate was revoked at the CA and the revocation recorded.</summary>
    Revoked,

    /// <summary>The certificate was already revoked; no CA call was made.</summary>
    AlreadyRevoked
}
