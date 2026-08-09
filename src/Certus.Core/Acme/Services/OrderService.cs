using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Security;
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
    private readonly DeviceAttestationPolicyService _devicePolicy;
    private readonly DomainPolicyAuditService _domainPolicyAudit;
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
        DeviceAttestationPolicyService devicePolicy,
        DomainPolicyAuditService domainPolicyAudit,
        ILogger<OrderService> logger)
    {
        _db = db;
        _adcsClient = adcsClient;
        _syncTrigger = syncTrigger;
        _devicePolicy = devicePolicy;
        _domainPolicyAudit = domainPolicyAudit;
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
            var isDevice = AcmeIdentifierTypes.IsDeviceType(identifier.Type);
            var isWildcard = !isDevice
                && identifier.Value.StartsWith("*.", StringComparison.Ordinal);
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

            if (isDevice)
            {
                // A device identity is proven by attestation alone
                // (draft-ietf-acme-device-attest-08 section 1): the
                // authorization offers exactly one device-attest-01 challenge
                // and none of the network challenges, which cannot say
                // anything about a serial number.
                authz.Challenges.Add(new AcmeChallenge
                {
                    ChallengeId = GenerateId(),
                    Type = DeviceAttest01ChallengeValidator.TypeName,
                    Token = GenerateToken(),
                    Status = "pending"
                });

                order.Authorizations.Add(authz);
                continue;
            }

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
        string? attestationObject = null,
        CancellationToken cancellationToken = default)
    {
        var challenge = await _db.AcmeChallenges
            .FirstOrDefaultAsync(c => c.ChallengeId == challengeId, cancellationToken);

        if (challenge == null || challenge.Status != "pending")
            return false;

        // A device attestation arrives with the response POST itself
        // (draft-ietf-acme-device-attest-08 section 5.1). Keep the base64url
        // string exactly as received: the background validator decodes it,
        // and the stored form doubles as the forensic record.
        if (attestationObject != null)
            challenge.AttestationObject = attestationObject;

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

        var orderIdentifiers = JsonSerializer.Deserialize<AcmeIdentifier[]>(order.IdentifiersJson)
            ?? Array.Empty<AcmeIdentifier>();

        if (orderIdentifiers.Any(i => AcmeIdentifierTypes.IsDeviceType(i.Type)))
        {
            // A device order binds the CSR to the attestation instead of
            // comparing DNS SANs; the checks live in one place below.
            var deviceError = await CheckDeviceCsrAsync(
                order, orderIdentifiers, csrDer, cancellationToken);
            if (deviceError != null)
            {
                _logger.LogWarning(
                    "Device CSR rejected for order {OrderId}: {Error}", orderId, deviceError);
                return (false, deviceError);
            }
        }
        else
        {
            // A dns order authorizes only dns identifiers, so the CSR may carry no
            // subject alternative name other than a DNS name. ADCS receives the raw
            // CSR, so any smuggled entry (an IP, an email, a UPN otherName, a
            // directoryName, or a PermanentIdentifier) would land in the issued
            // certificate. Parse with the same closed vocabulary parser the device
            // path uses, which reports everything it did not recognize, and refuse
            // before anything reaches the CA.
            CsrIdentity identity;
            try
            {
                identity = CsrHelper.ExtractCsrIdentity(csrDer);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "CSR for order {OrderId} could not be parsed", orderId);
                return (false, "The CSR could not be parsed or its signature did not verify.");
            }

            // Any non DNS SAN entry is unauthorized. A PermanentIdentifier is a
            // recognized type, so it does not set HasOtherSanEntries, but a dns
            // order authorizes none, so refuse it explicitly too.
            if (identity.HasOtherSanEntries || identity.PermanentIdentifiers.Count > 0)
            {
                _logger.LogWarning(
                    "CSR for order {OrderId} carries a subject alternative name the order did not authorize",
                    orderId);
                return (false,
                    "A dns order CSR must not carry subject alternative names other than DNS names.");
            }

            // Validate CSR SANs match order identifiers.
            // Compare the full identifier strings, wildcard marker included. Normalize only case
            // and surrounding whitespace. Do not strip "*.", apex and wildcard are distinct
            // identifiers and each must be validated on its own (RFC 8555 §7.4, §8). Stripping the
            // marker would let a non-wildcard authorization finalize a wildcard CSR, and the reverse.
            var orderDomains = orderIdentifiers
                .Where(i => i.Type == AcmeIdentifierTypes.Dns)
                .Select(i => i.Value.Trim().ToLowerInvariant())
                .ToHashSet();

            // Preserve the historical fallback: a CSR with no SAN names at all is identified by
            // its subject CN. Reached only after the reject above, so an empty DnsNames list means
            // the SAN carried nothing, never that a non-DNS entry was dropped.
            IEnumerable<string> csrNames = identity.DnsNames.Count > 0
                ? identity.DnsNames
                : identity.SubjectCns.Take(1);
            var csrDomains = csrNames
                .Select(s => s.Trim().ToLowerInvariant())
                .ToHashSet();

            if (!orderDomains.SetEquals(csrDomains))
            {
                _logger.LogWarning(
                    "CSR SAN mismatch for order {OrderId}. Order: [{OrderDomains}], CSR: [{CsrDomains}]",
                    orderId, string.Join(", ", orderDomains), string.Join(", ", csrDomains));
                return (false, "CSR SANs do not match order identifiers.");
            }

            // Issue #167: ADCS receives the raw CSR, so on a template that honours
            // the enrollee supplied subject an unvalidated CN would land in the
            // issued certificate. Require every CN, when present, to be one of the
            // order's dns identifiers (RFC 8555 §7.4: the CSR must indicate the
            // exact same set of requested identifiers). A CSR with no CN is fine;
            // modern clients are SAN only. Membership rather than set equality: the
            // check above already guarantees full coverage of the order, and
            // membership over every CN also closes the multi CN hole in the
            // fallback, which reads only the first CN.
            var mismatchedCn = identity.SubjectCns
                .Select(cn => cn.Trim().ToLowerInvariant())
                .FirstOrDefault(cn => !orderDomains.Contains(cn));
            if (mismatchedCn is not null)
            {
                _logger.LogWarning(
                    "CSR subject CN mismatch for order {OrderId}. Order: [{OrderDomains}], CN: {Cn}",
                    orderId, string.Join(", ", orderDomains), mismatchedCn);
                return (false, "The CSR subject CN must be one of the order's dns identifiers.");
            }
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
    /// The finalize checks for a device order
    /// (draft-ietf-acme-device-attest-08 section 7). Two invariants hold
    /// regardless of configuration: the CSR public key must equal the key
    /// the attestation proved (the second leg of the draft's three way
    /// binding; the identifier leg was checked at challenge time and the
    /// trust leg is the verifier's), and the CSR may not carry any SAN
    /// content beyond a matching PermanentIdentifier, because ADCS receives
    /// the raw CSR and an enrollee supplies subject template would put
    /// every unvetted name into the issued certificate. On top of that the
    /// template's binding mode decides how the identifier itself must
    /// appear. Returns the client facing error detail, or null to proceed.
    /// </summary>
    private async Task<string?> CheckDeviceCsrAsync(
        AcmeOrder order,
        AcmeIdentifier[] orderIdentifiers,
        byte[] csrDer,
        CancellationToken cancellationToken)
    {
        CsrIdentity identity;
        try
        {
            identity = CsrHelper.ExtractCsrIdentity(csrDer);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Device CSR for order {OrderId} could not be parsed", order.OrderId);
            return "The CSR could not be parsed or its signature did not verify.";
        }

        // newOrder guarantees exactly one device identifier per order.
        var deviceIdentifier = orderIdentifiers.First(
            i => AcmeIdentifierTypes.IsDeviceType(i.Type));
        var expected = deviceIdentifier.Value;

        var authz = order.Authorizations.FirstOrDefault(
            a => a.IdentifierType == deviceIdentifier.Type
                && a.IdentifierValue == expected);

        byte[] attestedSpki;
        try
        {
            attestedSpki = Convert.FromBase64String(authz?.AttestedSpki ?? string.Empty);
        }
        catch (FormatException)
        {
            attestedSpki = Array.Empty<byte>();
        }
        if (attestedSpki.Length == 0)
            return "No attested device key is on record for this order.";

        if (!attestedSpki.AsSpan().SequenceEqual(identity.SpkiDer))
            return "The CSR public key does not match the attested device key.";

        if (identity.DnsNames.Count > 0)
            return "A device order CSR must not carry DNS subject alternative names.";

        if (identity.HasOtherSanEntries)
            return "A device order CSR must not carry subject alternative names " +
                "other than a PermanentIdentifier matching the order identifier.";

        // A wrong identifier value anywhere always rejects, in every binding
        // mode: the comparison is octet for octet per the draft, against the
        // grammar string reassembled from the SAN's structured form.
        if (identity.PermanentIdentifiers.Any(
                pi => !string.Equals(pi, expected, StringComparison.Ordinal)))
            return "The CSR PermanentIdentifier does not match the order identifier.";

        var profile = await _devicePolicy.GetProfileAsync(order.TemplateId, cancellationToken);
        if (profile is not { Enabled: true })
            return "This template no longer accepts device orders.";

        var cnsMatching = identity.SubjectCns.Count(
            cn => string.Equals(cn, expected, StringComparison.Ordinal));

        switch (profile.CsrIdentifierBinding)
        {
            case CsrIdentifierBindingModes.SanRequired:
                if (identity.PermanentIdentifiers.Count == 0)
                    return "The CSR must carry the order identifier as a " +
                        "PermanentIdentifier subject alternative name.";
                if (cnsMatching != identity.SubjectCns.Count)
                    return "The CSR subject CN does not match the order identifier.";
                break;

            case CsrIdentifierBindingModes.None:
                // Privacy mode: the certificate must not name the device
                // identity. Other subject content is the client's business;
                // this path checks only that no CN names the identifier.
                if (identity.PermanentIdentifiers.Count > 0)
                    return "This template issues privacy preserving device certificates; " +
                        "the CSR must not carry a PermanentIdentifier subject alternative name.";
                if (cnsMatching > 0)
                    return "This template issues privacy preserving device certificates; " +
                        "the CSR subject must not name the device identifier.";
                break;

            default:
                // cn-or-san, and any unrecognized stored value behaves as this
                // default, the same convention the gate mode documents.
                if (cnsMatching != identity.SubjectCns.Count)
                    return "The CSR subject CN does not match the order identifier.";
                if (cnsMatching == 0 && identity.PermanentIdentifiers.Count == 0)
                    return "The CSR must carry the order identifier in the subject CN " +
                        "or as a PermanentIdentifier subject alternative name.";
                break;
        }

        return null;
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

        // The finalize leaf guard, the hard guarantee behind the advisory
        // template metadata check at new-order: parse what the CA actually
        // returned and never deliver anything outside the TLS capability
        // ceiling. An absent or undecodable DER is undetermined capability,
        // which refuses too.
        var capability = certResult.CertificateDer == null
            ? null
            : CertificateDerParser.ParseCapability(certResult.CertificateDer);
        var verdict = capability == null
            ? new CeilingVerdict(false, "undetermined",
                "The issued certificate could not be parsed, so its TLS capability cannot be verified.")
            : TlsCapabilityCeiling.Evaluate(capability);
        if (!verdict.Allowed)
        {
            await RefuseIssuedCertificateAsync(order, requestId, certResult, verdict);
            return;
        }

        // Record the leaf serial so a later revoke-cert request (RFC 8555 §7.6), which
        // carries the certificate itself, can locate this row. Use the same X509Certificate2
        // representation the revoke path parses with, so the two serials compare equal.
        var serialNumber = string.Empty;
        if (certResult.CertificateDer != null)
        {
            using var leaf = X509CertificateLoader.LoadCertificate(certResult.CertificateDer);
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
    /// The breach path of the finalize leaf guard: the CA issued something
    /// outside the TLS capability ceiling, so the client must never receive
    /// it and the certificate must not stay live. No AcmeCertificate row is
    /// created and order.CertificateId stays null, so no certificate URL
    /// ever exists and nothing is fetchable; the next sync ingests the
    /// revoked leaf as an ordinary inventory row. The auto revoke here is
    /// the only automated revocation in the product, and it only ever
    /// targets the certificate this very order obtained moments earlier. The
    /// order fails whether or not the revoke succeeds, so a CA outage mid
    /// flow can never cause delivery.
    /// </summary>
    private async Task RefuseIssuedCertificateAsync(
        AcmeOrder order,
        int requestId,
        CertificateResult certResult,
        CeilingVerdict verdict)
    {
        _logger.LogError(
            "Order {OrderId} on template {TemplateId} produced a certificate that violates " +
            "the TLS capability ceiling ({Reason}): {Message} It will not be delivered and " +
            "is being revoked (CA request {RequestId})",
            order.OrderId, order.TemplateId, verdict.ReasonCode, verdict.Message, requestId);

        // The same serial representation the delivery path records, so the
        // revoke targets exactly what the CA handed back.
        string? serialNumber = null;
        if (certResult.CertificateDer != null)
        {
            try
            {
                using var leaf = X509CertificateLoader.LoadCertificate(certResult.CertificateDer);
                serialNumber = leaf.SerialNumber;
            }
            catch (CryptographicException)
            {
                // Undecodable leaf: nothing to revoke by serial. The error
                // log above carries the CA request id for manual follow up.
            }
        }

        // The refusal is decided and logged; everything below is cleanup
        // that must not be abandoned by a client disconnect, the same tail
        // rule CertificateRevocationService follows. The revoke, the order
        // state, and the audit row all run on none: a cancellation between
        // them would otherwise leave a ceiling violating certificate live
        // with its order stranded in processing.
        if (serialNumber != null)
        {
            try
            {
                // Reason 5, cessation of operation.
                await _adcsClient.RevokeCertificateAsync(
                    serialNumber, reason: 5, CancellationToken.None);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex,
                    "The ceiling violating certificate (serial {Serial}, CA request {RequestId}) " +
                    "could not be revoked and remains live at the CA; revoke it by hand",
                    serialNumber, requestId);
            }
        }

        order.Status = "invalid";
        order.ErrorJson = JsonSerializer.Serialize(new AcmeError
        {
            Type = AcmeErrorType.ServerInternal,
            Detail = "The issued certificate did not meet this server's TLS certificate " +
                     "policy and was revoked. The certificate template configuration needs " +
                     "review by the administrator."
        });
        await _db.SaveChangesAsync(CancellationToken.None);

        // The audit row the dashboard labels as blocked by the TLS
        // certificate guardrail. The audit service swallows its own
        // failures, and the refusal is already committed above, so this can
        // run on none rather than risk a client disconnect abandoning it.
        var identifiers = JsonSerializer.Deserialize<AcmeIdentifier[]>(order.IdentifiersJson)
            ?? Array.Empty<AcmeIdentifier>();
        await _domainPolicyAudit.RecordAsync(
            order.Account.AccountId,
            order.TemplateId,
            identifiers,
            identifiers.Select(i => i.Value).ToList(),
            clientIp: null,
            stage: "finalize-guard",
            CancellationToken.None);

        // The revoked leaf still belongs in the inventory; nudge the sync so
        // it appears promptly rather than on the next timer tick.
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
