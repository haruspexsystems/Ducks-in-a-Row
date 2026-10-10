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
using Certus.Core.Setup;
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
    private readonly CertificateRevocationGate _revocationGate;
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
        CertificateRevocationGate revocationGate,
        DeviceAttestationPolicyService devicePolicy,
        DomainPolicyAuditService domainPolicyAudit,
        ILogger<OrderService> logger)
    {
        _db = db;
        _adcsClient = adcsClient;
        _syncTrigger = syncTrigger;
        _revocationGate = revocationGate;
        _devicePolicy = devicePolicy;
        _domainPolicyAudit = domainPolicyAudit;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new order with authorizations and challenges.
    /// RFC 8555 §7.4
    /// The optional replaces identifier (RFC 9773 §5) is stored verbatim; the
    /// caller must have run it through <see cref="ResolveReplacesAsync"/>
    /// first, which is what makes it the canonical form.
    /// </summary>
    public async Task<AcmeOrder> CreateOrderAsync(
        AcmeAccount account,
        string template,
        AcmeIdentifier[] identifiers,
        DateTime? notBefore,
        DateTime? notAfter,
        string? replacesCertificateId = null,
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
            ReplacesCertificateId = replacesCertificateId,
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
    /// Deactivates an authorization at its owner's request (RFC 8555 §7.5.2) and
    /// invalidates the order that depends on it.
    ///
    /// Takes the loaded entity rather than an id, like
    /// <c>AccountService.UpdateContactAsync</c>. That removes a "row went away"
    /// arm entirely instead of testing it: PR #267's review round found that
    /// folding such an arm into the refusal arm and handing back the stale entity
    /// re-created the very false success this family of fixes removes, one layer
    /// down. Nothing deletes an authorization row on its own, since the foreign
    /// key cascades from the order.
    /// </summary>
    public async Task<AuthorizationDeactivationResult> DeactivateAuthorizationAsync(
        AcmeAuthorization authz,
        CancellationToken cancellationToken = default)
    {
        // Idempotent: the client asked for a state that already holds, so report
        // success on the state and write nothing. Answering an error here would
        // make a retried deactivation look like a failure.
        if (string.Equals(authz.Status, "deactivated", StringComparison.Ordinal))
            return new AuthorizationDeactivationResult(
                AuthorizationDeactivationOutcome.AlreadyDeactivated, authz);

        // §7.5.2 names no source status, and the §7.1.6 state diagram draws the
        // arrow only from "valid". We allow "pending" as well, because a client
        // abandoning a validation it no longer wants is the case the section
        // exists for, and refusing it would leave that client no way to
        // relinquish. Terminal states refuse: the client asked for "deactivated"
        // and would be handed something else, which is a false success again.
        if (!string.Equals(authz.Status, "pending", StringComparison.Ordinal) &&
            !string.Equals(authz.Status, "valid", StringComparison.Ordinal))
            return new AuthorizationDeactivationResult(
                AuthorizationDeactivationOutcome.NotDeactivatable, authz);

        authz.Status = "deactivated";

        // The order can never be finalized now, so say so rather than leaving it
        // reading "ready". Written as a conditional UPDATE naming the statuses it
        // is legal to demote from, rather than as a test of authz.Order.Status:
        // that copy was loaded by the controller before this method was entered,
        // which PR #267 keeps that way deliberately, so it is a stale read by
        // construction and an exclusion list over it could never see a claim
        // another request committed since.
        //
        // "processing" is absent from the list, and that absence is the whole of
        // issue #312. Such an order has been claimed by a finalize and its CSR is
        // at the CA, so a demote lands on top of an issuance in flight and one of
        // the two writes is lost: either the completion overwrites this one and a
        // client is told "invalid" for an order that then reads "valid", or this
        // one overwrites the completion and leaves an "invalid" order still
        // holding its CertificateId and its AcmeCertificate row, which the
        // download path serves regardless of order status. The claim is the
        // issuance decision point and it required "ready", so every authorization
        // was valid at that instant and a deactivation arriving afterwards is
        // genuinely after the fact. RFC 8555 section 7.5.2 forbids treating a
        // deactivated authorization as sufficient for issuing; it was not the
        // basis for this issuance. A client that wants the certificate dead has
        // revoke-cert (section 7.6).
        //
        // An allow list rather than an exclusion list, so a status added later
        // fails closed. Same shape as the finalize claim. It still agrees with the
        // early return in RecalculateOrderStatusAsync by construction, which is
        // why that early return names "processing" too: the two move together.
        var errorJson = JsonSerializer.Serialize(new AcmeError
        {
            Type = AcmeErrorType.Unauthorized,
            Detail = "An authorization for this order was deactivated by the client."
        });

        // Both rows in one transaction. The single SaveChanges this replaced
        // covered them together, and splitting them would let a crash in between
        // leave a deactivated authorization under an order that still reads ready.
        // ExecuteUpdate cannot be batched into SaveChanges, so an explicit
        // transaction is what restores that guarantee; it enlists in
        // Database.CurrentTransaction the same way SaveChanges does. The
        // authorization saves first, so the UPDATE, which does not flush the
        // change tracker, is not racing pending tracked state of its own. No
        // retrying execution strategy is configured on this context (both hosts
        // use a bare UseSqlite), so no strategy wrapper is needed. If one is ever
        // added, this block is one of the two that has to be wrapped.
        await using var tx = await _db.Database.BeginTransactionAsync(cancellationToken);

        await _db.SaveChangesAsync(cancellationToken);

        var orderInvalidated = await _db.AcmeOrders
            .Where(o => o.Id == authz.OrderId &&
                (o.Status == "pending" || o.Status == "ready"))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(o => o.Status, "invalid")
                .SetProperty(o => o.ErrorJson, errorJson),
                cancellationToken) == 1;

        await tx.CommitAsync(cancellationToken);

        // ExecuteUpdate goes round the change tracker, so authz.Order still holds
        // what the controller loaded. The log line below reads its status, and a
        // log saying "left as ready" when the row says "processing" is the kind of
        // false witness this codebase keeps removing. Same trap the finalize claim
        // and RevokeCertificateAsync both document.
        await _db.Entry(authz.Order).ReloadAsync(cancellationToken);

        _logger.LogInformation(
            "Deactivated ACME authorization {AuthorizationId} for {Identifier}; " +
            "order {OrderId} {OrderOutcome}",
            authz.AuthorizationId, authz.IdentifierValue, authz.Order.OrderId,
            orderInvalidated
                ? "invalidated"
                : string.Equals(authz.Order.Status, "processing", StringComparison.Ordinal)
                    ? "left as processing; its CSR is already at the CA, so the certificate " +
                      "will still be delivered"
                    : $"left as {authz.Order.Status}");

        return new AuthorizationDeactivationResult(
            AuthorizationDeactivationOutcome.Deactivated, authz);
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
    ///
    /// The result carries a <see cref="FinalizeOutcome"/> rather than a bare bool
    /// because the refusals below are not one kind of thing. An order state refusal
    /// and a CSR refusal are different ACME errors, and a caller handed only an error
    /// string has to answer both the same way, which is how a lost claim race came to
    /// be reported as badCSR (issue #313).
    /// </summary>
    public async Task<FinalizeResult> FinalizeOrderAsync(
        string orderId,
        byte[] csrDer,
        CancellationToken cancellationToken = default)
    {
        var order = await GetOrderAsync(orderId, cancellationToken);
        if (order == null)
            return new FinalizeResult(FinalizeOutcome.NotFound, "Order not found.");

        // Word for word the refusal the controller's own ready pre-check gives, so a
        // client cannot tell which of the two fired (issue #313).
        if (order.Status != "ready")
            return new FinalizeResult(FinalizeOutcome.OrderNotReady,
                $"Order is not ready for finalization (status: {order.Status}).");

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
            return new FinalizeResult(FinalizeOutcome.Expired, "Order has expired.");
        }

        // RFC 8555 §7.5.2: the server must not treat a deactivated authorization as
        // sufficient for issuing a certificate. The demote in
        // DeactivateAuthorizationAsync means a deactivated authorization normally
        // leaves its order invalid, so the ready check above has already refused;
        // this is the last gate in front of the CA for a ready row that reached
        // here another way.
        //
        // A fresh query, not a read of order.Authorizations: the controller and this
        // method share one scoped DbContext, so a guard over the tracked collection
        // would see exactly what the controller already saw and could never fire.
        // Re-reading here catches a deactivation committed by another request since.
        // Translated to SQL, so ordinality comes from the column's BINARY collation
        // rather than from StringComparison, which EF cannot translate.
        //
        // The identifier is projected rather than counted so the refusal can name it,
        // which is what the controller's pre-check does. Cast to string? because
        // IdentifierValue is a non-nullable column, so without it the projection is
        // typed non-null and the null check below reads as dead code, when in fact
        // FirstOrDefaultAsync returns null here for the ordinary "no such row" case.
        var deactivatedIdentifier = await _db.AcmeAuthorizations
            .AsNoTracking()
            .Where(a => a.OrderId == order.Id && a.Status == "deactivated")
            .Select(a => (string?)a.IdentifierValue)
            .FirstOrDefaultAsync(cancellationToken);
        if (deactivatedIdentifier != null)
        {
            _logger.LogWarning(
                "Order {OrderId} rejected for finalization: an authorization is deactivated",
                orderId);
            // Word for word the controller's pre-check again (issue #313), and
            // orderNotReady rather than badCSR: §6.7 defines orderNotReady as a
            // finalize on an order that is not ready, and a deactivated authorization
            // is exactly a statement that it is not.
            return new FinalizeResult(FinalizeOutcome.OrderNotReady,
                $"The authorization for {deactivatedIdentifier} has been deactivated.");
        }

        var orderIdentifiers = JsonSerializer.Deserialize<AcmeIdentifier[]>(order.IdentifiersJson)
            ?? Array.Empty<AcmeIdentifier>();

        if (orderIdentifiers.Any(i => AcmeIdentifierTypes.IsDeviceType(i.Type)))
        {
            // The profile decision comes before any judgement about the CSR, which
            // is the order the controller's own finalize-device gate runs in: it
            // fires before the CSR is even base64 decoded. Deciding it after the
            // CSR checks, as this did, meant an order on a dead profile whose CSR
            // was also imperfect answered badCSR where the controller answers
            // rejectedIdentifier for the same order (issue #323).
            //
            // The window between the two reads is real and not theoretical. Device
            // attestation storage is DB backed and hot applies with no restart, so
            // an administrator disabling a profile mid request lands here.
            var profile = await _devicePolicy.GetProfileAsync(
                order.TemplateId, cancellationToken);
            if (profile is not { Enabled: true })
            {
                _logger.LogWarning(
                    "Device order {OrderId} refused at finalize: the template's device " +
                    "attestation profile is missing or disabled", orderId);
                return new FinalizeResult(FinalizeOutcome.DeviceNotOffered,
                    "This template no longer accepts device orders.");
            }

            // newOrder guarantees exactly one device identifier per order. Read
            // once here and handed to both checks below, so the device the
            // allowlist judges and the device the CSR is bound to are the same one
            // by construction rather than by two matching LINQ expressions.
            var deviceIdentifier = orderIdentifiers.First(
                i => AcmeIdentifierTypes.IsDeviceType(i.Type));

            // The allowlist half of the same gate, and the core side twin of the
            // controller's NotOnAllowlist arm (issue #335). Without it the
            // allowlist was checked exactly once on the finalize path, at the
            // controller's finalize-device gate before the CSR was even decoded,
            // and an entry deleted between that gate and the submit below still
            // got a certificate. The profile half above already fails closed here;
            // a public method that fails closed on one half of a gate and open on
            // the other is the defect, quite apart from how narrow the window is.
            //
            // Written as "not one of the admitting outcomes" rather than "equals
            // NotOnAllowlist": an allow list, not an exclusion list, so an outcome
            // added to the enum later refuses here instead of slipping through.
            // The same form EnforceDevicePolicyAsync and the challenge validator
            // use, so all three check points read alike.
            //
            // "open" gate mode never reaches the allowlist at all; CheckAgainstAsync
            // owns that rule, which is why this asks it rather than querying the
            // entries directly.
            var admission = await _devicePolicy.CheckAgainstAsync(
                profile, deviceIdentifier.Value, cancellationToken);
            if (admission is not (DeviceAttestationPolicyOutcome.AllowedOpen
                or DeviceAttestationPolicyOutcome.AllowedListed))
            {
                _logger.LogWarning(
                    "Device order {OrderId} refused at finalize: device {Identifier} is " +
                    "not admitted by the template's allowlist ({Outcome})",
                    orderId, deviceIdentifier.Value, admission);
                return new FinalizeResult(FinalizeOutcome.DeviceNotOnAllowlist,
                    "The device is no longer on this template's allowlist.");
            }

            // A device order binds the CSR to the attestation instead of
            // comparing DNS SANs; the checks live in one place below. It runs
            // after both policy decisions for the reason issue #323 records: a
            // refused device whose CSR is also imperfect must be told about the
            // refusal, which is the half only an administrator can fix.
            var deviceError = CheckDeviceCsr(order, deviceIdentifier, profile, csrDer);
            if (deviceError != null)
            {
                _logger.LogWarning(
                    "Device CSR rejected for order {OrderId}: {Error}", orderId, deviceError);
                return new FinalizeResult(FinalizeOutcome.BadCsr, deviceError);
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
                return new FinalizeResult(FinalizeOutcome.BadCsr,
                    "The CSR could not be parsed or its signature did not verify.");
            }

            // Any non DNS SAN entry is unauthorized. A PermanentIdentifier is a
            // recognized type, so it does not set HasOtherSanEntries, but a dns
            // order authorizes none, so refuse it explicitly too.
            if (identity.HasOtherSanEntries || identity.PermanentIdentifiers.Count > 0)
            {
                _logger.LogWarning(
                    "CSR for order {OrderId} carries a subject alternative name the order did not authorize",
                    orderId);
                return new FinalizeResult(FinalizeOutcome.BadCsr,
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
                return new FinalizeResult(FinalizeOutcome.BadCsr,
                    "CSR SANs do not match order identifiers.");
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
                return new FinalizeResult(FinalizeOutcome.BadCsr,
                    "The CSR subject CN must be one of the order's dns identifiers.");
            }
        }

        // Claim the order for issuance, and only from "ready" (issue #301). A
        // plain tracked write here would say "processing" unconditionally:
        // `order` was loaded before any of the checks above ran, so a demote
        // another request committed since would be silently written back to
        // "processing" and the CSR submitted anyway. Two reachable writers
        // demote a ready order from a separate scope while this one still holds
        // a copy saying "ready": DeactivateAuthorizationAsync above, and
        // AccountService.DeactivateAsync when the account is deactivated
        // mid finalize.
        //
        // One UPDATE, atomic on its own, so the row leaves "ready" exactly once
        // no matter how many finalizes arrive together. Zero rows means this
        // finalize lost the race, and it refuses before anything reaches the CA.
        // The CSR rides in the same statement, so the claim and the record of
        // what was claimed cannot come apart. Translated to SQL, so the status
        // comparison takes its ordinality from the column's BINARY collation
        // rather than from StringComparison, like the deactivation guard above.
        var claimed = await _db.AcmeOrders
            .Where(o => o.Id == order.Id && o.Status == "ready")
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(o => o.Status, "processing")
                .SetProperty(o => o.CsrDer, JwsService.Base64UrlEncode(csrDer)),
                cancellationToken);

        // ExecuteUpdate goes round the change tracker, so the tracked entity
        // still holds what it was loaded with. Reload on both paths. On the
        // winning path the caller re-reads the order through this same scoped
        // DbContext and would otherwise be handed the stale "ready" out of the
        // identity map, the trap RevokeCertificateAsync documents; on the
        // losing path the refusal below has to name the status that won.
        await _db.Entry(order).ReloadAsync(cancellationToken);

        if (claimed == 0)
        {
            _logger.LogWarning(
                "Order {OrderId} rejected for finalization: a concurrent request moved it " +
                "out of ready (it is now {Status})",
                orderId, order.Status);
            // Word for word the refusal the ready check above gives, so losing
            // this race is indistinguishable from arriving late, which is what
            // it is. The same outcome too, for the same reason (issue #313).
            return new FinalizeResult(FinalizeOutcome.OrderNotReady,
                $"Order is not ready for finalization (status: {order.Status}).");
        }

        // Set once the CA has answered with a request that is, or can become, a live
        // certificate, and read only by the failure arm, which is the one place
        // reachable with the request id known and nothing yet written down about it
        // (issue #321).
        int? submittedRequestId = null;

        try
        {
            // Everything from the submit on runs on none rather than the caller's
            // token (issue #321). The claim above is the issuance decision point:
            // the order has left "ready", the CSR it claimed is stored with it, and
            // the next call hands that CSR to the CA. A submit is not idempotent and
            // a claimed order can never be finalized again, so a client that hangs
            // up mid finalize gains nothing from abandoning the rest of this and
            // stands to lose the only record tying its order to the certificate.
            //
            // The submit itself is the narrower half of that. The COM client runs
            // its Submit inside Task.Run(work, token), and that overload only drops
            // the work before it starts: once the call is in flight the token is
            // inert, so an OperationCanceledException from it means the CSR never
            // reached the CA and passing none costs no extra thread time. Passing
            // none anyway is about the contract rather than today's implementation,
            // since IAdcsClient permits a client that does abort a request already
            // on the wire, and about the claim: the order is committed to this CSR
            // whether or not anyone is still listening.
            //
            // The writes below are where this was reachable today. A token cancelled
            // while the CSR was at the CA threw out of the save of AdcsRequestId, the
            // failure arm demoted the order to invalid, and its reload discarded the
            // request id the throw had left unsaved. The certificate was live at the
            // CA, the order read invalid, and nothing pointed one at the other.
            var result = await _adcsClient.SubmitCertificateRequestAsync(
                order.TemplateId, csrDer, CancellationToken.None);

            // Only the two outcomes that leave a certificate at the CA, now or when
            // an operator approves. A denial leaves nothing to reconcile, so its arm
            // failing gets the plain message below rather than a warning about an
            // orphan that does not exist.
            if (result.Status is SubmitStatus.Issued or SubmitStatus.Pending)
                submittedRequestId = result.RequestId;

            // Recorded the instant it is true, rather than as a side effect of
            // whichever arm below happens to save next. Nothing else in this scope
            // is dirty here, since the claim went through ExecuteUpdate and then
            // reloaded, so this flushes exactly that one column. It matters because
            // the completion below can now roll back, and a rollback that discarded
            // the only record of what the CA was asked would leave a certificate at
            // the CA with nothing in the database pointing at it.
            order.AdcsRequestId = result.RequestId;
            await _db.SaveChangesAsync(CancellationToken.None);

            if (result.Status == SubmitStatus.Issued)
            {
                // Certificate issued immediately, so fetch and store it. Past this
                // point the certificate exists at the CA, so IssueCertificateAsync
                // takes no cancellation token: the record gets written whether or
                // not the client is still listening.
                await IssueCertificateAsync(order, result.RequestId);
            }
            else if (result.Status == SubmitStatus.Pending)
            {
                // Pending CA approval — stay in "processing"
                _logger.LogInformation(
                    "Order {OrderId} submitted to ADCS (request {RequestId}), pending approval",
                    orderId, result.RequestId);
                await _db.SaveChangesAsync(CancellationToken.None);
            }
            else
            {
                // Denied or error. The CA's own message goes to the client in its own
                // words, as it always has: it is the CA's decision to report, not
                // ours to paraphrase. Its own words, not its own bytes. AdcsClient
                // sanitizes this before it ever leaves the COM path, and it is
                // sanitized again here (issue #362) because the class doc on
                // CertificateTextSanitizer gives the reason: sanitizing at the writer
                // rather than only in each client is what makes the guard hold for
                // any IAdcsClient, and this method is a writer to an ACME problem
                // document, to ErrorJson and to the log. Every function there is
                // idempotent, so the second pass changes nothing but the assumption.
                //
                // That message alone was not enough, and issue #356 is what it cost.
                // The lab CA answered a template Enroll denial with the bare string
                // "Denied by Policy Module", with no reason after it (request 109,
                // 2026-08-24), so the client learned that a decision had been made and
                // nothing whatever about why. The reason was there the whole time in
                // the request's status code, and now travels beside the message rather
                // than instead of it, so a policy module that does explain itself keeps
                // its own words.
                //
                // Microsoft's descriptions name no account and no host, which is why
                // they may go on the wire when DescribeDenialRemedy may not. That
                // remedy names this service's computer account, so it stays on the log
                // (issue #336), and only for a denial: an Error disposition is not a
                // permissions problem and pointing at a Security tab for it would
                // misdirect.
                //
                // Two forms of the CA's own half, because the log wants one line and
                // the wire keeps the line breaks a multi line denial was written with
                // (issue #362). The explanation is our own single line text either
                // way, so only the CA's half differs between them.
                var caMessage = CertificateTextSanitizer.SanitizeDispositionMessage(
                    result.Message);
                var caMessageForLog = CertificateTextSanitizer.SanitizeDispositionMessageForLog(
                    result.Message);
                var refusal = CaStatusCode.DescribeRefusal(caMessage, result.StatusCode);
                var refusalForLog = CaStatusCode.DescribeRefusal(
                    caMessageForLog, result.StatusCode);

                if (result.Status == SubmitStatus.Denied)
                    _logger.LogWarning(
                        "The CA denied order {OrderId} on template {Template}: {CaMessage} {Remedy}",
                        orderId, order.TemplateId, refusalForLog ?? "no reason given",
                        DescribeDenialRemedy(order.TemplateId));
                else
                    _logger.LogError(
                        "The CA reported an error for order {OrderId} on template {Template}: {CaMessage}",
                        orderId, order.TemplateId, refusalForLog ?? "no detail available");

                order.Status = "invalid";
                order.ErrorJson = JsonSerializer.Serialize(new AcmeError
                {
                    Type = AcmeErrorType.ServerInternal,
                    Detail = refusal ?? "Certificate request was denied by the CA."
                });
                await _db.SaveChangesAsync(CancellationToken.None);
                return new FinalizeResult(FinalizeOutcome.CaRefused,
                    refusal ?? "CA denied the certificate request.");
            }

            return new FinalizeResult(FinalizeOutcome.Submitted, null);
        }
        catch (CaUnavailableException ex)
        {
            // The CA could not be reached, which is not a refusal and not a
            // statement about the CSR (issue #324). Before this it fell into the
            // arm below: the order was burned to "invalid" for a CertSvc restart
            // and the client was told badCSR, which invites it to rebuild a key
            // and a CSR that were never the problem. This arm must come first,
            // because CaUnavailableException derives from InvalidOperationException.
            //
            // Two cases, and they differ by whether anything reached the CA.
            if (submittedRequestId is { } heldRequestId)
            {
                // The CSR reached the CA and its request id is already saved, so
                // only the collection failed. This is the pending arm by another
                // route: the order is still "processing" and PendingIssuanceService
                // completes it once the CA answers again (issue #319). Failing the
                // order here would strand a live leaf for a blip. Nothing is
                // written, deliberately.
                _logger.LogWarning(ex,
                    "Order {OrderId} was accepted by the CA as request {RequestId} but the CA " +
                    "became unavailable before its certificate could be collected, so it stays " +
                    "processing for the pending issuance sweep to finish",
                    orderId, heldRequestId);
                return new FinalizeResult(FinalizeOutcome.Submitted, null);
            }

            // Nothing reached the CA, which IAdcsClient promises this exception
            // means and AdcsClient now makes structural: the exception can only
            // escape its submit when the Submit call itself did not execute. So
            // the claim bought nothing, and it must not cost the client its order.
            // CreateOrderAsync never reuses a valid authorization, so a new order
            // is a full revalidation of every identifier for an outage, and
            // PendingIssuanceService already states the rule this follows: a CA
            // outage must never be what fails an order.
            //
            // Releasing rather than leaving it "processing" is the point. With no
            // AdcsRequestId the sweep leaves such a row alone until expiry, so
            // seven days of an order nothing will ever finish. Conditional from
            // "processing" like every other status write here, because the sweep
            // can abandon an order that straddled its own expiry meanwhile. CsrDer
            // is cleared so it keeps meaning "the CSR this order was claimed for",
            // and no ErrorJson is written: a ready order carrying an error is a
            // contradiction.
            var released = await _db.AcmeOrders
                .Where(o => o.Id == order.Id && o.Status == "processing")
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "ready")
                    .SetProperty(o => o.CsrDer, (string?)null),
                    CancellationToken.None);
            await _db.Entry(order).ReloadAsync(CancellationToken.None);

            if (released == 0)
                _logger.LogWarning(ex,
                    "Order {OrderId} had already left processing when the CA was found " +
                    "unavailable (it reads {Status}), so its claim was left as it stands",
                    orderId, order.Status);
            else
                // Warning rather than Information on purpose: this is the only
                // trail an operator has if a CA request ever turns up that no
                // order claims.
                _logger.LogWarning(ex,
                    "The CA was unavailable, so order {OrderId} was returned to ready with " +
                    "nothing submitted; the client can finalize it again", orderId);

            return new FinalizeResult(FinalizeOutcome.CaUnavailable,
                "The ADCS Certificate Authority is unavailable. Try again shortly.");
        }
        catch (CaAccessDeniedException ex)
        {
            // The CA was reached and refused this service's own credentials (issue
            // #336). Like the outage above this is not a refusal and not a statement
            // about the CSR, so it splits the same way, on whether anything reached
            // the CA. Unlike the outage it does not clear on its own, which is what
            // the log levels below say and the only real difference between them.
            //
            // Placed after the outage arm for reading order rather than for
            // precedence: this exception derives from UnauthorizedAccessException,
            // not from InvalidOperationException, so the two can never shadow each
            // other. It must stay above the general arm, which would otherwise
            // invalidate the order for a condition an administrator can fix.
            if (submittedRequestId is { } heldRequestId)
            {
                // The CSR reached the CA and its request id is already saved, so only
                // the collection was refused. Identical in shape to the outage's
                // pending arm and for the identical reason: the order is still
                // "processing", the certificate is real, and PendingIssuanceService
                // completes it once the permission is restored. Its own
                // CaAccessDeniedException arm already handles the sweep side. Failing
                // the order here would strand a live leaf over a missing ACL.
                // Nothing is written, deliberately.
                _logger.LogError(ex,
                    "Order {OrderId} was accepted by the CA as request {RequestId} but this " +
                    "service was denied access before its certificate could be collected, so " +
                    "it stays processing for the pending issuance sweep to finish. This will " +
                    "not clear on its own: {Message}",
                    orderId, heldRequestId, ex.Message);
                return new FinalizeResult(FinalizeOutcome.Submitted, null);
            }

            // Nothing reached the CA, which is what this exception means on the submit
            // path: AdcsClient raises it only when the Submit call itself did not
            // execute, the same structural promise IAdcsClient makes for a CA outage.
            // So the claim bought nothing and must not cost the client its order.
            // Released rather than left "processing", because with no AdcsRequestId
            // the sweep leaves such a row alone until expiry. Conditional from
            // "processing" like every other status write here, CsrDer cleared so it
            // keeps meaning "the CSR this order was claimed for", and no ErrorJson: a
            // ready order carrying an error is a contradiction.
            var releasedAfterDenial = await _db.AcmeOrders
                .Where(o => o.Id == order.Id && o.Status == "processing")
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "ready")
                    .SetProperty(o => o.CsrDer, (string?)null),
                    CancellationToken.None);
            await _db.Entry(order).ReloadAsync(CancellationToken.None);

            if (releasedAfterDenial == 0)
                _logger.LogError(ex,
                    "Order {OrderId} had already left processing when the CA refused this " +
                    "service's credentials (it reads {Status}), so its claim was left as it " +
                    "stands", orderId, order.Status);
            else
                // Error rather than the outage arm's Warning. An outage is expected to
                // pass; a withdrawn permission blocks every issuance until a person
                // acts, so this is the line that has to be worth waking up for. It
                // carries the remediation the client is deliberately not told.
                _logger.LogError(ex,
                    "The CA refused this service's credentials, so order {OrderId} was " +
                    "returned to ready with nothing submitted. Every finalize will fail the " +
                    "same way until this is fixed: {Message}",
                    orderId, ex.Message);

            return new FinalizeResult(FinalizeOutcome.CaAccessDenied,
                "The server could not submit the request to the CA. Try again shortly.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to submit CSR to ADCS for order {OrderId}", orderId);

            // This arm is a demote too, so it names its legal predecessor like the
            // rest (issue #312). It normally catches a submit that never reached the
            // CA, where the order is the "processing" this scope just claimed. But it
            // also covers everything IssueCertificateAsync does, including the far
            // side of the completion commit: the reload and the sync nudge that
            // follow it are ordinary calls that can throw, and by then the order is
            // committed "valid" with its certificate row stored. An unpredicated
            // write here would put that order back to "invalid" while its certificate
            // stayed downloadable, which is exactly the corruption the rest of this
            // change removes, reintroduced by the error path.
            var errorJson = JsonSerializer.Serialize(new AcmeError
            {
                Type = AcmeErrorType.ServerInternal,
                Detail = "Failed to submit certificate request to the CA."
            });
            var demoted = await _db.AcmeOrders
                .Where(o => o.Id == order.Id && o.Status == "processing")
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "invalid")
                    .SetProperty(o => o.ErrorJson, errorJson),
                    CancellationToken.None);
            await _db.Entry(order).ReloadAsync(CancellationToken.None);

            if (demoted == 0)
                _logger.LogWarning(
                    "Order {OrderId} had already left processing when the failure above was " +
                    "handled (it reads {Status}), so it was left as it stands",
                    orderId, order.Status);
            else if (submittedRequestId is { } requestId)
                // The order is now invalid and the CA holds a request that is, or can
                // become, a certificate, so this is exactly the orphan issue #321 is
                // about and the request id is what an operator needs to find it.
                // Reported here rather than beside the exception above, because only
                // the demote landing makes it true: on the zero rows path the order
                // completed and its certificate was delivered, and warning there
                // would send an operator hunting for an orphan that does not exist.
                // Same shape as the zero rows arm of IssueCertificateAsync, which
                // reports the other way this pairing can arise.
                _logger.LogError(
                    "Order {OrderId} was left invalid after the CA accepted its CSR as " +
                    "request {RequestId}, so a certificate may be live for it with nothing " +
                    "in the database pointing at it; reconcile CA request {RequestId} by hand",
                    orderId, requestId, requestId);

            // Reported as a failure either way. When the order did complete and only
            // the tail threw, the client retries the finalize and is told the order is
            // no longer ready, which is true and costs it nothing.
            return new FinalizeResult(FinalizeOutcome.CaRefused, "Failed to submit to CA.");
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
    ///
    /// Every refusal here is a statement about the CSR, and the caller answers all
    /// of them badCSR. That is only true because the caller decides both policy
    /// questions before calling and hands in what they were decided against: the
    /// profile (issue #323) and the identifier the allowlist admitted (issue #335).
    /// Neither a dead profile nor a delisted device is a complaint about the CSR,
    /// and neither may be answered as one.
    /// </summary>
    private string? CheckDeviceCsr(
        AcmeOrder order,
        AcmeIdentifier deviceIdentifier,
        DeviceAttestationProfile profile,
        byte[] csrDer)
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
    /// Finds the certificate an ARI identifier names (RFC 9773 §4.1), shared
    /// by the renewal info endpoint and the new-order replaces resolver so the
    /// two cannot drift on which certificates are addressable.
    ///
    /// Every row carrying the serial is considered, not just the first:
    /// serials are only unique per certificate authority, so an install
    /// re-pointed at a new CA can hold two rows sharing one serial, and the
    /// octet verification below is what picks the certificate actually named.
    /// The verification compares octets, never strings, because base64
    /// decoding tolerates non canonical trailing bits. The serial half
    /// restates what the row lookup already proved, deliberately: it guards a
    /// SerialNumber column that has drifted from its own stored PEM, the one
    /// shape the lookup cannot see. Only the parse sits in a try (the issue
    /// #332 lesson): an unreadable stored leaf cannot be verified and is
    /// skipped, and anything else that throws is this code's own bug and must
    /// surface as one.
    /// </summary>
    public async Task<AriCertificateMatch?> FindCertificateByAriOctetsAsync(
        byte[] keyIdentifier,
        byte[] serialNumber,
        CancellationToken cancellationToken = default)
    {
        var serialHex = AriCertificateId.SerialHex(serialNumber);
        if (serialHex.Length == 0)
            return null;

        var candidates = await _db.AcmeCertificates
            .AsNoTracking()
            .Include(c => c.Order)
            .Where(c => c.SerialNumber == serialHex)
            .ToListAsync(cancellationToken);

        foreach (var candidate in candidates)
        {
            X509Certificate2 leaf;
            try
            {
                leaf = X509Certificate2.CreateFromPem(candidate.CertificatePem);
            }
            catch (Exception)
            {
                continue;
            }

            if (!AriCertificateId.TryFromCertificate(leaf, out var leafKeyId, out var leafSerial)
                || !leafKeyId.AsSpan().SequenceEqual(keyIdentifier)
                || !leafSerial.AsSpan().SequenceEqual(serialNumber))
            {
                leaf.Dispose();
                continue;
            }

            var revokedAt = await ResolveRevocationInstantAsync(candidate, cancellationToken);
            return new AriCertificateMatch(candidate, leaf, revokedAt);
        }

        return null;
    }

    /// <summary>
    /// When the certificate is revoked, the instant the renew now window
    /// anchors on; null while it is live. Belt and braces on purpose: the
    /// ACME row is stamped by revoke-cert, the finalize guard and the
    /// dashboard, but a revocation done at the CA itself (certutil,
    /// certsrv.msc) reaches only the synced inventory, and the renew now
    /// window exists precisely for that case. The bridge key is the one the
    /// revocation stamps use in the other direction, unique on the inventory
    /// side, so this is a point read per poll.
    /// </summary>
    private async Task<DateTimeOffset?> ResolveRevocationInstantAsync(
        AcmeCertificate certificate, CancellationToken cancellationToken)
    {
        if (certificate.RevokedAt is { } stamped)
            return new DateTimeOffset(DateTime.SpecifyKind(stamped, DateTimeKind.Utc));

        if (certificate.AdcsRequestId <= 0)
            return null;

        var synced = await _db.SyncedCertificates
            .AsNoTracking()
            .Where(s => s.RequestId == certificate.AdcsRequestId)
            .Select(s => new { s.Status, s.RevokedAt })
            .FirstOrDefaultAsync(cancellationToken);
        if (synced == null)
            return null;

        if (synced.RevokedAt is { } fromSync)
            return new DateTimeOffset(DateTime.SpecifyKind(fromSync, DateTimeKind.Utc));

        // Revoked with no recorded instant: anchored on now, so the window is
        // in the past from this poll onward.
        return string.Equals(synced.Status, "Revoked", StringComparison.OrdinalIgnoreCase)
            ? DateTimeOffset.UtcNow
            : null;
    }

    /// <summary>
    /// Resolves the optional "replaces" member of a new-order request
    /// (RFC 9773 §5). <see cref="ReplacesOutcome.NotPresent"/> and
    /// <see cref="ReplacesOutcome.Resolved"/> are the two admitting outcomes;
    /// anything else refuses the whole new-order, because the section's MUST
    /// is to reflect the field once the order is accepted, so accepting the
    /// order while dropping the field is not an option.
    ///
    /// The canonical identifier returned on <see cref="ReplacesOutcome.Resolved"/>
    /// is the verified octets reformatted, so what the order records and later
    /// reflects is the certificate's stable identity even when the client sent
    /// a non canonical base64 spelling of it.
    ///
    /// The already-replaced test is the section's SHOULD and is a plain read:
    /// two orders racing it can both pass and both record the same
    /// certificate. Accepted: the check exists to stop duplicate renewal
    /// loops, not to serialize order creation, and the RFC permits servers
    /// that do not check at all.
    /// </summary>
    public async Task<(ReplacesOutcome Outcome, string? CanonicalId)> ResolveReplacesAsync(
        AcmeAccount account,
        AcmeIdentifier[] identifiers,
        string? replaces,
        CancellationToken cancellationToken = default)
    {
        if (replaces == null)
            return (ReplacesOutcome.NotPresent, null);

        if (!AriCertificateId.TryParse(replaces, out var keyIdentifier, out var serialNumber))
            return (ReplacesOutcome.Malformed, null);

        var match = await FindCertificateByAriOctetsAsync(
            keyIdentifier, serialNumber, cancellationToken);
        if (match == null)
            return (ReplacesOutcome.UnknownCertificate, null);
        match.Leaf.Dispose();

        if (match.Certificate.Order.AccountId != account.Id)
            return (ReplacesOutcome.NotOwned, null);

        var replacedIdentifiers =
            JsonSerializer.Deserialize<AcmeIdentifier[]>(match.Certificate.Order.IdentifiersJson)
            ?? Array.Empty<AcmeIdentifier>();
        var sharesOne = identifiers.Any(requested =>
            replacedIdentifiers.Any(replaced => SameIdentifier(requested, replaced)));
        if (!sharesOne)
            return (ReplacesOutcome.NoSharedIdentifier, null);

        // The verified octets are the canonical spelling by construction.
        var canonical = AriCertificateId.Format(keyIdentifier, serialNumber);

        // An allow list of the order shapes that count as a live replacement,
        // because the safe polarity here is not blocking: over blocking is a
        // permanent 409 lockout on the certificate, under blocking is at worst
        // a duplicate renewal the RFC tolerates. A valid order blocks for
        // ever. A processing order blocks unconditionally, because the pending
        // issuance sweep always settles it one way or the other. A pending or
        // ready order blocks only until its own expiry: expiry is lazy in this
        // schema (the finalize checks it per read and nothing ever writes it
        // back as a status), so an abandoned order would otherwise count as a
        // live replacement for the life of the database.
        var now = DateTime.UtcNow;
        var alreadyReplaced = await _db.AcmeOrders.AnyAsync(
            o => o.ReplacesCertificateId == canonical
                && (o.Status == "valid"
                    || o.Status == "processing"
                    || ((o.Status == "pending" || o.Status == "ready") && o.ExpiresAt > now)),
            cancellationToken);
        if (alreadyReplaced)
            return (ReplacesOutcome.AlreadyReplaced, null);

        return (ReplacesOutcome.Resolved, canonical);
    }

    /// <summary>
    /// Identifier equality for the shared-identifier check. DNS names trim
    /// and compare case insensitively, the same normalization the finalize
    /// applies when matching a CSR's names to an order; a device identifier's
    /// value is octet exact everywhere else in the product, so it is octet
    /// exact here too.
    /// </summary>
    private static bool SameIdentifier(AcmeIdentifier a, AcmeIdentifier b)
    {
        if (!string.Equals(a.Type, b.Type, StringComparison.Ordinal))
            return false;

        return AcmeIdentifierTypes.IsDeviceType(a.Type)
            ? string.Equals(a.Value, b.Value, StringComparison.Ordinal)
            : string.Equals(a.Value.Trim(), b.Value.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Revokes a stored certificate at the CA and records the revocation on the row.
    /// Returns <see cref="RevokeOutcome.AlreadyRevoked"/> without calling the CA when the
    /// certificate is already revoked (RFC 8555 §7.6). A
    /// <see cref="Certus.Core.Adcs.CaUnavailableException"/> from the CA propagates so the
    /// endpoint can map it to a 503.
    ///
    /// <para>
    /// Attempts for the same serial are serialized through
    /// <see cref="CertificateRevocationGate"/>, the same singleton the dashboard path
    /// uses, so of two simultaneous revocations only the winner reaches the CA and the
    /// loser is refused as already revoked (issue #226). The gate is shared rather than
    /// per surface because both surfaces run in one process: the production host is
    /// Certus.Service, which serves the ACME controllers out of the referenced
    /// Certus.Web assembly. The two serial forms meet on the gate's normalized key.
    /// </para>
    /// </summary>
    public async Task<RevokeOutcome> RevokeCertificateAsync(
        AcmeCertificate certificate,
        int reason,
        CancellationToken cancellationToken = default)
    {
        // The whole re-read, guard, CA call, record sequence runs under the per
        // serial gate; see CertificateRevocationGate for why the guard alone is
        // not enough. Waiting is unbounded and tied to the caller's token, so an
        // ACME client that gives up while parked behind a dashboard revocation's
        // in request resync cancels out cleanly, short of the CA.
        using var gateHandle = await _revocationGate.AcquireAsync(
            certificate.SerialNumber, cancellationToken);

        // Load bearing, and the whole point of holding the gate. The caller found
        // this entity through FindCertificateBySerialAsync, which tracks it, so the
        // RevokedAt below is whatever was true before the gate was acquired. Re-read
        // it here or the stale value reproduces the race with extra steps.
        //
        // ReloadAsync rather than a fresh query: EF answers a repeat query for a
        // tracked entity from this scope's identity map without overwriting the
        // property values, so `_db.AcmeCertificates.FirstOrDefault(...)` would hand
        // back this same instance still saying null and quietly undo the fix.
        // Reload refreshes the values in place and leaves the entity tracked for
        // the write below.
        await _db.Entry(certificate).ReloadAsync(cancellationToken);

        if (certificate.RevokedAt != null)
            return RevokeOutcome.AlreadyRevoked;

        await _adcsClient.RevokeCertificateAsync(certificate.SerialNumber, reason, cancellationToken);

        // The CA has revoked. That is now a fact, and everything below only records
        // it, so nothing here may be abandoned by a client disconnect and nothing
        // here may fail the request: the whole tail runs on CancellationToken.None
        // and swallows its own failures, the same rule
        // CertificateRevocationService.RecordRevocationAsync follows.
        await RecordRevocationAsync(certificate, reason);

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
    /// Writes what is now certain after a successful CA call: this certificate is
    /// revoked, with this reason, on the ACME row and on the dashboard's inventory
    /// row alike.
    ///
    /// <para>
    /// Best effort as a whole, and deliberately so. The CA has already acted, so a
    /// bookkeeping failure must not turn an accomplished revocation into a 500. The
    /// endpoint maps only the two CA exceptions
    /// (<c>RevokeCertController</c>), so anything thrown here would surface as a
    /// server error, and an ACME client answering a 500 with a retry would find
    /// <see cref="AcmeCertificate.RevokedAt"/> still null and send the CA a second
    /// revocation, which is the very thing the gate above exists to prevent.
    /// </para>
    /// </summary>
    private async Task RecordRevocationAsync(AcmeCertificate certificate, int reason)
    {
        var revokedAt = DateTime.UtcNow;

        try
        {
            certificate.RevokedAt = revokedAt;
            certificate.RevokedReason = reason;
            await _db.SaveChangesAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Certificate {CertId} (serial {Serial}) was revoked at the CA but the ACME " +
                "row could not be stamped. A later revoke-cert for it will reach the CA a " +
                "second time rather than answering alreadyRevoked",
                certificate.CertificateId, certificate.SerialNumber);
        }

        await StampInventoryRowAsync(certificate, reason, revokedAt);
    }

    /// <summary>
    /// Mirrors this revocation onto the dashboard's inventory row, the reverse of the
    /// stamp <c>CertificateRevocationService.RecordRevocationAsync</c> writes onto the
    /// ACME row (issue #226). Without it the cross surface guarantee is one way: the
    /// gate above only closes the window where the two revocations overlap, while the
    /// sync this method stands in for is a full CA pull wide. Inside that window a
    /// dashboard revoke would re-read an inventory row still saying Issued, pass every
    /// guard, and send the CA a second revocation.
    ///
    /// <para>
    /// Best effort as a whole, and deliberately so, for the same reason the dashboard's
    /// stamp is: the CA has already acted, so a bookkeeping failure must not turn an
    /// accomplished revocation into a 500 that invites the client to try again. A
    /// certificate that has not reached the inventory yet matches no row, which is
    /// harmless; the next sync brings it in already revoked.
    /// </para>
    /// </summary>
    private async Task StampInventoryRowAsync(
        AcmeCertificate certificate, int reason, DateTime revokedAt)
    {
        // The bridge key must identify one certificate. Every row this path can reach
        // carries a real CA request id, so this only ever refuses a row that was
        // stored without one, where the key would select by an unset value rather
        // than by identity. Stamping the inventory as revoked is not something to do
        // on a guess.
        if (certificate.AdcsRequestId <= 0)
        {
            _logger.LogWarning(
                "Certificate {CertId} (serial {Serial}) was revoked at the CA but carries " +
                "no CA request id, so the inventory row cannot be identified; it corrects " +
                "on the next sync",
                certificate.CertificateId, certificate.SerialNumber);
            return;
        }

        try
        {
            // Bridged on the CA request id, the same key #202 used in the other
            // direction. Written as a direct UPDATE rather than through a tracked
            // entity so it cannot be shadowed by this scope's identity map.
            await _db.SyncedCertificates
                .Where(c => c.RequestId == certificate.AdcsRequestId
                         && c.Status != nameof(CertificateStatus.Revoked))
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(c => c.Status, nameof(CertificateStatus.Revoked))
                    .SetProperty(c => c.RevokedAt, revokedAt)
                    .SetProperty(c => c.RevokedReason, reason),
                    CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Certificate {CertId} (serial {Serial}) was revoked at the CA but the " +
                "inventory row could not be stamped. The inventory corrects on the next " +
                "sync; until then a dashboard revocation may reach the CA a second time",
                certificate.CertificateId, certificate.SerialNumber);
        }
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

        // "processing" joins the terminal pair (issue #312). Once a finalize has
        // claimed an order, that order's status belongs to the issuance path until
        // the CA answers: the finalize itself, and since issue #319 the sweep that
        // waits out a CA holding the request for manager approval. This method runs
        // on the validation worker's own DbContext and would otherwise be a writer
        // racing that completion from outside it, and the one that is not a client
        // request at all. Issue #301 already stopped the ready arm re-arming a
        // claimed order; this stops the invalid arm demoting one.
        //
        // Nothing reachable is lost. The worker's three call sites either cannot
        // produce an unusable authorization under a processing order, or already
        // wrote the demote themselves: a challenge failing marks its authorization
        // invalid only when every challenge in it is invalid, and an order can only
        // be processing if the claim found it ready, which required every
        // authorization valid, so the sibling challenge that made it valid is still
        // valid; and a deactivation never reaches here at all, because
        // ChallengeValidationService returns early on a deactivated authorization
        // without calling this method, and DeactivateAuthorizationAsync writes its
        // own demote. The expiry arm does reach a processing order, and leaving it
        // alone is right rather than a loss: the order's own expiry was checked
        // before the claim, and an authorization ageing out afterwards does not
        // retroactively unauthorize an issuance already in flight. The
        // authorization and the challenge still go invalid, so the record of what
        // happened survives; only the order status is left to the finalize that
        // owns it.
        //
        // Widened here rather than as a predicate on the invalid arm because this
        // early return is the single statement of "this order's status is no longer
        // mine", it is what DeactivateAuthorizationAsync's allow list agrees with by
        // construction, and it covers any arm added later.
        if (order == null || order.Status is "valid" or "invalid" or "processing")
            return;

        // Any authorization that can never be valid again → order invalid.
        // RFC 8555 §7.5.2: a deactivated authorization is as fatal to the order as
        // a failed one, and without this arm it satisfies neither test below, so
        // this method was a silent no-op for one and an order could sit pending
        // for ever. DeactivateAuthorizationAsync writes the demote itself, in the
        // same SaveChanges as the status flip; this arm is what keeps the
        // validation worker's three call sites agreeing with that write.
        //
        // The one demote in the product that deliberately writes no ErrorJson, and
        // the silence is a decision rather than an oversight (issue #330). This is
        // also the commonest way an order dies, since it is what a failed challenge
        // produces. RFC 8555 section 7.1.6 puts the reason for exactly this failure
        // on the authorization and its challenge, not on the order: the challenge
        // carries the problem document that says which validation failed and how,
        // ToChallengeResponse projects it, and the order response already hands the
        // client the authorization URLs to follow. An order level error here would
        // be a second, vaguer copy of a reason the client can already read, written
        // on the path that runs most often. Adding one is a behaviour change to be
        // decided on its own, not a tidy up.
        if (order.Authorizations.Any(a => a.Status == "invalid" || a.Status == "deactivated"))
        {
            order.Status = "invalid";
            _logger.LogInformation(
                "Order {OrderId} is now invalid (an authorization is no longer usable)", order.OrderId);
        }
        // Check if all authorizations are valid → order ready. Only out of
        // "pending", never out of "processing" (issue #301): that order has
        // already been claimed by a finalize and its CSR is at the CA, so
        // handing it back to "ready" would invite a second finalize, which the
        // claim would then grant, and the account would hold two certificates
        // for one order. The sweep does reach a processing order: a second
        // challenge on an already valid authorization stays queued when the
        // client finalizes, and validating it lands here.
        else if (order.Status == "pending" && order.Authorizations.All(a => a.Status == "valid"))
        {
            order.Status = "ready";
            _logger.LogInformation("Order {OrderId} is now ready for finalization", order.OrderId);
        }
        // Otherwise: still pending

        await _db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Resolves one order whose issuance the CA has not finished deciding
    /// (issue #319). Called only by <see cref="PendingIssuanceService"/>, once
    /// per order per sweep.
    ///
    /// <para>
    /// This is the second half of the finalize's pending arm. That arm records
    /// the request id, leaves the order "processing" and returns, because a CA
    /// whose template carries CT_FLAG_PEND_ALL_REQUESTS answers every submit
    /// with "pending" and there is nothing more a client request can do. Until
    /// this method existed nothing revisited such an order: the only call site
    /// of <see cref="IssueCertificateAsync"/> was the finalize's own "issued"
    /// arm, so the certificate an operator approved was never delivered and the
    /// order never reached a terminal status either, leaving a client polling
    /// per RFC 8555 section 7.1.3 with "processing" for ever. Manager approval
    /// is an ordinary ADCS template setting, and the wizard's readiness
    /// checklist already warns about it and then lets the operator proceed
    /// (TemplateAcmeViability.RequiresManagerApproval), so this was reachable by
    /// following the product's own advice.
    /// </para>
    ///
    /// <para>
    /// The CA is asked before the expiry is applied, on purpose. An order past
    /// its expiry whose certificate the CA has already issued is better
    /// delivered than abandoned: abandoning it would strand a live certificate
    /// with no order pointing at it, which is the orphan issue #321 is about,
    /// and refusing to serve what was already issued is not the product's
    /// stance anywhere else (MayServe deliberately does not re-check expiry,
    /// see issue #318). The expiry decides how long we wait, not whether we
    /// hand over a certificate that exists.
    /// </para>
    ///
    /// <para>
    /// Writes run on <see cref="CancellationToken.None"/> below the CA call, the
    /// stance the whole issuance path takes since issue #321: once the CA has
    /// answered, the record is written whether or not the sweep is being shut
    /// down. The token gates the read and the CA round trip, where nothing has
    /// been written yet and the next tick simply retries.
    /// </para>
    /// </summary>
    /// <returns>What was done, for the sweep's log and for tests.</returns>
    public async Task<HeldOrderResolution> ResolveHeldOrderAsync(
        int orderId,
        CancellationToken cancellationToken = default)
    {
        // The account is included because the completion path can reach the
        // finalize leaf guard's breach arm, which writes a domain policy audit row
        // keyed on the account id. The authorizations are not: nothing below this
        // point reads them, and the finalize already decided this order's
        // authorizations were sufficient when it claimed it.
        var order = await _db.AcmeOrders
            .Include(o => o.Account)
            .FirstOrDefaultAsync(o => o.Id == orderId, cancellationToken);

        // Re-read rather than trust what the sweep's query saw. The sweep loads a
        // batch and then works through it one CA round trip at a time, so a row it
        // read at the top of the tick can have been answered by a finalize, or by
        // anything else, long before its turn comes.
        if (order == null || order.Status != "processing")
            return HeldOrderResolution.NotHeld;

        if (order.AdcsRequestId is not { } requestId)
        {
            // "processing" with no request id is the finalize's claim without the
            // save that follows its submit. Usually that is a finalize in flight
            // right now, which owns the order and must be left alone. It can also
            // be a process that died in that window, and then nobody knows what
            // the CA was asked, so there is no request to poll and no way back:
            // the order's own expiry is the only thing that can end it.
            //
            // Safe to demote on expiry despite the in flight case, because a
            // finalize refuses an expired order before it claims one, so reaching
            // here means a finalize would have had to run across the expiry
            // instant itself. If one ever did, its completion finds the row no
            // longer "processing" and reports the orphan rather than writing over
            // this.
            return DateTime.UtcNow > order.ExpiresAt
                ? await AbandonHeldOrderAsync(order, null)
                : HeldOrderResolution.NotHeld;
        }

        var certResult = await _adcsClient.GetCertificateAsync(requestId, cancellationToken);

        switch (certResult.Status)
        {
            case CertificateStatus.Issued:
                // The same call the finalize's issued arm makes, and deliberately
                // the same one rather than a copy: the finalize leaf guard, the
                // capability ceiling, the serial, the transactional insert and
                // status swap, and the inventory nudge all belong to a delivery
                // however it was triggered. It re-fetches the certificate, which
                // costs this path one extra round trip once in an order's life.
                await IssueCertificateAsync(order, requestId);
                return HeldOrderResolution.Collected;

            case CertificateStatus.Pending:
                return DateTime.UtcNow > order.ExpiresAt
                    ? await AbandonHeldOrderAsync(order, requestId)
                    : HeldOrderResolution.StillHeld;

            default:
                // Denied, Revoked, or Failed. Revoked means an operator approved
                // and then revoked before anyone collected it; Failed covers a
                // request the CA no longer has. None of the three can become a
                // certificate we may deliver, so they share one terminal answer.
                //
                // serverInternal matches the finalize's own denial arm word for
                // word, and since issue #324 that is by design rather than by
                // accident: the finalize answers 500 serverInternal for a CA
                // refusal too, so one refusal reads the same wherever it is
                // discovered. The two arms move together if the vocabulary ever
                // changes; a different one here would report the same refusal two
                // ways depending on when the CA decided.
                //
                // The detail now travels too (issue #365). The finalize reads its
                // reason from GetLastStatus, which reflects only the latest Submit,
                // RetrievePending or GetCACertificate and so has nothing to say on
                // this path; the same pair is in the request row either way, and
                // that is what GetRequestStatusAsync reads. DescribeRefusal is the
                // one composer for both arms, so a refusal cannot read two ways
                // depending on when the CA decided it.
                //
                // Denied and Failed only. Revoked is not a refusal of the request
                // and the CA records no explanation against a revoked row, so
                // asking would spend a round trip to be told nothing.
                var caRecord = certResult.Status is CertificateStatus.Denied
                    or CertificateStatus.Failed
                    ? await ReadRefusalReasonAsync(requestId, cancellationToken)
                    : null;
                var reason = CaStatusCode.DescribeRefusal(
                    caRecord?.DispositionMessage, caRecord?.StatusCode);

                // Both fallbacks are what this arm said before there was anything
                // to add, byte for byte, because a CA that explains nothing must
                // still answer exactly what it answered.
                var refusal = certResult.Status == CertificateStatus.Denied
                    ? reason ?? "Certificate request was denied by the CA."
                    : reason ?? $"The CA can no longer issue this request (it reads {certResult.Status}).";
                var refusalJson = JsonSerializer.Serialize(new AcmeError
                {
                    Type = AcmeErrorType.ServerInternal,
                    Detail = refusal
                });

                var refused = await _db.AcmeOrders
                    .Where(o => o.Id == order.Id && o.Status == "processing")
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.Status, "invalid")
                        .SetProperty(o => o.ErrorJson, refusalJson),
                        CancellationToken.None);
                await _db.Entry(order).ReloadAsync(CancellationToken.None);

                if (refused == 0)
                    return HeldOrderResolution.NotHeld;

                // A denial discovered here is the same denial the finalize's own arm
                // reports, so it says the same thing, remedy included (issue #336).
                // Revoked and Failed are not permissions problems and keep the plain
                // line: an operator sent to a Security tab for a revoked certificate
                // is being misdirected.
                //
                // The log form of the CA's own half, the way the finalize builds
                // one: the wire keeps the line breaks a multi line denial was
                // written with and the log gets them collapsed (issue #362). Safe
                // over the already sanitized message, because the log sanitize
                // re-runs the wire one first.
                var reasonForLog = CaStatusCode.DescribeRefusal(
                    CertificateTextSanitizer.SanitizeDispositionMessageForLog(
                        caRecord?.DispositionMessage),
                    caRecord?.StatusCode);

                if (certResult.Status == CertificateStatus.Denied)
                    _logger.LogWarning(
                        "Order {OrderId} is invalid: the CA denied its request {RequestId} on " +
                        "template {Template}: {CaMessage} {Remedy}",
                        order.OrderId, requestId, order.TemplateId,
                        reasonForLog ?? "no reason given",
                        DescribeDenialRemedy(order.TemplateId));
                else
                    _logger.LogInformation(
                        "Order {OrderId} is invalid: the CA {Status} its request {RequestId}: {CaMessage}",
                        order.OrderId, certResult.Status, requestId,
                        reasonForLog ?? "no detail available");
                return HeldOrderResolution.Refused;
        }
    }

    /// <summary>
    /// What the CA recorded against a request it refused, or null (issue #365).
    ///
    /// <para>
    /// Best effort, and the broad catch is the whole point rather than defensive
    /// habit. This runs after the CA has already answered and immediately before
    /// the order is written invalid, so a failure here must cost the detail and
    /// nothing else. An escaping <see cref="CaUnavailableException"/> or
    /// <see cref="CaAccessDeniedException"/> would be caught by
    /// <c>PendingIssuanceService</c> as an outage, which abandons the whole tick
    /// and leaves an order the CA has already denied sitting in "processing"
    /// because the reason lookup failed. That is the stance
    /// <see cref="SubmitResult.StatusCode"/> already documents for the submit
    /// path: a diagnostic that could turn a decided request into an undecided one
    /// would cost more than it buys.
    /// </para>
    ///
    /// <para>
    /// It takes the caller's token, so a shutdown skips a CA excursion whose
    /// answer nobody is waiting for, and the cancellation is swallowed into null
    /// like any other failure. The status write below it already runs on
    /// <see cref="CancellationToken.None"/>, so the refusal is recorded either
    /// way.
    /// </para>
    /// </summary>
    private async Task<CaRequestStatus?> ReadRefusalReasonAsync(
        int requestId, CancellationToken cancellationToken)
    {
        try
        {
            return await _adcsClient.GetRequestStatusAsync(requestId, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex,
                "The CA's reason for refusing request {RequestId} could not be read, so the " +
                "order reports the refusal without it", requestId);
            return null;
        }
    }

    /// <summary>
    /// The operator half of a CA denial (issue #336). The CA's own disposition
    /// message is what reaches the client, and it can say far less than its name
    /// suggests: the lab CA answers a template Enroll denial with the bare "Denied
    /// by Policy Module" and no reason at all. So this is what an operator gets
    /// instead, word for word the guidance
    /// <see cref="TlsCertificateEnroller"/> gives the setup wizard for the same
    /// disposition, reusing that class's own account description so the account is
    /// named one way across the product.
    ///
    /// Log only. It names the service's computer account, which belongs in the log
    /// and on the admin surfaces rather than in a problem document any ACME account
    /// holder can read.
    ///
    /// One helper rather than two literals because a denial can be discovered in two
    /// places, the finalize's own arm and the pending issuance sweep, and those two
    /// have to say the same thing about it. The same rule already keeps their wire
    /// answers identical.
    /// </summary>
    private static string DescribeDenialRemedy(string templateName)
    {
        // Deliberately broad, and the catch is the point rather than defensive habit.
        // DescribeServiceAccount reads Environment.MachineName and the domain name out
        // of the network stack, and both can throw: NetworkInformationException when
        // the stack cannot be queried, InvalidOperationException when the machine name
        // cannot be read. In the wizard that costs an enrollment which was failing
        // anyway. Here it would cost far more than it buys, because this string is an
        // eagerly evaluated argument to a log call that sits above the order's own
        // status write. A throw would skip that write, fall through to the general
        // catch, and replace the CA's own explanation with the generic "Failed to
        // submit certificate request to the CA." The line added to improve the
        // diagnostic would have destroyed the diagnostic already there.
        //
        // Not covered by a test: DescribeServiceAccount is static and reads the host,
        // so there is no seam to make it throw from here.
        string account;
        try
        {
            account = "the computer account " + TlsCertificateEnroller.DescribeServiceAccount();
        }
        catch (Exception)
        {
            account = "its own computer account";
        }

        return $"The service enrolls as {account}. This usually means that account " +
               $"lacks Enroll permission: grant it Enroll on the Security tab of the " +
               $"{templateName} template.";
    }

    /// <summary>
    /// Gives up on an order the CA never decided, once the order has passed the
    /// expiry it advertised to the client. Writes the demote as a conditional
    /// UPDATE from "processing" like every other status write that does not
    /// already own the row.
    /// </summary>
    /// <param name="requestId">
    /// The request the CA is still holding, or null when the finalize died before
    /// recording one. Only used for the warning: a held request an operator
    /// approves after this point becomes a certificate with no order behind it,
    /// and the request id is what an operator needs to find it. Nothing is
    /// revoked here. The finalize leaf guard's auto revoke is the only automated
    /// revocation in the product and it only ever touches a leaf that very order
    /// obtained moments earlier; revoking on a timer, against a request the CA
    /// has not even decided, is a different and much larger promise.
    /// </param>
    private async Task<HeldOrderResolution> AbandonHeldOrderAsync(AcmeOrder order, int? requestId)
    {
        var errorJson = JsonSerializer.Serialize(new AcmeError
        {
            Type = AcmeErrorType.ServerInternal,
            Detail = "The CA did not decide this request before the order expired."
        });

        var abandoned = await _db.AcmeOrders
            .Where(o => o.Id == order.Id && o.Status == "processing")
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(o => o.Status, "invalid")
                .SetProperty(o => o.ErrorJson, errorJson),
                CancellationToken.None);
        await _db.Entry(order).ReloadAsync(CancellationToken.None);

        if (abandoned == 0)
            return HeldOrderResolution.NotHeld;

        if (requestId is { } held)
            _logger.LogWarning(
                "Order {OrderId} expired while CA request {RequestId} was still waiting for a " +
                "manager decision, so the order is now invalid. If that request is approved " +
                "later it becomes a certificate with no ACME order behind it; deny CA request " +
                "{RequestId}, or revoke what it issues, by hand",
                order.OrderId, held, held);
        else
            _logger.LogWarning(
                "Order {OrderId} expired still claimed for issuance with no CA request recorded " +
                "against it, so the order is now invalid. A submission that was in flight when " +
                "the service last stopped may have reached the CA; check the CA for a request " +
                "carrying this order's names",
                order.OrderId);

        return HeldOrderResolution.Abandoned;
    }

    /// <summary>
    /// Fetches the certificate from ADCS and stores it. Transitions order to "valid".
    ///
    /// Takes no cancellation token on purpose. Its precondition is that the CA has
    /// already answered "issued", so the certificate exists whatever happens next
    /// and the record has to be written regardless of whether the client is still
    /// on the other end of the request. Running this on the caller's token left the
    /// order stuck in "processing" with a live certificate and no AcmeCertificate
    /// row whenever a client disconnected mid issuance, which is the same
    /// divergence between the record and reality that issue #312 is about and far
    /// easier to hit. RefuseIssuedCertificateAsync takes the same stance for the
    /// same reason.
    /// </summary>
    private async Task IssueCertificateAsync(
        AcmeOrder order,
        int requestId)
    {
        var certResult = await _adcsClient.GetCertificateAsync(requestId, CancellationToken.None);

        if (certResult.Status != CertificateStatus.Issued || certResult.CertificatePem == null)
        {
            // A demote, so it names the status it is legal from, like every other
            // status write that cannot be sure it still owns the row. It could be a
            // tracked write while this method had one call site and that caller had
            // just claimed the order itself. The sweep added by issue #319 is a
            // second caller which only re-read the row rather than claiming it, and
            // it reaches here whenever the CA answers "issued" to the sweep's own
            // question and then something else by the time this fetch repeats it,
            // an operator revoking in between being the obvious way. Unpredicated,
            // that would write "invalid" over a completion another scope had
            // committed, leaving an order that reads invalid while its certificate
            // row and CertificateId stand: exactly the corruption issue #312
            // removed, reintroduced through the retrieval failure arm.
            var errorJson = JsonSerializer.Serialize(new AcmeError
            {
                Type = AcmeErrorType.ServerInternal,
                Detail = "Failed to retrieve issued certificate from CA."
            });
            var failed = await _db.AcmeOrders
                .Where(o => o.Id == order.Id && o.Status == "processing")
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "invalid")
                    .SetProperty(o => o.ErrorJson, errorJson),
                    CancellationToken.None);
            await _db.Entry(order).ReloadAsync(CancellationToken.None);

            if (failed == 0)
                _logger.LogWarning(
                    "Order {OrderId} had already left processing when CA request {RequestId} " +
                    "could not be retrieved (it reads {Status}), so it was left as it stands",
                    order.OrderId, requestId, order.Status);
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

        // The certificate row and the status flip are one fact, so they commit as
        // one. ExecuteUpdate cannot be batched into SaveChanges, so an explicit
        // transaction is what holds them together, and without it both orderings
        // are wrong: insert then swap leaves an orphan AcmeCertificate row on a
        // crash, findable by serial through FindCertificateBySerialAsync, and swap
        // then insert leaves an order reading "valid" advertising a certificate URL
        // that 404s. RefuseIssuedCertificateAsync deliberately stays outside this,
        // and the ceiling verdict above is evaluated before the transaction opens
        // so that holds by construction: it makes an ADCS round trip, and holding
        // the SQLite write lock across a network call would park every other
        // writer behind it. No retrying execution strategy is configured, so no
        // strategy wrapper is needed; if one is ever added, this block is one of
        // the two that has to be wrapped.
        await using var tx = await _db.Database.BeginTransactionAsync(CancellationToken.None);

        _db.AcmeCertificates.Add(cert);
        await _db.SaveChangesAsync(CancellationToken.None);

        // "processing" to "valid", never out of anything else (issue #312). The
        // plain tracked write this replaced carried no predicate, so a demote
        // another scope committed while the CSR was at the CA was silently written
        // back to "valid" and the client held a certificate for an order it had
        // been told was invalid.
        //
        // Zero rows here used to mean a writer had regressed, because between #312
        // and #319 this method had one call site and no other scope could move a
        // claimed order. It has two call sites now: the finalize's issued arm and
        // the sweep that collects an order the CA was holding (issue #319). Those
        // two can legitimately reach the same order at once, when the CA answers
        // "issued" to a submit while a sweep tick is already asking about the
        // request id the finalize recorded a moment earlier. Both fetch the same
        // request and so hold the same certificate, so whichever loses has nothing
        // to add. The arm below tells the two apart by the status the row settled
        // on rather than by which caller it is, because that is what decides
        // whether a certificate has been left behind.
        var completed = await _db.AcmeOrders
            .Where(o => o.Id == order.Id && o.Status == "processing")
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(o => o.Status, "valid")
                .SetProperty(o => o.CertificateId, cert.CertificateId),
                CancellationToken.None);

        if (completed == 0)
        {
            await tx.RollbackAsync(CancellationToken.None);

            // The insert was accepted by the change tracker before the rollback, so
            // the entity would sit there as Unchanged, describing a row that does
            // not exist. Detach it or a later save in this scope reasons about a
            // ghost.
            _db.Entry(cert).State = EntityState.Detached;
            await _db.Entry(order).ReloadAsync(CancellationToken.None);

            if (order.Status == "valid")
                // The benign half, and the only one a race between the two call
                // sites can produce: the other one delivered this very certificate,
                // because both fetched the same CA request. Nothing is orphaned and
                // nothing needs an operator, so this must not read as an alarm.
                // Recorded at all only because a delivery arriving twice is worth
                // being able to see when reading back a log.
                _logger.LogInformation(
                    "Order {OrderId} was already completed by another writer while CA request " +
                    "{RequestId} was being collected, so this copy was discarded",
                    order.OrderId, requestId);
            else
                // The order was failed while its certificate was being collected, so
                // a live certificate now has no order pointing at it. Reachable
                // through the finalize's own failure arm and through an expiring
                // sweep, both of which report the orphan themselves, so this is a
                // second witness to it rather than the only one.
                _logger.LogError(
                    "Order {OrderId} was moved out of processing by another writer while its CSR " +
                    "was at the CA (it now reads {Status}), so its certificate will not be " +
                    "delivered. CA request {RequestId} issued a certificate that is live and has " +
                    "to be revoked by hand",
                    order.OrderId, order.Status, requestId);
            return;
        }

        await tx.CommitAsync(CancellationToken.None);

        // ExecuteUpdate goes round the change tracker, so the tracked order still
        // reads "processing". FinalizeOrderAsync returns success from here and the
        // controller re-reads the order through this same scoped DbContext to build
        // its response, so without this reload a client whose certificate is
        // already issued and stored is told its order is still processing. Same
        // trap the finalize claim documents, one layer down.
        await _db.Entry(order).ReloadAsync(CancellationToken.None);

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
                //
                // Deliberately not taken through CertificateRevocationGate, unlike
                // RevokeCertificateAsync above (issue #226). This leaf was issued
                // milliseconds ago and is refused rather than delivered, so its
                // serial is known to no client and is not in the inventory yet:
                // there is nothing to race with. Against that, this whole tail runs
                // on CancellationToken.None, so taking the gate here could park the
                // product's only automated revocation behind a dashboard resync with
                // no way to give up.
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

        // Conditional from "processing" for the reason the retrieval failure arm
        // above gives: since issue #319 this runs from the sweep as well as from
        // the finalize, and the sweep never claimed the row. Zero rows leaves the
        // breach reported and the leaf revoked, which is the part that matters and
        // has already happened by here.
        var breachJson = JsonSerializer.Serialize(new AcmeError
        {
            Type = AcmeErrorType.ServerInternal,
            Detail = "The issued certificate did not meet this server's TLS certificate " +
                     "policy and was revoked. The certificate template configuration needs " +
                     "review by the administrator."
        });
        var refused = await _db.AcmeOrders
            .Where(o => o.Id == order.Id && o.Status == "processing")
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(o => o.Status, "invalid")
                .SetProperty(o => o.ErrorJson, breachJson),
                CancellationToken.None);
        await _db.Entry(order).ReloadAsync(CancellationToken.None);

        if (refused == 0)
            _logger.LogError(
                "Order {OrderId} had already left processing when its certificate was refused " +
                "by the capability ceiling (it reads {Status}). CA request {RequestId} was " +
                "revoked regardless, so if that order reads valid it is advertising a revoked " +
                "certificate and needs attention by hand",
                order.OrderId, order.Status, requestId);

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
    /// The two halves of one invariant: an order and the certificate it issued must
    /// agree before that certificate is advertised or served over ACME. RFC 8555
    /// §7.4.2 describes fetching "the certificate URL provided in the order", so a
    /// certificate whose order does not name it is not that certificate, and §7.1.6
    /// puts the certificate in the order's "valid" state alone.
    ///
    /// Both are allow lists rather than exclusion lists, so a status added later
    /// fails closed. "valid" is the whole set: revocation stamps the certificate row
    /// and the inventory and never touches the order (see RecordRevocationAsync), so
    /// a revoked certificate stays downloadable under a valid order, which is right.
    /// Order expiry is checked lazily on the finalize path and never written back as
    /// a status, so an aged out order keeps serving the certificate it issued.
    ///
    /// Nothing in the product can currently produce a certificate whose order
    /// disagrees with it: the only site that writes an AcmeCertificate row commits
    /// it in the same transaction as the "processing" to "valid" swap, and since
    /// issue #312 no writer demotes a claimed or completed order. These are the last
    /// line of defence for a future path that lets the two drift apart (issue #318).
    /// </summary>
    public static bool MayServe(AcmeCertificate certificate) =>
        certificate.Order.Status == "valid"
        && certificate.Order.CertificateId == certificate.CertificateId;

    /// <inheritdoc cref="MayServe"/>
    public static bool MayAdvertise(AcmeOrder order) =>
        order.Status == "valid" && order.CertificateId != null;

    /// <summary>
    /// Builds the order response DTO with fully qualified URLs, and the problem
    /// document that says why the order failed.
    ///
    /// Until issue #330 this built the URLs alone. RFC 8555 section 7.1.3 gives an
    /// order an error member and section 7.1.6 is what tells a client to read it
    /// once the order goes invalid, so every writer of
    /// <see cref="AcmeOrder.ErrorJson"/> was writing into a column no client could
    /// reach and a failed order answered with a status and nothing else.
    /// </summary>
    public static OrderResponse ToResponse(AcmeOrder order, Func<string, string> urlBuilder)
    {
        var identifiers = JsonSerializer.Deserialize<AcmeIdentifier[]>(order.IdentifiersJson)
            ?? Array.Empty<AcmeIdentifier>();

        var response = new OrderResponse
        {
            Status = order.Status,
            Expires = AcmeTimestamps.Format(order.ExpiresAt),
            Identifiers = identifiers,
            NotBefore = AcmeTimestamps.Format(order.NotBefore),
            NotAfter = AcmeTimestamps.Format(order.NotAfter),
            // RFC 9773 §5's MUST: a "replaces" the server accepted is
            // reflected in every response for the order. Written once at
            // creation, never after, so no gate is needed here.
            Replaces = order.ReplacesCertificateId,
            Authorizations = order.Authorizations
                .Select(a => urlBuilder($"/acme/{order.TemplateId}/authz/{a.AuthorizationId}"))
                .ToArray(),
            Finalize = urlBuilder($"/acme/{order.TemplateId}/order/{order.OrderId}/finalize")
        };

        // The advertising half of the invariant MayServe enforces on the download.
        // This tested CertificateId alone, so a non valid order carrying a surviving
        // CertificateId handed the client a URL that the download now refuses, which
        // is worse than not offering it: the DTO's own doc comment already promised
        // this field appears only on a valid order.
        if (MayAdvertise(order))
        {
            response.Certificate = urlBuilder($"/acme/{order.TemplateId}/cert/{order.CertificateId}");
        }

        // The order half of what ToChallengeResponse below has always done for a
        // challenge, and written the same way on purpose (issue #330).
        //
        // Unconditional, unlike the certificate above. That field needed a gate
        // because CertificateId is a denormalized mirror nothing keeps in sync, so
        // the row can genuinely contradict itself. This column cannot: ErrorJson is
        // only ever written alongside "invalid" and committed with it, and nothing
        // brings an order back out of invalid (RecalculateOrderStatusAsync returns
        // early on it, and every other status write names its legal predecessors).
        // Restating that here would be a second copy of the invariant free to drift
        // from the writers, so the writers keep it and a test pins it instead.
        //
        // No catch around the deserialize, again matching the challenge. Every
        // writer serializes an AcmeError, so a column this cannot read means a hand
        // edited database, and answering 500 for one is the honest report.
        //
        // Null here is the ordinary case rather than a gap. An order invalidated
        // because a challenge failed deliberately carries no error of its own: the
        // reason lives on the authorization and its challenge, which is where
        // section 7.1.6 sends the client and which ToChallengeResponse already
        // projects. See the invalid arm of RecalculateOrderStatusAsync.
        if (order.ErrorJson != null)
        {
            response.Error = JsonSerializer.Deserialize<AcmeError>(order.ErrorJson);
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
            Expires = AcmeTimestamps.Format(authz.ExpiresAt),
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
            Validated = AcmeTimestamps.Format(challenge.ValidatedAt)
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

/// <summary>
/// Outcome of <see cref="OrderService.ResolveReplacesAsync"/>. The admitting
/// outcomes are <see cref="NotPresent"/> and <see cref="Resolved"/>; the
/// caller writes its refusal as "not one of the admitting outcomes", never by
/// enumerating refusals, so a value added later fails closed.
/// </summary>
public enum ReplacesOutcome
{
    /// <summary>The request named no certificate to replace.</summary>
    NotPresent,

    /// <summary>Verified; the canonical identifier accompanies it.</summary>
    Resolved,

    /// <summary>The identifier is not RFC 9773 §4.1 syntax.</summary>
    Malformed,

    /// <summary>
    /// Nothing this server issued matches the identifier, or the stored leaf
    /// disagrees with it octet for octet.
    /// </summary>
    UnknownCertificate,

    /// <summary>
    /// The certificate belongs to a different account. Answered on the wire
    /// exactly like <see cref="UnknownCertificate"/>: serials are not secrets,
    /// so the difference must not be observable to another account.
    /// </summary>
    NotOwned,

    /// <summary>
    /// The order shares no identifier with the certificate's own order, the
    /// first half of §5's SHOULD.
    /// </summary>
    NoSharedIdentifier,

    /// <summary>
    /// Another live order already names this certificate (a valid or
    /// processing one, or a pending or ready one still inside its own
    /// expiry). The one refusal with its own error type: 409 alreadyReplaced.
    /// </summary>
    AlreadyReplaced
}

/// <summary>
/// A certificate located and verified by its ARI identifier octets
/// (RFC 9773 §4.1): the stored row (untracked, order included), the parsed
/// leaf, which the caller owns and disposes, and, when the certificate is
/// revoked on either the ACME row or its synced inventory twin, the instant
/// the renew now window anchors on.
/// </summary>
public sealed record AriCertificateMatch(
    AcmeCertificate Certificate,
    X509Certificate2 Leaf,
    DateTimeOffset? RevokedAt);

/// <summary>
/// Outcome of <see cref="OrderService.DeactivateAuthorizationAsync"/>.
/// RFC 8555 §7.5.2.
///
/// <see cref="Deactivated"/> and <see cref="AlreadyDeactivated"/> produce the
/// same HTTP response on purpose and are still separate values: the distinction
/// between a write and a no-op is what the log line and the tests key off, and
/// collapsing them would erase it.
/// </summary>
public enum AuthorizationDeactivationOutcome
{
    /// <summary>The authorization was pending or valid and is now deactivated.</summary>
    Deactivated,

    /// <summary>It was already deactivated; nothing was written.</summary>
    AlreadyDeactivated,

    /// <summary>
    /// It is in a terminal status that cannot be deactivated. In practice that
    /// means "invalid": nothing in this codebase writes "expired" or "revoked"
    /// to an authorization, and an authorization always carries the same
    /// ExpiresAt as its order, so an aged out one is refused by the order expiry
    /// check on the finalize path instead.
    /// </summary>
    NotDeactivatable
}

/// <summary>
/// Result of <see cref="OrderService.DeactivateAuthorizationAsync"/>. The
/// authorization is never null: the method takes a loaded entity, so there is
/// no "row not found" arm to get wrong.
/// </summary>
public sealed record AuthorizationDeactivationResult(
    AuthorizationDeactivationOutcome Outcome,
    AcmeAuthorization Authorization);

/// <summary>
/// Why <see cref="OrderService.FinalizeOrderAsync"/> refused, or that it did not.
///
/// The vocabulary exists because a finalize can fail for reasons that are nothing
/// to do with the CSR, and the caller has to answer each with the ACME error
/// RFC 8555 section 6.7 defines for it. Before issue #313 the method returned a
/// bare bool, so every refusal reached the client as badCSR, and a client that had
/// simply lost a race was told to rebuild a CSR that was perfectly valid.
///
/// Each value names the answer rather than the condition it came from: three
/// separate checks (the ready check, the deactivated authorization guard, and the
/// lost claim) all resolve to <see cref="OrderNotReady"/>, which is the point.
/// </summary>
public enum FinalizeOutcome
{
    /// <summary>The order was claimed and the CSR went to the CA.</summary>
    Submitted,

    /// <summary>No order carries that ID.</summary>
    NotFound,

    /// <summary>
    /// The order is not in a state that can be finalized: it is not ready, one of
    /// its authorizations is deactivated (RFC 8555 section 7.5.2), or another
    /// request claimed it first.
    /// </summary>
    OrderNotReady,

    /// <summary>The order passed its expiry and is now invalid.</summary>
    Expired,

    /// <summary>The CSR itself is unacceptable, which is what badCSR means.</summary>
    BadCsr,

    /// <summary>
    /// The CA decided against the request, or the attempt to submit it failed for
    /// a reason that is not the CA being unreachable. The order is invalid and no
    /// CSR the client can build changes that, which is exactly what badCSR used to
    /// invite it to try (issue #324).
    ///
    /// Answers 500 serverInternal, which is the type this method already writes
    /// into the order's own error field on both arms, and the type
    /// <see cref="ResolveHeldOrderAsync"/> writes for the same refusal arriving
    /// later through the pending issuance sweep. So one refusal reads the same
    /// wherever it is discovered, and the wire stops contradicting the record.
    /// </summary>
    CaRefused,

    /// <summary>
    /// The CA could not be reached, so nothing was decided. Never a statement
    /// about the client's CSR and never permanent, so the order is not invalidated
    /// for it: the claim is released when nothing reached the CA, and left standing
    /// when the CSR did. Answers 503 serviceUnavailable, word for word what
    /// template resolution and revoke-cert already answer for a CA outage
    /// (issue #324).
    /// </summary>
    CaUnavailable,

    /// <summary>
    /// The CA was reached and refused this service's own credentials, so nothing
    /// was decided about the request. Never a statement about the client's CSR, and
    /// the one CA condition on this list an operator can actually fix, so the order
    /// is not invalidated for it: the claim is released when nothing reached the CA,
    /// and left standing when the CSR did, exactly as <see cref="CaUnavailable"/>
    /// splits (issue #336).
    ///
    /// Answers 503 serviceUnavailable, the same answer a CA outage gets. The two
    /// conditions differ in their cause and in their log level, not in what a client
    /// can do about either: come back once the server's operator has acted. 403
    /// unauthorized was the obvious candidate and is wrong, because RFC 8555 section
    /// 6.7 defines it as the client lacking authorization, and a correctly authorized
    /// client told that goes off to re-register for a misconfiguration on our side.
    /// The revoke-cert path reaches the same judgement from the other direction and
    /// answers this exception as a server condition too.
    ///
    /// Only ever reached from the submit side, where nothing reached the CA. A denial
    /// on the fetch means the CA holds a request already, which is the pending arm by
    /// another route and answers <see cref="Submitted"/>.
    /// </summary>
    CaAccessDenied,

    /// <summary>
    /// The template's device attestation profile is gone or disabled, so this
    /// order's device is refused. Not <see cref="BadCsr"/>, which is what it
    /// reached the client as before issue #323: the CSR is not the problem, and a
    /// client told badCSR rebuilds one that was perfectly good while the operator
    /// loses the pointer to the ACME page that rejectedIdentifier carries.
    ///
    /// Named for the one condition it carries rather than for device refusals in
    /// general, because the controller answers it with the gate's own body. That
    /// second device refusal is now <see cref="DeviceNotOnAllowlist"/>, and it has
    /// its own value for exactly the reason this paragraph anticipated: a delisted
    /// device must not be told the template accepts no device orders at all.
    /// </summary>
    DeviceNotOffered,

    /// <summary>
    /// The template still offers device orders, but this order's device is no
    /// longer admitted by the profile's allowlist (issue #335). A distinct value
    /// from <see cref="DeviceNotOffered"/> because the two are different facts
    /// about the world and point an operator at different fixes: one is the
    /// profile's enabled switch, the other is one allowlist entry.
    ///
    /// Both reach the client the same way. The controller answers either by
    /// re-running its own finalize-device gate, which names the device, writes the
    /// single audit row, and picks the wording; the arm in
    /// <c>MapFinalizeRefusal</c> is only the floor for an order whose identifiers
    /// no longer parse to a device at all.
    /// </summary>
    DeviceNotOnAllowlist,
}

/// <summary>
/// Result of <see cref="OrderService.FinalizeOrderAsync"/>. Shaped like
/// <see cref="AuthorizationDeactivationResult"/>: the outcome carries the decision
/// and <see cref="Success"/> is derived from it, so the two can never disagree.
/// <see cref="ErrorMessage"/> is null exactly when the outcome is
/// <see cref="FinalizeOutcome.Submitted"/>.
/// </summary>
public sealed record FinalizeResult(FinalizeOutcome Outcome, string? ErrorMessage)
{
    /// <summary>True only for <see cref="FinalizeOutcome.Submitted"/>.</summary>
    public bool Success => Outcome == FinalizeOutcome.Submitted;
}

/// <summary>
/// What <see cref="OrderService.ResolveHeldOrderAsync"/> did with one order the
/// CA had not finished deciding. Every member except
/// <see cref="StillHeld"/> and <see cref="NotHeld"/> means the order reached a
/// terminal status and the sweep will not see it again.
/// </summary>
public enum HeldOrderResolution
{
    /// <summary>
    /// The order was not one this sweep acts on: it is not "processing", it no
    /// longer exists, or a finalize claimed it and has not yet recorded what the
    /// CA was asked. The last of those is the ordinary case for the few hundred
    /// milliseconds a finalize spends at the CA.
    /// </summary>
    NotHeld,

    /// <summary>
    /// The CA is still holding the request for a manager decision, and the order
    /// has not passed its own expiry. It stays "processing" and is swept again.
    /// </summary>
    StillHeld,

    /// <summary>
    /// The CA had decided in the request's favour, so the completion path ran.
    /// This does not promise delivery: the finalize leaf guard can still refuse
    /// what the CA issued, which fails the order and revokes the leaf, and says
    /// so in its own log.
    /// </summary>
    Collected,

    /// <summary>
    /// The CA refused the request, or the request is no longer collectable
    /// (denied, revoked before anyone fetched it, or failed). The order is
    /// "invalid".
    /// </summary>
    Refused,

    /// <summary>
    /// The order passed its own expiry with the CA still undecided, so it was
    /// given up on and is "invalid". RFC 8555 section 7.1.3 makes the advertised
    /// "expires" the point after which the server considers an order invalid,
    /// and that field is the only deadline the client was ever told about.
    /// </summary>
    Abandoned,
}
