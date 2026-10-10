using System.Globalization;
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
/// ACME order endpoints: create, query, and finalize orders.
/// RFC 8555 §7.4
/// </summary>
[ApiController]
public sealed class OrderController : AcmeControllerBase
{
    private readonly OrderService _orderService;
    private readonly AccountService _accountService;
    private readonly NonceService _nonceService;
    private readonly JwsService _jwsService;
    private readonly TemplateService _templateService;
    private readonly AddressGuard _addressGuard;
    private readonly AllowedDomainsPolicy _allowedDomainsPolicy;
    private readonly DomainPolicyAuditService _domainPolicyAudit;
    private readonly EabCredentialService _eabCredentials;
    private readonly DeviceAttestationPolicyService _deviceAttestationPolicy;

    public OrderController(
        OrderService orderService,
        AccountService accountService,
        NonceService nonceService,
        JwsService jwsService,
        TemplateService templateService,
        AddressGuard addressGuard,
        AllowedDomainsPolicy allowedDomainsPolicy,
        DomainPolicyAuditService domainPolicyAudit,
        EabCredentialService eabCredentials,
        DeviceAttestationPolicyService deviceAttestationPolicy)
    {
        _orderService = orderService;
        _accountService = accountService;
        _nonceService = nonceService;
        _jwsService = jwsService;
        _templateService = templateService;
        _addressGuard = addressGuard;
        _allowedDomainsPolicy = allowedDomainsPolicy;
        _domainPolicyAudit = domainPolicyAudit;
        _eabCredentials = eabCredentials;
        _deviceAttestationPolicy = deviceAttestationPolicy;
    }

    /// <summary>
    /// POST /acme/{template}/new-order — create a new order.
    /// RFC 8555 §7.4
    /// </summary>
    [HttpPost("/acme/{template}/new-order")]
    [Consumes("application/jose+json")]
    [EnableRateLimiting(AcmeRateLimitPolicies.NewOrder)]
    public async Task<IActionResult> NewOrder(string template, CancellationToken ct)
    {
        // 1. Validate template — accept either programmatic name or display name.
        // Issue #17: store the canonical programmatic name in the order so the
        // eventual ADCS Submit call uses the form ADCS expects. Issue #85: the
        // template must also be enabled by the administrator's wizard selection.
        var (resolution, templateError) = await ResolveTemplateAsync(_templateService, template, ct);
        if (templateError != null)
            return templateError;
        var templateInfo = resolution.Template!;

        // 2. Authenticate JWS with kid
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        // 2b. An account bound to a revoked or expired EAB credential is
        // suspended. Unbound accounts skip this entirely (grandfathering).
        // The gate also carries the credential's domain namespace for the
        // policy check below, so one query serves both.
        var (eabGateError, eabGate) = await EnforceEabBindingGateAsync(auth.Account!, ct);
        if (eabGateError != null)
            return eabGateError;

        // 3. Parse the order request payload
        NewOrderRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<NewOrderRequest>(auth.PayloadBytes!);
        }
        catch (JsonException)
        {
            return AcmeError(400, AcmeErrorType.Malformed, "Invalid order request payload.");
        }

        if (request?.Identifiers == null || request.Identifiers.Length == 0)
            return AcmeError(400, AcmeErrorType.Malformed,
                "Order must contain at least one identifier.");

        // 4. Validate identifiers. The vocabulary lives in AcmeIdentifierTypes;
        // a permanent-identifier (draft-ietf-acme-device-attest-08) skips the
        // dns shape checks, because a device serial is not a host name and
        // "10.0.0.1" is a perfectly good asset tag that must not trip the
        // blocked literal screen.
        //
        // Order is load bearing here (issue #193). The device branch opens
        // with the offered check and reads nothing before it: not the empty
        // check, not the grammar, not the single identifier rule below. A
        // template that does not take device orders therefore refuses at the
        // same point in the loop, with the same body, as the unsupported type
        // check above would on a build that never implemented the draft, for
        // every value a client can send. Every device specific message stays
        // unreachable until an administrator turns the feature on. Do not
        // hoist a value check above this branch.
        var deviceIdentifierCount = 0;
        bool? deviceOrdersOffered = null;
        foreach (var id in request.Identifiers)
        {
            // A JSON null element. This is the one check that may sit above the
            // device branch, because it is not a value check: there is no type
            // read yet, and the answer is identical on a build that never
            // implemented the draft, so it tells a client nothing about the
            // feature. Without it the type check below dereferences null and a
            // malformed payload comes back as a 500 (issue #345).
            if (id is null)
                return AcmeError(400, AcmeErrorType.Malformed,
                    "Identifier must not be null.");

            if (!AcmeIdentifierTypes.IsSupported(id.Type))
                return UnsupportedIdentifierError(id.Type);

            // Only the supported device type takes this branch. hardware-module
            // is device typed but unsupported, so it refuses above and never
            // reaches the gate.
            if (id.Type == AcmeIdentifierTypes.PermanentIdentifier)
            {
                deviceIdentifierCount++;

                // Loaded once per request, and only when a device identifier
                // is actually present, so a dns order issues no extra query.
                deviceOrdersOffered ??=
                    await _deviceAttestationPolicy.IsOfferedAsync(templateInfo.Name, ct);
                if (!deviceOrdersOffered.Value)
                    return UnsupportedIdentifierError(id.Type);

                // TryParse rejects a null, empty, or whitespace only value with
                // its own message, so the device path does not need the shared
                // empty check below and must not run it: that check names no
                // device concept, but reaching it at all is what tells a client
                // the type was recognized.
                if (!PermanentIdentifierValue.TryParse(id.Value, out _, out var parseError))
                    return AcmeError(400, AcmeErrorType.Malformed, parseError);
                continue;
            }

            // The dns grammar (issue #345). Before this, a dns value was taken
            // on a non-empty check alone, so an IP address, a URL, a path
            // fragment or a shell metacharacter all became an authorization and
            // a challenge, and reached the http-01 fetch URL verbatim. The
            // refusal never echoes the value, matching the device branch above.
            if (!DnsIdentifierValue.TryParse(id.Value, out var dns, out var refusal))
                return AcmeError(400, MapDnsIdentifierRefusal(refusal.Value.Kind),
                    refusal.Value.Detail);

            // Reject obvious internal targets at order time. The grammar has
            // already refused every IP literal, so only "localhost" can still
            // fire this; keep it anyway, because it is the guard that states the
            // intent and it stays correct if the grammar is ever loosened. Names
            // that merely resolve to a blocked address are caught at validation
            // time by the egress guard, which is a different fence at a
            // different end of the path. The wildcard marker is already stripped
            // for us, so "*.localhost" is screened too.
            if (_addressGuard.IsBlockedLiteral(dns.Name))
                return AcmeError(400, AcmeErrorType.RejectedIdentifier,
                    $"Identifier '{id.Value}' is not permitted.");
        }

        // A device order carries exactly one permanent-identifier and nothing
        // else: the draft binds one attestation to one device identity, and a
        // mixed order would need network authorizations no device can complete.
        // This is a device specific rule, so it is only ever reached on a
        // template that offers device orders: the loop above has already
        // refused with the invisible answer otherwise.
        if (deviceIdentifierCount > 0 && request.Identifiers.Length != 1)
            return AcmeError(400, AcmeErrorType.Malformed,
                "An order for a permanent-identifier must contain exactly one identifier.");

        // 5. Enforce the identifier policy. Device orders take the device
        // attestation gate; the allowed domain policy has nothing to say
        // about a serial number and would refuse every one. Domain orders
        // enforce the administrator's allowed domain policy and, for a bound
        // account, the credential's domain namespace. A separate pass from
        // the loop above so the response can name every refused identifier at
        // once (RFC 8555 §6.7.1) instead of stopping at the first. Runs after
        // JWS auth so the refusal can be attributed to the account in the
        // audit trail.
        var policyError = deviceIdentifierCount > 0
            ? await EnforceDevicePolicyAsync(
                auth.Account!.AccountId, templateInfo.Name, request.Identifiers[0],
                "newOrder-device", invisibleWhenNotOffered: true, ct)
            : await EnforceDomainPolicyAsync(
                auth.Account!.AccountId, templateInfo.Name, request.Identifiers,
                "newOrder", eabGate, ct);
        if (policyError != null)
            return policyError;

        // 6. Parse optional notBefore/notAfter. Use DateTimeOffset with RoundtripKind so an
        // RFC 3339 timestamp that carries an offset (or a trailing Z) is honored rather than
        // assumed to be server local time.
        DateTime? notBefore = null, notAfter = null;
        if (request.NotBefore != null)
        {
            if (!DateTimeOffset.TryParse(request.NotBefore, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var nb))
                return AcmeError(400, AcmeErrorType.Malformed, "Invalid notBefore date.");
            notBefore = nb.UtcDateTime;
        }
        if (request.NotAfter != null)
        {
            if (!DateTimeOffset.TryParse(request.NotAfter, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var na))
                return AcmeError(400, AcmeErrorType.Malformed, "Invalid notAfter date.");
            notAfter = na.UtcDateTime;
        }

        // 6b. Resolve the optional "replaces" member (RFC 9773 §5). Anything
        // other than the two admitting outcomes refuses the whole order: the
        // section's MUST is to reflect the field once the order is accepted,
        // so accepting the order while dropping it is not an option.
        var (replacesOutcome, replacesCertificateId) = await _orderService.ResolveReplacesAsync(
            auth.Account!, request.Identifiers, request.Replaces, ct);
        if (replacesOutcome is not (ReplacesOutcome.NotPresent or ReplacesOutcome.Resolved))
        {
            var (replacesStatus, replacesErrorType, replacesDetail) =
                MapReplacesRefusal(replacesOutcome);
            return AcmeError(replacesStatus, replacesErrorType, replacesDetail);
        }

        // 7. Create the order. Pass the canonical programmatic name so that
        // OrderService.SubmitCertificateRequestAsync hands ADCS the value it
        // matches against (ADCS Submit's CertificateTemplate: attribute does
        // not accept the display name).
        var order = await _orderService.CreateOrderAsync(
            auth.Account!, templateInfo.Name, request.Identifiers, notBefore, notAfter,
            replacesCertificateId, ct);

        // 8. Return 201 Created with Location header
        var orderUrl = AcmeUrl($"/acme/{template}/order/{order.OrderId}");
        Response.Headers["Location"] = orderUrl;

        var response = OrderService.ToResponse(order, AcmeUrl);
        return StatusCode(201, response);
    }

    /// <summary>
    /// POST /acme/{template}/order/{orderId} — get order status (POST-as-GET).
    /// RFC 8555 §7.4. ACME clients poll this endpoint while waiting for the order to
    /// become ready or valid, so it is rate limited as polling rather than as general
    /// traffic. It carried no policy at all until issue #263: verifying a JWS and
    /// reading the order per request is not free, and "clients poll this" is served
    /// just as well by a generous bucket as by no bucket.
    /// </summary>
    [HttpPost("/acme/{template}/order/{orderId}")]
    [Consumes("application/jose+json")]
    [EnableRateLimiting(AcmeRateLimitPolicies.Poll)]
    public async Task<IActionResult> GetOrder(string template, string orderId, CancellationToken ct)
    {
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        var order = await _orderService.GetOrderAsync(orderId, ct);
        if (order == null)
            return AcmeError(404, AcmeErrorType.Malformed, "Order not found.");

        // Verify the order belongs to this account
        if (order.AccountId != auth.Account!.Id)
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "Order does not belong to this account.");

        var response = OrderService.ToResponse(order, AcmeUrl);
        return Ok(response);
    }

    /// <summary>
    /// POST /acme/{template}/order/{orderId}/finalize — submit CSR.
    /// RFC 8555 §7.4
    /// </summary>
    [HttpPost("/acme/{template}/order/{orderId}/finalize")]
    [Consumes("application/jose+json")]
    [EnableRateLimiting(AcmeRateLimitPolicies.General)]
    public async Task<IActionResult> FinalizeOrder(
        string template, string orderId, CancellationToken ct)
    {
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

        // An account bound to a revoked or expired EAB credential is
        // suspended here too: the order stays ready, like the domain policy
        // re-check below, so restoring the credential lets the client retry.
        var (eabGateError, eabGate) = await EnforceEabBindingGateAsync(auth.Account!, ct);
        if (eabGateError != null)
            return eabGateError;

        // Parse finalize request
        FinalizeRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<FinalizeRequest>(auth.PayloadBytes!);
        }
        catch (JsonException)
        {
            return AcmeError(400, AcmeErrorType.Malformed, "Invalid finalize request payload.");
        }

        if (request == null || string.IsNullOrWhiteSpace(request.Csr))
            return AcmeError(400, AcmeErrorType.BadCsr, "CSR is required.");

        // Verify order belongs to this account
        var order = await _orderService.GetOrderAsync(orderId, ct);
        if (order == null)
            return AcmeError(404, AcmeErrorType.Malformed, "Order not found.");
        if (order.AccountId != auth.Account!.Id)
            return AcmeError(403, AcmeErrorType.Unauthorized,
                "Order does not belong to this account.");

        if (DateTime.UtcNow > order.ExpiresAt)
            return AcmeError(403, AcmeErrorType.Malformed, "Order has expired.");

        if (order.Status != "ready")
            return AcmeError(403, AcmeErrorType.OrderNotReady,
                $"Order is not ready for finalization (status: {order.Status}).");

        // RFC 8555 §7.5.2: a deactivated authorization is never sufficient for
        // issuance. Deactivating one demotes its order to invalid, so the check
        // above normally refuses first; this covers a ready row that got here
        // another way. Same status and error type as that check on purpose: 6.7
        // defines orderNotReady as a finalize on an order that is not ready, and a
        // deactivated authorization is exactly a statement that it is not, so both
        // routes to the same refusal stay indistinguishable to a client.
        // GetOrderAsync already includes the authorizations, so this costs nothing.
        var deactivatedAuthz = order.Authorizations.FirstOrDefault(
            a => string.Equals(a.Status, "deactivated", StringComparison.Ordinal));
        if (deactivatedAuthz != null)
            return AcmeError(403, AcmeErrorType.OrderNotReady,
                $"The authorization for {deactivatedAuthz.IdentifierValue} has been deactivated.");

        // Re-check the identifier policy against the stored identifiers: the
        // device gate, the allowed domain policy, and the credential
        // namespace all hot apply, so any of them can tighten between order
        // creation and finalize. FinalizeOrderAsync verifies the CSR against
        // these identifiers, so nothing else needs parsing here. The order
        // stays ready: restoring the domain or the allowlist entry lets the
        // client retry it.
        var identifiers = JsonSerializer.Deserialize<AcmeIdentifier[]>(order.IdentifiersJson)
            ?? Array.Empty<AcmeIdentifier>();
        var deviceIdentifier = identifiers.FirstOrDefault(
            i => AcmeIdentifierTypes.IsDeviceType(i.Type));
        var policyError = deviceIdentifier != null
            ? await EnforceDevicePolicyAsync(
                auth.Account!.AccountId, order.TemplateId, deviceIdentifier,
                "finalize-device", invisibleWhenNotOffered: false, ct)
            : await EnforceDomainPolicyAsync(
                auth.Account!.AccountId, order.TemplateId, identifiers, "finalize", eabGate, ct);
        if (policyError != null)
            return policyError;

        // Decode CSR
        byte[] csrDer;
        try
        {
            csrDer = JwsService.Base64UrlDecode(request.Csr);
        }
        catch (FormatException)
        {
            return AcmeError(400, AcmeErrorType.BadCsr, "Invalid base64url encoding for CSR.");
        }

        // Finalize. The refusals are not all about the CSR, so the outcome decides
        // the answer rather than one catch-all badCSR (issue #313).
        var finalize = await _orderService.FinalizeOrderAsync(orderId, csrDer, ct);
        if (!finalize.Success)
        {
            // The gate above and FinalizeOrderAsync take the device attestation
            // decision separately, so an administrator disabling the profile
            // (issue #323) or deleting the device's allowlist entry (issue #335)
            // between the two lands here rather than there. Answer either by
            // running the gate again rather than by rebuilding its body: that is
            // its answer by construction, so the two cannot drift, the subproblem
            // names the same device, the wording is the gate's own for each of the
            // two conditions, and the finalize-device audit row is written once, by
            // the same writer, carrying the client IP that only this layer has.
            //
            // Null means the profile or the entry came back in between, which
            // leaves the floor mapping below rather than a false success: the
            // finalize has already refused and the order was never claimed.
            //
            // Parenthesised on purpose. C# binds the whole "or" pattern to the
            // "is" before the "&&" applies, so the bare form means the same
            // thing, but wrapped over two lines it reads as though the null
            // guard were a third peer of the "or". The guard is what makes the
            // non null argument below safe, so the grouping is spelled out
            // rather than left to a reader checking precedence.
            if ((finalize.Outcome is FinalizeOutcome.DeviceNotOffered
                    or FinalizeOutcome.DeviceNotOnAllowlist)
                && deviceIdentifier != null)
            {
                var deviceRefusal = await EnforceDevicePolicyAsync(
                    auth.Account!.AccountId, order.TemplateId, deviceIdentifier,
                    "finalize-device", invisibleWhenNotOffered: false, ct);
                if (deviceRefusal != null)
                    return deviceRefusal;
            }

            var (refusalStatus, refusalType) = MapFinalizeRefusal(finalize.Outcome);
            return AcmeError(
                refusalStatus, refusalType, finalize.ErrorMessage ?? "Finalization failed.");
        }

        // Re-fetch order to get updated status
        order = await _orderService.GetOrderAsync(orderId, ct);
        if (order == null)
            return AcmeError(500, AcmeErrorType.ServerInternal,
                "Order could not be reloaded after finalization.");
        var orderUrl = AcmeUrl($"/acme/{template}/order/{order.OrderId}");
        Response.Headers["Location"] = orderUrl;

        var response = OrderService.ToResponse(order, AcmeUrl);
        return Ok(response);
    }

    /// <summary>
    /// The ACME answer for a refused finalize (issue #313). Call it only on a
    /// refusal: <see cref="FinalizeOutcome.Submitted"/> is not one and throws.
    /// Every order state refusal here has a twin among this controller's own
    /// checks above, and must give the same answer as its twin: which of two
    /// racing checks happened to fire is not something a client should be able
    /// to see, let alone act on.
    ///
    /// Public and static so it can be tested on its own. <see cref="OrderService"/>
    /// is sealed and injected concretely, so an integration test has no seam to
    /// force these arms with, and the arms that matter only fire on a genuine race
    /// in any case.
    ///
    /// There is deliberately no catch-all arm answering badCSR. That is exactly the
    /// mis-mapping this method exists to undo, and it would silently swallow any
    /// outcome added later; the throw plus the completeness test over
    /// <see cref="FinalizeOutcome"/> makes such an addition fail a test instead.
    ///
    /// The two device outcomes have a richer twin in the finalize body, which
    /// re-runs the device gate to produce the subproblem and the audit row. The
    /// arms here are their floor, for the case where the order's identifiers no
    /// longer name a device.
    /// </summary>
    public static (int Status, string ErrorType) MapFinalizeRefusal(FinalizeOutcome outcome) =>
        outcome switch
        {
            // 404 malformed, matching the order lookup above.
            FinalizeOutcome.NotFound => (404, AcmeErrorType.Malformed),

            // 403 orderNotReady, matching the ready pre-check and the deactivated
            // authorization pre-check above. RFC 8555 section 6.7.
            FinalizeOutcome.OrderNotReady => (403, AcmeErrorType.OrderNotReady),

            // 403 malformed, matching the expiry pre-check above.
            FinalizeOutcome.Expired => (403, AcmeErrorType.Malformed),

            // The CSR really is unacceptable. The only arm badCSR belongs on.
            FinalizeOutcome.BadCsr => (400, AcmeErrorType.BadCsr),

            // 500 serverInternal, the type the order's own error field already
            // records for this and the type the pending issuance sweep writes for
            // the same refusal arriving later. The CA decided against the request
            // or the attempt failed; the order is invalid either way and no CSR
            // the client can build changes that, which is exactly what badCSR used
            // to invite it to try (issue #324).
            FinalizeOutcome.CaRefused => (500, AcmeErrorType.ServerInternal),

            // 503 serviceUnavailable, word for word what ResolveTemplateAsync
            // answers when it cannot reach the CA and what revoke-cert answers
            // when the revoke cannot. Retryable, and the order is still there to
            // retry, because the finalize released its claim (issue #324).
            FinalizeOutcome.CaUnavailable => (503, AcmeErrorType.ServiceUnavailable),

            // 503 serviceUnavailable as well, and deliberately the same answer as the
            // outage above rather than a distinct one (issue #336). The two differ in
            // cause, in log level and in what an operator must do, but not in anything
            // the client can act on: the request was never decided, the order is still
            // there, and the only useful instruction is to come back later. 403
            // unauthorized is what this looks like and is wrong, because RFC 8555
            // section 6.7 gives that type to a client lacking authorization, and the
            // client here is perfectly authorized; it would go off to re-register over
            // a permission missing on our side of the CA. The detail stays generic on
            // this wire: the remediation names the service's own computer account, and
            // that belongs in the log and on the admin surfaces, not in a problem
            // document any ACME account holder can read.
            FinalizeOutcome.CaAccessDenied => (503, AcmeErrorType.ServiceUnavailable),

            // 400 rejectedIdentifier, matching this controller's own device gate.
            // The finalize branch above answers both outcomes with the gate's whole
            // body, subproblem and audit row included, so these arms are the floor
            // rather than the answer: they are reached only if the order's
            // identifiers no longer parse to a device identifier. The two share an
            // answer on the wire because the gate refuses a dead profile
            // (issue #323) and a delisted device (issue #335) the same way; what
            // separates them is the detail the gate writes, not the error type.
            FinalizeOutcome.DeviceNotOffered => (400, AcmeErrorType.RejectedIdentifier),
            FinalizeOutcome.DeviceNotOnAllowlist => (400, AcmeErrorType.RejectedIdentifier),

            _ => throw new ArgumentOutOfRangeException(
                nameof(outcome), outcome, "Not a finalize refusal."),
        };

    /// <summary>
    /// Maps a "replaces" refusal (RFC 9773 §5) to its wire form, the
    /// <see cref="MapFinalizeRefusal"/> pattern: the two admitting outcomes
    /// throw rather than map, there is no catch-all refusal arm, and a test
    /// enumerates the vocabulary so a <see cref="ReplacesOutcome"/> added
    /// later fails a test instead of inventing an answer.
    /// </summary>
    public static (int Status, string ErrorType, string Detail) MapReplacesRefusal(
        ReplacesOutcome outcome) =>
        outcome switch
        {
            ReplacesOutcome.Malformed => (400, AcmeErrorType.Malformed,
                "Invalid ARI certificate identifier in 'replaces'."),

            // One wording for a certificate that does not exist and one that
            // belongs to another account. Serials are not secrets, so the wire
            // must not tell an account holder which of the two it hit: the
            // same stance revoke-cert takes with its byte equality 404.
            ReplacesOutcome.UnknownCertificate => (400, AcmeErrorType.Malformed,
                "The 'replaces' certificate is not one this server issued to this account."),
            ReplacesOutcome.NotOwned => (400, AcmeErrorType.Malformed,
                "The 'replaces' certificate is not one this server issued to this account."),

            ReplacesOutcome.NoSharedIdentifier => (400, AcmeErrorType.Malformed,
                "The order shares no identifier with the 'replaces' certificate."),

            // RFC 9773 §5's one prescribed answer: HTTP 409 with alreadyReplaced.
            ReplacesOutcome.AlreadyReplaced => (409, AcmeErrorType.AlreadyReplaced,
                "The 'replaces' certificate has already been marked as replaced by another order."),

            _ => throw new ArgumentOutOfRangeException(
                nameof(outcome), outcome, "Not a replaces refusal."),
        };

    /// <summary>
    /// Runs the domain checks over the identifiers, records a refusal in the
    /// audit trail, and builds the compound response. Null when everything
    /// is allowed. Shared by newOrder and finalize so the two stages cannot
    /// drift on the refusal contract. The global allowed domain list runs
    /// first and stays the ceiling; the credential namespace, present when
    /// the account is bound to a credential that carries one, can only
    /// narrow further. The two refusals audit under distinct stages
    /// ("newOrder" versus "newOrder-eab") so the activity feed tells a
    /// server policy refusal from a credential namespace refusal.
    /// </summary>
    private async Task<IActionResult?> EnforceDomainPolicyAsync(
        string accountId,
        string templateId,
        AcmeIdentifier[] identifiers,
        string stage,
        EabBindingGate? binding,
        CancellationToken ct)
    {
        var disallowed = _allowedDomainsPolicy.FindDisallowed(identifiers);
        if (disallowed.Count > 0)
        {
            await _domainPolicyAudit.RecordAsync(
                accountId, templateId, identifiers, disallowed,
                HttpContext.Connection.RemoteIpAddress?.ToString(), stage, ct);
            return DomainPolicyError(disallowed);
        }

        // An empty namespace list means the credential adds no restriction,
        // never "refuse everything" (FindDisallowedAgainst's contract).
        if (binding == null || binding.Namespaces.Count == 0)
            return null;

        var outsideNamespace = AllowedDomainsPolicy.FindDisallowedAgainst(
            identifiers, binding.Namespaces);
        if (outsideNamespace.Count == 0)
            return null;

        await _domainPolicyAudit.RecordAsync(
            accountId, templateId, identifiers, outsideNamespace,
            HttpContext.Connection.RemoteIpAddress?.ToString(), stage + "-eab", ct);
        return NamespacePolicyError(binding.Name, outsideNamespace);
    }

    /// <summary>
    /// The refusal for an identifier type this server will not take an
    /// order for. Deliberately also the response for a permanent-identifier
    /// order on a template with no active device attestation profile, byte
    /// for byte and at the same point in the identifier loop: what stays
    /// private is whether this template has device attestation turned on,
    /// and a client probing with a malformed value learns no more than one
    /// probing with a well formed one (issue #193).
    ///
    /// The narrower claim is the honest one. Every build since the device
    /// attestation train ships the feature compiled in, and the directory
    /// meta points at documentation that describes it, so the product never
    /// hid that the draft is implemented. What a client must not learn is
    /// this template's configuration. Note the probe needs an account,
    /// because this loop runs after the JWS authentication above, but
    /// registration is self service on any template that does not require
    /// external account binding, so that is a low bar rather than a defence.
    /// </summary>
    private IActionResult UnsupportedIdentifierError(string type) =>
        AcmeError(400, AcmeErrorType.UnsupportedIdentifier,
            $"Unsupported identifier type: '{type}'.");

    /// <summary>
    /// The ACME error a dns identifier refusal reaches the client as (issue
    /// #345). Two arms, drawing the line RFC 8555 section 6.7 draws and the
    /// device branch already follows: a value the grammar cannot read is
    /// malformed, and a value that reads perfectly well but names something
    /// this server will not issue for is rejectedIdentifier. No catch-all arm,
    /// so a kind added later throws rather than quietly answering whichever
    /// error happened to be last; DnsIdentifierRefusalMappingTests walks every
    /// kind, so that throw is a failing test and not a production surprise.
    /// </summary>
    public static string MapDnsIdentifierRefusal(DnsIdentifierRefusalKind kind) =>
        kind switch
        {
            // Not a host name: a URL, a path, a metacharacter, an oversize
            // label, a trailing dot, a Unicode U label. The client sent
            // something this server cannot read as an identifier at all.
            DnsIdentifierRefusalKind.Malformed => AcmeErrorType.Malformed,

            // A well-formed IP address. Nothing is wrong with the syntax; this
            // server issues for host names, so the disposition is the policy
            // one, matching the blocked literal screen next to it.
            DnsIdentifierRefusalKind.IpLiteral => AcmeErrorType.RejectedIdentifier,

            _ => throw new ArgumentOutOfRangeException(
                nameof(kind), kind, "Not a dns identifier refusal."),
        };

    /// <summary>
    /// The device order gate (draft-ietf-acme-device-attest-08 plus this
    /// server's per template allowlist), replacing the domain policy for
    /// permanent-identifier orders. Shared by newOrder and finalize so the
    /// two stages cannot drift. With
    /// <paramref name="invisibleWhenNotOffered"/> (newOrder) a template
    /// with no active profile answers with the invisible
    /// unsupportedIdentifier refusal and no audit row; at finalize the
    /// client already holds a device order, so every refusal is named and
    /// audited. The order is left untouched on a finalize refusal, so
    /// restoring the profile or the allowlist entry lets the client retry.
    /// Null when the device is admitted.
    ///
    /// Since issue #193 the newOrder identifier loop runs its own offered
    /// check before it reads the value, so the invisible branch here is the
    /// second line of defence rather than the first: it now only fires when
    /// an administrator disables the profile between that check and this
    /// one. Keep it. The parameter is still load bearing for the finalize
    /// caller, which passes false, and dropping the newOrder invisibility
    /// would reopen the leak on that race.
    /// </summary>
    private async Task<IActionResult?> EnforceDevicePolicyAsync(
        string accountId,
        string templateId,
        AcmeIdentifier identifier,
        string stage,
        bool invisibleWhenNotOffered,
        CancellationToken ct)
    {
        var outcome = await _deviceAttestationPolicy.CheckAsync(templateId, identifier.Value, ct);
        if (outcome is DeviceAttestationPolicyOutcome.AllowedOpen
            or DeviceAttestationPolicyOutcome.AllowedListed)
            return null;

        var notOffered = outcome is DeviceAttestationPolicyOutcome.NoProfile
            or DeviceAttestationPolicyOutcome.Disabled;
        if (notOffered && invisibleWhenNotOffered)
            return UnsupportedIdentifierError(identifier.Type);

        await _domainPolicyAudit.RecordAsync(
            accountId, templateId, new[] { identifier }, new[] { identifier.Value },
            HttpContext.Connection.RemoteIpAddress?.ToString(), stage, ct);

        return DevicePolicyError(identifier, notOffered
            ? "this template no longer accepts device orders"
            : "the device is not on the template's allowlist");
    }

    /// <summary>
    /// The rejectedIdentifier response for a device the attestation policy
    /// refuses: the same shape as <see cref="DomainPolicyError"/>, with a
    /// detail that points the operator at the device attestation settings
    /// instead of the domain list.
    /// </summary>
    private IActionResult DevicePolicyError(AcmeIdentifier identifier, string reason)
    {
        var subproblems = new[]
        {
            new AcmeError
            {
                Type = AcmeErrorType.RejectedIdentifier,
                Detail = $"Device '{identifier.Value}' is refused: {reason}.",
                Identifier = identifier,
            },
        };

        return AcmeError(400, AcmeErrorType.RejectedIdentifier,
            $"This server's device attestation policy does not allow issuance for device " +
            $"'{identifier.Value}': {reason}. An administrator can change the device " +
            "attestation settings on the ACME page.",
            subproblems);
    }

    /// <summary>
    /// The compound rejectedIdentifier response for domains the allowed
    /// domain policy refuses: one subproblem per refused identifier
    /// (RFC 8555 §6.7.1) under a top level detail that points the operator
    /// at the fix. 400 matches the existing rejectedIdentifier path above.
    /// </summary>
    private IActionResult DomainPolicyError(IReadOnlyList<string> disallowed)
    {
        var subproblems = disallowed.Select(value => new AcmeError
        {
            Type = AcmeErrorType.RejectedIdentifier,
            Detail = $"Domain '{value}' is not in this server's allowed domain list.",
            Identifier = new AcmeIdentifier { Type = "dns", Value = value },
        }).ToArray();

        return AcmeError(400, AcmeErrorType.RejectedIdentifier,
            "This server's domain policy does not allow issuance for: "
            + string.Join(", ", disallowed)
            + ". An administrator can change the allowed domains on the Settings page.",
            subproblems);
    }

    /// <summary>
    /// The compound rejectedIdentifier response for domains outside the
    /// bound credential's namespace: the same shape as
    /// <see cref="DomainPolicyError"/> with a detail that names the
    /// credential, because the fix (widen the namespace, or use a different
    /// credential) is different from the global list fix.
    /// </summary>
    private IActionResult NamespacePolicyError(
        string credentialName, IReadOnlyList<string> disallowed)
    {
        var subproblems = disallowed.Select(value => new AcmeError
        {
            Type = AcmeErrorType.RejectedIdentifier,
            Detail = $"Domain '{value}' is outside the domain namespace of external " +
                     $"account credential '{credentialName}'.",
            Identifier = new AcmeIdentifier { Type = "dns", Value = value },
        }).ToArray();

        return AcmeError(400, AcmeErrorType.RejectedIdentifier,
            $"The external account credential '{credentialName}' this account registered " +
            "with does not allow issuance for: " + string.Join(", ", disallowed)
            + ". An administrator can change the credential's domain namespace on the ACME page.",
            subproblems);
    }

    /// <summary>
    /// The order time gate for external account binding (RFC 8555 §7.3.4 is
    /// silent on this; it is this server's policy): an account bound to a
    /// revoked or expired credential may not create or finalize orders until
    /// an administrator restores the credential. Runs only when the account
    /// carries a binding, so grandfathered accounts pay no lookup, and it is
    /// deliberately absent from the poll endpoints (order fetch, challenges).
    /// The gate is returned alongside the error so the caller can hand its
    /// namespace to the domain policy check without a second query; it is
    /// null exactly when the account is unbound.
    /// </summary>
    private async Task<(IActionResult? Error, EabBindingGate? Gate)> EnforceEabBindingGateAsync(
        AcmeAccount account, CancellationToken ct)
    {
        if (account.ExternalAccountCredentialId is not int credentialId)
            return (null, null);

        var gate = await _eabCredentials.GetBindingGateAsync(credentialId, ct);
        IActionResult? error = gate.Status switch
        {
            EabBindingGateStatus.Allowed => null,
            EabBindingGateStatus.Expired => AcmeError(403, AcmeErrorType.Unauthorized,
                $"This account is bound to external account credential '{gate.Name}', which " +
                $"expired on {gate.ExpiresAt:u}. New orders are suspended. Contact your administrator."),
            EabBindingGateStatus.Missing => AcmeError(403, AcmeErrorType.Unauthorized,
                "This account is bound to an external account credential that no longer " +
                "exists. New orders are suspended. Contact your administrator."),
            _ => AcmeError(403, AcmeErrorType.Unauthorized,
                $"This account is bound to external account credential '{gate.Name}', which " +
                "has been revoked. New orders are suspended. Contact your administrator."),
        };
        return (error, gate);
    }
}
