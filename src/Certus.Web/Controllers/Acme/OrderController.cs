using System.Globalization;
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
    [EnableRateLimiting("acme-new-order")]
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
        var deviceIdentifierCount = 0;
        foreach (var id in request.Identifiers)
        {
            if (!AcmeIdentifierTypes.IsSupported(id.Type))
                return UnsupportedIdentifierError(id.Type);

            if (string.IsNullOrWhiteSpace(id.Value))
                return AcmeError(400, AcmeErrorType.Malformed,
                    "Identifier value must not be empty.");

            if (id.Type == AcmeIdentifierTypes.PermanentIdentifier)
            {
                deviceIdentifierCount++;
                if (!PermanentIdentifierValue.TryParse(id.Value, out _, out var parseError))
                    return AcmeError(400, AcmeErrorType.Malformed, parseError);
                continue;
            }

            // Reject obvious internal targets at order time (localhost, blocked IP literals).
            // Names that only resolve to a blocked address are caught at validation time by
            // the egress guard. Strip a wildcard label first so "*.localhost" is screened too.
            var host = id.Value.StartsWith("*.", StringComparison.Ordinal) ? id.Value[2..] : id.Value;
            if (_addressGuard.IsBlockedLiteral(host))
                return AcmeError(400, AcmeErrorType.RejectedIdentifier,
                    $"Identifier '{id.Value}' is not permitted.");
        }

        // A device order carries exactly one permanent-identifier and nothing
        // else: the draft binds one attestation to one device identity, and a
        // mixed order would need network authorizations no device can complete.
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

        // 7. Create the order. Pass the canonical programmatic name so that
        // OrderService.SubmitCertificateRequestAsync hands ADCS the value it
        // matches against (ADCS Submit's CertificateTemplate: attribute does
        // not accept the display name).
        var order = await _orderService.CreateOrderAsync(
            auth.Account!, templateInfo.Name, request.Identifiers, notBefore, notAfter, ct);

        // 8. Return 201 Created with Location header
        var orderUrl = AcmeUrl($"/acme/{template}/order/{order.OrderId}");
        Response.Headers["Location"] = orderUrl;

        var response = OrderService.ToResponse(order, AcmeUrl);
        return StatusCode(201, response);
    }

    /// <summary>
    /// POST /acme/{template}/order/{orderId} — get order status (POST-as-GET).
    /// RFC 8555 §7.4. Intentionally not rate limited: ACME clients poll this endpoint
    /// while waiting for the order to become ready or valid.
    /// </summary>
    [HttpPost("/acme/{template}/order/{orderId}")]
    [Consumes("application/jose+json")]
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
    [EnableRateLimiting("acme-general")]
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

        // Finalize
        var (success, errorMessage) = await _orderService.FinalizeOrderAsync(orderId, csrDer, ct);
        if (!success)
            return AcmeError(400, AcmeErrorType.BadCsr, errorMessage ?? "Finalization failed.");

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
    /// for byte: a probing client cannot tell a server without the device
    /// attestation feature from a template that has it turned off, so the
    /// feature stays invisible until an administrator enables it.
    /// </summary>
    private IActionResult UnsupportedIdentifierError(string type) =>
        AcmeError(400, AcmeErrorType.UnsupportedIdentifier,
            $"Unsupported identifier type: '{type}'.");

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
