using System.Globalization;
using System.Text.Json;
using System.Threading.RateLimiting;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
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

    public OrderController(
        OrderService orderService,
        AccountService accountService,
        NonceService nonceService,
        JwsService jwsService,
        TemplateService templateService,
        AddressGuard addressGuard)
    {
        _orderService = orderService;
        _accountService = accountService;
        _nonceService = nonceService;
        _jwsService = jwsService;
        _templateService = templateService;
        _addressGuard = addressGuard;
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
        var resolution = await _templateService.ResolveAsync(template, ct);
        var templateError = TemplateAccessError(resolution, template);
        if (templateError != null)
            return templateError;
        var templateInfo = resolution.Template!;

        // 2. Authenticate JWS with kid
        var auth = await AuthenticateKidJwsAsync(
            _jwsService, _nonceService, _accountService, template, ct);
        if (!auth.IsAuthenticated)
            return auth.ErrorResult!;

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

        // 4. Validate identifiers
        foreach (var id in request.Identifiers)
        {
            if (id.Type != "dns")
                return AcmeError(400, AcmeErrorType.UnsupportedIdentifier,
                    $"Unsupported identifier type: '{id.Type}'. Only 'dns' is supported.");

            if (string.IsNullOrWhiteSpace(id.Value))
                return AcmeError(400, AcmeErrorType.Malformed,
                    "Identifier value must not be empty.");

            // Reject obvious internal targets at order time (localhost, blocked IP literals).
            // Names that only resolve to a blocked address are caught at validation time by
            // the egress guard. Strip a wildcard label first so "*.localhost" is screened too.
            var host = id.Value.StartsWith("*.", StringComparison.Ordinal) ? id.Value[2..] : id.Value;
            if (_addressGuard.IsBlockedLiteral(host))
                return AcmeError(400, AcmeErrorType.RejectedIdentifier,
                    $"Identifier '{id.Value}' is not permitted.");
        }

        // 5. Parse optional notBefore/notAfter. Use DateTimeOffset with RoundtripKind so an
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

        // 6. Create the order. Pass the canonical programmatic name so that
        // OrderService.SubmitCertificateRequestAsync hands ADCS the value it
        // matches against (ADCS Submit's CertificateTemplate: attribute does
        // not accept the display name).
        var order = await _orderService.CreateOrderAsync(
            auth.Account!, templateInfo.Name, request.Identifiers, notBefore, notAfter, ct);

        // 7. Return 201 Created with Location header
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
}
