using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Security;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Web.Controllers.Dashboard;

/// <summary>
/// Dashboard API: certificate inventory, search, and statistics.
/// These endpoints serve the React dashboard frontend.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class CertificatesController : ControllerBase
{
    private const string PemMediaType = "application/x-pem-file";
    private const string DerMediaType = "application/pkix-cert";

    private readonly CertificateQueryService _queryService;
    private readonly TemplateService _templateService;
    private readonly CertificateSyncService _syncService;
    private readonly CertificateRevocationService _revocationService;
    private readonly SetupService _setupService;
    private readonly CertusOptions _certusOptions;
    private readonly ILogger<CertificatesController> _logger;

    public CertificatesController(
        CertificateQueryService queryService,
        TemplateService templateService,
        CertificateSyncService syncService,
        CertificateRevocationService revocationService,
        SetupService setupService,
        IOptions<CertusOptions> certusOptions,
        ILogger<CertificatesController> logger)
    {
        _queryService = queryService;
        _templateService = templateService;
        _syncService = syncService;
        _revocationService = revocationService;
        _setupService = setupService;
        _certusOptions = certusOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/certificates — search and paginate the certificate inventory.
    /// </summary>
    /// <remarks>
    /// expiringBefore and expiringAfter are instants, not days: the caller
    /// resolves its own timezone and sends UTC, and
    /// <see cref="UtcWallClock.Normalize(DateTime?)"/> holds them to the UTC
    /// wall clock the inventory is stored as.
    ///
    /// Both bounds are inclusive, unlike the exclusive Before bounds on the ACME
    /// accounts inventory. That difference is deliberate. There the dates are
    /// registration and last order timestamps an admin filters by whole local
    /// day, and an exclusive upper bound is what lets one day be expressed as a
    /// pair of instants. These two are an arbitrary expiry window rather than a
    /// day, and they predate the lifecycle state chips (issue #155), so a link
    /// built before those keeps the boundary it was built with.
    /// </remarks>
    [HttpGet]
    public async Task<IActionResult> ListCertificates(
        [FromQuery] string? search,
        [FromQuery] string? template,
        [FromQuery] string? status,
        [FromQuery] string? state,
        [FromQuery] DateTime? expiringBefore,
        [FromQuery] DateTime? expiringAfter,
        [FromQuery] string? sortBy,
        [FromQuery] bool sortDesc = false,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50,
        CancellationToken ct = default)
    {
        // An unrecognised lifecycle state is an error, not something to ignore
        // (issue #155). Quietly dropping the filter would answer a question
        // about expiry with the whole inventory, which reads as "nothing is
        // expiring" rather than as a broken request.
        if (!string.IsNullOrWhiteSpace(state) && !CertificateQueryService.IsKnownState(state))
        {
            return Problem(
                statusCode: StatusCodes.Status400BadRequest,
                title: "Unknown certificate state",
                detail: $"'{state}' is not a certificate state. Use valid, expiring, expired, or revoked.");
        }

        // Clamp take to reasonable limits
        take = Math.Clamp(take, 1, 200);
        skip = Math.Max(0, skip);

        var query = new CertificateSearchQuery(
            Search: search,
            TemplateName: template,
            Status: status,
            State: state,
            ExpiringBefore: UtcWallClock.Normalize(expiringBefore),
            ExpiringAfter: UtcWallClock.Normalize(expiringAfter),
            SortBy: sortBy,
            SortDesc: sortDesc,
            Skip: skip,
            Take: take);

        var result = await _queryService.QueryAsync(query, ct);
        return Ok(result);
    }

    /// <summary>
    /// GET /api/certificates/{id} — get a single certificate by ID.
    /// </summary>
    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetCertificate(int id, CancellationToken ct)
    {
        var cert = await _queryService.GetDetailByIdAsync(id, ct);
        if (cert == null)
            return NotFound();

        return Ok(cert);
    }

    /// <summary>
    /// POST /api/certificates/{id}/revoke — revoke this one certificate at
    /// the CA (issue #159). The highest blast radius action on the dashboard:
    /// the CA revokes any certificate in its database, Ducks issued or not,
    /// and outside Certificate Hold there is no undo.
    ///
    /// The body carries the reason the admin chose and the serial they
    /// confirmed in the dialog; the service refuses on any mismatch, so the
    /// action stays bound to the exact certificate that was on screen. On
    /// success the response's certificate is the row as the resync read it
    /// back from the CA, never an optimistic local edit. AdminOnly and the
    /// CSRF header guard both apply class wide, the same as every other
    /// mutating dashboard endpoint. There is deliberately no bulk variant
    /// and no revoke from the list view.
    /// </summary>
    [HttpPost("{id:int}/revoke")]
    public async Task<IActionResult> RevokeCertificate(
        int id,
        [FromBody] RevokeCertificateRequest request,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.SerialNumber))
        {
            return Problem(
                statusCode: StatusCodes.Status400BadRequest,
                title: "Missing certificate serial",
                detail: "The request must carry the certificate's serial number so the " +
                        "revocation is bound to the certificate confirmed in the dialog.");
        }

        // Negotiate always yields a name for an authorized admin; the
        // fallback covers the Development only Auth:Mode=Disabled escape
        // hatch, where there is no identity to attribute the action to.
        var actor = User.Identity?.Name ?? "(anonymous)";

        try
        {
            var result = await _revocationService.RevokeAsync(
                id, request.Reason, request.SerialNumber, actor, ct);

            switch (result.Status)
            {
                case CertificateRevocationStatus.Revoked:
                    // Re-read after the resync so the page renders the CA's
                    // own account of the revocation.
                    var detail = await _queryService.GetDetailByIdAsync(id, ct);
                    return Ok(new
                    {
                        outcome = "revoked",
                        resynced = result.Resynced,
                        certificate = detail,
                    });

                case CertificateRevocationStatus.AlreadyRevoked:
                    return Problem(
                        type: DashboardProblemType.CertificateAlreadyRevoked,
                        title: "Certificate is already revoked",
                        detail: "The certification authority already lists this certificate as " +
                                "revoked, so no second revocation was sent.",
                        statusCode: StatusCodes.Status409Conflict);

                case CertificateRevocationStatus.NotRevocable:
                    return Problem(
                        type: DashboardProblemType.CertificateNotRevocable,
                        title: "Nothing to revoke",
                        detail: "This row is a request that never became a certificate, so " +
                                "there is nothing to revoke at the certification authority.",
                        statusCode: StatusCodes.Status409Conflict);

                case CertificateRevocationStatus.TargetMismatch:
                    return Problem(
                        type: DashboardProblemType.RevocationTargetMismatch,
                        title: "Confirmation does not match this certificate",
                        detail: "The serial number confirmed in the dialog is not this " +
                                "certificate's serial. Reload the page and try again.",
                        statusCode: StatusCodes.Status409Conflict);

                case CertificateRevocationStatus.InvalidReason:
                    return Problem(
                        type: DashboardProblemType.InvalidRevocationReason,
                        title: "Invalid revocation reason",
                        detail: "The revocation reason must be one of the RFC 5280 codes 0 " +
                                "to 6.",
                        statusCode: StatusCodes.Status400BadRequest);

                // 403 rather than the 409 family for the two policy refusals:
                // these are authorization decisions, not state conflicts, and
                // retrying changes nothing.
                case CertificateRevocationStatus.BlockedByGuardrail:
                    return Problem(
                        type: DashboardProblemType.RevocationBlockedByGuardrail,
                        title: "Blocked by the TLS certificate guardrail",
                        detail: result.RefusalDetail ??
                                "This is not a TLS server or client certificate, so the " +
                                "dashboard will not revoke it.",
                        statusCode: StatusCodes.Status403Forbidden);

                case CertificateRevocationStatus.OutOfScope:
                    return Problem(
                        type: DashboardProblemType.RevocationOutOfScope,
                        title: "Outside the configured revocation scope",
                        detail: result.RefusalDetail ??
                                "The revocation scope configured in Settings does not cover " +
                                "this certificate.",
                        statusCode: StatusCodes.Status403Forbidden);

                case CertificateRevocationStatus.NotFound:
                    return NotFound();

                default:
                    return Problem(
                        type: DashboardProblemType.CaError,
                        title: "Certificate Authority error",
                        detail: "The certification authority refused the revocation. The " +
                                "inventory was refreshed; check the certificate's current status.",
                        statusCode: StatusCodes.Status500InternalServerError);
            }
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "Revocation of certificate {CertificateId}: CA is unavailable", id);
            return Problem(
                type: DashboardProblemType.CaUnavailable,
                title: "Certificate Authority is unavailable",
                detail: "The ADCS Certificate Authority cannot be reached. The certificate was " +
                        "not revoked. Try again shortly.",
                statusCode: 503);
        }
        catch (CaAccessDeniedException ex)
        {
            _logger.LogWarning(ex, "Revocation of certificate {CertificateId}: CA denied access", id);
            return Problem(
                type: DashboardProblemType.CaAccessDenied,
                title: "CA revoke access denied",
                detail: ex.Message,
                statusCode: 503);
        }
    }

    /// <summary>
    /// GET /api/certificates/{id}/pem — this one certificate as a PEM text
    /// download (issue #158).
    ///
    /// The leaf on its own, never a chain. An admin who needs the issuing CA
    /// and root already has them in Settings, CA certificates, and keeping this
    /// response to a single certificate is the free tier line the epic draws:
    /// handing back a certificate the admin already owns is basic management,
    /// exporting the inventory is not.
    ///
    /// Served from the DER captured at sync time, so it answers for revoked
    /// certificates and while the CA is unreachable, neither of which the live
    /// retrieval path can do.
    /// </summary>
    [HttpGet("{id:int}/pem")]
    public async Task<IActionResult> DownloadPem(int id, CancellationToken ct)
    {
        using var certificate = await LoadCertificateAsync(id, ct);
        if (certificate == null)
            return CertificateUnavailable(id);

        // Trailing newline so the file ends the way every other PEM producer
        // ends it, matching CaCertificatesController.
        var pem = certificate.ExportCertificatePem() + "\n";
        return File(Encoding.ASCII.GetBytes(pem), PemMediaType, FileName(certificate, id) + ".pem");
    }

    /// <summary>
    /// GET /api/certificates/{id}/der — this one certificate as a binary .cer
    /// download, the form that opens straight in the Windows certificate
    /// viewer. Same single certificate rule as the PEM endpoint above.
    /// </summary>
    [HttpGet("{id:int}/der")]
    public async Task<IActionResult> DownloadDer(int id, CancellationToken ct)
    {
        using var certificate = await LoadCertificateAsync(id, ct);
        if (certificate == null)
            return CertificateUnavailable(id);

        return File(certificate.RawData, DerMediaType, FileName(certificate, id) + ".cer");
    }

    /// <summary>
    /// The stored certificate for one row, parsed, or null when there is
    /// nothing to serve: no such row, a row the sync never captured a
    /// certificate blob for, or bytes that no longer decode. The caller answers
    /// 404 for all of them, because from the admin's side they are one thing.
    ///
    /// Parsing here rather than streaming the stored bytes straight out is what
    /// lets both endpoints share one code path, and it means a corrupted column
    /// surfaces as "not available" instead of as a download that fails to open.
    /// </summary>
    private async Task<X509Certificate2?> LoadCertificateAsync(int id, CancellationToken ct)
    {
        var der = await _queryService.GetRawCertificateAsync(id, ct);
        if (der is not { Length: > 0 })
            return null;

        try
        {
            return X509CertificateLoader.LoadCertificate(der);
        }
        catch (CryptographicException ex)
        {
            _logger.LogWarning(ex,
                "Stored certificate bytes for certificate {CertificateId} could not be decoded", id);
            return null;
        }
    }

    private ObjectResult CertificateUnavailable(int id) => Problem(
        type: DashboardProblemType.CertificateUnavailable,
        title: "No certificate to download",
        detail: $"Certificate {id} has no stored certificate. A request that never became a " +
                "certificate has none, and a row synced before this version will gain one on the " +
                "next sync from the certificate authority.",
        statusCode: StatusCodes.Status404NotFound);

    /// <summary>
    /// A download file name for one certificate, sanitized by
    /// CertificateTextSanitizer.SanitizeFileNameComponent, mirroring the CA
    /// certificate downloads in CaCertificatesController.
    ///
    /// The precedence matches certificateDisplayName on the dashboard: the
    /// subject common name, then the first SAN, then the serial. An ACME issued
    /// certificate routinely carries no subject DN at all, so the SAN step is
    /// the normal case rather than a fallback. The internal id is the last
    /// resort, so the file is always named something.
    ///
    /// A name made entirely of format characters now sanitizes to nothing and
    /// falls through to the next candidate rather than naming the file after a
    /// string that renders as empty (issue #232).
    /// </summary>
    private static string FileName(X509Certificate2 certificate, int id)
    {
        var candidate = CertificateTextSanitizer.SanitizeFileNameComponent(
            certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false));

        if (candidate == null)
            candidate = CertificateTextSanitizer.SanitizeFileNameComponent(FirstDnsName(certificate));

        if (candidate == null)
            candidate = CertificateTextSanitizer.SanitizeFileNameComponent(certificate.SerialNumber);

        return candidate ?? $"certificate-{id}";
    }

    /// <summary>The first DNS SAN, or null when the certificate carries none.</summary>
    private static string? FirstDnsName(X509Certificate2 certificate)
    {
        try
        {
            return certificate.Extensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .FirstOrDefault()
                ?.EnumerateDnsNames()
                .FirstOrDefault();
        }
        catch (CryptographicException)
        {
            return null; // Malformed SAN extension; fall through to the serial.
        }
    }

    /// <summary>
    /// GET /api/certificates/stats — dashboard summary statistics.
    /// </summary>
    [HttpGet("stats")]
    public async Task<IActionResult> GetStats(CancellationToken ct)
    {
        var stats = await _queryService.GetStatsAsync(ct);
        return Ok(stats);
    }

    /// <summary>
    /// POST /api/certificates/sync — pull the inventory from the CA now.
    /// Runs a full sync and returns its counts, so the dashboard Refresh
    /// button reflects the CA immediately instead of waiting for the next
    /// interval tick. Concurrent requests serialize on the sync gate inside
    /// CertificateSyncService.
    /// </summary>
    [HttpPost("sync")]
    public async Task<IActionResult> TriggerSync(CancellationToken ct)
    {
        try
        {
            var result = await _syncService.SyncCertificatesAsync(ct);
            return Ok(result);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "Manual sync: CA is unavailable");
            return Problem(
                type: DashboardProblemType.CaUnavailable,
                title: "Certificate Authority is unavailable",
                detail: "The ADCS Certificate Authority cannot be reached. Try again shortly.",
                statusCode: 503);
        }
        catch (CaAccessDeniedException ex)
        {
            _logger.LogWarning(ex, "Manual sync: CA view access denied");
            return Problem(
                type: DashboardProblemType.CaAccessDenied,
                title: "CA view access denied",
                detail: ex.Message,
                statusCode: 503);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Manual sync failed");
            return Problem(
                type: DashboardProblemType.CaError,
                title: "Certificate Authority error",
                detail: "An unexpected error occurred while syncing from the certificate authority.",
                statusCode: 503);
        }
    }

    /// <summary>
    /// GET /api/certificates/sync-status — the connected CA and the outcome
    /// of the most recent inventory sync (issue #157). Served from memory on
    /// the sync service singleton; no CA round trip, safe for the page
    /// headers to poll.
    /// </summary>
    [HttpGet("sync-status")]
    public IActionResult GetSyncStatus()
    {
        // One snapshot read, so the attempt and the success stay a consistent
        // pair even when a sync completes mid request.
        var status = _syncService.Status;
        var attempt = status.LastAttempt;

        return Ok(new
        {
            caName = _certusOptions.CaDisplayName,
            caMode = _setupService.CaMode,
            lastAttemptAt = attempt?.AttemptedAtUtc,
            lastOutcome = attempt is null ? null : Describe(attempt.Outcome),
            lastMessage = attempt?.Message,
            // A failure the header should show, as opposed to no attempt yet.
            failed = attempt is not null && attempt.Outcome != CertificateSyncOutcome.Success,
            lastSuccess = status.LastSuccess?.Result,
        });
    }

    /// <summary>The camelCase outcome name the dashboard switches on.</summary>
    private static string Describe(CertificateSyncOutcome outcome) => outcome switch
    {
        CertificateSyncOutcome.Success => "success",
        CertificateSyncOutcome.CaUnavailable => "caUnavailable",
        CertificateSyncOutcome.CaAccessDenied => "caAccessDenied",
        _ => "failed",
    };

    /// <summary>
    /// GET /api/templates — list available ADCS certificate templates.
    /// </summary>
    [HttpGet("/api/templates")]
    public async Task<IActionResult> ListTemplates(CancellationToken ct)
    {
        try
        {
            var templates = await _templateService.GetTemplatesAsync(ct);

            // The existing fields plus the ceiling verdict per template, so
            // an admin surface can grey out what the guardrail would refuse
            // anyway. tlsCapable is null when the AD metadata is unverified;
            // the finalize leaf check still decides at issuance either way.
            var annotated = templates.Select(t =>
            {
                var verdict = t.ExtendedKeyUsages == null
                    ? null
                    : TlsCapabilityCeiling.Evaluate(
                        new CertificateCapability(t.ExtendedKeyUsages, null, null));
                return new
                {
                    name = t.Name,
                    displayName = t.DisplayName,
                    oid = t.Oid,
                    // The OID as published is the one value this endpoint hands
                    // out that nothing else reports on, so a deceptive
                    // character in it travels with it (issue #292). The fault
                    // itself carries no OID text, which is the point: a caller
                    // that renders the value can say why it may not read as it
                    // looks without being handed the characters again.
                    //
                    // The display name fault is deliberately not carried here.
                    // The setup wizard already explains it where the
                    // remediation lives and the URL guard already refuses it,
                    // so a copy on this endpoint would be a second one nothing
                    // reads and one more thing to keep in step.
                    oidWarning = SetupTemplateNameWarning.From(
                        TemplateNameUsability.Inspect(t).OidFault),
                    extendedKeyUsages = t.ExtendedKeyUsages,
                    viability = t.Viability,
                    ekuVerified = t.ExtendedKeyUsages != null,
                    tlsCapable = verdict == null ? (bool?)null : verdict.Allowed,
                    tlsBlockedReason = verdict is { Allowed: false } ? verdict.Message : null,
                };
            }).ToList();

            return Ok(annotated);
        }
        catch (CaUnavailableException ex)
        {
            _logger.LogWarning(ex, "Templates endpoint: CA is unavailable");
            return Problem(
                type: DashboardProblemType.CaUnavailable,
                title: "Certificate Authority is unavailable",
                detail: "The ADCS Certificate Authority cannot be reached. Try again shortly.",
                statusCode: 503);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve templates from CA");
            return Problem(
                type: DashboardProblemType.CaError,
                title: "Certificate Authority error",
                detail: "An unexpected error occurred while contacting the certificate authority.",
                statusCode: 503);
        }
    }
}

/// <summary>
/// Body of POST /api/certificates/{id}/revoke: the RFC 5280 reason code the
/// admin chose and the serial number they confirmed, echoed back so the
/// server can verify the action targets the certificate that was on screen.
/// </summary>
public sealed record RevokeCertificateRequest(int Reason, string? SerialNumber);
