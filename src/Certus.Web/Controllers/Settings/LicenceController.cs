using Certus.Core.Modules;
using Certus.Web.Audit;
using Certus.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Controllers.Settings;

/// <summary>
/// The licence API (licence design section 13.2, issue #413): what the module host believes, a
/// preview of a candidate file, and the changes an administrator can make to the licence store.
///
/// <para>The core never reads a licence's meaning. It keeps the bytes in the store and asks the
/// module, which alone verifies them, what it makes of them. Every answer is built from the core's
/// own views in <see cref="LicenceViews"/>, never from a contract type (deviation Dv15), and never
/// repeats the uploaded bytes. A file that has not passed the signature contributes nothing but its
/// status and reason code.</para>
///
/// <para>Admin only, by the class attribute and the fallback policy, and every mutating route is
/// CSRF protected by the global middleware, like the rest of the admin surface. Nothing here is on
/// the certificate issuance or renewal path: a module in any state, or no module at all, changes
/// what this controller answers and nothing else.</para>
/// </summary>
[ApiController]
[Route("api/settings/licence")]
[Authorize(Policy = CertusPolicies.AdminOnly)]
public sealed class LicenceController : ControllerBase
{
    /// <summary>
    /// The largest licence file accepted, in bytes (design section 13.2). A real licence is under a
    /// kilobyte; the action reads one byte past this and refuses, so the cap holds under TestServer,
    /// which does not enforce <see cref="MaxRequestBytes"/>.
    /// </summary>
    public const int MaxLicenceBytes = 16 * 1024;

    /// <summary>The request size Kestrel enforces before the action reads anything.</summary>
    public const int MaxRequestBytes = 20 * 1024;

    /// <summary>The media type of a licence upload: the file is a JWS (design section 7.1).</summary>
    public const string LicenceMediaType = "application/jose+json";

    private readonly ILicenceStatusSource _status;
    private readonly IModuleHostControl _control;
    private readonly LicenceFileStore _store;
    private readonly ILogger<LicenceController> _logger;

    public LicenceController(
        ILicenceStatusSource status,
        IModuleHostControl control,
        LicenceFileStore store,
        ILogger<LicenceController> logger)
    {
        _status = status;
        _control = control;
        _store = store;
        _logger = logger;
    }

    /// <summary>
    /// GET /api/settings/licence: the module's state, which licence files are stored, and the
    /// licence status with its display fields. It reads only in memory state and two file
    /// existence checks, so it cannot fail on a module in any state.
    /// </summary>
    [HttpGet("")]
    public IActionResult Get() => Ok(Describe(_status.Current));

    /// <summary>
    /// POST /api/settings/licence/inspect: the module's verdict on a candidate, with nothing
    /// written. With no module loaded there is nothing to judge it, and the candidate reads null.
    /// </summary>
    [HttpPost("inspect")]
    [AdminAuditExempt("judges a candidate file and writes nothing")]
    [Consumes(LicenceMediaType)]
    [RequestSizeLimit(MaxRequestBytes)]
    public async Task<IActionResult> Inspect(CancellationToken ct)
    {
        var (bytes, refusal) = await ReadLicenceAsync(ct);
        if (refusal is not null)
            return refusal;

        var inspected = await _control.InspectAsync(bytes, ct);
        return Ok(new LicenceInspectResponse(
            LicenceViews.Module(_status.Current),
            inspected is null ? null : LicenceViews.Candidate(inspected)));
    }

    /// <summary>
    /// PUT /api/settings/licence: installs a licence, keeping the one it replaces as the previous
    /// licence. A candidate the module judges worse than the installed one is refused 409
    /// WouldDowngrade unless the request carries <c>?confirm=true</c> (design section 9.5); the
    /// module makes that judgement, not the core. With no module loaded the bytes are stored as
    /// "stored, not verified", so the order the module and the licence arrive in does not matter.
    /// A loaded module that cannot judge the file answers 503, and nothing is stored.
    /// </summary>
    [HttpPut("")]
    [AdminAudit("licence.installed")]
    [Consumes(LicenceMediaType)]
    [RequestSizeLimit(MaxRequestBytes)]
    public async Task<IActionResult> Put([FromQuery] bool confirm, CancellationToken ct)
    {
        var (bytes, refusal) = await ReadLicenceAsync(ct);
        if (refusal is not null)
            return refusal;

        if (OpenStore() is { } storeRefusal)
            return storeRefusal;

        var inspected = await _control.InspectAsync(bytes, ct);

        // No verdict from a module that is still loaded means its Inspect threw: it is there to
        // judge the file and could not. Storing then would skip the downgrade check entirely, so
        // refuse instead. No verdict with no module loaded (none installed, set aside, refused by
        // the folder gate, built for another contract, or one that just ran out of time and is now
        // Unresponsive) is the ordinary "stored, not verified".
        if (inspected is null && _status.Current.ModuleState == ModuleState.Loaded && !ct.IsCancellationRequested)
        {
            _logger.LogWarning("The paid module did not judge an uploaded licence, so it was not installed");
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new
            {
                error = "The paid module could not check this licence, so nothing was changed. " +
                        "Try again; if it keeps failing, the service log says why.",
            });
        }

        var candidate = inspected is null ? null : LicenceViews.Candidate(inspected);

        if (candidate is { WorseThanInstalled: true } && !confirm)
        {
            return Conflict(new LicenceDowngradeResponse(
                "WouldDowngrade",
                "This licence is worse than the one installed. Send the request again with " +
                "confirm=true to install it anyway.",
                LicenceViews.Module(_status.Current),
                candidate));
        }

        // The last point the request can be abandoned for free: nothing has been written. A caller
        // that went away during the inspect also lands here, which matters because an inspect it
        // cancelled reads null and would otherwise store the file as unjudged.
        ct.ThrowIfCancellationRequested();

        if (Write(() => _store.Save(bytes)) is { } writeFailure)
            return writeFailure;

        _control.Reevaluate();

        var licence = candidate?.Licence ?? LicenceViews.StoredNotVerified();
        Audit(candidate is { WorseThanInstalled: true } ? "install-downgrade" : "install", licence);
        return Ok(Describe(_status.Current, licence));
    }

    /// <summary>
    /// DELETE /api/settings/licence: removes the active licence, keeping it as the previous one so
    /// "Restore previous licence" can undo the removal.
    /// </summary>
    [HttpDelete("")]
    [AdminAudit("licence.removed")]
    public IActionResult Delete()
    {
        if (OpenStore() is { } storeRefusal)
            return storeRefusal;

        // What is being removed, for the audit line, read before it goes.
        var removed = LicenceViews.Current(_status.Current, _store.HasActive);

        var deleted = false;
        if (Write(() => deleted = _store.DeleteActive()) is { } writeFailure)
            return writeFailure;
        if (!deleted)
            return NotFound(new { error = "No licence is installed." });

        _control.Reevaluate();

        Audit("remove", removed);
        return Ok(Describe(_status.Current));
    }

    /// <summary>
    /// POST /api/settings/licence/restore-previous: undoes the last replacement or removal. The
    /// restored file is inspected at once, so the answer and the audit line describe the licence
    /// that is now active rather than the evaluation of the one it replaced.
    /// </summary>
    [HttpPost("restore-previous")]
    [AdminAudit("licence.previous-restored")]
    public async Task<IActionResult> RestorePrevious()
    {
        if (OpenStore() is { } storeRefusal)
            return storeRefusal;

        var restored = false;
        if (Write(() => restored = _store.RestorePrevious()) is { } writeFailure)
            return writeFailure;
        if (!restored)
            return NotFound(new { error = "No previous licence is kept." });

        _control.Reevaluate();

        // Past the write, so the caller's token is no longer consulted: the audit line has to be
        // written whether or not the client is still listening.
        var active = _store.ReadActive();
        var inspected = active is null ? null : await _control.InspectAsync(active, CancellationToken.None);
        var licence = inspected is null ? LicenceViews.StoredNotVerified() : LicenceViews.Candidate(inspected).Licence;

        Audit("restore-previous", licence);
        return Ok(Describe(_status.Current, licence));
    }

    /// <summary>
    /// POST /api/settings/licence/retry-module: clears a quarantine and asks for a restart, so the
    /// next start is a fresh attempt. Where no restarter is available (the dev host registers a
    /// no-op) it says so, and the operator restarts the process themselves.
    /// </summary>
    [HttpPost("retry-module")]
    [AdminAudit("licence.module-retried")]
    public IActionResult RetryModule()
    {
        var current = _status.Current;
        if (!current.ModuleState.IsSetAside())
            return Conflict(new { error = "The paid module is not set aside, so there is nothing to retry." });

        var restartScheduled = _control.RequestRetry();

        Audit("retry-module", LicenceViews.Current(current, _store.HasActive));
        return Ok(new
        {
            restartScheduled,
            message = restartScheduled
                ? "The service is restarting to try the paid module again."
                : "Restart the service to try the paid module again.",
        });
    }

    /// <summary>
    /// The answer to GET and to every successful change. The store is read at the time of the
    /// request, its trust verdict included, so a folder refused a moment ago reads as refused at once
    /// rather than after the module host's next tick.
    /// </summary>
    private LicenceStatusResponse Describe(LicenceStatusView current, LicenceView? licence = null) => new(
        LicenceViews.Module(current),
        new LicenceStoreView(_store.HasActive, _store.HasPrevious, Untrusted: !_store.Verify().IsReady),
        licence ?? LicenceViews.Current(current, _store.HasActive));

    /// <summary>
    /// Reads the upload, at most <see cref="MaxLicenceBytes"/> plus one byte, so a larger body is
    /// refused without being read in full. Kestrel's own limit surfaces as a
    /// <see cref="BadHttpRequestException"/> carrying 413, which is answered with its own status
    /// rather than left to become a 500.
    /// </summary>
    private async Task<(byte[] Bytes, IActionResult? Refusal)> ReadLicenceAsync(CancellationToken ct)
    {
        var buffer = new byte[MaxLicenceBytes + 1];
        var total = 0;
        try
        {
            int read;
            while (total < buffer.Length && (read = await Request.Body.ReadAsync(buffer.AsMemory(total), ct)) > 0)
                total += read;
        }
        catch (BadHttpRequestException ex)
        {
            // Kestrel's size limit is the expected case, but the same exception carries a malformed
            // chunked body (400) and a body sent too slowly (408), which are not about size.
            var error = ex.StatusCode == StatusCodes.Status413PayloadTooLarge
                ? TooLarge
                : "The request body could not be read.";
            return ([], StatusCode(ex.StatusCode, new { error }));
        }

        if (total > MaxLicenceBytes)
            return ([], StatusCode(StatusCodes.Status413PayloadTooLarge, new { error = TooLarge }));

        if (total == 0)
            return ([], BadRequest(new { error = "The request carried no licence file." }));

        return (buffer[..total], null);
    }

    private static string TooLarge => $"A licence file is at most {MaxLicenceBytes} bytes.";

    /// <summary>
    /// Readies the licence folder before a change, and refuses one that is not trusted (design
    /// section 12.3). The folder is verified and never repaired, so the answer tells an
    /// administrator to delete it and let the service recreate it.
    /// </summary>
    private IActionResult? OpenStore()
    {
        var state = _store.Open();
        if (state.IsReady)
            return null;

        _logger.LogError(
            "The licence folder {Folder} was refused, so the licence was not changed: {Reason}",
            _store.Folder, state.RefusalReason);
        return Conflict(new
        {
            error = "The licence folder cannot be trusted, so nothing was changed. An administrator " +
                    "must delete the folder named in the service log; the service then recreates it.",
        });
    }

    /// <summary>Runs a store write, answering a file system failure as a 500 that names no path.</summary>
    private IActionResult? Write(Action write)
    {
        try
        {
            write();
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogError(ex, "The licence store in {Folder} could not be written", _store.Folder);
            return StatusCode(StatusCodes.Status500InternalServerError, new
            {
                error = "The licence could not be written. The service log has the details.",
            });
        }
    }

    /// <summary>
    /// One audit line per successful change (design section 13.2): who, what, and the licence id and
    /// tier. Those come from a verified view or not at all, so nothing an unverified file says is
    /// logged (deviation Dv4).
    /// </summary>
    private void Audit(string action, LicenceView licence)
    {
        // Negotiate always yields a name for an authorized admin; the fallback covers the
        // Development only Auth:Mode=Disabled escape hatch.
        _logger.LogInformation(
            "Licence audit: action={Action} by={Actor} status={Status} lid={LicenceId} tier={Tier}",
            action,
            User.Identity?.Name ?? "(anonymous)",
            licence.Status,
            licence.LicenceId ?? "none",
            licence.Tier ?? "none");

        // The same words into the audit trail row (issue #634). The downgrade
        // confirmation is part of the action word, so it stays visible there.
        this.AdminAudit().Describe(
            $"licence {licence.LicenceId ?? "none"}",
            after: $"{action}: status {licence.Status}, tier {licence.Tier ?? "none"}");
    }
}

/// <summary>The answer to GET and to every change: the module, the stored files and the licence.</summary>
public sealed record LicenceStatusResponse(ModuleView Module, LicenceStoreView Stored, LicenceView Licence);

/// <summary>The answer to an inspect. The candidate is null when no module was loaded to judge it.</summary>
public sealed record LicenceInspectResponse(ModuleView Module, LicenceCandidateView? Candidate);

/// <summary>The 409 an upload gets when the module judges it worse than the installed licence.</summary>
public sealed record LicenceDowngradeResponse(string Code, string Error, ModuleView Module, LicenceCandidateView Candidate);
