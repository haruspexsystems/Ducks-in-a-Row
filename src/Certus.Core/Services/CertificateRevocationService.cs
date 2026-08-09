using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Services;

/// <summary>
/// Revokes one certificate at the CA on behalf of a dashboard admin
/// (issue #159). This is the highest blast radius action in the product:
/// the CA itself will revoke any certificate in its database, and outside
/// Certificate Hold there is no undo. The service therefore refuses early
/// and loudly (already revoked, not a certificate, serial mismatch, unknown
/// reason), refuses anything the TLS capability ceiling cannot vouch for
/// (see <see cref="RevocationEligibilityService"/>), and writes one
/// structured audit event for every attempt, refused or not, with the
/// actor, the serial, the reason, and the outcome.
///
/// The local row is never stamped optimistically. After a successful CA
/// call the inventory is resynced in-request, the same
/// <see cref="CertificateSyncService.SyncCertificatesAsync"/> the dashboard
/// Refresh button uses, so the page shows the CA's own account of the
/// revocation rather than a guess.
/// </summary>
public class CertificateRevocationService
{
    /// <summary>
    /// The reason codes the dashboard accepts, RFC 5280 §5.3.1 values 0 to 6
    /// (7 is unassigned). The remaining codes stay out deliberately: 8
    /// (Remove From CRL) un-revokes a held certificate rather than revoking
    /// anything, and ICertAdmin::RevokeCertificate documents acceptance of
    /// 0 to 6 only, so 9 (Privilege Withdrawn) and 10 (AA Compromise) are
    /// excluded until a probe against a real CA proves they work. The
    /// frontend picker offers exactly this set.
    /// </summary>
    private const int MaxPermittedReason = 6;

    private readonly CertusDbContext _db;
    private readonly IAdcsClient _adcsClient;
    private readonly CertificateSyncService _syncService;
    private readonly CertificateRevocationGate _gate;
    private readonly RevocationEligibilityService _eligibility;
    private readonly ILogger<CertificateRevocationService> _logger;

    public CertificateRevocationService(
        CertusDbContext db,
        IAdcsClient adcsClient,
        CertificateSyncService syncService,
        CertificateRevocationGate gate,
        RevocationEligibilityService eligibility,
        ILogger<CertificateRevocationService> logger)
    {
        _db = db;
        _adcsClient = adcsClient;
        _syncService = syncService;
        _gate = gate;
        _eligibility = eligibility;
        _logger = logger;
    }

    /// <summary>
    /// Revokes the certificate with the given inventory id at the CA.
    /// <paramref name="expectedSerial"/> is the serial the admin confirmed in
    /// the dialog; a mismatch refuses the action, so the request is bound to
    /// exactly the certificate that was on screen, independent of the UI
    /// level confirmation. <see cref="CaUnavailableException"/> and
    /// <see cref="CaAccessDeniedException"/> propagate to the caller with
    /// local state untouched; every other CA failure comes back as
    /// <see cref="CertificateRevocationStatus.CaError"/> after a corrective
    /// resync, because the usual cause is a certificate already revoked out
    /// of band, and the resync is what makes the page tell that truth.
    /// Attempts for the same serial are serialized through
    /// <see cref="CertificateRevocationGate"/>, so of two simultaneous
    /// requests only the winner reaches the CA and the loser is refused as
    /// already revoked (issue #203).
    /// </summary>
    public async Task<CertificateRevocationResult> RevokeAsync(
        int id,
        int reason,
        string expectedSerial,
        string actor,
        CancellationToken cancellationToken = default)
    {
        // The whole read, guard, CA call, record sequence runs under the per
        // serial gate; see CertificateRevocationGate for why the guards alone
        // are not enough.
        using var gateHandle = await _gate.AcquireAsync(expectedSerial, cancellationToken);

        // No tracking, deliberately: the resync below writes this row from
        // its own scope, and the controller then re-reads it through
        // CertificateQueryService.GetDetailByIdAsync, whose FindAsync answers
        // from this scope's identity map before it asks the database. A
        // tracked instance here would hand that read the pre revocation row
        // and the response would claim the certificate is still issued.
        var entity = await _db.SyncedCertificates.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        if (entity == null)
        {
            Audit(actor, id, serial: null, reason, "notFound");
            return new CertificateRevocationResult(CertificateRevocationStatus.NotFound);
        }

        if (reason is < 0 or > MaxPermittedReason)
        {
            Audit(actor, id, entity.SerialNumber, reason, "invalidReason");
            return new CertificateRevocationResult(CertificateRevocationStatus.InvalidReason);
        }

        // Refuse a second revocation outright rather than letting the CA
        // reject it; the acceptance criteria require that no second CA call
        // is made for an already revoked certificate.
        if (entity.Status == nameof(CertificateStatus.Revoked))
        {
            Audit(actor, id, entity.SerialNumber, reason, "alreadyRevoked");
            return new CertificateRevocationResult(CertificateRevocationStatus.AlreadyRevoked);
        }

        // Pending, Denied, and Failed rows come from the CA's request table
        // and never had a certificate, so there is nothing to revoke.
        if (entity.Status != nameof(CertificateStatus.Issued) ||
            string.IsNullOrWhiteSpace(entity.SerialNumber))
        {
            Audit(actor, id, entity.SerialNumber, reason, "notRevocable");
            return new CertificateRevocationResult(CertificateRevocationStatus.NotRevocable);
        }

        if (string.IsNullOrWhiteSpace(expectedSerial) ||
            !SerialNumbers.NormalizedEquals(expectedSerial, entity.SerialNumber))
        {
            Audit(actor, id, entity.SerialNumber, reason, "targetMismatch");
            return new CertificateRevocationResult(CertificateRevocationStatus.TargetMismatch);
        }

        // The eligibility gate, evaluated before the CA is ever contacted:
        // the TLS capability ceiling refuses anything that is not a TLS
        // server or client certificate, whatever the row's provenance, and
        // refuses when the capability cannot be determined at all.
        var eligibility = await _eligibility.EvaluateAsync(entity, cancellationToken);
        if (!eligibility.Allowed)
        {
            var outOfScope = eligibility.BlockedKind == "out-of-scope";
            Audit(actor, id, entity.SerialNumber, reason,
                outOfScope ? "outOfScope" : "blockedByGuardrail");
            return new CertificateRevocationResult(
                outOfScope
                    ? CertificateRevocationStatus.OutOfScope
                    : CertificateRevocationStatus.BlockedByGuardrail,
                RefusalDetail: eligibility.Detail);
        }

        try
        {
            await _adcsClient.RevokeCertificateAsync(entity.SerialNumber, reason, cancellationToken);
        }
        catch (CaUnavailableException)
        {
            Audit(actor, id, entity.SerialNumber, reason, "caUnavailable", LogLevel.Warning);
            throw;
        }
        catch (CaAccessDeniedException)
        {
            Audit(actor, id, entity.SerialNumber, reason, "caAccessDenied", LogLevel.Warning);
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The CA refused for a reason we did not predict. The usual one is
            // a certificate revoked out of band (CA console, certutil) since
            // the last sync, so resync and answer from the corrected row.
            _logger.LogError(ex,
                "CA refused revocation of certificate {CertificateId} (serial {Serial})",
                id, entity.SerialNumber);
            await TryResyncAsync();
            var corrected = await _db.SyncedCertificates.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == id, CancellationToken.None);

            if (corrected?.Status == nameof(CertificateStatus.Revoked))
            {
                Audit(actor, id, entity.SerialNumber, reason, "alreadyRevoked");
                return new CertificateRevocationResult(CertificateRevocationStatus.AlreadyRevoked);
            }

            Audit(actor, id, entity.SerialNumber, reason, "caError", LogLevel.Warning);
            return new CertificateRevocationResult(CertificateRevocationStatus.CaError);
        }

        // The CA has revoked. That is now a fact, and everything below records
        // it, so nothing here may be abandoned by a client disconnect: the
        // whole tail runs on CancellationToken.None.
        await RecordRevocationAsync(entity, reason);

        // The resync is what makes the dashboard report the CA's own account
        // of the revocation, rather than the floor written just above.
        var resynced = await TryResyncAsync();

        Audit(actor, id, entity.SerialNumber, reason, "revoked");
        return new CertificateRevocationResult(CertificateRevocationStatus.Revoked, resynced);
    }

    /// <summary>
    /// Writes what is now certain after a successful CA call: this certificate
    /// is revoked, with this reason. Best effort as a whole, and deliberately
    /// so. The CA has already acted, so a bookkeeping failure here must not
    /// throw away the audit event or the resync that follow it, and must not
    /// turn an accomplished revocation into a 500 that invites the admin to
    /// try again.
    /// </summary>
    private async Task RecordRevocationAsync(SyncedCertificate entity, int reason)
    {
        var revokedAt = DateTime.UtcNow;

        try
        {
            // The inventory row, as a floor rather than as the answer. The
            // resync below overwrites all three fields with what the CA
            // reports, which is the account the dashboard should show, so
            // this only ever survives when the resync could not run.
            //
            // Not optimistic, and not decoration: the already revoked guard
            // above reads this column, so without a stamp a failed resync
            // would leave the row saying Issued and let a retry send the CA a
            // second revocation for a certificate it has already revoked.
            //
            // Written as a direct UPDATE rather than through a tracked entity
            // on purpose. The controller re-reads this row through
            // CertificateQueryService.GetDetailByIdAsync, whose FindAsync
            // answers from this scope's identity map first, so a tracked copy
            // here would shadow whatever the resync wrote and hand the caller
            // this floor instead of the CA's account.
            await _db.SyncedCertificates
                .Where(c => c.Id == entity.Id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(c => c.Status, nameof(CertificateStatus.Revoked))
                    .SetProperty(c => c.RevokedAt, revokedAt)
                    .SetProperty(c => c.RevokedReason, reason),
                    CancellationToken.None);

            // An ACME issued certificate also carries a row in
            // AcmeCertificates, and the ACME revoke-cert endpoint answers
            // alreadyRevoked from that row's RevokedAt without calling the CA
            // (RFC 8555 §7.6). Stamp it, or an ACME client revoking after a
            // dashboard revoke would trigger a second CA call and get a
            // server error instead of alreadyRevoked. Nothing else ever
            // repairs this row; the certificate sync does not touch it.
            await _db.AcmeCertificates
                .Where(a => a.AdcsRequestId == entity.RequestId && a.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(a => a.RevokedAt, revokedAt)
                    .SetProperty(a => a.RevokedReason, reason),
                    CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Certificate {CertificateId} (serial {Serial}) was revoked at the CA but the " +
                "local records could not be updated. The inventory corrects on the next sync; " +
                "an ACME client may see a second revocation attempt reach the CA",
                entity.Id, entity.SerialNumber);
        }
    }

    private async Task<bool> TryResyncAsync()
    {
        try
        {
            await _syncService.SyncCertificatesAsync(CancellationToken.None);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Inventory resync after a revocation attempt failed; the row corrects on the next sync");
            return false;
        }
    }

    /// <summary>
    /// The audit trail: one structured event per attempt, whatever the
    /// outcome. Grep target: "Certificate revocation attempt".
    /// </summary>
    private void Audit(
        string actor, int certificateId, string? serial, int reason, string outcome,
        LogLevel level = LogLevel.Information)
    {
        _logger.Log(level,
            "Certificate revocation attempt by {Actor}: certificate {CertificateId}, serial {Serial}, reason {Reason}, outcome {Outcome}",
            actor, certificateId, serial ?? "(none)", reason, outcome);
    }
}

/// <summary>Outcome of <see cref="CertificateRevocationService.RevokeAsync"/>.</summary>
public sealed record CertificateRevocationResult(
    CertificateRevocationStatus Status,
    bool Resynced = false,
    string? RefusalDetail = null);

/// <summary>
/// How a dashboard revocation attempt ended. Distinct from the ACME side's
/// <c>RevokeOutcome</c>, which only ever sees certificates Ducks issued;
/// this surface fronts the whole CA database and has more ways to refuse.
/// </summary>
public enum CertificateRevocationStatus
{
    /// <summary>The CA revoked the certificate.</summary>
    Revoked,

    /// <summary>Already revoked; no CA call was made (or the CA said so itself).</summary>
    AlreadyRevoked,

    /// <summary>No inventory row with that id.</summary>
    NotFound,

    /// <summary>A request row with no certificate behind it, or no serial.</summary>
    NotRevocable,

    /// <summary>The reason code is outside the accepted 0 to 6 set.</summary>
    InvalidReason,

    /// <summary>The confirmed serial does not match the row's serial.</summary>
    TargetMismatch,

    /// <summary>
    /// The TLS capability ceiling refused: not a TLS server or client
    /// certificate, or its capability could not be determined. No setting
    /// can widen this; the refusal detail names the offending usage.
    /// </summary>
    BlockedByGuardrail,

    /// <summary>
    /// The configured revocation scope does not cover this certificate. The
    /// admin can widen the scope in Settings.
    /// </summary>
    OutOfScope,

    /// <summary>The CA refused the revocation for an unanticipated reason.</summary>
    CaError
}
