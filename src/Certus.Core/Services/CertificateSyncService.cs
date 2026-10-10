using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Services;

/// <summary>
/// Background service that periodically syncs the certificate inventory
/// from the ADCS CA database into the local SQLite database.
/// This gives the Certus dashboard full visibility into ALL certificates
/// issued by the CA, not just those issued through the ACME proxy.
/// </summary>
public sealed class CertificateSyncService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IAdcsClient _adcsClient;
    private readonly CertificateSyncTrigger _trigger;
    private readonly ILogger<CertificateSyncService> _logger;
    private readonly TimeSpan _syncInterval;
    private readonly int _requestHistoryDays;

    // EF turns a Contains over a list into one parameter per element and
    // SQLite's older default ceiling is 999, so the one place that reloads an
    // unbounded id list chunks well under it. The disposition passes need no
    // such guard: they read and write in batches of 100.
    private const int BackfillChunkSize = 500;

    // Serializes the timer loop, the ACME issuance nudge, and the manual sync
    // endpoint: only one full CA pull runs at a time.
    private readonly SemaphoreSlim _syncGate = new(1, 1);

    // The last sync attempt and the last success, read by the sync status
    // endpoint (issue #157). Kept in memory on purpose, the
    // HttpsCertificateAutoRenewalService.LastAttempt pattern: the durable
    // product of a sync is the inventory itself, and the first sync after
    // startup repopulates this within seconds. One volatile reference to an
    // immutable pair, so a reader always sees a consistent attempt and
    // success combination; the read of the previous success on the failure
    // path is safe because every write happens under the sync gate.
    private volatile CertificateSyncStatusSnapshot _status = new(null, null);

    public CertificateSyncService(
        IServiceScopeFactory scopeFactory,
        IAdcsClient adcsClient,
        CertificateSyncTrigger trigger,
        IOptions<CertusOptions> options,
        ILogger<CertificateSyncService> logger)
    {
        _scopeFactory = scopeFactory;
        _adcsClient = adcsClient;
        _trigger = trigger;
        _logger = logger;
        _syncInterval = TimeSpan.FromMinutes(
            Math.Max(CertusOptions.MinSyncIntervalMinutes, options.Value.SyncIntervalMinutes));
        // Negative reads the same as zero: the request dispositions are not synced.
        _requestHistoryDays = Math.Max(0, options.Value.RequestHistoryDays);
    }

    /// <summary>
    /// The most recent sync attempt this process made, success or failure, or
    /// null before the first one. In memory only: after a restart the status
    /// reads as never synced until the startup sync runs a few seconds later.
    /// </summary>
    public CertificateSyncAttempt? LastAttempt => _status.LastAttempt;

    /// <summary>The most recent successful sync, or null when none has succeeded yet.</summary>
    public CertificateSyncAttempt? LastSuccess => _status.LastSuccess;

    /// <summary>
    /// The consistent attempt and success pair for the sync status endpoint.
    /// Read this once rather than the two properties separately, or a sync
    /// completing between the two reads can pair a stale attempt with a
    /// newer success.
    /// </summary>
    public CertificateSyncStatusSnapshot Status => _status;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Certificate sync service started (interval: {Interval} minutes)",
            _syncInterval.TotalMinutes);

        // Initial sync after a short delay to let the app start up
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SyncCertificatesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Certificate sync failed");
            }

            try
            {
                // Wake on the interval or on a trigger fire (manual sync from
                // the API, or the debounced nudge after an ACME issuance),
                // whichever comes first.
                await _trigger.WaitAsync(_syncInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("Certificate sync service stopped");
    }

    /// <summary>
    /// Performs a full sync of the certificate inventory from ADCS.
    /// Queries the CA once per disposition, pulling the whole disposition in a
    /// single view enumeration and paging it in memory for the batched database
    /// writes. Revoked certificates are synced explicitly so that a certificate
    /// revoked on the CA has its local status updated on the next cycle. Relying
    /// on the default query would only ever return issued rows, and the dashboard
    /// would keep showing a stale "Issued" status forever after a revocation.
    /// Pending, denied, and failed requests are synced too, bounded to
    /// <see cref="CertusOptions.RequestHistoryDays"/>, so the detail page can
    /// show the CA's own explanation of why a request is stuck. Those rows carry
    /// no certificate and are hidden from the default certificate list; the
    /// status filter is how an admin reaches them.
    /// </summary>
    public async Task<CertificateSyncResult> SyncCertificatesAsync(CancellationToken cancellationToken)
    {
        await _syncGate.WaitAsync(cancellationToken);
        try
        {
            var result = await SyncCertificatesCoreAsync(cancellationToken);
            var attempt = new CertificateSyncAttempt(
                DateTime.UtcNow, CertificateSyncOutcome.Success, Message: null, Result: result);
            _status = new CertificateSyncStatusSnapshot(attempt, attempt);
            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A cancelled sync (service shutdown, client disconnect) is not an
            // outcome the operator should see. Everything else is recorded and
            // rethrown so the manual sync endpoint can map it. The previous
            // success is carried forward into the new snapshot.
            var attempt = new CertificateSyncAttempt(
                DateTime.UtcNow,
                ex switch
                {
                    CaUnavailableException => CertificateSyncOutcome.CaUnavailable,
                    CaAccessDeniedException => CertificateSyncOutcome.CaAccessDenied,
                    _ => CertificateSyncOutcome.Failed,
                },
                ex.Message,
                Result: null);
            _status = new CertificateSyncStatusSnapshot(attempt, _status.LastSuccess);
            throw;
        }
        finally
        {
            _syncGate.Release();
        }
    }

    private async Task<CertificateSyncResult> SyncCertificatesCoreAsync(CancellationToken cancellationToken)
    {
        _logger.LogDebug("Starting certificate sync from ADCS CA");

        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var totalSynced = 0;
        var totalCreated = 0;
        var totalUpdated = 0;
        const int batchSize = 100;

        // The CA view has no single "all dispositions" mode, so each disposition
        // is its own pass. A row has one disposition, so a request appears in
        // exactly one pass.
        //
        // Issued and revoked are the certificate inventory and are pulled in
        // full. Pending, denied, and failed are requests that carry no
        // certificate; they are pulled so the dashboard can show the CA's own
        // explanation of why a request is stuck (issue #151), but bounded to a
        // recent window, because those three tables grow without limit on a busy
        // CA. A window of zero or less turns the three passes off entirely.
        //
        // The window bounds different columns for different passes (issue
        // #187). Pending is bounded by SubmittedWhen, the only timestamp an
        // undecided request has. Denied and failed are bounded by ResolvedWhen,
        // when the CA decided: a request submitted before the window and denied
        // inside it must still be picked up, or its local row keeps saying
        // Pending forever after the CA refused it. Bounding those two by
        // SubmittedWhen was exactly that bug.
        var passes = new List<(CertificateStatus Status, DateTime? SubmittedAfter, DateTime? ResolvedAfter)>
        {
            (CertificateStatus.Issued, null, null),
            (CertificateStatus.Revoked, null, null)
        };

        if (_requestHistoryDays > 0)
        {
            var windowStart = DateTime.UtcNow.AddDays(-_requestHistoryDays);
            passes.Add((CertificateStatus.Pending, windowStart, null));
            passes.Add((CertificateStatus.Denied, null, windowStart));
            passes.Add((CertificateStatus.Failed, null, windowStart));
        }

        // Rows with no usable subject, for either of two reasons: the CA handed
        // back nothing anywhere (a SAN only certificate with a missing
        // RawCertificate blob), or what it handed back sanitized away to nothing
        // because it was entirely control or format characters. The backfill does
        // not care which, so both routes land in the same list. Resolved after the
        // disposition passes from the certificates this proxy issued itself.
        //
        // Request ids rather than tracked entities (issue #184). The loop below no
        // longer loads every row it sees, and it clears the change tracker between
        // batches, so an entity reference captured here would be detached by the
        // time the backfill ran and its writes would go nowhere. Nothing is lost:
        // a row with no subject can never be in the skip set, so it is always
        // either created or loaded on the path that can name it.
        var emptySubjectRequestIds = new List<int>();

        // Request ids whose stored row already holds everything a parse of the
        // certificate's DER would produce, so the client can skip that parse
        // (issue #184). Read once for the whole cycle rather than per pass: a row
        // carries one disposition and so appears in exactly one pass, and a row
        // created during this cycle is absent from the set and therefore parsed,
        // which is the answer we want for it.
        var alreadyDetailed = await ReadAlreadyDetailedAsync(db, cancellationToken);

        // Taken before the first CA query, and load bearing for the stamp repair
        // after the passes. It is the instant everything this cycle learns from
        // the CA is no older than, so it separates what the CA has told us now
        // from what we believed before asking. See
        // ClearReleasedRevocationStampsAsync.
        var passesStartedAt = DateTime.UtcNow;

        foreach (var (status, submittedAfter, resolvedAfter) in passes)
        {
            // ICertView exposes no server-side row offset and QueryCertificatesAsync
            // re-opens the view on every call, so paging the CA with a growing Skip
            // would re-read the view from the top each batch (O(N^2) COM dispatches).
            // Pull the whole disposition in a single enumeration, then page it in
            // memory for the batched database writes.
            var query = new CertificateQuery(
                Status: status,
                Take: int.MaxValue,
                SubmittedAfter: submittedAfter,
                ResolvedAfter: resolvedAfter,
                AlreadyDetailed: alreadyDetailed);

            IReadOnlyList<CertificateInfo> certs;
            try
            {
                certs = await _adcsClient.QueryCertificatesAsync(query, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException
                and not CaUnavailableException
                and not CaAccessDeniedException)
            {
                // One disposition failing must not cost the others. The three
                // request passes lean on a time restriction (SubmittedWhen for
                // pending, ResolvedWhen for denied and failed) combined with
                // the Disposition one. The AdcsQiProbe run on the lab CA
                // (2026-08-04) proved both pairs apply together there, but
                // another CA build refusing one still must not take the
                // certificate inventory down with it. A CA that is down or
                // denying view access is different: it fails every pass the
                // same way, so those two typed exceptions propagate to the
                // caller, which records the outcome and lets the manual sync
                // endpoint return its 503 (issue #157).
                _logger.LogError(ex,
                    "Certificate sync pass for the {Status} disposition failed; continuing with the remaining passes",
                    status);
                continue;
            }

            foreach (var batch in certs.Chunk(batchSize))
            {
                cancellationToken.ThrowIfCancellationRequested();

                // One projected read for the whole batch, replacing a
                // FirstOrDefaultAsync per row (issue #184). Every column
                // UpdateEntity can write except the certificate blob itself,
                // which is present only as a "is it there" flag: the blob is the
                // expensive part of the row and its sole use in the update is the
                // write once test, so nothing needs the bytes.
                var wanted = batch.Select(c => c.RequestId).ToList();
                var stored = (await db.SyncedCertificates
                        .Where(s => wanted.Contains(s.RequestId))
                        .Select(s => new StoredRowState(
                            s.RequestId,
                            s.SerialNumber,
                            s.Subject,
                            s.SubjectAlternativeNames,
                            s.TemplateName,
                            s.NotBefore,
                            s.NotAfter,
                            s.Status,
                            s.Requestor,
                            s.RequestDate,
                            s.RevokedAt,
                            s.RevokedReason,
                            s.KeyAlgorithm,
                            s.KeySizeBits,
                            s.SignatureAlgorithmOid,
                            s.Sha256Thumbprint,
                            s.ExtendedKeyUsageOids,
                            s.KeyUsage,
                            s.RawCertificate != null,
                            s.DispositionMessage,
                            s.StatusCode))
                        .ToListAsync(cancellationToken))
                    .ToDictionary(s => s.RequestId);

                // Rows the CA still describes exactly as we stored them. Their
                // only write is LastSyncedAt, so they are never loaded and never
                // tracked; the whole batch's worth goes out as one statement below.
                var unchanged = new List<int>();

                // Rows that genuinely moved. Loaded tracked, blob and all, because
                // UpdateEntity reads RawCertificate for its write once test and is
                // still the only thing that writes a synced row.
                var changed = new List<CertificateInfo>();

                foreach (var cert in batch)
                {
                    if (!stored.TryGetValue(cert.RequestId, out var state))
                    {
                        var entity = MapToEntity(cert);
                        db.SyncedCertificates.Add(entity);
                        if (string.IsNullOrWhiteSpace(entity.Subject))
                            emptySubjectRequestIds.Add(entity.RequestId);
                        totalCreated++;
                    }
                    else
                    {
                        if (IsUnchanged(state, cert))
                        {
                            unchanged.Add(cert.RequestId);
                            // Decided from the projection, because an unchanged
                            // row is never loaded. A stored subject that is still
                            // blank is exactly the row the ACME backfill exists
                            // for, and it stays blank cycle after cycle until
                            // some later order names it.
                            if (string.IsNullOrWhiteSpace(state.Subject))
                                emptySubjectRequestIds.Add(cert.RequestId);
                        }
                        else
                        {
                            changed.Add(cert);
                        }

                        // Counted the same way it always has been: every row the
                        // CA handed back for a row we already had. The manual sync
                        // endpoint reports this to an operator as "updated", which
                        // has always meant seen rather than altered, and pairs with
                        // LastSyncedAt meaning when we last saw the row.
                        totalUpdated++;
                    }

                    totalSynced++;
                }

                if (changed.Count > 0)
                {
                    var changedIds = changed.Select(c => c.RequestId).ToList();
                    var entities = await db.SyncedCertificates
                        .Where(s => changedIds.Contains(s.RequestId))
                        .ToDictionaryAsync(s => s.RequestId, cancellationToken);

                    foreach (var cert in changed)
                    {
                        // A row read into the projection a moment ago and gone now
                        // cannot happen (nothing deletes a SyncedCertificate), but
                        // the lookup is guarded rather than asserted so a future
                        // sweep that does delete costs a skipped update, not a
                        // faulted sync.
                        if (!entities.TryGetValue(cert.RequestId, out var existing))
                            continue;

                        UpdateEntity(existing, cert);
                        if (string.IsNullOrWhiteSpace(existing.Subject))
                            emptySubjectRequestIds.Add(existing.RequestId);
                    }
                }

                await db.SaveChangesAsync(cancellationToken);

                if (unchanged.Count > 0)
                {
                    // The one write an unchanged row still earns. ExecuteUpdate
                    // goes round the change tracker, which normally means the
                    // caller owes a ReloadAsync, but nothing here re-reads these
                    // rows: they were never loaded, the set is disjoint from the
                    // rows SaveChanges just wrote, and the tracker is cleared on
                    // the next line anyway.
                    await db.SyncedCertificates
                        .Where(s => unchanged.Contains(s.RequestId))
                        .ExecuteUpdateAsync(
                            setters => setters.SetProperty(s => s.LastSyncedAt, DateTime.UtcNow),
                            cancellationToken);
                }

                // Detach what this batch touched. Without it the tracker grows to
                // the size of the whole inventory and every SaveChanges rescans
                // all of it, so the change detection cost over a cycle is
                // quadratic in the number of certificates and every loaded blob
                // is held, plus its snapshot, until the cycle ends.
                db.ChangeTracker.Clear();
            }
        }

        // Repair ACME rows still stamped revoked for a certificate the CA has
        // since released from hold (issue #375). The inventory heals itself in
        // UpdateEntity above; nothing until now healed the other row.
        //
        // A failure here must not cost the sync, the same stance the
        // supersession relink below takes: the inventory is the product, and the
        // next cycle repeats the whole test from scratch, so one bad pass is self
        // correcting. It is logged at Error rather than swallowed because until
        // it succeeds the certificate keeps answering a renew now window it has
        // grown out of.
        try
        {
            var cleared = await ClearReleasedRevocationStampsAsync(
                db, passesStartedAt, cancellationToken);
            if (cleared > 0)
                _logger.LogInformation(
                    "Cleared the revocation stamp on {Count} ACME certificate(s) the CA has " +
                    "released from hold", cleared);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex,
                "Clearing the revocation stamp on released certificates failed; the inventory " +
                "synced and the stamps are retested on the next cycle");
        }

        // Lazily resolve names the CA could not provide, from the ACME store.
        // No empty rows means no extra queries.
        if (emptySubjectRequestIds.Count > 0)
        {
            var filled = await BackfillSubjectsFromAcmeStoreAsync(
                db, emptySubjectRequestIds, cancellationToken);
            if (filled > 0)
            {
                await db.SaveChangesAsync(cancellationToken);
                _logger.LogInformation(
                    "Backfilled {Count} names from the ACME store", filled);
            }
        }

        // Recompute which certificate replaced which (issue #154). After the
        // subject backfill above, not before: a name resolved this cycle is half
        // the matching key, and a row still nameless here keys to null and so
        // joins no lineage at all until some later cycle names it.
        //
        // A failure here must not cost the sync. The inventory is the product;
        // the supersession link is an annotation on top of it, and the next cycle
        // rebuilds the whole map anyway, so one bad pass is self correcting. Same
        // stance as the per disposition catch above.
        try
        {
            var relinked = await SupersessionLinker.RelinkAsync(db, cancellationToken);
            if (relinked > 0)
            {
                await db.SaveChangesAsync(cancellationToken);
                _logger.LogInformation(
                    "Updated supersession links on {Count} certificate(s)", relinked);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex,
                "Recomputing certificate supersession links failed; the inventory synced and the " +
                "links will be rebuilt on the next cycle");
        }

        _logger.LogInformation(
            "Certificate sync complete: {Total} processed ({Created} new, {Updated} updated)",
            totalSynced, totalCreated, totalUpdated);

        return new CertificateSyncResult(totalSynced, totalCreated, totalUpdated, DateTime.UtcNow);
    }

    /// <summary>
    /// Clears <see cref="AcmeCertificate.RevokedAt"/> on certificates the CA has
    /// released from CertificateHold (issue #375).
    ///
    /// <para>
    /// Revocation was terminal in the ACME half of the data model: every writer
    /// only ever stamps that column, so a certificate revoked with reason 6 and
    /// later released at the CA kept answering a renew now window on
    /// <c>renewalInfo</c> for the rest of its life, and revoke-cert kept refusing
    /// as <c>alreadyRevoked</c>. The inventory row healed on the next sync, in
    /// <see cref="UpdateEntity"/>; nothing healed this one, which
    /// <c>CertificateRevocationService.RecordRevocationAsync</c> said in as many
    /// words.
    /// </para>
    ///
    /// <para>
    /// The stance the repair takes is that <b>only the CA's own record may clear a
    /// stamp, and only a reading of it taken after the stamp was written</b>. That
    /// is sound because the reverse ordering is an invariant of every writer:
    /// <c>OrderService.RecordRevocationAsync</c> and
    /// <c>CertificateRevocationService.RecordRevocationAsync</c> both stamp only
    /// after the CA call has returned, so a stamp implies the CA had already
    /// revoked. A later CA reading that says otherwise can only be a release.
    /// </para>
    ///
    /// <para>
    /// One writer, so both symptoms go together and neither reader needs a rule of
    /// its own to drift from: with the column cleared,
    /// <c>OrderService.ResolveRevocationInstantAsync</c> falls through to the
    /// inventory and reports the certificate live, and the
    /// <c>alreadyRevoked</c> gate in <c>OrderService.RevokeCertificateAsync</c>
    /// lets a fresh revocation reach the CA.
    /// </para>
    ///
    /// <para>
    /// Each term of the predicate is load bearing, and every one of them fails in
    /// the safe direction, because reading a revoked certificate as live is the
    /// costly mistake and reading a live one as revoked is only an early renewal:
    /// </para>
    ///
    /// <list type="bullet">
    /// <item><description>
    /// <c>RevokedAt &lt; passesStartedAt</c> protects a revocation that landed
    /// while this cycle was running. The CA data in hand was fetched before it,
    /// so it cannot be evidence about it.
    /// </description></item>
    /// <item><description>
    /// <c>LastSyncedAt &gt;= passesStartedAt</c> requires the inventory row to
    /// have been seen in <b>this</b> cycle, so a stale row, or one the CA has
    /// stopped returning, can never clear anything. It also makes the repair
    /// self gating: when the issued pass fails, no issued row is restamped and
    /// this matches nothing at all.
    /// </description></item>
    /// <item><description>
    /// <c>Status == Issued</c> is an allow list, not <c>!= Revoked</c>. Pending,
    /// Denied and Failed rows carry no live certificate, and a disposition added
    /// later must not start clearing revocations on its own.
    /// </description></item>
    /// <item><description>
    /// <c>AdcsRequestId &gt; 0</c> is the same identity guard
    /// <c>OrderService.StampInventoryRowAsync</c> applies to the same bridge in
    /// the other direction: an unset key selects by an unset value rather than by
    /// identity, and un-revoking on a guess is not something to do.
    /// </description></item>
    /// </list>
    ///
    /// <para>
    /// Written as one set based statement rather than from a Revoked to Issued
    /// transition spotted in the pass loop. A transition fires once, so a
    /// database whose inventory healed before this repair existed would never be
    /// repaired at all, and the stuck row it left is the one an operator would
    /// actually report.
    /// </para>
    ///
    /// <para>
    /// It costs one statement per cycle. The outer filter is a scan of
    /// <c>AcmeCertificates</c>, which has no index on
    /// <see cref="AcmeCertificate.RevokedAt"/> and does not want one: the table
    /// holds a row per ACME issued certificate, the scan runs once every sync
    /// interval, and the revoked rows it keeps are a small fraction of it. Only
    /// those reach the subquery, which is a point lookup on the unique index over
    /// <see cref="SyncedCertificate.RequestId"/>.
    /// </para>
    /// </summary>
    /// <returns>The number of stamps cleared.</returns>
    private static async Task<int> ClearReleasedRevocationStampsAsync(
        CertusDbContext db, DateTime passesStartedAt, CancellationToken cancellationToken)
    {
        // Hoisted so the comparison is a constant in the expression tree.
        var issued = nameof(CertificateStatus.Issued);

        // ExecuteUpdate goes round the change tracker, which normally leaves the
        // caller owing a ReloadAsync. Nothing here re-reads these rows: the sync
        // never loads an AcmeCertificate, and the tracker was cleared at the end
        // of the last batch.
        return await db.AcmeCertificates
            .Where(a => a.RevokedAt != null
                     && a.RevokedAt < passesStartedAt
                     && a.AdcsRequestId > 0
                     && db.SyncedCertificates.Any(s =>
                            s.RequestId == a.AdcsRequestId
                            && s.Status == issued
                            && s.RevokedAt == null
                            && s.LastSyncedAt >= passesStartedAt))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(a => a.RevokedAt, (DateTime?)null)
                .SetProperty(a => a.RevokedReason, (int?)null),
                cancellationToken);
    }

    /// <summary>
    /// Request ids whose stored row already holds everything a parse of the
    /// certificate's own DER would produce, so the CA client can skip that parse
    /// (issue #184). One projected read of integers: no blob, no tracking.
    ///
    /// The predicate is derived from what the parse actually feeds, not from a
    /// single sentinel, and each term is load bearing:
    ///
    /// RawCertificate is the strictest of the three, because it is the one
    /// written once and never reassigned, and because the crypto columns and this
    /// one arrived in separate migrations four days apart. A database that synced
    /// between them holds crypto detail and a null blob, and the only thing that
    /// ever fills that blob is the write in UpdateEntity. Skipping such a row on
    /// the strength of its crypto columns alone would strand it with no
    /// certificate to download, permanently, with nothing to say why.
    ///
    /// Sha256Thumbprint stands for the crypto block. Every other member of
    /// CertificateCryptoDetail is legitimately null on a perfectly good
    /// certificate (no EKU extension, no key usage extension, an algorithm whose
    /// strength is not a bit count, an empty algorithm OID), so none of them can
    /// tell "not parsed" from "parsed, nothing to record". The thumbprint is null
    /// only when the certificate did not decode at all.
    ///
    /// A blank Subject keeps a row out of the set because the parsed subject is
    /// the last link in the fallback chain that fills it. It also means every row
    /// the ACME backfill cares about stays on the path that loads it. Comparing
    /// against the empty string rather than testing for whitespace is exact here,
    /// and not merely what translates to SQL: the column is declared required, and
    /// every writer that can reach it goes through CertificateTextSanitizer, which
    /// trims and answers null for a value that is nothing but whitespace. So the
    /// stored value is either empty or genuinely a name.
    ///
    /// SubjectAlternativeNames is deliberately absent. Null is an ordinary answer
    /// for a certificate with no SAN extension, or one whose names are of a kind
    /// the stored "dns:"/"ip:" format does not spell, such as a device leaf
    /// carrying only a PermanentIdentifier. Requiring it would exclude those rows
    /// from the skip for ever; omitting it costs nothing, because the write is
    /// guarded on null and a skipped pass therefore cannot blank the column.
    /// </summary>
    private static async Task<IReadOnlySet<int>> ReadAlreadyDetailedAsync(
        CertusDbContext db, CancellationToken ct)
    {
        var ids = await db.SyncedCertificates
            .Where(c => c.RawCertificate != null
                     && c.Sha256Thumbprint != null
                     && c.Subject != "")
            .Select(c => c.RequestId)
            .ToListAsync(ct);
        return ids.ToHashSet();
    }

    private static SyncedCertificate MapToEntity(CertificateInfo cert)
    {
        return new SyncedCertificate
        {
            RequestId = cert.RequestId,
            SerialNumber = cert.SerialNumber,
            // Sanitized here as well as in the client that produced it. The
            // sanitizer is idempotent, so this costs nothing on a value that
            // already went through AdcsClient, and it is what makes the guard
            // hold for every IAdcsClient rather than only the real one:
            // MockAdcsClient signs the CSR subject verbatim (issue #224).
            Subject = CertificateTextSanitizer.SanitizeSubject(cert.Subject) ?? "",
            SubjectAlternativeNames = cert.SubjectAlternativeNames,
            // Sanitized at the writer for the same reason the subject above is,
            // and it is the same guard: the CA authors this and the real client
            // strips it, but doing it here is what makes the guard hold for every
            // IAdcsClient rather than only that one (issue #378).
            TemplateName = CertificateTextSanitizer.SanitizeTemplateName(cert.TemplateName) ?? "",
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Status = cert.Status.ToString(),
            Requestor = cert.Requestor,
            RequestDate = cert.RequestDate,
            RevokedAt = cert.RevokedWhen,
            RevokedReason = cert.RevokedReason,
            KeyAlgorithm = cert.CryptoDetail?.KeyAlgorithm,
            KeySizeBits = cert.CryptoDetail?.KeySizeBits,
            SignatureAlgorithmOid = cert.CryptoDetail?.SignatureAlgorithmOid,
            Sha256Thumbprint = cert.CryptoDetail?.Sha256Thumbprint,
            ExtendedKeyUsageOids = cert.CryptoDetail?.ExtendedKeyUsageOids,
            KeyUsage = cert.CryptoDetail?.KeyUsage,
            RawCertificate = cert.RawCertificate,
            DispositionMessage = cert.DispositionMessage,
            StatusCode = cert.StatusCode,
            FirstSyncedAt = DateTime.UtcNow,
            LastSyncedAt = DateTime.UtcNow
        };
    }

    private static void UpdateEntity(SyncedCertificate entity, CertificateInfo cert)
    {
        entity.SerialNumber = cert.SerialNumber;
        // A certificate's subject and SANs never legitimately change. A pass
        // that returns them empty (a revoked row the CA hands back without a
        // RawCertificate blob) must not blank a name we already synced.
        //
        // The emptiness is tested on the sanitized value, not the raw one. A
        // subject that is nothing but control or format characters sanitizes away
        // to null, and treating that as a name would write an empty string over a
        // good one. It does mean such a row keeps whatever it already held, which
        // is why DatabaseInitializer sweeps the stored values once at startup.
        var subject = CertificateTextSanitizer.SanitizeSubject(cert.Subject);
        if (!string.IsNullOrWhiteSpace(subject))
            entity.Subject = subject;
        if (cert.SubjectAlternativeNames != null)
            entity.SubjectAlternativeNames = cert.SubjectAlternativeNames;
        // Unconditional, unlike the subject above, because there is no fallback
        // chain to protect: a blank template is the CA saying it recorded none,
        // not a pass that had nothing to say, so keeping a previous value would
        // be inventing one.
        entity.TemplateName = CertificateTextSanitizer.SanitizeTemplateName(cert.TemplateName) ?? "";
        entity.NotBefore = cert.NotBefore;
        entity.NotAfter = cert.NotAfter;
        entity.Status = cert.Status.ToString();
        entity.Requestor = cert.Requestor;
        entity.RequestDate = cert.RequestDate;
        // Straight overwrite on purpose: a certificate released from
        // CertificateHold reappears in the Issued pass with null revocation
        // values, which correctly clears these fields.
        entity.RevokedAt = cert.RevokedWhen;
        entity.RevokedReason = cert.RevokedReason;
        // Same guard as the subject and SANs above, for the same reason. A
        // certificate's cryptographic detail never legitimately changes, and the
        // revoked pass can hand back a row with no RawCertificate blob, which
        // parses to no detail at all. Overwriting unconditionally would blank
        // the fields the issued pass captured the moment a certificate is
        // revoked. Null here means "this pass had nothing to say", not "empty".
        if (cert.CryptoDetail != null)
        {
            entity.KeyAlgorithm = cert.CryptoDetail.KeyAlgorithm;
            entity.KeySizeBits = cert.CryptoDetail.KeySizeBits;
            entity.SignatureAlgorithmOid = cert.CryptoDetail.SignatureAlgorithmOid;
            entity.Sha256Thumbprint = cert.CryptoDetail.Sha256Thumbprint;
            entity.ExtendedKeyUsageOids = cert.CryptoDetail.ExtendedKeyUsageOids;
            entity.KeyUsage = cert.CryptoDetail.KeyUsage;
        }
        // The certificate's own bytes are written once and never reassigned,
        // which is stricter than the guard above and deliberately so. It carries
        // the same "a null pass has nothing to say" rule, and adds two things.
        // Rows synced before this column existed are backfilled by the first
        // pass that carries a blob, at no cost. And because every pass decodes a
        // fresh array from base64, reassigning would hand the change tracker a
        // new byte[] instance for every certificate on every cycle, which risks
        // an UPDATE across the whole table on a sync that changed nothing.
        if (entity.RawCertificate == null && cert.RawCertificate != null)
            entity.RawCertificate = cert.RawCertificate;
        // The CA's explanation is cleared by the disposition, not by a null. A
        // request approved after pending reappears in the Issued pass with both
        // values null and must lose its "waiting for CA manager approval" text,
        // so those dispositions overwrite straight. On a request disposition a
        // null means the column was unreadable this pass, which is survivable by
        // design (see the column guard in AdcsClient), and overwriting then would
        // erase an explanation an earlier healthy pass had already captured.
        var carriesExplanation = cert.Status is CertificateStatus.Pending
            or CertificateStatus.Denied
            or CertificateStatus.Failed;

        if (!carriesExplanation || cert.DispositionMessage != null)
            entity.DispositionMessage = cert.DispositionMessage;
        if (!carriesExplanation || cert.StatusCode != null)
            entity.StatusCode = cert.StatusCode;
        entity.LastSyncedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Every column <see cref="UpdateEntity"/> can write, read straight out of
    /// the database without the certificate blob. RawCertificate is present only
    /// as <see cref="HasRawCertificate"/>, because the update reads it for one
    /// thing, the write once test, and the bytes are the expensive part of the row.
    /// </summary>
    private sealed record StoredRowState(
        int RequestId,
        string SerialNumber,
        string Subject,
        string? SubjectAlternativeNames,
        string TemplateName,
        DateTime NotBefore,
        DateTime NotAfter,
        string Status,
        string? Requestor,
        DateTime RequestDate,
        DateTime? RevokedAt,
        int? RevokedReason,
        string? KeyAlgorithm,
        int? KeySizeBits,
        string? SignatureAlgorithmOid,
        string? Sha256Thumbprint,
        string? ExtendedKeyUsageOids,
        int? KeyUsage,
        bool HasRawCertificate,
        string? DispositionMessage,
        int? StatusCode);

    /// <summary>
    /// Whether <see cref="UpdateEntity"/> would change nothing but LastSyncedAt
    /// if it ran against this row with this CA reading. The partner of that method
    /// and deliberately adjacent to it: this is the one place in the product where
    /// the same rules are written twice, so the two move together or not at all.
    ///
    /// The pairing is held by a test rather than by care. CertificateSyncServiceTests
    /// varies one mirrored column at a time and asserts a full cycle still writes
    /// it through, so a column added to UpdateEntity and forgotten here fails there
    /// rather than going quietly unsynced. Getting it wrong in this direction is
    /// the dangerous one: a false "unchanged" drops a real update from the CA.
    ///
    /// Each clause below mirrors one write in UpdateEntity, in the same order,
    /// including its guard. Where the write is guarded, "unchanged" means either
    /// the guard refuses the write or the value it would write is already there.
    /// </summary>
    private static bool IsUnchanged(StoredRowState state, CertificateInfo cert)
    {
        if (state.SerialNumber != cert.SerialNumber)
            return false;

        var subject = CertificateTextSanitizer.SanitizeSubject(cert.Subject);
        if (!string.IsNullOrWhiteSpace(subject) && state.Subject != subject)
            return false;

        if (cert.SubjectAlternativeNames != null &&
            state.SubjectAlternativeNames != cert.SubjectAlternativeNames)
            return false;

        // Compared sanitized against sanitized, the way the subject above is.
        // The stored value went through the strip on its way in, so comparing it
        // against a raw incoming one would call every row changed on every cycle
        // and rewrite the whole inventory each time, which is exactly the cost
        // issue #184 removed.
        if (state.TemplateName != (CertificateTextSanitizer.SanitizeTemplateName(cert.TemplateName) ?? "") ||
            state.NotBefore != cert.NotBefore ||
            state.NotAfter != cert.NotAfter ||
            state.Status != cert.Status.ToString() ||
            state.Requestor != cert.Requestor ||
            state.RequestDate != cert.RequestDate ||
            state.RevokedAt != cert.RevokedWhen ||
            state.RevokedReason != cert.RevokedReason)
            return false;

        if (cert.CryptoDetail is { } crypto &&
            (state.KeyAlgorithm != crypto.KeyAlgorithm ||
             state.KeySizeBits != crypto.KeySizeBits ||
             state.SignatureAlgorithmOid != crypto.SignatureAlgorithmOid ||
             state.Sha256Thumbprint != crypto.Sha256Thumbprint ||
             state.ExtendedKeyUsageOids != crypto.ExtendedKeyUsageOids ||
             state.KeyUsage != crypto.KeyUsage))
            return false;

        // The write once column. A row that has no blob and is being handed one
        // has changed, however identical everything else is; a row that has one
        // is never handed another.
        if (!state.HasRawCertificate && cert.RawCertificate != null)
            return false;

        var carriesExplanation = cert.Status is CertificateStatus.Pending
            or CertificateStatus.Denied
            or CertificateStatus.Failed;

        if ((!carriesExplanation || cert.DispositionMessage != null) &&
            state.DispositionMessage != cert.DispositionMessage)
            return false;

        if ((!carriesExplanation || cert.StatusCode != null) &&
            state.StatusCode != cert.StatusCode)
            return false;

        return true;
    }

    /// <summary>
    /// Resolves display names for synced rows whose subject is empty, from what
    /// this proxy already knows about the requests it submitted itself. Two
    /// disjoint lookups, because a row reaches this point for one of two
    /// unrelated reasons: it is a certificate the CA handed back without a
    /// usable subject anywhere, or it is a request that never became a
    /// certificate at all. Mutates the tracked entities and returns how many
    /// were filled; the caller saves.
    ///
    /// Takes request ids and loads the rows itself rather than being handed
    /// entities the disposition passes tracked (issue #184). Those passes no
    /// longer keep every row attached, so a reference captured there would be
    /// detached by now and the writes below would be dropped silently.
    /// </summary>
    private static async Task<int> BackfillSubjectsFromAcmeStoreAsync(
        CertusDbContext db, List<int> emptyRequestIds, CancellationToken ct)
    {
        // Chunked for the same reason SupersessionLinker chunks: EF turns a
        // Contains over a list into one parameter per element and SQLite's older
        // default ceiling is 999. A first sync over an inventory the CA cannot
        // name is the run that reaches those numbers.
        var emptyRows = new List<SyncedCertificate>(emptyRequestIds.Count);
        foreach (var chunk in emptyRequestIds.Distinct().Chunk(BackfillChunkSize))
        {
            emptyRows.AddRange(await db.SyncedCertificates
                .Where(s => chunk.Contains(s.RequestId))
                .ToListAsync(ct));
        }

        if (emptyRows.Count == 0)
            return 0;

        var filled = await BackfillFromIssuedCertificatesAsync(db, emptyRows, ct);
        filled += await BackfillFromPendingOrdersAsync(db, emptyRows, ct);
        return filled;
    }

    /// <summary>
    /// Certificate rows: matched by serial against the certificates this proxy
    /// issued itself. A request row can never match here, because it carries no
    /// certificate and therefore no serial number.
    /// </summary>
    private static async Task<int> BackfillFromIssuedCertificatesAsync(
        CertusDbContext db, List<SyncedCertificate> emptyRows, CancellationToken ct)
    {
        var wanted = emptyRows
            .Where(r => !string.IsNullOrWhiteSpace(r.SerialNumber))
            .GroupBy(r => SerialNumbers.Normalize(r.SerialNumber))
            .Where(g => g.Key.Length > 0)
            .ToDictionary(g => g.Key, g => g.ToList());
        if (wanted.Count == 0)
            return 0;

        // Two steps: serials first (cheap strings, matched in memory because
        // the normalization does not translate to SQL), then the PEM and
        // order identifiers for the matches only.
        var candidates = await db.AcmeCertificates
            .Select(a => new { a.Id, a.SerialNumber })
            .ToListAsync(ct);
        var matchIds = candidates
            .Where(c => !string.IsNullOrEmpty(c.SerialNumber)
                        && wanted.ContainsKey(SerialNumbers.Normalize(c.SerialNumber)))
            .Select(c => c.Id)
            .ToList();
        if (matchIds.Count == 0)
            return 0;

        var rows = await db.AcmeCertificates
            .Where(a => matchIds.Contains(a.Id))
            .Select(a => new { a.SerialNumber, a.CertificatePem, a.Order.IdentifiersJson })
            .ToListAsync(ct);

        var filled = 0;
        foreach (var row in rows)
        {
            // Sanitized like every other subject source. The PEM subject is
            // X509Certificate2.Subject over a leaf this proxy issued, which is
            // narrower than an arbitrary CA row but still unbounded against the
            // 500 character column.
            var name = CertificateTextSanitizer.SanitizeSubject(
                SubjectFromPem(row.CertificatePem) ?? FirstIdentifier(row.IdentifiersJson));
            if (string.IsNullOrWhiteSpace(name))
                continue;
            foreach (var target in wanted[SerialNumbers.Normalize(row.SerialNumber)])
            {
                if (string.IsNullOrWhiteSpace(target.Subject))
                {
                    target.Subject = name;
                    filled++;
                }
            }
        }
        return filled;
    }

    /// <summary>
    /// Request rows: pending, denied, and failed rows come from the CA's request
    /// table and carry no certificate, so the serial match above can never reach
    /// them, and the CA's own request subject columns are empty whenever the CSR
    /// carried no subject DN. That is the normal shape of an ACME CSR, so
    /// without this the product's own issuance path is exactly the one that
    /// leaves a stuck request identifiable only by its number.
    ///
    /// An ACME order records the CA request ID it was submitted under, on the
    /// pending branch and the denied branch alike (see OrderService), so the
    /// order is reachable from the synced row and its identifiers are the name.
    /// The identifiers are used rather than the order's stored CSR because they
    /// are names this server itself validated and authorized for that order; the
    /// CSR is requester input and would have to be sanitized before it could be
    /// shown. A device attestation order is covered by the same lookup:
    /// its first identifier is the permanent-identifier value, which is the
    /// device serial and the right thing to show.
    /// </summary>
    private static async Task<int> BackfillFromPendingOrdersAsync(
        CertusDbContext db, List<SyncedCertificate> emptyRows, CancellationToken ct)
    {
        var wanted = emptyRows
            .Where(r => string.IsNullOrWhiteSpace(r.SerialNumber) && r.RequestId > 0)
            .GroupBy(r => r.RequestId)
            .ToDictionary(g => g.Key, g => g.ToList());
        if (wanted.Count == 0)
            return 0;

        // One query for the whole batch. AdcsRequestId is nullable because an
        // order only acquires one once it reaches ADCS, and an order that never
        // got that far has no request row to name.
        var requestIds = wanted.Keys.ToList();
        var orders = await db.AcmeOrders
            .Where(o => o.AdcsRequestId != null && requestIds.Contains(o.AdcsRequestId.Value))
            .Select(o => new { RequestId = o.AdcsRequestId!.Value, o.IdentifiersJson })
            .ToListAsync(ct);

        var filled = 0;
        foreach (var order in orders)
        {
            // Sanitized despite being a name this server validated. Both
            // identifier guards now refuse the deceptive character classes
            // outright (issue #234 brought PermanentIdentifierValue into line
            // with the rest), so this is no longer the only thing standing
            // between a bidirectional override and the Subject column. It stays
            // because it also bounds the value to MaxSubjectLength before the
            // write, and that bound is not optional.
            var name = CertificateTextSanitizer.SanitizeSubject(
                FirstIdentifier(order.IdentifiersJson));
            if (string.IsNullOrWhiteSpace(name))
                continue;
            if (!wanted.TryGetValue(order.RequestId, out var targets))
                continue;
            foreach (var target in targets)
            {
                // Anything the CA itself supplied wins over this local fallback,
                // which is why the emptiness is re-checked per row rather than
                // trusted from when the list was built.
                if (string.IsNullOrWhiteSpace(target.Subject))
                {
                    target.Subject = name;
                    filled++;
                }
            }
        }
        return filled;
    }

    /// <summary>Subject DN of the leaf in a PEM chain, else its first SAN, else null.</summary>
    private static string? SubjectFromPem(string pem)
    {
        try
        {
            // CreateFromPem parses the first certificate in the chain, which
            // is the leaf (RFC 8555 7.4.2 ordering; the revoke endpoint uses
            // the same loader on this column).
            using var leaf = X509Certificate2.CreateFromPem(pem);
            if (!string.IsNullOrWhiteSpace(leaf.Subject))
                return leaf.Subject;
            var san = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            var dns = san?.EnumerateDnsNames().FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(dns))
                return dns;
            return san?.EnumerateIPAddresses().FirstOrDefault()?.ToString();
        }
        catch (CryptographicException)
        {
            return null; // Unreadable stored PEM: fall through to the order identifiers.
        }
    }

    /// <summary>First identifier value from an ACME identifiers JSON array, or null.</summary>
    private static string? FirstIdentifier(string identifiersJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(identifiersJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
                return doc.RootElement[0].TryGetProperty("value", out var v) ? v.GetString() : null;
        }
        catch (JsonException)
        {
            // Malformed identifiers JSON: nothing to offer.
        }
        return null;
    }
}

/// <summary>
/// Outcome of one full certificate sync, returned to the manual sync endpoint.
/// </summary>
public sealed record CertificateSyncResult(
    [property: JsonPropertyName("processed")] int Processed,
    [property: JsonPropertyName("created")] int Created,
    [property: JsonPropertyName("updated")] int Updated,
    [property: JsonPropertyName("completedAtUtc")] DateTime CompletedAtUtc);

/// <summary>How one full sync attempt ended.</summary>
public enum CertificateSyncOutcome
{
    Success,
    CaUnavailable,
    CaAccessDenied,
    Failed,
}

/// <summary>
/// One recorded sync attempt, held in memory by <see cref="CertificateSyncService"/>
/// for the sync status endpoint. Result is non null only on success.
/// </summary>
public sealed record CertificateSyncAttempt(
    DateTime AttemptedAtUtc,
    CertificateSyncOutcome Outcome,
    string? Message,
    CertificateSyncResult? Result);

/// <summary>
/// The most recent sync attempt and the most recent success, swapped in as
/// one unit so no reader can observe a mismatched pair.
/// </summary>
public sealed record CertificateSyncStatusSnapshot(
    CertificateSyncAttempt? LastAttempt,
    CertificateSyncAttempt? LastSuccess);
