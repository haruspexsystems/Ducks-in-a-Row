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
        var emptySubjectRows = new List<SyncedCertificate>();

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
                ResolvedAfter: resolvedAfter);

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

                foreach (var cert in batch)
                {
                    var existing = await db.SyncedCertificates
                        .FirstOrDefaultAsync(s => s.RequestId == cert.RequestId, cancellationToken);

                    if (existing == null)
                    {
                        var entity = MapToEntity(cert);
                        db.SyncedCertificates.Add(entity);
                        if (string.IsNullOrWhiteSpace(entity.Subject))
                            emptySubjectRows.Add(entity);
                        totalCreated++;
                    }
                    else
                    {
                        UpdateEntity(existing, cert);
                        if (string.IsNullOrWhiteSpace(existing.Subject))
                            emptySubjectRows.Add(existing);
                        totalUpdated++;
                    }

                    totalSynced++;
                }

                await db.SaveChangesAsync(cancellationToken);
            }
        }

        // Lazily resolve names the CA could not provide, from the ACME store.
        // No empty rows means no extra queries.
        if (emptySubjectRows.Count > 0)
        {
            var filled = await BackfillSubjectsFromAcmeStoreAsync(db, emptySubjectRows, cancellationToken);
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
            TemplateName = cert.TemplateName,
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
        entity.TemplateName = cert.TemplateName;
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
    /// Resolves display names for synced rows whose subject is empty, from what
    /// this proxy already knows about the requests it submitted itself. Two
    /// disjoint lookups, because a row reaches this point for one of two
    /// unrelated reasons: it is a certificate the CA handed back without a
    /// usable subject anywhere, or it is a request that never became a
    /// certificate at all. Mutates the tracked entities and returns how many
    /// were filled; the caller saves.
    /// </summary>
    private static async Task<int> BackfillSubjectsFromAcmeStoreAsync(
        CertusDbContext db, List<SyncedCertificate> emptyRows, CancellationToken ct)
    {
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
            // Sanitized despite being a name this server validated. The dns
            // identifier checks are strict, but a permanent-identifier value only
            // has to clear PermanentIdentifierValue, which refuses control
            // characters and says nothing about the format class the bidirectional
            // overrides live in.
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
