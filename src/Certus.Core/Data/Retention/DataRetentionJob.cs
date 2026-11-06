using System.Security.Cryptography.X509Certificates;
using Certus.Core.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Data.Retention;

/// <summary>
/// One pass of the retention rule (issue #637, CRA risk R18): removes the rows
/// whose period under <see cref="RetentionOptions"/> has run out, in bounded
/// batches, and reports the counts. <see cref="DataRetentionService"/> runs it
/// once a day; the tests drive it directly on an in memory database.
///
/// <para><b>What each class means.</b></para>
/// <list type="bullet">
/// <item>
/// <description><b>Finished orders.</b> An order is finished when it reached
/// <c>valid</c> or <c>invalid</c>; nothing in this schema writes any other
/// terminal status. The schema records no finishing instant, so the pass
/// measures from the facts it has, both of which bound the real instant from
/// above: a valid order finished when its certificate was stored
/// (<c>AcmeCertificate.IssuedAt</c>), and an invalid order finished no later
/// than its own expiry (<c>ExpiresAt</c>, seven days after creation), because
/// every demoter runs before expiry and the pending issuance sweep abandons an
/// order within one tick of it. Measuring from an upper bound never removes
/// anything early; it can keep an invalid order up to a week longer than the
/// period says.</description>
/// </item>
/// <item>
/// <description><b>A valid order's own row and its certificate record stay
/// while the certificate is live.</b> Renewal information (ARI), the
/// <c>replaces</c> field on a renewal order and ACME revoke-cert all find the
/// certificate through <c>AcmeCertificates</c>, and that row hangs off the
/// order. Removing a valid order at 90 days would refuse the renewal of every
/// year long certificate that names it in <c>replaces</c>, and leave a
/// compromised certificate unrevokable over ACME. So at the period the pass
/// removes the order's authorizations and challenges, which is where the
/// identifiers, tokens and attestation objects live, and removes the order and
/// its certificate record only once the certificate has been expired for the
/// same period. The expiry is read from the stored PEM, since the row carries
/// none; a certificate that cannot be parsed is kept and counted.</description>
/// </item>
/// <item>
/// <description><b>Deactivated accounts.</b> Deactivation is the last write an
/// account takes, so <c>UpdatedAt</c> is its instant. At the period the pass
/// removes the contact addresses, and deletes the row once the order rule has
/// removed the account's last order, so an account's issuance records are never
/// pulled out from under a live certificate by the account rule.</description>
/// </item>
/// <item>
/// <description><b>Alert history.</b> The three alert tables, by the instant
/// each alert was sent. The rows also stop a stage being sent twice, and a two
/// year old stage belongs to a certificate, CRL or licence long past.</description>
/// </item>
/// <item>
/// <description><b>The administrator audit trail.</b> Audit rows by the
/// instant of the action and the failed sign in counts by the hour they
/// cover, at <see cref="RetentionOptions.EffectiveAuditTrailDays"/>, which is
/// never under 90 days (issue #634): a shorter configured period is raised to
/// the floor and the pass logs that it did so.</description>
/// </item>
/// <item>
/// <description><b>Never the CA inventory mirror.</b> <c>SyncedCertificates</c>
/// reflects what the CA holds, the sync would recreate any row removed, and the
/// inventory feature exists to show user certificates too.</description>
/// </item>
/// </list>
///
/// <para><b>Batches.</b> Each statement touches at most
/// <see cref="RetentionOptions.EffectiveBatchSize"/> rows, so no single write
/// holds the database long enough for ACME traffic or the dashboard to notice,
/// and the pass loops until a class has no more rows due. The deletes under one
/// order batch run in one transaction, so a crash mid batch leaves whole orders
/// rather than parents without children.</para>
/// </summary>
public sealed class DataRetentionJob
{
    /// <summary>
    /// The most batches one step may run in a pass. A step whose rows leave the
    /// due set as they are removed cannot loop for ever, and this cap turns a
    /// future bug that breaks that property into a logged warning instead of a
    /// spinning service. At the default batch size it is 5 million rows a day.
    /// </summary>
    internal const int MaxBatchesPerStep = 10_000;

    private readonly CertusDbContext _db;
    private readonly RetentionOptions _options;
    private readonly ILogger<DataRetentionJob> _logger;
    private readonly TimeProvider _time;

    public DataRetentionJob(
        CertusDbContext db,
        IOptions<RetentionOptions> options,
        ILogger<DataRetentionJob> logger,
        TimeProvider? timeProvider = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Applies every enabled class once and logs the counts. Cancellation
    /// stops between batches; a batch already started completes.
    /// </summary>
    public async Task<DataRetentionReport> RunAsync(CancellationToken cancellationToken = default)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        var report = new DataRetentionReport();

        if (RetentionOptions.IsEnabled(_options.FinishedOrderDays))
            await RemoveFinishedOrdersAsync(now, report, cancellationToken).ConfigureAwait(false);

        if (RetentionOptions.IsEnabled(_options.DeactivatedAccountDays))
            await RemoveDeactivatedAccountsAsync(now, report, cancellationToken).ConfigureAwait(false);

        if (RetentionOptions.IsEnabled(_options.AlertHistoryDays))
            await RemoveAlertHistoryAsync(now, report, cancellationToken).ConfigureAwait(false);

        if (RetentionOptions.IsEnabled(_options.EffectiveAuditTrailDays))
            await RemoveAuditTrailAsync(now, report, cancellationToken).ConfigureAwait(false);

        // One line a day, counts included, whether or not anything was due: an
        // operator reading the log should be able to see the rule ran.
        _logger.LogInformation(
            "Data retention pass finished in {Batches} batch(es): removed {InvalidOrders} invalid order(s), " +
            "{ValidOrders} valid order(s) with expired certificates, {Authorizations} authorization(s), " +
            "{Challenges} challenge(s), {CertificateRecords} certificate record(s); " +
            "removed the contacts of {AccountContacts} deactivated account(s) and deleted {Accounts}; " +
            "removed {Alerts} certificate, {CrlAlerts} CRL and {LicenceAlerts} licence alert history row(s); " +
            "removed {AuditEntries} administrator audit row(s) and {SignInFailures} failed sign in count(s). " +
            "Periods: finished orders {OrderDays} day(s), deactivated accounts {AccountDays} day(s), " +
            "alert history {AlertDays} day(s), audit trail {AuditDays} day(s); 0 means the class is kept for ever.",
            report.Batches, report.InvalidOrdersRemoved, report.ValidOrdersRemoved,
            report.AuthorizationsRemoved, report.ChallengesRemoved, report.CertificateRecordsRemoved,
            report.AccountContactsRemoved, report.AccountsRemoved,
            report.AlertHistoryRemoved, report.CrlAlertHistoryRemoved, report.LicenceAlertHistoryRemoved,
            report.AuditEntriesRemoved, report.SignInFailuresRemoved,
            _options.FinishedOrderDays, _options.DeactivatedAccountDays, _options.AlertHistoryDays,
            _options.EffectiveAuditTrailDays);

        if (report.UnreadableCertificates > 0)
        {
            _logger.LogWarning(
                "Data retention kept {Count} valid order(s) whose stored certificate could not be parsed, " +
                "so its expiry is unknown. They are checked again on the next pass.",
                report.UnreadableCertificates);
        }

        return report;
    }

    // ---- Finished orders ----

    private async Task RemoveFinishedOrdersAsync(
        DateTime now, DataRetentionReport report, CancellationToken ct)
    {
        var cutoff = now.AddDays(-_options.FinishedOrderDays);

        // Invalid orders: the whole order. An invalid order finished no later
        // than its expiry, so expiry before the cutoff means the period has run.
        await ForEachBatchAsync(
            "invalid orders",
            batch => _db.AcmeOrders
                .Where(o => o.Status == "invalid" && o.ExpiresAt < cutoff)
                .OrderBy(o => o.Id)
                .Select(o => o.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                await DeleteOrdersAsync(ids, report, ct).ConfigureAwait(false);
                report.InvalidOrdersRemoved += ids.Count;
            },
            report, ct).ConfigureAwait(false);

        // Valid orders, first half: the authorizations and challenges go at the
        // period, measured from the certificate's storage (or from the order's
        // expiry on the odd valid order with no certificate record). The
        // Authorizations.Any() term is what takes a finished order out of the due
        // set, so the loop ends. The "finished before the cutoff" predicate is
        // written out in both valid order queries rather than shared through a
        // method, because EF cannot translate a call to one.
        await ForEachBatchAsync(
            "valid order authorizations",
            batch => _db.AcmeOrders
                .Where(o => o.Status == "valid"
                    && o.Authorizations.Any()
                    && (_db.AcmeCertificates.Any(c => c.OrderId == o.Id && c.IssuedAt < cutoff)
                        || (!_db.AcmeCertificates.Any(c => c.OrderId == o.Id) && o.ExpiresAt < cutoff)))
                .OrderBy(o => o.Id)
                .Select(o => o.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                await using var tx = await _db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
                await DeleteAuthorizationsOfOrdersAsync(ids, report, ct).ConfigureAwait(false);
                await tx.CommitAsync(ct).ConfigureAwait(false);
            },
            report, ct).ConfigureAwait(false);

        // Valid orders, second half: the order and its certificate record, once
        // the certificate has been expired for the period. The expiry lives only
        // inside the stored PEM, so this pages through the candidates by id and
        // reads each one; the live ones are read again tomorrow, which costs one
        // parse per live certificate per day.
        var lastId = 0;
        var batchSize = _options.EffectiveBatchSize;
        for (var batches = 0; batches < MaxBatchesPerStep; batches++)
        {
            ct.ThrowIfCancellationRequested();

            var page = await _db.AcmeOrders
                .Where(o => o.Status == "valid"
                    && o.Id > lastId
                    && (_db.AcmeCertificates.Any(c => c.OrderId == o.Id && c.IssuedAt < cutoff)
                        || (!_db.AcmeCertificates.Any(c => c.OrderId == o.Id) && o.ExpiresAt < cutoff)))
                .OrderBy(o => o.Id)
                .Select(o => new
                {
                    o.Id,
                    Certificate = _db.AcmeCertificates
                        .Where(c => c.OrderId == o.Id)
                        .Select(c => c.CertificatePem)
                        .FirstOrDefault(),
                })
                .Take(batchSize)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            if (page.Count == 0)
                break;

            lastId = page[^1].Id;
            var due = new List<int>(page.Count);
            foreach (var row in page)
            {
                // No certificate record at all: nothing live hangs off this
                // order, so the order period alone decides.
                if (row.Certificate is null)
                {
                    due.Add(row.Id);
                    continue;
                }

                var notAfter = ReadNotAfter(row.Certificate);
                if (notAfter is null)
                    report.UnreadableCertificates++;
                else if (notAfter.Value < cutoff)
                    due.Add(row.Id);
            }

            if (due.Count > 0)
            {
                await DeleteOrdersAsync(due, report, ct).ConfigureAwait(false);
                report.ValidOrdersRemoved += due.Count;
            }

            report.Batches++;
            if (page.Count < batchSize)
                break;
        }
    }

    /// <summary>
    /// The certificate's expiry on the UTC wall clock, or null when the stored
    /// text is not a certificate this runtime can read. <c>NotAfter</c> comes
    /// back on the local clock, which is why it is converted.
    /// </summary>
    internal static DateTime? ReadNotAfter(string certificatePem)
    {
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            return certificate.NotAfter.ToUniversalTime();
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Deletes whole orders: challenges, authorizations, certificate records
    /// and then the orders, in one transaction. Children go first on purpose,
    /// rather than leaning on the cascade the model declares, so the counts are
    /// real and the result does not depend on the connection's foreign key
    /// pragma.
    /// </summary>
    private async Task DeleteOrdersAsync(List<int> orderIds, DataRetentionReport report, CancellationToken ct)
    {
        await using var tx = await _db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);

        await DeleteAuthorizationsOfOrdersAsync(orderIds, report, ct).ConfigureAwait(false);

        report.CertificateRecordsRemoved += await _db.AcmeCertificates
            .Where(c => orderIds.Contains(c.OrderId))
            .ExecuteDeleteAsync(ct)
            .ConfigureAwait(false);

        await _db.AcmeOrders
            .Where(o => orderIds.Contains(o.Id))
            .ExecuteDeleteAsync(ct)
            .ConfigureAwait(false);

        await tx.CommitAsync(ct).ConfigureAwait(false);
    }

    private async Task DeleteAuthorizationsOfOrdersAsync(
        List<int> orderIds, DataRetentionReport report, CancellationToken ct)
    {
        report.ChallengesRemoved += await _db.AcmeChallenges
            .Where(c => orderIds.Contains(c.Authorization.OrderId))
            .ExecuteDeleteAsync(ct)
            .ConfigureAwait(false);

        report.AuthorizationsRemoved += await _db.AcmeAuthorizations
            .Where(a => orderIds.Contains(a.OrderId))
            .ExecuteDeleteAsync(ct)
            .ConfigureAwait(false);
    }

    // ---- Deactivated accounts ----

    private async Task RemoveDeactivatedAccountsAsync(
        DateTime now, DataRetentionReport report, CancellationToken ct)
    {
        var cutoff = now.AddDays(-_options.DeactivatedAccountDays);

        // The contact addresses first, whether or not the row can go yet: the
        // period is about the personal data, and an account holding a two year
        // certificate keeps its row for as long as the order rule needs it.
        await ForEachBatchAsync(
            "deactivated account contacts",
            batch => _db.AcmeAccounts
                .Where(a => a.Status == "deactivated"
                    && a.ContactJson != null
                    && (a.UpdatedAt ?? a.CreatedAt) < cutoff)
                .OrderBy(a => a.Id)
                .Select(a => a.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                report.AccountContactsRemoved += await _db.AcmeAccounts
                    .Where(a => ids.Contains(a.Id))
                    .ExecuteUpdateAsync(setters => setters.SetProperty(a => a.ContactJson, (string?)null), ct)
                    .ConfigureAwait(false);
            },
            report, ct).ConfigureAwait(false);

        // Then the rows nothing refers to any more.
        await ForEachBatchAsync(
            "deactivated accounts",
            batch => _db.AcmeAccounts
                .Where(a => a.Status == "deactivated"
                    && (a.UpdatedAt ?? a.CreatedAt) < cutoff
                    && !_db.AcmeOrders.Any(o => o.AccountId == a.Id))
                .OrderBy(a => a.Id)
                .Select(a => a.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                report.AccountsRemoved += await _db.AcmeAccounts
                    .Where(a => ids.Contains(a.Id))
                    .ExecuteDeleteAsync(ct)
                    .ConfigureAwait(false);
            },
            report, ct).ConfigureAwait(false);
    }

    // ---- Alert history ----

    private async Task RemoveAlertHistoryAsync(
        DateTime now, DataRetentionReport report, CancellationToken ct)
    {
        var cutoff = now.AddDays(-_options.AlertHistoryDays);

        await ForEachBatchAsync(
            "certificate alert history",
            batch => _db.AlertsSent
                .Where(a => a.SentAt < cutoff)
                .OrderBy(a => a.Id)
                .Select(a => a.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                report.AlertHistoryRemoved += await _db.AlertsSent
                    .Where(a => ids.Contains(a.Id))
                    .ExecuteDeleteAsync(ct)
                    .ConfigureAwait(false);
            },
            report, ct).ConfigureAwait(false);

        await ForEachBatchAsync(
            "CRL alert history",
            batch => _db.CrlAlertsSent
                .Where(a => a.SentAt < cutoff)
                .OrderBy(a => a.Id)
                .Select(a => a.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                report.CrlAlertHistoryRemoved += await _db.CrlAlertsSent
                    .Where(a => ids.Contains(a.Id))
                    .ExecuteDeleteAsync(ct)
                    .ConfigureAwait(false);
            },
            report, ct).ConfigureAwait(false);

        await ForEachBatchAsync(
            "licence alert history",
            batch => _db.LicenceAlertsSent
                .Where(a => a.SentAt < cutoff)
                .OrderBy(a => a.Id)
                .Select(a => a.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                report.LicenceAlertHistoryRemoved += await _db.LicenceAlertsSent
                    .Where(a => ids.Contains(a.Id))
                    .ExecuteDeleteAsync(ct)
                    .ConfigureAwait(false);
            },
            report, ct).ConfigureAwait(false);
    }

    // ---- The administrator audit trail ----

    private async Task RemoveAuditTrailAsync(
        DateTime now, DataRetentionReport report, CancellationToken ct)
    {
        // The floor is applied, never silently (issue #634): the configured
        // value is named beside the one in force, once per pass.
        if (_options.AuditTrailRaisedToFloor)
        {
            _logger.LogWarning(
                "Certus:Retention:AuditTrailDays is {Configured}, below the floor of {Floor} day(s) the " +
                "administrator audit trail is never kept under; the floor is applied instead.",
                _options.AuditTrailDays, RetentionOptions.AuditTrailFloorDays);
        }

        var cutoff = now.AddDays(-_options.EffectiveAuditTrailDays);

        await ForEachBatchAsync(
            "administrator audit rows",
            batch => _db.AdminAuditEntries
                .Where(e => e.OccurredAt < cutoff)
                .OrderBy(e => e.Id)
                .Select(e => e.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                report.AuditEntriesRemoved += await _db.AdminAuditEntries
                    .Where(e => ids.Contains(e.Id))
                    .ExecuteDeleteAsync(ct)
                    .ConfigureAwait(false);
            },
            report, ct).ConfigureAwait(false);

        // A bucket covers one hour, so a row goes once the whole hour it
        // counts is past the cutoff.
        var bucketCutoff = cutoff.AddHours(-1);
        await ForEachBatchAsync(
            "failed sign in counts",
            batch => _db.AdminSignInFailures
                .Where(f => f.BucketStart < bucketCutoff)
                .OrderBy(f => f.Id)
                .Select(f => f.Id)
                .Take(batch)
                .ToListAsync(ct),
            async ids =>
            {
                report.SignInFailuresRemoved += await _db.AdminSignInFailures
                    .Where(f => ids.Contains(f.Id))
                    .ExecuteDeleteAsync(ct)
                    .ConfigureAwait(false);
            },
            report, ct).ConfigureAwait(false);
    }

    // ---- The batch loop ----

    /// <summary>
    /// Selects the ids due in one batch and acts on them, until a batch comes
    /// back short. Every <paramref name="act"/> must take its rows out of the
    /// due set (delete them, or change the column the selection tests), or the
    /// cap ends the step with a warning.
    /// </summary>
    private async Task ForEachBatchAsync(
        string step,
        Func<int, Task<List<int>>> selectDue,
        Func<List<int>, Task> act,
        DataRetentionReport report,
        CancellationToken ct)
    {
        var batchSize = _options.EffectiveBatchSize;
        for (var batches = 0; batches < MaxBatchesPerStep; batches++)
        {
            ct.ThrowIfCancellationRequested();

            var ids = await selectDue(batchSize).ConfigureAwait(false);
            if (ids.Count == 0)
                return;

            await act(ids).ConfigureAwait(false);
            report.Batches++;

            if (ids.Count < batchSize)
                return;
        }

        _logger.LogWarning(
            "Data retention stopped the {Step} step after {Batches} batches with rows still due; " +
            "the rest waits for the next pass.",
            step, MaxBatchesPerStep);
    }
}
