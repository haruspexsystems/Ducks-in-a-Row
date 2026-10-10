using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Acme.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Crl;

/// <summary>
/// Watches the certificate revocation lists of every CA in the configured CA's
/// chain, and warns before one lapses (issue #447).
///
/// Why this is not part of <see cref="ExpiryMonitorService"/>: it watches a
/// different kind of thing. A leaf expiring breaks one service and is one row in
/// the inventory; a CRL expiring breaks revocation checking for everything its
/// CA ever signed, is not in the inventory at all, and for an offline root is
/// replaced by a person rather than by a timer. The rules
/// (<see cref="CrlAlertRules"/>), the history table and the subject are all
/// different, and the only thing genuinely shared is the delivery channel.
///
/// Three decisions about the pass are worth stating.
///
/// **It runs even when no alert channel is configured.** The leaf monitor
/// returns early in that case, and it is right to: it has nothing else to do.
/// This one also fills the card that shows what it can see, which on a free
/// install with no SMTP is the whole feature.
///
/// **A failure anywhere costs that one thing.** A CA that cannot be reached
/// leaves the distribution point reads running, and an unreachable distribution
/// point leaves the others running, because the copies of a CRL fail
/// independently and the interesting case is exactly when one of them does.
///
/// **What cannot be read is still warned about.** The rules run against the last
/// copy successfully read, flagged as stale in the alert. An unreachable
/// distribution point is not evidence that the CRL behind it was renewed, and
/// going quiet there would turn a network fault into a silent loss of the only
/// warning an estate gets.
/// </summary>
public sealed class CrlMonitorService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly AlertOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<CrlMonitorService> _logger;

    /// <summary>
    /// How long a CA read stays good for. The CA hands over whole CRLs, which on
    /// a busy estate are megabytes of revocation entries, so re-reading hourly
    /// for a CRL that says it will not be replaced for another six days is pure
    /// traffic. Anything overdue, unknown or past its dates is read regardless.
    /// </summary>
    private static readonly TimeSpan MaxCaReadAge = TimeSpan.FromHours(12);

    /// <summary>The source value for a CRL read from the certificate authority itself.</summary>
    public const string CaSource = "ca";

    private const string ScopeIssuing = "issuing";
    private const string ScopeParent = "parent";
    private const string KindBase = "base";
    private const string KindDelta = "delta";

    /// <summary>
    /// The clock is optional and defaults to the real one, the way
    /// <see cref="AlertTestThrottle"/> and <see cref="NonceService"/> take
    /// theirs: neither host registers a TimeProvider, and a test supplies a fake
    /// one directly.
    /// </summary>
    public CrlMonitorService(
        IServiceScopeFactory scopeFactory,
        IOptions<AlertOptions> options,
        ILogger<CrlMonitorService> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Crl.Enabled)
        {
            _logger.LogInformation("CRL monitoring is disabled, so no CRL is being watched.");
            return;
        }

        var interval = TimeSpan.FromMinutes(Math.Max(1, _options.Crl.CheckIntervalMinutes));
        _logger.LogInformation(
            "CRL monitoring started, checking every {Interval} minute(s).", interval.TotalMinutes);

        // The same settling delay the leaf monitor takes, so a service starting
        // up is not reading a CA before it has finished binding everything.
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(30), _timeProvider, stoppingToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // One bad pass must not end the monitor for the life of the
                // service, the same stance the leaf monitor takes.
                _logger.LogError(ex, "The CRL check failed. The next one runs as scheduled.");
            }

            try
            {
                await Task.Delay(interval, _timeProvider, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// One pass: read what the chain says, read every CRL that can be read,
    /// record it, and send whatever the rules say is due. Public so tests drive
    /// it directly rather than through the timer.
    /// </summary>
    public async Task CheckAsync(CancellationToken cancellationToken = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<CertusDbContext>();
        var adcs = services.GetRequiredService<IAdcsClient>();
        var caReader = services.GetRequiredService<ICaCrlReader>();
        var fetcher = services.GetRequiredService<ICrlDistributionPointFetcher>();

        var now = _timeProvider.GetUtcNow();
        var rows = await db.MonitoredCrls.ToListAsync(cancellationToken).ConfigureAwait(false);

        var chain = await ReadChainAsync(adcs, cancellationToken).ConfigureAwait(false);
        try
        {
            if (chain.Count == 0)
            {
                _logger.LogWarning(
                    "The CA chain could not be read, so this CRL check has nothing new to look at. " +
                    "Warnings continue against the {Count} CRL(s) already recorded.", rows.Count);
            }

            var caRead = await ReadCaCrlsAsync(caReader, chain, rows, now, db, cancellationToken)
                .ConfigureAwait(false);

            var targets = BuildTargets(chain, caRead.Snapshot, caRead.Succeeded, rows);
            await ReadDistributionPointsAsync(fetcher, targets, rows, now, db, cancellationToken)
                .ConfigureAwait(false);

            if (chain.Count > 0 && caRead.Succeeded)
                PruneVanishedSources(db, rows, targets);

            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await SendDueAlertsAsync(db, services, now, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach (var certificate in chain)
                certificate.Dispose();
        }
    }

    #region Reading

    private async Task<List<X509Certificate2>> ReadChainAsync(
        IAdcsClient adcs, CancellationToken cancellationToken)
    {
        try
        {
            var der = await adcs.GetCaCertificateChainAsync(cancellationToken).ConfigureAwait(false);
            return [.. der.Select(X509CertificateLoader.LoadCertificate)];
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "The CA certificate chain could not be read.");
            return [];
        }
    }

    /// <summary>
    /// Reads the CA's own CRLs, when there is reason to. Returns the snapshot
    /// and whether the read happened at all, because pruning depends on knowing
    /// the CA's current distribution points and must not run on a guess.
    /// </summary>
    private async Task<(CaCrlSnapshot? Snapshot, bool Succeeded)> ReadCaCrlsAsync(
        ICaCrlReader caReader,
        List<X509Certificate2> chain,
        List<MonitoredCrl> rows,
        DateTimeOffset now,
        CertusDbContext db,
        CancellationToken cancellationToken)
    {
        if (chain.Count == 0)
            return (null, false);

        var caRows = rows.Where(r => r.Source == CaSource).ToList();
        if (!CaReadIsDue(caRows, now))
        {
            _logger.LogDebug(
                "The CA's own CRLs were read recently and are not due for replacement, so the CA is not being asked again.");
            foreach (var row in caRows)
                row.LastCheckedAt = now.UtcDateTime;

            return (CaCrlSnapshot.Empty, false);
        }

        try
        {
            var snapshot = await caReader.ReadAsync(cancellationToken).ConfigureAwait(false);
            foreach (var record in snapshot.Crls)
                RecordCaCrl(db, rows, chain[0], record, now);

            return (snapshot, true);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "The CA's own CRLs could not be read.");
            foreach (var row in caRows)
            {
                row.LastCheckedAt = now.UtcDateTime;
                row.LastError = Truncate(ex.Message, 500);
            }

            return (null, false);
        }
    }

    /// <summary>
    /// Whether to ask the CA at all this pass. Anything unknown, overdue or
    /// stale says yes; a CRL that is current and not due for replacement says no.
    /// </summary>
    private static bool CaReadIsDue(List<MonitoredCrl> caRows, DateTimeOffset now)
    {
        if (caRows.Count == 0)
            return true;

        return caRows.Any(row =>
            row.LastReadAt is null
            || row.NextPublish is null
            || row.NextUpdate is null
            || row.NextPublish <= now.UtcDateTime
            || row.NextUpdate <= now.UtcDateTime
            || now.UtcDateTime - row.LastReadAt.Value > MaxCaReadAge);
    }

    private async Task ReadDistributionPointsAsync(
        ICrlDistributionPointFetcher fetcher,
        List<MonitorTarget> targets,
        List<MonitoredCrl> rows,
        DateTimeOffset now,
        CertusDbContext db,
        CancellationToken cancellationToken)
    {
        foreach (var target in targets)
        {
            foreach (var url in target.Urls)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var stored = SourceKey(url);

                // Whichever row for this source was read most recently carries
                // the validators worth sending. Not keyed on the expected issuer:
                // after a CA key renewal the row is keyed by the new key, and a
                // conditional request that missed its own entity tag would
                // download the whole CRL again every pass.
                var existing = rows
                    .Where(r => r.Scope == target.Scope && r.Source == stored)
                    .OrderByDescending(r => r.LastReadAt ?? DateTime.MinValue)
                    .FirstOrDefault();

                var result = await fetcher
                    .FetchAsync(url, existing?.ETag, ToOffset(existing?.LastModified), cancellationToken)
                    .ConfigureAwait(false);

                if (!result.Ok)
                {
                    MarkSourceFailed(db, rows, target, stored, result.Error, now);
                    continue;
                }

                if (result.NotModified)
                {
                    // The stored facts are still the facts. This is the whole
                    // point of the conditional request.
                    foreach (var row in rows.Where(r => r.Source == stored && r.Scope == target.Scope))
                    {
                        row.LastCheckedAt = now.UtcDateTime;
                        row.LastReadAt = now.UtcDateTime;
                        row.LastError = null;
                    }

                    continue;
                }

                var recorded = false;
                foreach (var der in result.Crls)
                {
                    if (RecordFetchedCrl(db, rows, target, stored, der, result, now))
                        recorded = true;
                }

                if (!recorded)
                {
                    MarkSourceFailed(
                        db, rows, target, stored,
                        "Nothing at this distribution point could be read as a CRL for this CA.", now);
                }
            }
        }
    }

    #endregion

    #region Recording

    private void RecordCaCrl(
        CertusDbContext db,
        List<MonitoredCrl> rows,
        X509Certificate2 caCertificate,
        CaCrlRecord record,
        DateTimeOffset now)
    {
        var issuerKeyId = record.AuthorityKeyIdentifierHex ?? KeyIdentifierOf(caCertificate);
        var kind = record.IsDelta ? KindDelta : KindBase;
        var row = FindOrCreate(db, rows, ScopeIssuing, issuerKeyId, kind, CaSource);

        row.IssuerName = SafeName(caCertificate.Subject);
        row.CrlNumber = record.CrlNumberHex;
        row.InstanceKey = InstanceKeyFor(record.CrlNumberHex, record.ThisUpdate);
        row.ThisUpdate = record.ThisUpdate.UtcDateTime;
        row.NextUpdate = record.NextUpdate?.UtcDateTime;
        row.NextPublish = record.NextPublish?.UtcDateTime;
        row.AutoPublished = CrlAlertRules.IsAutoPublished(
            CrlScope.Issuing, record.ThisUpdate, record.NextUpdate, _options.ThresholdDays);
        row.PublishFlags = record.PublishFlags;

        // Nothing to verify a signature against here, and nothing to gain: the
        // CA handed this over on its own authenticated channel.
        row.SignatureStatus = null;
        row.LastCheckedAt = now.UtcDateTime;
        row.LastReadAt = now.UtcDateTime;
        row.LastError = null;
    }

    /// <summary>
    /// Records one CRL read from a distribution point. Returns false when the
    /// bytes are not a CRL this target should be watching, which is how a
    /// directory entry holding several CRLs, one per CA key, is handled: the
    /// ones for other keys are somebody else's row.
    /// </summary>
    private bool RecordFetchedCrl(
        CertusDbContext db,
        List<MonitoredCrl> rows,
        MonitorTarget target,
        string url,
        byte[] der,
        CrlFetchResult result,
        DateTimeOffset now)
    {
        if (!CrlHeaderReader.TryRead(der, out var header, out var error))
        {
            _logger.LogWarning(
                "What {Url} served could not be read as a CRL: {Error}", url, error);
            return false;
        }

        if (!CrlSignatureVerifier.MatchesIssuer(header!, target.ExpectedIssuer))
        {
            _logger.LogDebug(
                "A CRL at {Url} is issued by {Issuer}, which is not the CA expected there.",
                url, header!.IssuerName);
            return false;
        }

        var signature = CrlSignatureVerifier.Verify(header!, target.ExpectedIssuer);
        if (signature == CrlSignatureResult.Failed)
        {
            // Not recorded at all. A CRL whose signature is wrong is not a CRL
            // this CA published, and recording its dates would let anything that
            // can answer for a distribution point hold off a warning.
            _logger.LogWarning(
                "A CRL at {Url} claims to be from {Issuer} and is not signed by it. Ignored.",
                url, header!.IssuerName);
            return false;
        }

        var issuerKeyId = header!.AuthorityKeyIdentifierHex ?? target.ExpectedIssuerKeyId;
        var kind = header.IsDelta ? KindDelta : KindBase;
        var row = FindOrCreate(db, rows, target.Scope, issuerKeyId, kind, url);

        row.IssuerName = SafeName(header.IssuerName);
        row.CrlNumber = header.CrlNumberHex;
        row.InstanceKey = InstanceKeyFor(header.CrlNumberHex, header.ThisUpdate);
        row.ThisUpdate = header.ThisUpdate.UtcDateTime;
        row.NextUpdate = header.NextUpdate?.UtcDateTime;
        row.NextPublish = header.NextPublish?.UtcDateTime;
        row.AutoPublished = CrlAlertRules.IsAutoPublished(
            target.Scope == ScopeIssuing ? CrlScope.Issuing : CrlScope.Parent,
            header.ThisUpdate,
            header.NextUpdate,
            _options.ThresholdDays);
        row.SignatureStatus = signature switch
        {
            CrlSignatureResult.Verified => "verified",
            CrlSignatureResult.AlgorithmNotSupported => "unsupported",
            CrlSignatureResult.NoPublicKey => "no-key",
            _ => "failed",
        };
        // The row a silent source left behind is keyed by the issuer the chain
        // expected, and the CRL that has now turned up may be signed by a
        // different key of that CA. Without this the URL would appear twice on
        // the card for ever: once with the CRL, once as never read.
        foreach (var placeholder in rows
            .Where(r => r.Scope == target.Scope
                && r.Source == url
                && r.LastReadAt is null
                && !ReferenceEquals(r, row))
            .ToList())
        {
            rows.Remove(placeholder);
            db.MonitoredCrls.Remove(placeholder);
        }

        row.ETag = Truncate(result.ETag, 200);
        row.LastModified = result.LastModified?.UtcDateTime;
        row.LastCheckedAt = now.UtcDateTime;
        row.LastReadAt = now.UtcDateTime;
        row.LastError = null;
        return true;
    }

    private void MarkSourceFailed(
        CertusDbContext db,
        List<MonitoredCrl> rows,
        MonitorTarget target,
        string url,
        string? error,
        DateTimeOffset now)
    {
        var existing = rows
            .Where(r => r.Scope == target.Scope && r.Source == url)
            .ToList();

        if (existing.Count == 0)
        {
            // Nothing has ever been read here, so the row exists to say that the
            // distribution point is named and silent. The expected issuer is
            // what identifies it until a CRL turns up.
            var row = FindOrCreate(db, rows, target.Scope, target.ExpectedIssuerKeyId, KindBase, url);
            row.IssuerName = SafeName(target.ExpectedIssuerName);
            row.LastCheckedAt = now.UtcDateTime;
            row.LastError = Truncate(error, 500);
            return;
        }

        foreach (var row in existing)
        {
            row.LastCheckedAt = now.UtcDateTime;
            row.LastError = Truncate(error, 500);
        }
    }

    private static void PruneVanishedSources(
        CertusDbContext db, List<MonitoredCrl> rows, List<MonitorTarget> targets)
    {
        var live = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var target in targets)
        {
            if (target.Scope == ScopeIssuing)
                live.Add(Key(target.Scope, CaSource));

            foreach (var url in target.Urls)
                live.Add(Key(target.Scope, url));
        }

        // A CA whose distribution points were reconfigured leaves rows behind
        // that nothing publishes any more, and those rows would go on ageing
        // towards an expiry warning about a CRL nobody serves.
        var vanished = rows.Where(r => !live.Contains(Key(r.Scope, r.Source))).ToList();
        foreach (var row in vanished)
        {
            rows.Remove(row);
            db.MonitoredCrls.Remove(row);
        }

        static string Key(string scope, string source) => $"{scope}|{source}";
    }

    #endregion

    #region Alerting

    private async Task SendDueAlertsAsync(
        CertusDbContext db,
        IServiceProvider services,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var observed = await db.MonitoredCrls
            .Where(r => r.InstanceKey != null && r.NextUpdate != null)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        if (observed.Count == 0)
            return;

        var notifiers = services.GetServices<IAlertNotifier>().Where(n => n.IsEnabled).ToList();
        if (notifiers.Count == 0)
        {
            // Nothing is recorded either, which is the point: an install that
            // configures email a week from now should get the warnings it has
            // been missing, not a history saying they were already handled. The
            // card reads the observations above and is unaffected.
            _logger.LogDebug(
                "No alert channel is configured, so CRL state was recorded and nothing was sent.");
            return;
        }

        // One alert per CRL instance, however many places it is served from.
        var groups = observed
            .GroupBy(r => (r.IssuerKeyId, r.Kind, r.InstanceKey))
            .ToList();

        foreach (var group in groups)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var newest = group.OrderByDescending(r => r.LastReadAt ?? DateTime.MinValue).First();
            if (newest.ThisUpdate is null || newest.NextUpdate is null)
                continue;

            var stages = CrlAlertRules.StagesDue(
                now,
                new DateTimeOffset(newest.ThisUpdate.Value, TimeSpan.Zero),
                new DateTimeOffset(newest.NextUpdate.Value, TimeSpan.Zero),
                ToOffset(newest.NextPublish),
                newest.AutoPublished,
                _options.ThresholdDays);

            if (stages.Count == 0)
                continue;

            var alreadySent = await db.CrlAlertsSent
                .Where(a => a.IssuerKeyId == newest.IssuerKeyId
                    && a.Kind == newest.Kind
                    && a.InstanceKey == newest.InstanceKey)
                .Select(a => a.Stage)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);

            var newer = NewerCrlNumber(observed, newest);
            var sources = group.Select(r => r.Source).OrderBy(s => s, StringComparer.Ordinal).ToList();

            foreach (var stage in stages)
            {
                if (alreadySent.Contains(stage))
                    continue;

                await SendAsync(db, notifiers, newest, stage, sources, newer, now, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task SendAsync(
        CertusDbContext db,
        List<IAlertNotifier> notifiers,
        MonitoredCrl row,
        string stage,
        List<string> sources,
        string? newerCrlNumber,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var alert = new CrlAlert(
            stage,
            row.IssuerName,
            row.Kind,
            row.Scope,
            row.NextUpdate!.Value,
            (row.NextUpdate.Value - now.UtcDateTime).TotalHours,
            sources,
            row.CrlNumber,
            newerCrlNumber,
            row.LastReadAt);

        var channels = new List<string>();
        var allSucceeded = true;
        string? lastError = null;

        foreach (var notifier in notifiers)
        {
            var result = await notifier.SendCrlAlertAsync(alert, cancellationToken).ConfigureAwait(false);
            channels.Add(notifier.Channel);

            if (!result.Success)
            {
                allSucceeded = false;
                lastError = result.ErrorMessage;
            }
        }

        _logger.LogInformation(
            "CRL {Stage} warning for {Issuer} ({Kind}, number {Number}), served from {Sources}.",
            stage, row.IssuerName, row.Kind, row.CrlNumber ?? "(none)", string.Join(", ", sources));

        // Recorded whether or not a channel accepted it, which is what the leaf
        // monitor does and for the same reason: a failed delivery is visible in
        // the history, and a warning that repeats every hour because the relay
        // is down is worse than one that was missed once.
        db.CrlAlertsSent.Add(new CrlAlertSent
        {
            IssuerKeyId = row.IssuerKeyId,
            Kind = row.Kind,
            InstanceKey = row.InstanceKey!,
            Stage = stage,
            IssuerName = row.IssuerName,
            NextUpdate = row.NextUpdate,
            SentAt = now.UtcDateTime,
            Channels = Truncate(string.Join(",", channels), 50) ?? string.Empty,
            Success = allSucceeded,
            ErrorMessage = Truncate(lastError, 1000),
        });
    }

    /// <summary>
    /// The number of a newer CRL from the same CA key being served somewhere
    /// else. That is the shape of a renewal that reached one location and not
    /// another, which is the commonest way a root CRL renewal goes wrong, and it
    /// changes the remedy from "publish a CRL" to "copy the one you have".
    /// </summary>
    private static string? NewerCrlNumber(List<MonitoredCrl> observed, MonitoredCrl row)
    {
        if (row.ThisUpdate is null)
            return null;

        return observed
            .Where(r => r.IssuerKeyId == row.IssuerKeyId
                && r.Kind == row.Kind
                && r.InstanceKey != row.InstanceKey
                && r.ThisUpdate > row.ThisUpdate)
            .OrderByDescending(r => r.ThisUpdate)
            .Select(r => r.CrlNumber)
            .FirstOrDefault();
    }

    #endregion

    #region Targets and helpers

    /// <summary>
    /// A CA whose CRL is being watched, and where to read it.
    /// </summary>
    private sealed record MonitorTarget(
        string Scope,
        string ExpectedIssuerKeyId,
        string ExpectedIssuerName,
        X509Certificate2 ExpectedIssuer,
        IReadOnlyList<string> Urls);

    private static List<MonitorTarget> BuildTargets(
        List<X509Certificate2> chain,
        CaCrlSnapshot? snapshot,
        bool caAnswered,
        List<MonitoredCrl> rows)
    {
        var targets = new List<MonitorTarget>();
        if (chain.Count == 0)
            return targets;

        // The configured CA's own CRL, at the URLs it tells its clients to read.
        //
        // Those URLs come from the CA, and the CA is deliberately not asked on
        // most passes, so on those the ones already known are used instead.
        // Without that, the copies published where clients actually read them
        // would be checked once every twelve hours rather than every pass, and a
        // stale copy is precisely what this feature is watching for.
        //
        // The fallback turns on whether the CA answered, never on whether the
        // list came back empty. A CA that has just been reconfigured to publish
        // nowhere answers with an empty list, and treating that as "no answer"
        // would keep reading a location it no longer names and keep it out of
        // the prune below for ever.
        var ownUrls = caAnswered && snapshot is not null
            ? snapshot.DistributionPointUrls
            : rows
                .Where(r => r.Scope == ScopeIssuing && r.Source != CaSource)
                .Select(r => r.Source)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

        targets.Add(new MonitorTarget(
            ScopeIssuing,
            KeyIdentifierOf(chain[0]),
            chain[0].Subject,
            chain[0],
            ownUrls));

        // The CRL covering each certificate in the chain is published by the CA
        // above it, and named on the certificate itself. For a two tier estate
        // that is the offline root's CRL, which is the whole point of the issue.
        for (var i = 0; i < chain.Count - 1; i++)
        {
            var issuer = chain[i + 1];
            var cdp = CdpExtensionReader.ReadFrom(chain[i]);
            if (cdp.Urls.Count == 0)
                continue;

            targets.Add(new MonitorTarget(
                ScopeParent,
                KeyIdentifierOf(issuer),
                issuer.Subject,
                issuer,
                cdp.Urls));
        }

        return targets;
    }

    private static MonitoredCrl FindOrCreate(
        CertusDbContext db,
        List<MonitoredCrl> rows,
        string scope,
        string issuerKeyId,
        string kind,
        string source)
    {
        var existing = rows.FirstOrDefault(r =>
            r.Scope == scope
            && r.IssuerKeyId == issuerKeyId
            && r.Kind == kind
            && r.Source == source);

        if (existing is not null)
            return existing;

        var row = new MonitoredCrl
        {
            Scope = scope,
            IssuerKeyId = issuerKeyId,
            Kind = kind,
            Source = source,
        };

        rows.Add(row);
        db.MonitoredCrls.Add(row);
        return row;
    }

    /// <summary>
    /// The subject key identifier of a CA certificate, which is what its own
    /// CRLs carry as their authority key identifier. Falls back to a hash of the
    /// encoded subject for a certificate that carries no key identifier, so the
    /// row still has a stable key.
    /// </summary>
    internal static string KeyIdentifierOf(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .FirstOrDefault();

        if (extension is not null && !string.IsNullOrEmpty(extension.SubjectKeyIdentifier))
            return extension.SubjectKeyIdentifier.ToUpperInvariant();

        var hash = SHA256.HashData(certificate.SubjectName.RawData);
        return Convert.ToHexString(hash.AsSpan(0, 20));
    }

    /// <summary>
    /// What identifies one publication of a CRL. The CRL number is the right
    /// answer and RFC 5280 requires it; the publication instant is the fallback
    /// for a CA that omits it, and is just as good at telling one publication
    /// from the next.
    /// </summary>
    internal static string InstanceKeyFor(string? crlNumberHex, DateTimeOffset thisUpdate) =>
        string.IsNullOrEmpty(crlNumberHex)
            ? "t" + thisUpdate.UtcTicks.ToString()
            : crlNumberHex;

    private static string SafeName(string? name) =>
        CertificateTextSanitizer.SanitizeSubject(name) ?? "(unknown)";

    /// <summary>
    /// What a source is stored as. Applied before the row is looked up rather
    /// than only when it is created: a URL longer than the column would
    /// otherwise never match its own row again and grow a new one every pass.
    /// </summary>
    private static string SourceKey(string url) => Truncate(url, 512) ?? url;

    private static string? Truncate(string? value, int max) =>
        value is null ? null : value.Length <= max ? value : value[..max];

    private static DateTimeOffset? ToOffset(DateTime? value) =>
        value is null ? null : new DateTimeOffset(value.Value, TimeSpan.Zero);

    #endregion
}
