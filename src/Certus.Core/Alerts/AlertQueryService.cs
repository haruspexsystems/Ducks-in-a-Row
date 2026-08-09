using System.Text.Json.Serialization;
using Certus.Core.Data;
using Certus.Core.Setup;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Alerts;

/// <summary>
/// Queries alert history for the dashboard.
/// </summary>
public sealed class AlertQueryService
{
    private readonly CertusDbContext _db;
    private readonly ILogger<AlertQueryService> _logger;
    private readonly AlertOptions _alertOptions;
    private readonly IReadOnlyList<IAlertNotifier> _notifiers;
    private readonly ServerCertificateIdentity _serverCertificate;

    /// <param name="alertOptions">
    /// IOptions, not IOptionsMonitor. ExpiryMonitorService snapshots its options
    /// at construction, so a monitor would let the ladder and the dashboard's
    /// expiry window be computed against thresholds the engine is not actually
    /// using. Every consumer shares this one snapshot, which since issue #161
    /// includes the config endpoint, because AlertsController reads it from here
    /// rather than injecting its own options.
    /// </param>
    /// <param name="notifiers">
    /// Every registered notifier, so the ladder can tell "monitoring is on but
    /// nothing is configured" apart from "monitoring is off". That distinction is
    /// invisible in the AlertsSent table, because the monitor writes no row at
    /// all in either case.
    /// </param>
    public AlertQueryService(
        CertusDbContext db,
        ILogger<AlertQueryService> logger,
        IOptions<AlertOptions> alertOptions,
        IEnumerable<IAlertNotifier> notifiers,
        ServerCertificateIdentity serverCertificate)
    {
        _db = db;
        _logger = logger;
        _alertOptions = alertOptions.Value;
        _notifiers = notifiers.ToList();
        _serverCertificate = serverCertificate;
    }

    /// <summary>
    /// The alert configuration as the dashboard is allowed to see it (issue #161).
    /// Wiring only; <see cref="AlertConfigView.From"/> holds the rules and is
    /// tested without a database.
    /// </summary>
    public AlertConfigView GetConfig() => AlertConfigView.From(_alertOptions, _notifiers);

    /// <summary>
    /// Gets recent alert history with pagination.
    /// </summary>
    public async Task<AlertHistoryResult> GetHistoryAsync(
        int skip = 0, int take = 50,
        CancellationToken cancellationToken = default)
    {
        var totalCount = await _db.AlertsSent.CountAsync(cancellationToken);

        var items = await _db.AlertsSent
            .OrderByDescending(a => a.SentAt)
            .Skip(skip)
            .Take(take)
            .Select(a => new AlertHistoryItem
            {
                Id = a.Id,
                CertificateId = a.CertificateId,
                Subject = a.Certificate != null ? a.Certificate.Subject : "Unknown",
                SerialNumber = a.Certificate != null ? a.Certificate.SerialNumber : "Unknown",
                ThresholdDays = a.ThresholdDays,
                SentAt = a.SentAt,
                Channels = a.Channels,
                Success = a.Success,
                ErrorMessage = a.ErrorMessage,
            })
            .ToListAsync(cancellationToken);

        // After materialisation, because the projection above runs in SQL. The
        // recorded message is whatever the notifier reported, and the webhook
        // notifier builds its errors from the receiver's response body or from a
        // raw exception message, either of which can carry the webhook URL and
        // the token embedded in it (issue #161). The detail page has been
        // rendering these strings verbatim since issue #160.
        foreach (var item in items)
        {
            item.ErrorMessage = AlertErrorRedactor.Redact(item.ErrorMessage, _alertOptions);
        }

        return new AlertHistoryResult(items, totalCount, skip, take);
    }

    /// <summary>
    /// Gets summary alert statistics.
    /// </summary>
    public async Task<AlertSummary> GetSummaryAsync(CancellationToken cancellationToken = default)
    {
        var totalSent = await _db.AlertsSent.CountAsync(cancellationToken);
        var failedCount = await _db.AlertsSent.CountAsync(a => !a.Success, cancellationToken);
        var uniqueCerts = await _db.AlertsSent
            .Select(a => a.CertificateId)
            .Distinct()
            .CountAsync(cancellationToken);

        var lastSent = await _db.AlertsSent
            .OrderByDescending(a => a.SentAt)
            .Select(a => (DateTime?)a.SentAt)
            .FirstOrDefaultAsync(cancellationToken);

        return new AlertSummary(totalSent, failedCount, uniqueCerts, lastSent);
    }

    /// <summary>
    /// The alert ladder for one certificate, for its detail page (issue #160):
    /// the thresholds that fired, the ones that failed, and the ones that should
    /// have fired and did not.
    ///
    /// Returns null when no such certificate exists, so the caller can answer
    /// 404 rather than an empty ladder that reads as "nothing was ever sent".
    /// </summary>
    public async Task<CertificateAlertHistory?> GetForCertificateAsync(
        int certificateId,
        CancellationToken cancellationToken = default)
    {
        // Projected, not the entity: SyncedCertificate carries the raw DER, and
        // none of it is needed to answer this.
        var certificate = await _db.SyncedCertificates
            .Where(c => c.Id == certificateId)
            .Select(c => new CertificateAlertFacts(
                c.Id, c.Status, c.SerialNumber, c.NotAfter, c.FirstSyncedAt))
            .FirstOrDefaultAsync(cancellationToken);

        if (certificate == null)
            return null;

        // Scoped to the one certificate and covered by the unique index on
        // (CertificateId, ThresholdDays), so this is a seek. Unpaginated on
        // purpose: the row count per certificate is bounded by the number of
        // configured thresholds.
        var rows = await _db.AlertsSent
            .Where(a => a.CertificateId == certificateId)
            .ToListAsync(cancellationToken);

        var context = new AlertLadderContext(
            AlertingEnabled: _alertOptions.Enabled,
            EnabledChannels: _notifiers.Where(n => n.IsEnabled).Select(n => n.Channel).ToList(),
            CheckIntervalMinutes: _alertOptions.CheckIntervalMinutes,
            ThresholdDays: _alertOptions.ThresholdDays,
            IsOwnCertificate: _serverCertificate.IsOwnCertificate(certificate.SerialNumber));

        var ladder = CertificateAlertLadder.Build(certificate, rows, context, DateTime.UtcNow);

        // Same reason as GetHistoryAsync: the recorded error is whatever the
        // notifier reported, and the detail page renders it verbatim.
        foreach (var threshold in ladder.Thresholds)
        {
            threshold.ErrorMessage = AlertErrorRedactor.Redact(threshold.ErrorMessage, _alertOptions);
        }

        return ladder;
    }
}

/// <summary>Alert history result with pagination.</summary>
public sealed record AlertHistoryResult(
    [property: JsonPropertyName("items")] IReadOnlyList<AlertHistoryItem> Items,
    [property: JsonPropertyName("totalCount")] int TotalCount,
    [property: JsonPropertyName("skip")] int Skip,
    [property: JsonPropertyName("take")] int Take)
{
    [JsonPropertyName("hasMore")]
    public bool HasMore => Skip + Take < TotalCount;
}

/// <summary>A single alert history entry.</summary>
public sealed class AlertHistoryItem
{
    [JsonPropertyName("id")]
    public int Id { get; set; }

    [JsonPropertyName("certificateId")]
    public int CertificateId { get; set; }

    [JsonPropertyName("subject")]
    public string Subject { get; set; } = string.Empty;

    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; set; } = string.Empty;

    [JsonPropertyName("thresholdDays")]
    public int ThresholdDays { get; set; }

    [JsonPropertyName("sentAt")]
    public DateTime SentAt { get; set; }

    [JsonPropertyName("channels")]
    public string Channels { get; set; } = string.Empty;

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("errorMessage")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ErrorMessage { get; set; }
}

/// <summary>Alert summary statistics.</summary>
public sealed record AlertSummary(
    [property: JsonPropertyName("totalAlertsSent")] int TotalAlertsSent,
    [property: JsonPropertyName("failedAlerts")] int FailedAlerts,
    [property: JsonPropertyName("uniqueCertificatesAlerted")] int UniqueCertificatesAlerted,
    [property: JsonPropertyName("lastAlertSent")] DateTime? LastAlertSent);
