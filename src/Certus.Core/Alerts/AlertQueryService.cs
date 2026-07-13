using System.Text.Json.Serialization;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Alerts;

/// <summary>
/// Queries alert history for the dashboard.
/// </summary>
public sealed class AlertQueryService
{
    private readonly CertusDbContext _db;
    private readonly ILogger<AlertQueryService> _logger;

    public AlertQueryService(CertusDbContext db, ILogger<AlertQueryService> logger)
    {
        _db = db;
        _logger = logger;
    }

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
