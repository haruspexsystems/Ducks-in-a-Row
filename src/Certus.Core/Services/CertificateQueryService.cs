using System.Text.Json;
using System.Text.Json.Serialization;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Services;

/// <summary>
/// Queries the synced certificate inventory for the dashboard.
/// Provides search, filter, sort, and pagination over the local SQLite database.
/// </summary>
public sealed class CertificateQueryService
{
    private readonly CertusDbContext _db;
    private readonly ILogger<CertificateQueryService> _logger;

    public CertificateQueryService(CertusDbContext db, ILogger<CertificateQueryService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Queries the certificate inventory with filtering, sorting, and pagination.
    /// </summary>
    public async Task<PagedResult<CertificateSummary>> QueryAsync(
        CertificateSearchQuery query,
        CancellationToken cancellationToken = default)
    {
        var q = _db.SyncedCertificates.AsQueryable();

        // Filters
        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var search = query.Search.ToLower();
            q = q.Where(c =>
                c.Subject.ToLower().Contains(search) ||
                c.SerialNumber.ToLower().Contains(search) ||
                (c.SubjectAlternativeNames != null && c.SubjectAlternativeNames.ToLower().Contains(search)));
        }

        if (!string.IsNullOrWhiteSpace(query.TemplateName))
            q = q.Where(c => c.TemplateName == query.TemplateName);

        if (!string.IsNullOrWhiteSpace(query.Status))
            q = q.Where(c => c.Status == query.Status);

        if (query.ExpiringBefore.HasValue)
            q = q.Where(c => c.NotAfter <= query.ExpiringBefore.Value);

        if (query.ExpiringAfter.HasValue)
            q = q.Where(c => c.NotAfter >= query.ExpiringAfter.Value);

        // Total count (before pagination)
        var totalCount = await q.CountAsync(cancellationToken);

        // Sorting. The switch chooses the primary key, then we always append the
        // primary key Id as a unique tiebreaker. Without it, rows that share a
        // primary value have no defined order, so Skip/Take paging could repeat or
        // drop a row at a page boundary (most likely on the default NotAfter sort,
        // where many certificates share an expiry).
        var ordered = query.SortBy?.ToLower() switch
        {
            "subject" => query.SortDesc ? q.OrderByDescending(c => c.Subject) : q.OrderBy(c => c.Subject),
            "template" => query.SortDesc ? q.OrderByDescending(c => c.TemplateName) : q.OrderBy(c => c.TemplateName),
            "notbefore" => query.SortDesc ? q.OrderByDescending(c => c.NotBefore) : q.OrderBy(c => c.NotBefore),
            "status" => query.SortDesc ? q.OrderByDescending(c => c.Status) : q.OrderBy(c => c.Status),
            "requestdate" => query.SortDesc ? q.OrderByDescending(c => c.RequestDate) : q.OrderBy(c => c.RequestDate),
            _ => query.SortDesc ? q.OrderByDescending(c => c.NotAfter) : q.OrderBy(c => c.NotAfter) // default: expiry
        };

        q = ordered.ThenBy(c => c.Id);

        // Pagination
        var rows = await q
            .Skip(query.Skip)
            .Take(query.Take)
            .Select(c => new
            {
                Summary = new CertificateSummary
                {
                    Id = c.Id,
                    RequestId = c.RequestId,
                    SerialNumber = c.SerialNumber,
                    Subject = c.Subject,
                    SubjectAlternativeNames = c.SubjectAlternativeNames,
                    TemplateName = c.TemplateName,
                    NotBefore = c.NotBefore,
                    NotAfter = c.NotAfter,
                    Status = c.Status,
                    Requestor = c.Requestor,
                    RequestDate = c.RequestDate,
                    RevokedAt = c.RevokedAt,
                    RevokedReason = c.RevokedReason
                },
                // Correlated scalar subquery: the contact JSON of the ACME
                // account whose order produced this CA request, when one
                // exists. There is no foreign key between the synced inventory
                // and the ACME tables; the value bridge is
                // SyncedCertificate.RequestId == AcmeCertificate.AdcsRequestId.
                ContactJson = _db.AcmeCertificates
                    .Where(a => a.AdcsRequestId == c.RequestId)
                    .OrderBy(a => a.Id)
                    .Select(a => a.Order.Account.ContactJson)
                    .FirstOrDefault()
            })
            .ToListAsync(cancellationToken);

        // The mailto parse is not translatable to SQL, so it runs here, on the
        // already paged rows only.
        var items = rows.Select(r =>
        {
            r.Summary.AcmeContactEmail = ExtractFirstMailto(r.ContactJson);
            return r.Summary;
        }).ToList();

        return new PagedResult<CertificateSummary>(items, totalCount, query.Skip, query.Take);
    }

    /// <summary>
    /// Gets the full detail for a single certificate by its internal ID,
    /// including the ACME account contact email when the certificate was
    /// issued through the ACME proxy.
    /// </summary>
    public async Task<CertificateDetail?> GetDetailByIdAsync(
        int id, CancellationToken cancellationToken = default)
    {
        var entity = await _db.SyncedCertificates.FindAsync(new object[] { id }, cancellationToken);
        if (entity == null)
            return null;

        // Same value bridge as the list projection: RequestId links the synced
        // inventory row to the ACME certificate that produced it, when one exists.
        var contactJson = await _db.AcmeCertificates
            .Where(a => a.AdcsRequestId == entity.RequestId)
            .OrderBy(a => a.Id)
            .Select(a => a.Order.Account.ContactJson)
            .FirstOrDefaultAsync(cancellationToken);

        return new CertificateDetail
        {
            Id = entity.Id,
            RequestId = entity.RequestId,
            SerialNumber = entity.SerialNumber,
            Subject = entity.Subject,
            SubjectAlternativeNames = entity.SubjectAlternativeNames,
            TemplateName = entity.TemplateName,
            NotBefore = entity.NotBefore,
            NotAfter = entity.NotAfter,
            Status = entity.Status,
            Requestor = entity.Requestor,
            RequestDate = entity.RequestDate,
            RevokedAt = entity.RevokedAt,
            RevokedReason = entity.RevokedReason,
            AcmeContactEmail = ExtractFirstMailto(contactJson),
            FirstSyncedAt = entity.FirstSyncedAt,
            LastSyncedAt = entity.LastSyncedAt
        };
    }

    /// <summary>
    /// Pulls the first mailto contact out of an ACME account's ContactJson,
    /// which is a JSON array of RFC 8555 contact URIs. Returns null for a
    /// missing, malformed, or mailto free list so callers render a placeholder.
    /// </summary>
    internal static string? ExtractFirstMailto(string? contactJson)
    {
        if (string.IsNullOrWhiteSpace(contactJson))
            return null;

        try
        {
            var contacts = JsonSerializer.Deserialize<string[]>(contactJson);
            var mailto = contacts?.FirstOrDefault(c =>
                c != null && c.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase));
            var email = mailto?["mailto:".Length..];
            return string.IsNullOrWhiteSpace(email) ? null : email;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Gets summary statistics for the dashboard.
    /// </summary>
    public async Task<CertificateStats> GetStatsAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var in30Days = now.AddDays(30);

        var total = await _db.SyncedCertificates.CountAsync(cancellationToken);

        var issued = await _db.SyncedCertificates
            .CountAsync(c => c.Status == "Issued", cancellationToken);

        var expiringSoon = await _db.SyncedCertificates
            .CountAsync(c => c.Status == "Issued" && c.NotAfter <= in30Days && c.NotAfter > now,
                cancellationToken);

        var expired = await _db.SyncedCertificates
            .CountAsync(c => c.Status == "Issued" && c.NotAfter <= now,
                cancellationToken);

        var revoked = await _db.SyncedCertificates
            .CountAsync(c => c.Status == "Revoked", cancellationToken);

        return new CertificateStats(total, issued, expiringSoon, expired, revoked);
    }
}

/// <summary>
/// Search/filter parameters for certificate queries.
/// </summary>
public sealed record CertificateSearchQuery(
    string? Search = null,
    string? TemplateName = null,
    string? Status = null,
    DateTime? ExpiringBefore = null,
    DateTime? ExpiringAfter = null,
    string? SortBy = null,
    bool SortDesc = false,
    int Skip = 0,
    int Take = 50);

/// <summary>
/// A certificate summary for list views.
/// </summary>
public class CertificateSummary
{
    [JsonPropertyName("id")]
    public int Id { get; set; }

    [JsonPropertyName("requestId")]
    public int RequestId { get; set; }

    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; set; } = string.Empty;

    [JsonPropertyName("subject")]
    public string Subject { get; set; } = string.Empty;

    [JsonPropertyName("subjectAlternativeNames")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SubjectAlternativeNames { get; set; }

    [JsonPropertyName("templateName")]
    public string TemplateName { get; set; } = string.Empty;

    [JsonPropertyName("notBefore")]
    public DateTime NotBefore { get; set; }

    [JsonPropertyName("notAfter")]
    public DateTime NotAfter { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("requestor")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Requestor { get; set; }

    [JsonPropertyName("requestDate")]
    public DateTime RequestDate { get; set; }

    [JsonPropertyName("revokedAt")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTime? RevokedAt { get; set; }

    [JsonPropertyName("revokedReason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? RevokedReason { get; set; }

    /// <summary>
    /// The contact email of the ACME account that requested this certificate,
    /// resolved at query time from the account's current contact list. Null
    /// for certificates issued outside the ACME proxy or when the account has
    /// no mailto contact.
    /// </summary>
    [JsonPropertyName("acmeContactEmail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AcmeContactEmail { get; set; }
}

/// <summary>
/// Full certificate detail for the single certificate endpoint.
/// </summary>
public sealed class CertificateDetail : CertificateSummary
{
    [JsonPropertyName("firstSyncedAt")]
    public DateTime FirstSyncedAt { get; set; }

    [JsonPropertyName("lastSyncedAt")]
    public DateTime LastSyncedAt { get; set; }
}

/// <summary>
/// Paginated result set.
/// </summary>
public sealed record PagedResult<T>(
    [property: JsonPropertyName("items")] IReadOnlyList<T> Items,
    [property: JsonPropertyName("totalCount")] int TotalCount,
    [property: JsonPropertyName("skip")] int Skip,
    [property: JsonPropertyName("take")] int Take)
{
    [JsonPropertyName("hasMore")]
    public bool HasMore => Skip + Take < TotalCount;
}

/// <summary>
/// Dashboard summary statistics.
/// </summary>
public sealed record CertificateStats(
    [property: JsonPropertyName("totalCertificates")] int TotalCertificates,
    [property: JsonPropertyName("issuedCertificates")] int IssuedCertificates,
    [property: JsonPropertyName("expiringSoon")] int ExpiringSoon,
    [property: JsonPropertyName("expired")] int Expired,
    [property: JsonPropertyName("revokedCertificates")] int RevokedCertificates);
