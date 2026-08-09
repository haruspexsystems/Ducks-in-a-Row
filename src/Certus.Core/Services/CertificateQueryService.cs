using System.Linq.Expressions;
using System.Text.Json;
using System.Text.Json.Serialization;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Services;

/// <summary>
/// Queries the synced certificate inventory for the dashboard.
/// Provides search, filter, sort, and pagination over the local SQLite database.
/// </summary>
public sealed class CertificateQueryService
{
    // SyncedCertificate.Status holds CertificateStatus.ToString(). These two are
    // the dispositions that produced a certificate; the rest (Pending, Denied,
    // Failed) are requests that did not, and are excluded from the unfiltered
    // inventory and from its total.
    internal const string IssuedStatus = nameof(Adcs.CertificateStatus.Issued);
    internal const string RevokedStatus = nameof(Adcs.CertificateStatus.Revoked);

    /// <summary>
    /// The four lifecycle states the dashboard stat cards and the certificate
    /// list chips both name (issue #155), as one predicate over the inventory.
    /// Returns null for an unrecognised name.
    /// </summary>
    /// <remarks>
    /// This is deliberately the only place a state is defined. Both
    /// <see cref="QueryAsync"/> and <see cref="GetStatsAsync"/> read it, so a
    /// card and the list it deep links to cannot describe different sets. They
    /// did before: the card counted issued certificates only, while the list
    /// filtered on the expiry date alone and so also returned the revoked ones
    /// that happened to be past their NotAfter.
    ///
    /// The three issued states partition Status == Issued with no gap and no
    /// overlap, so valid + expiring + expired always equals the issued count.
    /// </remarks>
    internal static Expression<Func<SyncedCertificate, bool>>? StatePredicate(
        string? state, DateTime now, DateTime warningCutoff) => state?.ToLowerInvariant() switch
    {
        "valid" => c => c.Status == IssuedStatus && c.NotAfter > warningCutoff,
        "expiring" => c => c.Status == IssuedStatus && c.NotAfter <= warningCutoff && c.NotAfter > now,
        "expired" => c => c.Status == IssuedStatus && c.NotAfter <= now,
        "revoked" => c => c.Status == RevokedStatus,
        _ => null
    };

    /// <summary>
    /// Whether <paramref name="state"/> names one of the four lifecycle states.
    /// Asks <see cref="StatePredicate"/> rather than carrying a second list, so
    /// the API's idea of the vocabulary cannot drift from the query's.
    /// </summary>
    public static bool IsKnownState(string? state) =>
        StatePredicate(state, DateTime.UnixEpoch, DateTime.UnixEpoch) is not null;

    private readonly CertusDbContext _db;
    private readonly ILogger<CertificateQueryService> _logger;
    private readonly AlertOptions _alertOptions;
    private readonly RevocationEligibilityService _revocationEligibility;

    // IOptions, not IOptionsMonitor: ExpiryMonitorService snapshots the same way
    // at construction, so the dashboard and the engine that sends the alert
    // emails always read one value. A live-reloading dashboard would report a
    // window the alerting engine is not actually using.
    public CertificateQueryService(
        CertusDbContext db,
        ILogger<CertificateQueryService> logger,
        IOptions<AlertOptions> alertOptions,
        RevocationEligibilityService revocationEligibility)
    {
        _db = db;
        _logger = logger;
        _revocationEligibility = revocationEligibility;
        _alertOptions = alertOptions.Value;
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
        {
            q = q.Where(c => c.Status == query.Status);
        }
        else
        {
            // The inventory is certificates. Pending, denied, and failed rows
            // are requests that never became one: they carry no serial, no
            // subject, and no expiry, so on the default expiry sort they would
            // occupy the whole first page and bury the real certificates. They
            // stay out of the unfiltered list and the status filter is how an
            // admin reaches them.
            q = q.Where(c => c.Status == IssuedStatus || c.Status == RevokedStatus);
        }

        // The lifecycle state chips (issue #155). Resolved here rather than sent
        // as a pair of timestamps, so a bookmarked or shared "expiring soon"
        // link still means "expiring soon" next month, and follows the operator
        // if they later widen the alert threshold. It also settles the boundary
        // on the server's clock rather than the browser's.
        if (!string.IsNullOrWhiteSpace(query.State))
        {
            var stateNow = DateTime.UtcNow;
            var predicate = StatePredicate(
                query.State, stateNow, stateNow.AddDays(_alertOptions.ExpiryWarningDays));

            // Unknown names are rejected at the API edge, so reaching here with
            // one means an internal caller passed a typo. Refusing everything is
            // the safe read: a filter that silently matched all rows would look
            // like an answer.
            q = predicate is null ? q.Where(_ => false) : q.Where(predicate);
        }

        // Still honoured alongside State, and ANDed with it. These are the
        // general purpose range filter and predate the chips; links built before
        // #155 keep working.
        //
        // Both bounds are inclusive, and both are UTC wall clocks like every
        // other DateTime in the model. A bound that arrived over HTTP is held to
        // that clock at the API edge; see UtcWallClock for what the MVC binder
        // already guarantees on the query string path and what normalizing
        // regardless adds.
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
        //
        // "notafter" has a case of its own even though the default arm already
        // lands there, so that every column the table marks sortable is named
        // here (issue #156). Before that the Expires header sorted correctly only
        // by coincidence, and any later change to the default would have broken
        // it silently.
        //
        // An unrecognised key stays a silent fallthrough to the default rather
        // than an error. That silence is a contract rather than an oversight:
        // Query_SortBySupersession_IsNotASortKey asserts it, because declining to
        // sort by a paid tier concept has to look exactly like never having
        // offered it.
        var ordered = query.SortBy?.ToLower() switch
        {
            "subject" => query.SortDesc ? q.OrderByDescending(c => c.Subject) : q.OrderBy(c => c.Subject),
            "template" => query.SortDesc ? q.OrderByDescending(c => c.TemplateName) : q.OrderBy(c => c.TemplateName),
            "notbefore" => query.SortDesc ? q.OrderByDescending(c => c.NotBefore) : q.OrderBy(c => c.NotBefore),
            "notafter" => query.SortDesc ? q.OrderByDescending(c => c.NotAfter) : q.OrderBy(c => c.NotAfter),
            "status" => query.SortDesc ? q.OrderByDescending(c => c.Status) : q.OrderBy(c => c.Status),
            "requestdate" => query.SortDesc ? q.OrderByDescending(c => c.RequestDate) : q.OrderBy(c => c.RequestDate),
            "requestor" => query.SortDesc ? q.OrderByDescending(c => c.Requestor) : q.OrderBy(c => c.Requestor),
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
                    RevokedReason = c.RevokedReason,
                    // The same value bridge as ContactJson below, asked as an
                    // existence question instead. Inside the projection on
                    // purpose: it translates to a correlated EXISTS in this one
                    // statement, served by IX_AcmeCertificates_AdcsRequestId, so
                    // the paged list gains no extra round trip.
                    IssuedByAcme = _db.AcmeCertificates
                        .Any(a => a.AdcsRequestId == c.RequestId),
                    // Already on the row, computed once per sync by
                    // SupersessionLinker, so badging the list costs no extra
                    // query and cannot become an N plus 1.
                    SupersededById = c.SupersededByCertificateId
                },
                // Correlated scalar subquery: the contact JSON of the ACME
                // account whose order produced this CA request, when one
                // exists. There is no foreign key between the synced inventory
                // and the ACME tables; the value bridge is
                // SyncedCertificate.RequestId == AcmeCertificate.AdcsRequestId.
                //
                // Read by the table's last column only. See
                // CertificateSummary.AcmeContactEmail for why this and the
                // parse below are expected to leave with issue #156.
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

        // Asked separately rather than folded into the lookup above so it uses
        // the identical predicate to the list projection and the two endpoints
        // cannot drift. One indexed EXISTS on a single certificate page.
        var issuedByAcme = await _db.AcmeCertificates
            .AnyAsync(a => a.AdcsRequestId == entity.RequestId, cancellationToken);

        // Both ends of the inferred supersession relationship (issue #154). Two
        // small queries on one row's behalf, which is what a detail page is for;
        // the reverse lookup is indexed. The forward id is stored, so the
        // successor is a direct read, while the predecessors are whoever names
        // this row.
        var supersededBy = entity.SupersededByCertificateId == null
            ? null
            : await LinkQuery(_db.SyncedCertificates
                    .Where(c => c.Id == entity.SupersededByCertificateId))
                .FirstOrDefaultAsync(cancellationToken);

        var supersedes = await LinkQuery(_db.SyncedCertificates
                .Where(c => c.SupersededByCertificateId == entity.Id)
                .OrderBy(c => c.NotBefore)
                .ThenBy(c => c.Id))
            .ToListAsync(cancellationToken);

        // The revoke button's server side reason, computed only under the
        // exact condition the button renders (an issued certificate with a
        // serial), so revoked rows and request rows carry nothing. The same
        // evaluator enforces in CertificateRevocationService, so the reason
        // shown and the refusal enforced cannot drift.
        string? revocationBlocked = null;
        string? revocationBlockedDetail = null;
        if (entity.Status == nameof(CertificateStatus.Issued) &&
            !string.IsNullOrWhiteSpace(entity.SerialNumber))
        {
            var eligibility = await _revocationEligibility.EvaluateAsync(entity, cancellationToken);
            if (!eligibility.Allowed)
            {
                revocationBlocked = eligibility.BlockedKind;
                revocationBlockedDetail = eligibility.Detail;
            }
        }

        return new CertificateDetail
        {
            RevocationBlocked = revocationBlocked,
            RevocationBlockedDetail = revocationBlockedDetail,
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
            DispositionMessage = entity.DispositionMessage,
            StatusCode = entity.StatusCode,
            AcmeContactEmail = ExtractFirstMailto(contactJson),
            IssuedByAcme = issuedByAcme,
            // Detail only. The list projection in QueryAsync deliberately does
            // not carry these; see the note on CertificateDetail.
            KeyAlgorithm = entity.KeyAlgorithm,
            KeySizeBits = entity.KeySizeBits,
            SignatureAlgorithmOid = entity.SignatureAlgorithmOid,
            Sha256Thumbprint = entity.Sha256Thumbprint,
            ExtendedKeyUsageOids = entity.ExtendedKeyUsageOids,
            KeyUsage = entity.KeyUsage,
            // Whether the download endpoints have anything to serve, not the
            // bytes themselves: the DER never travels in a JSON response.
            CanDownload = entity.RawCertificate != null,
            FirstSyncedAt = entity.FirstSyncedAt,
            LastSyncedAt = entity.LastSyncedAt,
            SupersededById = entity.SupersededByCertificateId,
            SupersededBy = supersededBy,
            Supersedes = supersedes
        };
    }

    /// <summary>
    /// The stored DER for one certificate, for the single certificate download
    /// (issue #158), or null when the row does not exist or carried no
    /// decodable certificate blob. The caller cannot tell those two apart and
    /// does not need to: both mean there is nothing to hand the admin.
    ///
    /// A projected read rather than loading the entity, so the blob is fetched
    /// only on the one path that actually serves it.
    ///
    /// Deliberately by internal id and one certificate at a time. There is no
    /// bulk or multiple certificate counterpart to this method, and adding one
    /// would cross the free tier boundary the epic draws: exporting the
    /// inventory is a paid feature, handing an admin a certificate they already
    /// own is not.
    /// </summary>
    public async Task<byte[]?> GetRawCertificateAsync(
        int id, CancellationToken cancellationToken = default)
    {
        return await _db.SyncedCertificates
            .Where(c => c.Id == id)
            .Select(c => c.RawCertificate)
            .FirstOrDefaultAsync(cancellationToken);
    }

    /// <summary>
    /// Projects synced rows to the trimmed shape both supersession directions
    /// render, so the two lookups cannot drift apart.
    /// </summary>
    private static IQueryable<CertificateLink> LinkQuery(IQueryable<SyncedCertificate> source)
    {
        return source.Select(c => new CertificateLink(
            c.Id,
            c.Subject,
            c.SubjectAlternativeNames,
            c.SerialNumber,
            c.NotBefore,
            c.NotAfter,
            c.Status,
            c.Requestor));
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
        // The operator's widest alert threshold, not a literal (issue #152), so
        // this count and the alert emails always describe the same certificates.
        var warningCutoff = now.AddDays(_alertOptions.ExpiryWarningDays);

        // Counts the same set the unfiltered list shows, so the stat card and
        // the list below it can never disagree. Pending, denied, and failed
        // request rows are not certificates and are not part of the total.
        var total = await _db.SyncedCertificates
            .CountAsync(c => c.Status == IssuedStatus || c.Status == RevokedStatus,
                cancellationToken);

        var issued = await _db.SyncedCertificates
            .CountAsync(c => c.Status == IssuedStatus, cancellationToken);

        // Counted through the same predicates the list filters on (issue #155),
        // so a card and the filtered list it links to can never disagree.
        var expiringSoon = await _db.SyncedCertificates
            .CountAsync(StatePredicate("expiring", now, warningCutoff)!, cancellationToken);

        var expired = await _db.SyncedCertificates
            .CountAsync(StatePredicate("expired", now, warningCutoff)!, cancellationToken);

        var revoked = await _db.SyncedCertificates
            .CountAsync(StatePredicate("revoked", now, warningCutoff)!, cancellationToken);

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
    // One of the four lifecycle states (valid, expiring, expired, revoked), or
    // null for no state filter. See CertificateQueryService.StatePredicate.
    string? State = null,
    // Inclusive bounds on NotAfter, as UTC wall clocks like every other date in
    // the model. See CertificatesController.ListCertificates for why these stay
    // inclusive while the ACME accounts inventory's Before bounds are exclusive.
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
    ///
    /// The list pays a real per page price for this: a correlated scalar
    /// subquery over the RequestId value bridge, then a mailto parse in memory
    /// for every row. It earns that only because the certificate table's last
    /// column renders it, and that column is its only reader.
    ///
    /// It is expected to stop earning it. Issue #156 reworks that column and
    /// leaves one question open on purpose: whether the ACME contact belongs in
    /// the list at all, or on the detail page only. The recommendation is detail
    /// page only. The CA requester is present on every certificate rather than
    /// only the ones Ducks issued, so it is the better use of a fixed column
    /// slot, and <see cref="IssuedByAcme"/> has badged provenance in the list
    /// since #189, which is the question this email column was standing in for.
    /// If #156 settles it that way, drop the subquery and the parse from
    /// QueryAsync and let this go back to being detail only.
    ///
    /// Note what that does and does not mean: drop the population, not the
    /// property. <see cref="CertificateDetail"/> inherits this member, so
    /// deleting it here also deletes it from the detail page, which is the one
    /// surface that genuinely renders it. Doing either before #156 blanks a live
    /// column for no gain.
    /// </summary>
    [JsonPropertyName("acmeContactEmail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AcmeContactEmail { get; set; }

    /// <summary>
    /// Whether Ducks issued this certificate through the ACME proxy. True is
    /// good evidence that an ACME client is renewing it, not proof that the
    /// client is still running. False means the certificate reached the
    /// inventory from the CA database only, issued by auto enrolment, by the
    /// Certification Authority console, or by a person with certreq, and
    /// nothing in Ducks renews it.
    ///
    /// Not derivable from <see cref="AcmeContactEmail"/>: that resolves through
    /// the ACME account's contact list, so it is null on a certificate Ducks
    /// did issue whenever the account carries no mailto contact.
    ///
    /// Always serialized, so the dashboard never has to read an absent property
    /// as false.
    /// </summary>
    [JsonPropertyName("issuedByAcme")]
    public bool IssuedByAcme { get; set; }

    /// <summary>
    /// The later certificate that appears to have replaced this one, or null
    /// (issue #154). Ducks' own inference from template plus names; the CA does
    /// not report renewals. The list needs it because badging a superseded row is
    /// the whole point, and a page of 25 rows can never work the answer out for
    /// itself.
    ///
    /// This sits on the summary rather than below the boundary the detail type
    /// describes, and that is not a breach of it. What that boundary keeps out is
    /// inventory reporting material: counting and filtering the fleet by
    /// cryptographic property is a paid tier feature. This is a per row
    /// annotation, the same kind of thing as <see cref="IssuedByAcme"/> above. It
    /// is deliberately absent from <see cref="CertificateSearchQuery"/>, from
    /// every sort key, and from every aggregate, so it cannot quietly become one.
    /// </summary>
    [JsonPropertyName("supersededById")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? SupersededById { get; set; }
}

/// <summary>
/// One end of an inferred supersession relationship: enough of the other
/// certificate to name it, link to it, and let the reader judge the inference
/// for themselves.
///
/// Requestor is here as evidence, not decoration. The failure mode of this whole
/// feature is two teams independently asking the same template for the same
/// hostname, which is indistinguishable from a renewal by names alone; seeing
/// two different requesters is how a reader spots it. The ACME contact would say
/// the same thing but costs another join, and this is already the detail page.
/// </summary>
public sealed record CertificateLink(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("subjectAlternativeNames")] string? SubjectAlternativeNames,
    [property: JsonPropertyName("serialNumber")] string SerialNumber,
    [property: JsonPropertyName("notBefore")] DateTime NotBefore,
    [property: JsonPropertyName("notAfter")] DateTime NotAfter,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("requestor")] string? Requestor);

/// <summary>
/// Full certificate detail for the single certificate endpoint.
///
/// The cryptographic fields below live here and not on
/// <see cref="CertificateSummary"/> on purpose, and the inheritance direction is
/// what enforces it: nothing added here can reach the list projection. They must
/// not become a list column, a filter, a sort key, or an aggregate. Inventory
/// and reporting by key algorithm, including migration progress toward
/// post quantum algorithms, is a paid tier feature; showing one certificate's
/// own key detail on its own page is what any certificate viewer does.
///
/// Every value is a code as the certificate carries it. The dashboard resolves
/// the display labels, the same way it labels revocation reason codes, so no
/// locale dependent name is ever persisted.
/// </summary>
public sealed class CertificateDetail : CertificateSummary
{
    /// <summary>
    /// The CA's own explanation of what happened to the request, verbatim.
    /// Present only on Pending, Denied, and Failed rows. The dashboard renders
    /// it as text attributed to the CA and never rewords it.
    ///
    /// Here rather than on the summary for the same structural reason as the
    /// cryptographic fields, plus one of its own: this is text authored outside
    /// Ducks and partly influenced by whoever submitted the request, so the
    /// fewer responses that carry it the better. Only the detail page renders it.
    /// </summary>
    [JsonPropertyName("dispositionMessage")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DispositionMessage { get; set; }

    /// <summary>
    /// The HRESULT the CA recorded against the request. Present only alongside
    /// <see cref="DispositionMessage"/>. Signed, so the dashboard formats it
    /// unsigned to reach the familiar 0x8009xxxx form.
    /// </summary>
    [JsonPropertyName("statusCode")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? StatusCode { get; set; }

    [JsonPropertyName("keyAlgorithm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyAlgorithm { get; set; }

    [JsonPropertyName("keySizeBits")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? KeySizeBits { get; set; }

    [JsonPropertyName("signatureAlgorithmOid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SignatureAlgorithmOid { get; set; }

    [JsonPropertyName("sha256Thumbprint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Sha256Thumbprint { get; set; }

    [JsonPropertyName("extendedKeyUsageOids")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExtendedKeyUsageOids { get; set; }

    [JsonPropertyName("keyUsage")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? KeyUsage { get; set; }

    /// <summary>
    /// Whether this certificate can be downloaded, which is to say whether the
    /// sync ever captured a decodable certificate blob for it. The dashboard
    /// hides the download and copy actions when this is false, rather than
    /// offering a button that can only fail.
    ///
    /// A flag and never the bytes: the DER leaves only through the two single
    /// certificate download endpoints, never inside a JSON response. Always
    /// written, unlike the nullable fields above, because "false" is a real
    /// answer the page needs and an absent property would read the same way as
    /// a response from an older build.
    /// </summary>
    [JsonPropertyName("canDownload")]
    public bool CanDownload { get; set; }

    /// <summary>
    /// Why the revoke action is unavailable: "guardrail" when the TLS
    /// capability ceiling refuses the certificate, "out-of-scope" when the
    /// configured revocation scope does not cover it, null when revocation
    /// is available or the row is not revocable at all (not Issued, or no
    /// serial), where the button does not render in the first place.
    /// </summary>
    [JsonPropertyName("revocationBlocked")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RevocationBlocked { get; set; }

    /// <summary>
    /// The human sentence behind <see cref="RevocationBlocked"/>, the same
    /// text the revoke endpoint returns in its 403 problem detail.
    /// </summary>
    [JsonPropertyName("revocationBlockedDetail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RevocationBlockedDetail { get; set; }

    [JsonPropertyName("firstSyncedAt")]
    public DateTime FirstSyncedAt { get; set; }

    [JsonPropertyName("lastSyncedAt")]
    public DateTime LastSyncedAt { get; set; }

    /// <summary>
    /// The certificate that appears to have replaced this one, resolved so the
    /// page can name it and show the dates the inference rests on. The summary
    /// already carries its id; this is the same link with enough of the row
    /// attached to render it.
    /// </summary>
    [JsonPropertyName("supersededBy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CertificateLink? SupersededBy { get; set; }

    /// <summary>
    /// The certificates this one appears to have replaced. Usually none or one.
    ///
    /// A list rather than a single value because of how the revoked rule bites: a
    /// revoked certificate never supersedes, so when one sits between two issued
    /// certificates in a lineage, both it and the certificate before it name the
    /// same successor, and the reverse lookup legitimately returns two rows.
    /// </summary>
    [JsonPropertyName("supersedes")]
    public IReadOnlyList<CertificateLink> Supersedes { get; set; } = Array.Empty<CertificateLink>();
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
