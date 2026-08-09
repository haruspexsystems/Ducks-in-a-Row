using System.Text.Json;
using System.Text.Json.Serialization;
using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Services;

/// <summary>
/// Computes the aggregate metrics that back the dashboard widgets
/// (fleet health, validation-method mix, recent activity, daily issuance).
///
/// All figures are certificate-centric and derived from the locally synced
/// inventory (<see cref="Data.Entities.SyncedCertificate"/>) plus the ACME
/// working tables. This keeps the dashboard truthful about the full CA
/// database rather than only proxy traffic.
/// </summary>
public sealed class DashboardMetricsService
{
    private readonly CertusDbContext _db;
    private readonly ILogger<DashboardMetricsService> _logger;
    private readonly AlertOptions _alertOptions;

    /// <summary>The validation methods we always surface, in display order.</summary>
    private static readonly string[] CanonicalChallengeTypes =
        { "http-01", "dns-01", "tls-alpn-01", "device-attest-01" };

    // IOptions rather than IOptionsMonitor, for the reason given on
    // CertificateQueryService: the donut and the stat card beside it must read
    // the same window as the alerting engine.
    public DashboardMetricsService(
        CertusDbContext db,
        ILogger<DashboardMetricsService> logger,
        IOptions<AlertOptions> alertOptions)
    {
        _db = db;
        _logger = logger;
        _alertOptions = alertOptions.Value;
    }

    /// <summary>
    /// Fleet health: a single 0-100 score plus the segment breakdown that
    /// drives the donut. Segments are mutually exclusive.
    /// </summary>
    public async Task<FleetHealthDto> GetFleetHealthAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        // Same operator-configured window the stat card beside this donut uses
        // (issue #152). These two render on one screen, so a literal here would
        // just relocate the contradiction rather than remove it.
        var warningCutoff = now.AddDays(_alertOptions.ExpiryWarningDays);

        var valid = await _db.SyncedCertificates
            .CountAsync(c => c.Status == "Issued" && c.NotAfter > warningCutoff, cancellationToken);

        var expiring = await _db.SyncedCertificates
            .CountAsync(c => c.Status == "Issued" && c.NotAfter <= warningCutoff && c.NotAfter > now, cancellationToken);

        var expired = await _db.SyncedCertificates
            .CountAsync(c => c.Status == "Issued" && c.NotAfter <= now, cancellationToken);

        var pending = await _db.SyncedCertificates
            .CountAsync(c => c.Status == "Pending", cancellationToken);

        // Score = share of lifecycle-relevant certs that are comfortably valid.
        // Pending certs are excluded from the denominator (not yet a health signal).
        // Null when nothing is scoreable yet: a fresh install renders a neutral
        // empty state, not "100% Healthy".
        // Tunable: see docs/ducksinarow-dashboard-delta.md.
        var scored = valid + expiring + expired;
        int? score = scored == 0 ? null : (int)Math.Round(100.0 * valid / scored);

        var segments = new List<HealthSegmentDto>
        {
            new("valid",    "Valid",    valid,    "success"),
            new("expiring", "Expiring", expiring, "warning"),
            new("expired",  "Expired",  expired,  "danger"),
            new("pending",  "Pending",  pending,  "pending"),
        };

        return new FleetHealthDto(score, segments);
    }

    /// <summary>
    /// Count of successful validations grouped by challenge type. Always returns
    /// every canonical method (zero when unused) so the widget is stable.
    /// device-attest-01 is included and reads zero on installs without a device
    /// attestation profile. Reflects proxy-issued challenges only.
    /// </summary>
    public async Task<IReadOnlyList<ValidationMethodDto>> GetValidationMethodsAsync(
        CancellationToken cancellationToken = default)
    {
        var counts = await _db.AcmeChallenges
            .Where(c => c.Status == "valid")
            .GroupBy(c => c.Type)
            .Select(g => new { Type = g.Key, Count = g.Count() })
            .ToListAsync(cancellationToken);

        var byType = counts.ToDictionary(x => x.Type, x => x.Count, StringComparer.OrdinalIgnoreCase);

        return CanonicalChallengeTypes
            .Select(t => new ValidationMethodDto(t, byType.TryGetValue(t, out var n) ? n : 0))
            .ToList();
    }

    /// <summary>
    /// A best effort recent activity feed from five sources: issued ACME
    /// certificates, expiry alerts (warnings), certificates from the synced
    /// inventory that have since expired, certificates the CA has revoked,
    /// and orders refused by the allowed domain policy. Ordered newest
    /// first.
    ///
    /// The first four are synthesized from state tables, not a durable event
    /// log (see the delta doc); the policy rejections are the one durable
    /// source, because a refusal never creates a certificate row to
    /// synthesize from.
    /// </summary>
    public async Task<IReadOnlyList<ActivityItemDto>> GetActivityAsync(
        int take = 20, CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, 100);
        var now = DateTime.UtcNow;

        // Issued — from the ACME certificate store, joined to its order for context.
        var issued = await _db.AcmeCertificates
            .Include(c => c.Order)
            .OrderByDescending(c => c.IssuedAt)
            .Take(take)
            .Select(c => new { c.IssuedAt, c.Order.IdentifiersJson, c.Order.TemplateId })
            .ToListAsync(cancellationToken);

        var items = new List<ActivityItemDto>(take * 5);

        foreach (var c in issued)
        {
            items.Add(new ActivityItemDto(
                Id: $"issued-{c.IssuedAt.Ticks}",
                Type: "issued",
                Cn: FirstIdentifier(c.IdentifiersJson),
                Tmpl: c.TemplateId,
                Timestamp: c.IssuedAt));
        }

        // Warnings — from the expiry alert history.
        var alerts = await _db.AlertsSent
            .Include(a => a.Certificate)
            .OrderByDescending(a => a.SentAt)
            .Take(take)
            .Select(a => new { a.Id, a.SentAt, a.ThresholdDays, Subject = a.Certificate != null ? a.Certificate.Subject : "Unknown" })
            .ToListAsync(cancellationToken);

        foreach (var a in alerts)
        {
            items.Add(new ActivityItemDto(
                Id: $"alert-{a.Id}",
                Type: "warning",
                Cn: ExtractCn(a.Subject),
                Tmpl: $"enters {a.ThresholdDays}-day window",
                Timestamp: a.SentAt));
        }

        // Expired — issued certs from the synced inventory that have lapsed.
        var expired = await _db.SyncedCertificates
            .Where(c => c.Status == "Issued" && c.NotAfter <= now)
            .OrderByDescending(c => c.NotAfter)
            .Take(take)
            .Select(c => new { c.RequestId, c.Subject, c.TemplateName, c.NotAfter })
            .ToListAsync(cancellationToken);

        foreach (var c in expired)
        {
            items.Add(new ActivityItemDto(
                Id: $"expired-{c.RequestId}",
                Type: "expired",
                Cn: ExtractCn(c.Subject),
                Tmpl: c.TemplateName,
                Timestamp: c.NotAfter));
        }

        // Revoked — from the synced inventory, stamped with the CA's revocation time.
        var revoked = await _db.SyncedCertificates
            .Where(c => c.Status == "Revoked" && c.RevokedAt != null)
            .OrderByDescending(c => c.RevokedAt)
            .Take(take)
            .Select(c => new { c.RequestId, c.Subject, c.TemplateName, c.RevokedAt })
            .ToListAsync(cancellationToken);

        foreach (var c in revoked)
        {
            items.Add(new ActivityItemDto(
                Id: $"revoked-{c.RequestId}",
                Type: "revoked",
                Cn: ExtractCn(c.Subject),
                Tmpl: c.TemplateName,
                Timestamp: c.RevokedAt!.Value));
        }

        // Rejected: orders a domain policy refused, either the global allow
        // list or an EAB credential's namespace.
        var rejections = await _db.DomainPolicyRejections
            .OrderByDescending(r => r.OccurredAt)
            .Take(take)
            .Select(r => new { r.Id, r.OccurredAt, r.RejectedIdentifiers, r.Stage })
            .ToListAsync(cancellationToken);

        foreach (var r in rejections)
        {
            // The stage names which policy refused, so the label can point the
            // admin at the page that fixes it: the "-device" stages are the
            // device attestation gate (the ACME page's device attestation
            // card), the "-eab" stages are a credential's domain namespace
            // (the ACME page), the "-guard" stage is the TLS capability
            // ceiling's finalize leaf check (the template configuration),
            // the bare stages are the global allow list (Settings). Labeling
            // them the same would send the admin to the wrong page. Every
            // suffix branch must stay above the bare fallback.
            var source =
                r.Stage.EndsWith("-device", StringComparison.Ordinal)
                    ? "blocked by the device attestation policy"
                : r.Stage.EndsWith("-eab", StringComparison.Ordinal)
                    ? "blocked by the EAB credential's domain namespace"
                : r.Stage.EndsWith("-guard", StringComparison.Ordinal)
                    ? "blocked by the TLS certificate guardrail"
                : "blocked by the domain allow list";
            items.Add(new ActivityItemDto(
                Id: $"rejected-{r.Id}",
                Type: "rejected",
                Cn: FirstRejectedIdentifier(r.RejectedIdentifiers),
                Tmpl: source,
                Timestamp: r.OccurredAt));
        }

        return items
            .OrderByDescending(i => i.Timestamp)
            .Take(take)
            .ToList();
    }

    /// <summary>
    /// The first name from the comma joined rejected identifier column, for
    /// the activity feed's one line summary.
    /// </summary>
    private static string FirstRejectedIdentifier(string commaJoined)
    {
        var comma = commaJoined.IndexOf(',');
        return comma < 0 ? commaJoined : commaJoined[..comma];
    }

    /// <summary>
    /// Daily new-certificate counts for the last <paramref name="days"/> days,
    /// bucketed by request date. Renewals are returned as a zero series because
    /// the CA database does not currently distinguish a renewal from a new
    /// issuance (see the delta doc).
    /// </summary>
    public async Task<RegistrationSeriesDto> GetRegistrationsAsync(
        int days = 30, CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, 90);
        var since = DateTime.UtcNow.Date.AddDays(-(days - 1));

        // Pull the dates in range and bucket in memory — avoids SQLite date-function
        // translation quirks and keeps the query trivially indexable.
        //
        // Certificates only. Since issue #151 the sync also stores pending,
        // denied, and failed requests, and every one of them carries a
        // RequestDate inside this window by construction, because the request
        // passes are bounded to the same recent history. Without this filter a
        // denial would be counted as a certificate issued that day.
        //
        // Revoked counts: it was still issued on the day it was issued, and a
        // trend of what the CA produced must not rewrite its own history every
        // time an operator revokes something.
        var requestDates = await _db.SyncedCertificates
            .Where(c => (c.Status == "Issued" || c.Status == "Revoked") && c.RequestDate >= since)
            .Select(c => c.RequestDate)
            .ToListAsync(cancellationToken);

        var registrations = new int[days];
        foreach (var dt in requestDates)
        {
            var idx = (dt.Date - since).Days;
            if (idx >= 0 && idx < days)
                registrations[idx]++;
        }

        var renewals = new int[days]; // not yet distinguishable — see delta doc

        return new RegistrationSeriesDto(registrations, renewals);
    }

    /// <summary>
    /// Extracts the CN from a subject DN, falling back to the raw string.
    ///
    /// The fallback is reached often rather than rarely: a SAN only certificate
    /// is stored with a bare name and no "CN=" at all, and the feed shows that
    /// name verbatim.
    ///
    /// Until issue #231 this read up to the first comma, which cut a common name
    /// that carried a quoted one in half. <see cref="DistinguishedNameParser"/>
    /// is now the one place that decides where a name ends.
    /// </summary>
    private static string ExtractCn(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject)) return "Unknown";
        return DistinguishedNameParser.CommonName(subject) ?? subject;
    }

    /// <summary>Returns the first identifier value from an ACME identifiers JSON array.</summary>
    private static string FirstIdentifier(string identifiersJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(identifiersJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
            {
                var first = doc.RootElement[0];
                if (first.TryGetProperty("value", out var value))
                    return value.GetString() ?? "unknown";
            }
        }
        catch (JsonException)
        {
            // Malformed payload — fall through to the placeholder.
        }
        return "unknown";
    }
}

/// <summary>
/// Fleet health score plus the donut segment breakdown. Score is null when no
/// certificate is scoreable yet (fresh install), so the frontend can render a
/// neutral empty state instead of a misleading 100.
/// </summary>
public sealed record FleetHealthDto(
    [property: JsonPropertyName("score")] int? Score,
    [property: JsonPropertyName("segments")] IReadOnlyList<HealthSegmentDto> Segments);

/// <summary>A single fleet-health segment (mutually exclusive bucket).</summary>
public sealed record HealthSegmentDto(
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("count")] int Count,
    [property: JsonPropertyName("tone")] string Tone);

/// <summary>Successful validations for one challenge type.</summary>
public sealed record ValidationMethodDto(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("count")] int Count);

/// <summary>A single synthesized activity-feed entry.</summary>
public sealed record ActivityItemDto(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("cn")] string Cn,
    [property: JsonPropertyName("tmpl")] string Tmpl,
    [property: JsonPropertyName("timestamp")] DateTime Timestamp);

/// <summary>Daily issuance and renewal counts (renewals currently always zero).</summary>
public sealed record RegistrationSeriesDto(
    [property: JsonPropertyName("registrations")] IReadOnlyList<int> Registrations,
    [property: JsonPropertyName("renewals")] IReadOnlyList<int> Renewals);
