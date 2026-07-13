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

    // Serializes the timer loop, the ACME issuance nudge, and the manual sync
    // endpoint: only one full CA pull runs at a time.
    private readonly SemaphoreSlim _syncGate = new(1, 1);

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
    }

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
    /// Queries the CA once per disposition we mirror, issued and revoked, pulling
    /// the whole disposition in a single view enumeration and paging it in memory
    /// for the batched database writes. Revoked certificates are synced explicitly
    /// so that a certificate revoked on the CA has its local status updated on the
    /// next cycle. Relying on the default query would only ever return issued rows,
    /// and the dashboard would keep showing a stale "Issued" status forever after a
    /// revocation.
    /// </summary>
    public async Task<CertificateSyncResult> SyncCertificatesAsync(CancellationToken cancellationToken)
    {
        await _syncGate.WaitAsync(cancellationToken);
        try
        {
            return await SyncCertificatesCoreAsync(cancellationToken);
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

        // The CA view has no single "all dispositions" mode, and an unrestricted
        // view would also return denied, pending, and failed request rows that
        // carry no certificate. We mirror exactly the dispositions the dashboard
        // cares about: currently issued certificates and revoked ones. A row has
        // one disposition, so each certificate appears in exactly one pass.
        var statuses = new[] { CertificateStatus.Issued, CertificateStatus.Revoked };

        // Rows the CA handed back with no usable subject anywhere (SAN only
        // certificates with a missing RawCertificate blob). Resolved after the
        // disposition passes from the certificates this proxy issued itself.
        var emptySubjectRows = new List<SyncedCertificate>();

        foreach (var status in statuses)
        {
            // ICertView exposes no server-side row offset and QueryCertificatesAsync
            // re-opens the view on every call, so paging the CA with a growing Skip
            // would re-read the view from the top each batch (O(N^2) COM dispatches).
            // Pull the whole disposition in a single enumeration, then page it in
            // memory for the batched database writes.
            var query = new CertificateQuery(Status: status, Take: int.MaxValue);
            var certs = await _adcsClient.QueryCertificatesAsync(query, cancellationToken);

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
                    "Backfilled {Count} certificate names from the ACME store", filled);
            }
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
            Subject = cert.Subject,
            SubjectAlternativeNames = cert.SubjectAlternativeNames,
            TemplateName = cert.TemplateName,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Status = cert.Status.ToString(),
            Requestor = cert.Requestor,
            RequestDate = cert.RequestDate,
            RevokedAt = cert.RevokedWhen,
            RevokedReason = cert.RevokedReason,
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
        if (!string.IsNullOrWhiteSpace(cert.Subject))
            entity.Subject = cert.Subject;
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
        entity.LastSyncedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Resolves display names for synced rows whose subject is empty by
    /// matching serials against the certificates this proxy issued itself.
    /// Mutates the tracked entities and returns how many were filled; the
    /// caller saves.
    /// </summary>
    private static async Task<int> BackfillSubjectsFromAcmeStoreAsync(
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
            var name = SubjectFromPem(row.CertificatePem) ?? FirstIdentifier(row.IdentifiersJson);
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
