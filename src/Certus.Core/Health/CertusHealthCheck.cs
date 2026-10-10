using Certus.Core.Adcs;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Health;

/// <summary>
/// Health check that verifies:
/// 1. Database connectivity (SQLite can be queried)
/// 2. ADCS CA accessibility (optional — degraded if unavailable)
/// </summary>
public sealed class CertusHealthCheck : IHealthCheck
{
    private readonly CertusDbContext _db;
    private readonly IAdcsClient _adcsClient;
    private readonly CaHealthCache _caHealthCache;
    private readonly ILogger<CertusHealthCheck> _logger;

    public CertusHealthCheck(
        CertusDbContext db,
        IAdcsClient adcsClient,
        CaHealthCache caHealthCache,
        ILogger<CertusHealthCheck> logger)
    {
        _db = db;
        _adcsClient = adcsClient;
        _caHealthCache = caHealthCache;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var data = new Dictionary<string, object>();
        var isHealthy = true;
        string? degradedReason = null;

        // Check database connectivity. The result is not surfaced over /health
        // (the default writer emits only the status), so a single connectivity
        // probe is enough; counting rows would be wasted work.
        try
        {
            if (await _db.Database.CanConnectAsync(cancellationToken))
            {
                data["database"] = "connected";
            }
            else
            {
                data["database"] = "unreachable";
                isHealthy = false;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Health check: database connectivity check failed");
            data["database"] = $"error: {ex.Message}";
            isHealthy = false;
        }

        // Check CA connectivity. A CA problem alone is degraded, not unhealthy
        // (we can still serve cached data), so record it and decide at the end.
        // We never return here: a database failure must outrank CA degradation.
        // The probe runs through CaHealthCache so the anonymous readiness endpoint
        // cannot drive a fresh CA round trip on every request.
        try
        {
            var ca = await _caHealthCache.GetOrProbeAsync(async ct =>
            {
                try
                {
                    var caInfo = await _adcsClient.GetCaInfoAsync(ct);
                    return new CaHealthSnapshot(caInfo.IsAccessible, caInfo.Name, null);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw; // do not cache a cancelled probe
                }
                catch (CaUnavailableException)
                {
                    // An unreachable CA, or none configured yet. GetCaInfoAsync
                    // throws this since issue #440 rather than answering "not
                    // accessible", and it must still read exactly as it did:
                    // degraded, with no warning every 30 seconds.
                    return new CaHealthSnapshot(false, null, null);
                }
                catch (CaAccessDeniedException ex)
                {
                    // A CA that refuses the service's account. Unlike an outage
                    // it will not pass on its own, so the reason stays in the
                    // data, naming the right to grant. AdcsClient has already
                    // logged it at Error, so there is no second warning here on
                    // every probe.
                    return new CaHealthSnapshot(false, null, ex.Message);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Health check: CA connectivity check failed");
                    return new CaHealthSnapshot(false, null, ex.Message);
                }
            }, cancellationToken);

            data["ca"] = ca.Error is not null
                ? $"error: {ca.Error}"
                : (ca.IsAccessible ? "accessible" : "not accessible");
            if (ca.Name is not null)
                data["caName"] = ca.Name;

            if (ca.Error is not null)
                degradedReason = "CA connectivity check failed";
            else if (!ca.IsAccessible)
                degradedReason = "CA is not accessible";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }

        // Database failure outranks CA degradation: if the database is down the
        // instance cannot serve, so report Unhealthy (503) even when the CA is also down.
        if (!isHealthy)
        {
            return HealthCheckResult.Unhealthy("System health check failed", data: data);
        }

        return degradedReason is not null
            ? HealthCheckResult.Degraded(degradedReason, data: data)
            : HealthCheckResult.Healthy("All systems operational", data);
    }
}
