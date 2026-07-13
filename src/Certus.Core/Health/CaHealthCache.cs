namespace Certus.Core.Health;

/// <summary>
/// Caches the result of the CA connectivity probe for a short window so the anonymous
/// readiness endpoint cannot drive a fresh CA round trip on every request. Registered as a
/// singleton and shared by every health check invocation.
/// </summary>
public sealed class CaHealthCache
{
    private readonly TimeSpan _ttl;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile Entry? _entry;

    /// <summary>Creates a cache with the default 30 second freshness window.</summary>
    public CaHealthCache() : this(TimeSpan.FromSeconds(30))
    {
    }

    /// <summary>Creates a cache with an explicit freshness window (used by tests).</summary>
    public CaHealthCache(TimeSpan ttl)
    {
        _ttl = ttl;
    }

    /// <summary>
    /// Returns the cached snapshot while it is still within the freshness window; otherwise
    /// runs <paramref name="probe"/> once, stores its result, and returns it. Concurrent
    /// callers that arrive while the cache is stale wait on a single probe rather than each
    /// running their own.
    /// </summary>
    public async Task<CaHealthSnapshot> GetOrProbeAsync(
        Func<CancellationToken, Task<CaHealthSnapshot>> probe,
        CancellationToken cancellationToken)
    {
        var entry = _entry;
        if (entry is not null && DateTime.UtcNow - entry.CapturedAtUtc < _ttl)
            return entry.Snapshot;

        // WaitAsync is outside the try so a cancellation here never reaches the Release.
        await _gate.WaitAsync(cancellationToken);
        try
        {
            // Re-check: another caller may have refreshed the entry while we waited.
            entry = _entry;
            if (entry is not null && DateTime.UtcNow - entry.CapturedAtUtc < _ttl)
                return entry.Snapshot;

            var snapshot = await probe(cancellationToken);
            _entry = new Entry(snapshot, DateTime.UtcNow);
            return snapshot;
        }
        finally
        {
            _gate.Release();
        }
    }

    private sealed record Entry(CaHealthSnapshot Snapshot, DateTime CapturedAtUtc);
}

/// <summary>
/// Immutable result of one CA connectivity probe. <see cref="Error"/> is non null when the
/// probe threw; otherwise <see cref="IsAccessible"/> reports whether the CA answered.
/// </summary>
public sealed record CaHealthSnapshot(bool IsAccessible, string? Name, string? Error);
