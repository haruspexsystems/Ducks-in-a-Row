namespace Certus.Core.ServiceRights;

/// <summary>
/// Keeps the last service rights report for the Settings page, so opening that
/// page does not send the CA and the directory a fresh round of reads every time
/// (issue #440). The CRL card takes the same care for the same reason. A check
/// asked for explicitly ("Check again") always runs.
///
/// Shaped like <see cref="Certus.Core.Health.CaHealthCache"/>: a freshness
/// window, and one run at a time, so concurrent page loads share a check rather
/// than each starting their own. A report is kept per key, the CA and the
/// template list it was run for, so a changed configuration never serves a report
/// about the old one.
/// </summary>
public sealed class ServiceRightsReportCache
{
    private readonly TimeSpan _ttl;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile Entry? _entry;

    /// <summary>Creates a cache with the default ten minute window.</summary>
    public ServiceRightsReportCache() : this(TimeSpan.FromMinutes(10))
    {
    }

    /// <summary>Creates a cache with an explicit window (tests).</summary>
    public ServiceRightsReportCache(TimeSpan ttl)
    {
        _ttl = ttl;
    }

    /// <summary>
    /// The kept report for <paramref name="key"/> while it is fresh, otherwise
    /// the result of one run of <paramref name="run"/>. <paramref name="force"/>
    /// always runs.
    /// </summary>
    public async Task<ServiceRightsReport> GetOrRunAsync(
        string key,
        Func<CancellationToken, Task<ServiceRightsReport>> run,
        bool force,
        CancellationToken cancellationToken)
    {
        if (!force && Fresh(_entry, key) is { } kept)
            return kept;

        // WaitAsync is outside the try so a cancellation here never reaches the Release.
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!force && Fresh(_entry, key) is { } keptMeanwhile)
                return keptMeanwhile;

            var report = await run(cancellationToken).ConfigureAwait(false);
            _entry = new Entry(key, report, DateTime.UtcNow);
            return report;
        }
        finally
        {
            _gate.Release();
        }
    }

    private ServiceRightsReport? Fresh(Entry? entry, string key) =>
        entry is not null
        && string.Equals(entry.Key, key, StringComparison.Ordinal)
        && DateTime.UtcNow - entry.CapturedAtUtc < _ttl
            ? entry.Report
            : null;

    private sealed record Entry(string Key, ServiceRightsReport Report, DateTime CapturedAtUtc);
}
