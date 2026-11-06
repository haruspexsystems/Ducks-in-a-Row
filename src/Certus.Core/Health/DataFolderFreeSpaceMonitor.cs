using Certus.Core.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Health;

/// <summary>
/// Watches the free space on the volume that holds the data folder, for the
/// health check (issue #632, CRA R04). Every ACME table grows until the
/// retention rule (#637) prunes it, the SQLite database and its write ahead
/// log share the volume with the log files, and a full volume turns every
/// write into an error with no warning first. This reports the number; it
/// never deletes anything.
///
/// <para>
/// A singleton, because the warning has to be throttled across health probes.
/// The readiness endpoint is anonymous, so a warning per probe would let
/// anyone fill the log file by polling it. The warning is written once when
/// the volume drops below the threshold, then at most once a day while it
/// stays there, and a recovery is written once at Information.
/// </para>
/// </summary>
public sealed class DataFolderFreeSpaceMonitor
{
    /// <summary>How often the warning repeats while the volume stays low.</summary>
    internal static readonly TimeSpan RepeatInterval = TimeSpan.FromDays(1);

    /// <summary>One megabyte, the unit the setting and the health data use.</summary>
    internal const long Megabyte = 1024L * 1024L;

    private readonly string _dataDirectory;
    private readonly IOptions<CertusOptions> _options;
    private readonly ILogger<DataFolderFreeSpaceMonitor> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly Func<string, long?> _probe;
    private readonly object _gate = new();

    private bool _low;
    private DateTimeOffset _lastWarnedAt;

    /// <summary>
    /// Creates the monitor for a data folder. <paramref name="probe"/> reads the
    /// free bytes on the volume that holds a path, or null when it cannot; tests
    /// supply one, production uses <see cref="DriveInfo"/>.
    /// </summary>
    public DataFolderFreeSpaceMonitor(
        string dataDirectory,
        IOptions<CertusOptions> options,
        ILogger<DataFolderFreeSpaceMonitor> logger,
        TimeProvider? timeProvider = null,
        Func<string, long?>? probe = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        _dataDirectory = dataDirectory;
        _options = options;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _probe = probe ?? ReadFreeBytes;
    }

    /// <summary>The folder whose volume is watched.</summary>
    public string DataDirectory => _dataDirectory;

    /// <summary>
    /// Reads the volume and reports. Degraded (<see cref="FreeSpaceReport.Low"/>)
    /// only when the free space is known and below the threshold; a volume the
    /// probe cannot read is reported as unknown, not as low, because a failed
    /// read says nothing about the disk and a degraded readiness probe with no
    /// evidence would send an operator looking for space that is there.
    /// </summary>
    public FreeSpaceReport Check()
    {
        var thresholdMegabytes = _options.Value.FreeSpaceWarningMegabytes;
        var enabled = thresholdMegabytes > 0;
        // Saturate rather than multiply blindly: a value past long.MaxValue / 1 MB
        // would wrap negative and the check would never fire again.
        var thresholdBytes = enabled ? Math.Min(thresholdMegabytes, long.MaxValue / Megabyte) * Megabyte : 0L;
        var freeBytes = _probe(_dataDirectory);
        var low = enabled && freeBytes is { } free && free < thresholdBytes;

        lock (_gate)
        {
            var now = _timeProvider.GetUtcNow();
            if (low && (!_low || now - _lastWarnedAt >= RepeatInterval))
            {
                _logger.LogWarning(
                    "Free space on the volume holding the data folder {DataDirectory} is " +
                    "{FreeMegabytes} MB, below the {ThresholdMegabytes} MB warning threshold " +
                    "(Certus:FreeSpaceWarningMegabytes). The health endpoint reports degraded " +
                    "until space is freed; nothing is deleted automatically",
                    _dataDirectory, ToMegabytes(freeBytes!.Value), thresholdMegabytes);
                _lastWarnedAt = now;
            }
            else if (!low && _low)
            {
                _logger.LogInformation(
                    "Free space on the volume holding the data folder {DataDirectory} is back " +
                    "above the {ThresholdMegabytes} MB warning threshold",
                    _dataDirectory, thresholdMegabytes);
            }
            _low = low;
        }

        return new FreeSpaceReport(freeBytes, thresholdMegabytes, low);
    }

    private static long ToMegabytes(long bytes) => bytes / Megabyte;

    private static long? ReadFreeBytes(string path)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(path));
            if (string.IsNullOrEmpty(root))
                return null;
            return new DriveInfo(root).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }
}

/// <summary>
/// One reading. <see cref="FreeBytes"/> is null when the volume could not be
/// read; <see cref="ThresholdMegabytes"/> at or below zero means the check is
/// off; <see cref="Low"/> is the degraded verdict.
/// </summary>
public sealed record FreeSpaceReport(long? FreeBytes, long ThresholdMegabytes, bool Low)
{
    /// <summary>The line the health endpoint's data carries.</summary>
    public string Describe()
    {
        if (ThresholdMegabytes <= 0)
            return "check disabled";
        if (FreeBytes is null)
            return "unknown";
        var free = FreeBytes.Value / DataFolderFreeSpaceMonitor.Megabyte;
        return Low
            ? $"{free} MB free, below the {ThresholdMegabytes} MB warning threshold"
            : $"{free} MB free";
    }
}

/// <summary>Registration shared by both hosts, so the deployed one cannot miss it.</summary>
public static class DataFolderFreeSpaceMonitorExtensions
{
    /// <summary>
    /// Registers the monitor for the data directory the host resolved. The health
    /// check takes it as a required dependency, so a host that forgets this fails
    /// to build the check rather than silently skipping the disk.
    /// </summary>
    public static IServiceCollection AddDataFolderFreeSpaceMonitor(
        this IServiceCollection services, string dataDirectory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        services.TryAddSingleton(sp => new DataFolderFreeSpaceMonitor(
            dataDirectory,
            sp.GetRequiredService<IOptions<CertusOptions>>(),
            sp.GetRequiredService<ILogger<DataFolderFreeSpaceMonitor>>(),
            sp.GetService<TimeProvider>()));

        return services;
    }
}
