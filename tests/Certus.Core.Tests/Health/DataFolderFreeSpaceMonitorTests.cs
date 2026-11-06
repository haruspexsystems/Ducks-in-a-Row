using Certus.Core.Configuration;
using Certus.Core.Health;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Certus.Core.Tests.Health;

/// <summary>
/// The free space monitor's verdict and, above all, its log throttle: the
/// readiness endpoint is anonymous, so a warning per probe would let anyone
/// fill the log file by polling it (issue #632).
/// </summary>
public class DataFolderFreeSpaceMonitorTests
{
    private const long Megabyte = 1024L * 1024L;

    private readonly ILogger<DataFolderFreeSpaceMonitor> _logger =
        Substitute.For<ILogger<DataFolderFreeSpaceMonitor>>();
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 10, 22, 8, 0, 0, TimeSpan.Zero));
    private long? _freeBytes = 4096 * Megabyte;

    private DataFolderFreeSpaceMonitor Create(long thresholdMegabytes = 1024) =>
        new(Path.GetTempPath(),
            Options.Create(new CertusOptions { FreeSpaceWarningMegabytes = thresholdMegabytes }),
            _logger, _clock, _ => _freeBytes);

    private int Logged(LogLevel level) => _logger.ReceivedCalls()
        .Count(call => call.GetMethodInfo().Name == nameof(ILogger.Log)
                       && call.GetArguments()[0] is LogLevel l && l == level);

    [Fact]
    public void Defaults_WarnBelowOneGigabyte()
    {
        new CertusOptions().FreeSpaceWarningMegabytes.Should().Be(1024);
    }

    [Fact]
    public void Check_AboveTheThreshold_IsNotLow_AndLogsNothing()
    {
        var report = Create().Check();

        report.Low.Should().BeFalse();
        report.FreeBytes.Should().Be(4096 * Megabyte);
        Logged(LogLevel.Warning).Should().Be(0);
    }

    [Fact]
    public void Check_ExactlyAtTheThreshold_IsNotLow()
    {
        _freeBytes = 1024 * Megabyte;

        Create().Check().Low.Should().BeFalse("the threshold is where the warning starts, not where it ends");
    }

    [Fact]
    public void Check_BelowTheThreshold_IsLow_AndWarnsOnce_NotPerProbe()
    {
        _freeBytes = 10 * Megabyte;
        var monitor = Create();

        for (var i = 0; i < 100; i++)
            monitor.Check().Low.Should().BeTrue();

        Logged(LogLevel.Warning).Should().Be(1);
    }

    [Fact]
    public void Check_StillLowADayLater_WarnsAgain()
    {
        _freeBytes = 10 * Megabyte;
        var monitor = Create();
        monitor.Check();

        _clock.Advance(DataFolderFreeSpaceMonitor.RepeatInterval - TimeSpan.FromMinutes(1));
        monitor.Check();
        Logged(LogLevel.Warning).Should().Be(1, "the repeat is daily, not sooner");

        _clock.Advance(TimeSpan.FromMinutes(1));
        monitor.Check();
        Logged(LogLevel.Warning).Should().Be(2);
    }

    [Fact]
    public void Check_Recovering_LogsOnceAtInformation_AndWarnsAgainOnTheNextDrop()
    {
        _freeBytes = 10 * Megabyte;
        var monitor = Create();
        monitor.Check();

        _freeBytes = 4096 * Megabyte;
        monitor.Check().Low.Should().BeFalse();
        monitor.Check();
        Logged(LogLevel.Information).Should().Be(1);

        _freeBytes = 10 * Megabyte;
        monitor.Check().Low.Should().BeTrue();
        Logged(LogLevel.Warning).Should().Be(2, "a new drop is a new event, whatever the clock says");
    }

    [Fact]
    public void Check_AbsurdThreshold_DoesNotWrapNegative()
    {
        // 9,999,999,999,999 MB times a megabyte is past long.MaxValue. Multiplied
        // blindly it wraps negative and the check never fires; saturated, every
        // real volume reads as low, which is the honest answer to that setting.
        _freeBytes = 4096 * Megabyte;

        Create(thresholdMegabytes: 9_999_999_999_999).Check().Low.Should().BeTrue();
    }

    [Fact]
    public void Check_ThresholdZero_IsOff()
    {
        _freeBytes = 0;
        var report = Create(thresholdMegabytes: 0).Check();

        report.Low.Should().BeFalse();
        report.Describe().Should().Be("check disabled");
        Logged(LogLevel.Warning).Should().Be(0);
    }

    [Fact]
    public void Check_VolumeUnreadable_IsUnknown_NotLow()
    {
        _freeBytes = null;
        var report = Create().Check();

        report.Low.Should().BeFalse();
        report.Describe().Should().Be("unknown");
    }

    [Fact]
    public void Check_WithTheRealProbe_ReadsTheVolumeOfTheFolder()
    {
        // The default probe on a folder that exists answers a number. The dev
        // box has more than a megabyte free or nothing else in this suite runs.
        var monitor = new DataFolderFreeSpaceMonitor(
            Path.GetTempPath(), Options.Create(new CertusOptions { FreeSpaceWarningMegabytes = 1 }), _logger);

        var report = monitor.Check();

        report.FreeBytes.Should().NotBeNull().And.BeGreaterThan(Megabyte);
        report.Low.Should().BeFalse();
    }
}
