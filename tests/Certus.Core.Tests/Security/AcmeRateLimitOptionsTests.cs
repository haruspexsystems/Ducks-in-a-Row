using Certus.Core.Security;
using FluentAssertions;
using Xunit;

namespace Certus.Core.Tests.Security;

/// <summary>
/// The Retry-After a refusal reports is computed from the options rather than
/// read off the limiter, because SlidingWindowRateLimiter supplies no RetryAfter
/// metadata of its own (issue #263). These pin the arithmetic that stands in for
/// it, including the two values that would otherwise divide by zero or report
/// nothing useful.
/// </summary>
public class AcmeRateLimitOptionsTests
{
    [Fact]
    public void RetryAfterSeconds_AtTheDefaults_IsOneSegmentNotTheWholeWindow()
    {
        var options = new AcmeRateLimitOptions();

        // 60 second window over 6 segments. The whole window, 60, is what a fixed
        // window limiter reports and is what this deliberately does not say.
        options.RetryAfterSeconds.Should().Be(10);
        options.RetryAfterSeconds.Should().NotBe(options.WindowSeconds);
    }

    [Theory]
    [InlineData(60, 6, 10)]
    [InlineData(60, 1, 60)]   // one segment is a fixed window, so the whole window
    [InlineData(60, 12, 5)]
    [InlineData(10, 3, 4)]    // 3.33 rounds up: never advertise sooner than a segment
    [InlineData(1, 6, 1)]     // never zero, which would invite an immediate retry
    public void RetryAfterSeconds_RoundsUpAndStaysPositive(
        int windowSeconds, int segments, int expected)
    {
        var options = new AcmeRateLimitOptions
        {
            WindowSeconds = windowSeconds,
            SegmentsPerWindow = segments
        };

        options.RetryAfterSeconds.Should().Be(expected);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-4)]
    public void RetryAfterSeconds_WithAnUnusableSegmentCount_DoesNotThrow(int segments)
    {
        // StartupValidator warns about these and the limiter throws on them, but
        // this property is read from the rejection path, which must not be the
        // thing that faults while reporting a refusal.
        var options = new AcmeRateLimitOptions { SegmentsPerWindow = segments };

        options.RetryAfterSeconds.Should().Be(60);
    }

    [Theory]
    [InlineData(0, 60, 1)]        // below the floor the limiter throws on
    [InlineData(-4, 60, 1)]
    [InlineData(6, 60, 6)]        // the default is left alone
    [InlineData(60, 60, 60)]      // one second a segment is the finest that means anything
    [InlineData(600, 60, 60)]     // finer than a second is clamped away
    [InlineData(100_000, 60, 60)]
    [InlineData(10, 0, 1)]        // a nonsense window cannot produce a nonsense ceiling
    public void EffectiveSegmentsPerWindow_IsClampedAtBothEnds(
        int segments, int windowSeconds, int expected)
    {
        // The count is held per partition and a partition is a source address, so
        // an unclamped value is multiplied by the number of callers. Retry-After
        // is whole seconds, so a segment shorter than one cannot be expressed
        // anyway.
        var options = new AcmeRateLimitOptions
        {
            SegmentsPerWindow = segments,
            WindowSeconds = windowSeconds
        };

        options.EffectiveSegmentsPerWindow.Should().Be(expected);
    }

    [Fact]
    public void RetryAfterSeconds_ReadsTheClampedSegmentCount_NotTheRawOne()
    {
        // The limiter builds its window from the same clamped value. If these two
        // read different properties, the interval a refusal advertises would not
        // be the interval the limiter actually works to.
        var options = new AcmeRateLimitOptions
        {
            SegmentsPerWindow = 100_000,
            WindowSeconds = 60
        };

        options.EffectiveSegmentsPerWindow.Should().Be(60);
        options.RetryAfterSeconds.Should().Be(1);
    }
}
