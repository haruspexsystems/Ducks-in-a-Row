using Certus.Core.Alerts;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// The cooldown on operator triggered test sends (issue #161). Driven by a fake
/// clock so none of this waits a real minute.
/// </summary>
public class AlertTestThrottleTests
{
    [Fact]
    public void TryAcquire_FirstCall_Succeeds()
    {
        var sut = new AlertTestThrottle(new TestTimeProvider());

        sut.TryAcquire(out var retryAfter).Should().BeTrue();
        retryAfter.Should().Be(TimeSpan.Zero);
    }

    [Fact]
    public void TryAcquire_SecondCallWithinTheWindow_FailsWithRemainingTime()
    {
        var time = new TestTimeProvider();
        var sut = new AlertTestThrottle(time);

        sut.TryAcquire(out _).Should().BeTrue();
        time.Now = time.Now.AddSeconds(20);

        sut.TryAcquire(out var retryAfter).Should().BeFalse();
        retryAfter.TotalSeconds.Should().Be(AlertTestThrottle.CooldownSeconds - 20);
    }

    [Fact]
    public void TryAcquire_AfterTheWindow_SucceedsAgain()
    {
        var time = new TestTimeProvider();
        var sut = new AlertTestThrottle(time);

        sut.TryAcquire(out _).Should().BeTrue();
        time.Now = time.Now.AddSeconds(AlertTestThrottle.CooldownSeconds);

        sut.TryAcquire(out _).Should().BeTrue();
    }

    [Fact]
    public void TryAcquire_RefusalDoesNotExtendTheWindow()
    {
        // A held down button must not push the cooldown out indefinitely. Only a
        // successful acquire arms it.
        var time = new TestTimeProvider();
        var sut = new AlertTestThrottle(time);

        sut.TryAcquire(out _).Should().BeTrue();

        time.Now = time.Now.AddSeconds(30);
        sut.TryAcquire(out _).Should().BeFalse();

        time.Now = time.Now.AddSeconds(30);
        sut.TryAcquire(out _).Should().BeTrue();
    }

    [Fact]
    public void TryAcquire_IsAtomicUnderConcurrentCallers()
    {
        // The check and the arm happen under one lock, so a burst of presses
        // cannot produce two overlapping sends. This is why the throttle arms on
        // entry rather than on completion.
        var sut = new AlertTestThrottle(new TestTimeProvider());
        var winners = 0;

        Parallel.For(0, 64, i =>
        {
            if (sut.TryAcquire(out _))
                Interlocked.Increment(ref winners);
        });

        winners.Should().Be(1);
    }

    /// <summary>A controllable clock, the same shape NonceServiceTests uses.</summary>
    private sealed class TestTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
