using System.Diagnostics;
using Certus.Core.Services;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Services;

/// <summary>
/// Tests for the sync wake trigger: immediate fires, buffered fires, interval
/// timeout behavior, and debounce coalescing for ACME issuance bursts.
///
/// Every test drives a <see cref="FakeTimeProvider"/> rather than sleeping.
/// FireDebounced arms its timer synchronously, so Advance is what expires the
/// window, and the callback runs on the advancing thread before Advance returns.
/// The wall clock version of this class flaked under a loaded machine (issue
/// #289): a 20 ms debounce went undelivered inside a 10 second wait, which no
/// larger timeout could have fixed.
///
/// What Advance cannot do is deliver the result to the awaiting test. Whether the
/// wake comes from Fire writing to the channel or from the timeout cancelling the
/// read, resuming WaitAsync costs one thread pool work item, so every test here is
/// exposed to a saturated pool no matter which assertion it makes. That is why the
/// safety net is Bounded and not a bare timeout, and why no test in this class may
/// read elapsed wall time as evidence about the trigger (issue #381).
/// </summary>
public class CertificateSyncTriggerTests
{
    private static readonly TimeSpan LongWait = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ShortWait = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// How long a single attempt waits before it stops and asks whether the thread
    /// pool is the reason. Not a verdict on its own, see <see cref="Bounded"/>.
    /// </summary>
    private static readonly TimeSpan Attempt = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The hard stop, so a genuine hang still ends the test rather than the run.
    /// Only reached when the pool never recovers, which kills the suite anyway.
    /// </summary>
    private static readonly TimeSpan Ceiling = TimeSpan.FromMinutes(5);

    /// <summary>How long the pool gets to start one queued work item before it counts as starved.</summary>
    private static readonly TimeSpan PoolProbe = TimeSpan.FromSeconds(5);

    /// <summary>
    /// What a healthy pool needs to deliver a completion that is already queued.
    /// Measured in microseconds; a second is pure headroom.
    /// </summary>
    private static readonly TimeSpan Grace = TimeSpan.FromSeconds(1);

    /// <summary>
    /// A real time safety net around every wait. The fake clock moves only where a
    /// test calls Advance, so a regression that stopped a fire arriving would leave
    /// the wait pending forever and hang the run rather than fail it. This turns
    /// that back into a reported failure (issue #289).
    ///
    /// It is never the assertion, and since issue #381 it no longer pretends that a
    /// bare wall clock bound can be one. Completing
    /// <see cref="CertificateSyncTrigger.WaitAsync"/> always costs one thread pool
    /// work item, because the channel it reads leaves AllowSynchronousContinuations
    /// at its default of false, so a saturated pool delays the completion by exactly
    /// as long as the saturation lasts: measured at 5001.9 ms against a 5000 ms hold
    /// with 32 blocking work items on four cores. Neither ConfigureAwait(false) nor
    /// blocking on the task escapes it, because the cost is paid before the test
    /// observes anything (both measured at the same 5 s, against 0.6 ms and 0.3 ms
    /// unloaded). A fixed bound therefore asserts that the pool's queue drains in
    /// time, which is not a fact about this class, and that is the assertion that
    /// failed on a four way loaded box on 2026-09-04.
    ///
    /// So the bound elapsing is a question, not an answer: ask the pool to run one
    /// work item, and only call the wait a regression once the pool has shown that
    /// it can. A real regression still reports in about <see cref="Attempt"/>,
    /// because a healthy pool answers the probe immediately.
    /// </summary>
    private static async Task<bool> Bounded(Task<bool> wait)
    {
        var elapsed = Stopwatch.StartNew();

        while (true)
        {
            try
            {
                return await wait.WaitAsync(Attempt);
            }
            catch (TimeoutException)
            {
                if (elapsed.Elapsed >= Ceiling)
                    throw new TimeoutException(
                        $"The wait did not complete within {Ceiling.TotalMinutes:F0} minutes and the "
                        + "thread pool never became responsive. Treat this as a hung run, not as a "
                        + "verdict on the trigger.");

                if (!await PoolRanAWorkItemAsync())
                    continue; // Starved: the bound just elapsed, it proved nothing.

                // The pool is running work, so a completion that had been queued
                // would have arrived. One more short look settles whether it did.
                try
                {
                    return await wait.WaitAsync(Grace);
                }
                catch (TimeoutException)
                {
                    throw new TimeoutException(
                        $"The wait was still pending after {elapsed.Elapsed.TotalSeconds:F0}s with a "
                        + "responsive thread pool, so the fire never arrived. This is a regression in "
                        + "CertificateSyncTrigger, not a loaded box.");
                }
            }
        }
    }

    /// <summary>
    /// True when the thread pool started a freshly queued work item within
    /// <see cref="PoolProbe"/>. This is the same resource the completion of a wait
    /// needs, so a false here means the elapsed bound measured the box and not the
    /// code under test.
    ///
    /// preferLocal is false on purpose, and it is what makes the answer safe rather
    /// than merely usually right. The global queue is first in, first out, so a probe
    /// queued there sits behind the completion this method is asking about, and the
    /// probe running proves the completion already ran. Left to prefer a local queue
    /// it would be pushed on the current worker's own stack, which is last in, first
    /// out and is drained ahead of the global one, so the probe could overtake the
    /// very completion it is meant to vouch for and report a healthy pool while the
    /// answer was still queued.
    /// </summary>
    private static async Task<bool> PoolRanAWorkItemAsync()
    {
        var ran = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ThreadPool.UnsafeQueueUserWorkItem(
            static tcs => tcs.TrySetResult(), ran, preferLocal: false);

        try
        {
            await ran.Task.WaitAsync(PoolProbe);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
    }

    [Fact]
    public async Task Fire_WakesAPendingWait()
    {
        var time = new FakeTimeProvider();
        using var trigger = new CertificateSyncTrigger(time);
        var wait = trigger.WaitAsync(LongWait, CancellationToken.None);

        trigger.Fire();

        (await Bounded(wait)).Should().BeTrue();
    }

    [Fact]
    public async Task Fire_BeforeAnyWait_IsBufferedForTheNextWait()
    {
        var time = new FakeTimeProvider();
        using var trigger = new CertificateSyncTrigger(time);

        trigger.Fire();

        (await Bounded(trigger.WaitAsync(LongWait, CancellationToken.None))).Should().BeTrue();
    }

    [Fact]
    public async Task Wait_ReturnsFalseWhenTheTimeoutElapses()
    {
        var time = new FakeTimeProvider();
        using var trigger = new CertificateSyncTrigger(time);

        var wait = trigger.WaitAsync(ShortWait, CancellationToken.None);
        time.Advance(ShortWait);

        (await Bounded(wait)).Should().BeFalse();
    }

    [Fact]
    public async Task Wait_ThrowsOnlyOnCallerCancellation()
    {
        var time = new FakeTimeProvider();
        using var trigger = new CertificateSyncTrigger(time);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => trigger.WaitAsync(LongWait, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task FireDebounced_CoalescesABurstIntoOneFire()
    {
        var time = new FakeTimeProvider();
        using var trigger = new CertificateSyncTrigger(time);
        var delay = TimeSpan.FromMilliseconds(50);

        trigger.FireDebounced(delay);
        trigger.FireDebounced(delay);
        trigger.FireDebounced(delay);

        time.Advance(delay);

        // The burst produces exactly one fire...
        (await Bounded(trigger.WaitAsync(LongWait, CancellationToken.None))).Should().BeTrue();

        // ...and nothing more is pending afterwards. Advancing well past the
        // window proves the other two calls left no timer armed behind them.
        var second = trigger.WaitAsync(TimeSpan.FromMilliseconds(200), CancellationToken.None);
        time.Advance(TimeSpan.FromMilliseconds(200));
        (await Bounded(second)).Should().BeFalse();
    }

    [Fact]
    public async Task FireDebounced_AfterTheWindowCloses_FiresAgain()
    {
        var time = new FakeTimeProvider();
        using var trigger = new CertificateSyncTrigger(time);
        var delay = TimeSpan.FromMilliseconds(20);

        trigger.FireDebounced(delay);
        time.Advance(delay);
        (await Bounded(trigger.WaitAsync(LongWait, CancellationToken.None))).Should().BeTrue();

        trigger.FireDebounced(delay);
        time.Advance(delay);
        (await Bounded(trigger.WaitAsync(LongWait, CancellationToken.None))).Should().BeTrue();
    }

}
