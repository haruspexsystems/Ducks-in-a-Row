using System.Diagnostics;

namespace Certus.Tests.Shared;

/// <summary>
/// A real time safety net around a wait that a regression would leave pending for ever, so the
/// regression reports instead of hanging the run (issue #289). Lifted from
/// <c>CertificateSyncTriggerTests.Bounded</c> in Certus.Core.Tests, which carries the measurements
/// behind it (issue #381), and linked into the test projects that need it as a source file.
///
/// <para>The bound elapsing is a question, not an answer. A completion that costs a thread pool work
/// item arrives late on a saturated pool by exactly as long as the saturation lasts, so a fixed bound
/// asserts that the pool drained in time, which is not a fact about the code under test. When the
/// bound elapses this asks the pool to run one freshly queued work item, and calls the wait a
/// regression only once the pool has shown that it can. A real regression still reports in about
/// <see cref="Attempt"/>, because a healthy pool answers the probe at once.</para>
/// </summary>
internal static class PoolAwareWait
{
    /// <summary>How long one attempt waits before it stops and asks whether the pool is the reason.</summary>
    public static readonly TimeSpan Attempt = TimeSpan.FromSeconds(30);

    /// <summary>The hard stop, so a genuine hang still ends the test rather than the run.</summary>
    public static readonly TimeSpan Ceiling = TimeSpan.FromMinutes(5);

    /// <summary>How long the pool gets to start one queued work item before it counts as starved.</summary>
    private static readonly TimeSpan PoolProbe = TimeSpan.FromSeconds(5);

    /// <summary>What a healthy pool needs to deliver a completion that is already queued.</summary>
    private static readonly TimeSpan Grace = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Awaits <paramref name="wait"/>, throwing a <see cref="TimeoutException"/> that names
    /// <paramref name="what"/> once it is still pending with a responsive thread pool.
    /// </summary>
    public static async Task<T> Bounded<T>(Task<T> wait, string what)
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
                        $"Waiting for {what} did not finish within {Ceiling.TotalMinutes:F0} minutes and the "
                        + "thread pool never became responsive. Treat this as a hung run, not as a verdict.");

                if (!await PoolRanAWorkItemAsync())
                    continue; // Starved: the bound just elapsed, and it proved nothing.

                try
                {
                    return await wait.WaitAsync(Grace);
                }
                catch (TimeoutException)
                {
                    throw new TimeoutException(
                        $"Still waiting for {what} after {elapsed.Elapsed.TotalSeconds:F0}s with a responsive "
                        + "thread pool. This is a regression, not a loaded box.");
                }
            }
        }
    }

    /// <summary>
    /// True when the pool started a freshly queued work item within <see cref="PoolProbe"/>.
    /// preferLocal is false so the probe joins the global first in, first out queue behind any
    /// completion already queued, and its running proves that completion ran.
    /// </summary>
    private static async Task<bool> PoolRanAWorkItemAsync()
    {
        var ran = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ThreadPool.UnsafeQueueUserWorkItem(static tcs => tcs.TrySetResult(), ran, preferLocal: false);

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
}
