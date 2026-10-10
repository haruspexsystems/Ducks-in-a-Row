using System.Threading.Channels;

namespace Certus.Core.Services;

/// <summary>
/// Wakes the certificate sync loop ahead of its interval. Registered as a
/// singleton shared by the background sync service (which waits on it), the
/// manual sync endpoint, and the ACME issuance path (which nudges it so a
/// freshly issued certificate reaches the dashboard inventory without waiting
/// for the next timer tick).
/// </summary>
public sealed class CertificateSyncTrigger : IDisposable
{
    // Capacity one with DropWrite: any number of fires while a wake is already
    // queued collapse into that single wake. The sync always pulls the full
    // inventory, so one wake covers every request that preceded it.
    private readonly Channel<bool> _channel = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });

    private readonly TimeProvider _timeProvider;

    // One timer for the lifetime of the trigger, re-armed by each debounce
    // window. Created disarmed so its callback cannot run before the field is
    // assigned; _debouncePending guarantees only one arm is ever outstanding,
    // which is what makes a single shared timer equivalent to one per call.
    private readonly ITimer _debounceTimer;

    private int _debouncePending;

    /// <summary>
    /// Creates the trigger. The optional <paramref name="timeProvider"/> lets tests drive
    /// the debounce window and the wait timeout without sleeping; production resolves the
    /// default (<see cref="TimeProvider.System"/>) because the DI registration passes no
    /// argument.
    /// </summary>
    public CertificateSyncTrigger(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _debounceTimer = _timeProvider.CreateTimer(
            _ =>
            {
                // Reset before firing so a call arriving right after the fire
                // opens a fresh debounce window instead of being swallowed.
                Volatile.Write(ref _debouncePending, 0);
                Fire();
            },
            state: null,
            dueTime: Timeout.InfiniteTimeSpan,
            period: Timeout.InfiniteTimeSpan);
    }

    /// <summary>
    /// Requests a sync now. Extra fires while one is already queued are dropped.
    /// </summary>
    public void Fire() => _channel.Writer.TryWrite(true);

    /// <summary>
    /// Requests a sync after a short delay, coalescing a burst of calls into a
    /// single fire. The delay runs from the first call of the burst, so a
    /// steady stream of calls cannot postpone the sync indefinitely.
    /// </summary>
    /// <remarks>
    /// The window is armed synchronously here rather than inside a queued work
    /// item, so a busy thread pool can delay the fire but can never delay the
    /// window from opening, and can never strand <c>_debouncePending</c> set
    /// (which would silently drop every later debounce for the life of the
    /// process).
    /// </remarks>
    public void FireDebounced(TimeSpan delay)
    {
        if (Interlocked.CompareExchange(ref _debouncePending, 1, 0) != 0)
            return;

        try
        {
            _debounceTimer.Change(delay, Timeout.InfiniteTimeSpan);
        }
        catch (ObjectDisposedException)
        {
            // Host shutdown disposed the trigger while an issuance was still in
            // flight. The nudge is best effort and there is no sync loop left to
            // wake, so dropping it is the whole response.
            Volatile.Write(ref _debouncePending, 0);
        }
    }

    /// <summary>
    /// Waits for a fire or the timeout, whichever comes first. Returns true
    /// when fired, false when the timeout elapsed. Throws only when the
    /// caller's token is canceled.
    /// </summary>
    public async Task<bool> WaitAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        // The timeout rides the injected clock rather than CancelAfter, which
        // always uses the system one, so a test can expire the wait on demand.
        using var timeoutSource = new CancellationTokenSource(timeout, _timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, timeoutSource.Token);
        try
        {
            return await _channel.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false; // The interval elapsed with no trigger.
        }
    }

    /// <summary>Releases the debounce timer. The DI container calls this at host shutdown.</summary>
    public void Dispose() => _debounceTimer.Dispose();
}
