using System.Threading.Channels;

namespace Certus.Core.Services;

/// <summary>
/// Wakes the certificate sync loop ahead of its interval. Registered as a
/// singleton shared by the background sync service (which waits on it), the
/// manual sync endpoint, and the ACME issuance path (which nudges it so a
/// freshly issued certificate reaches the dashboard inventory without waiting
/// for the next timer tick).
/// </summary>
public sealed class CertificateSyncTrigger
{
    // Capacity one with DropWrite: any number of fires while a wake is already
    // queued collapse into that single wake. The sync always pulls the full
    // inventory, so one wake covers every request that preceded it.
    private readonly Channel<bool> _channel = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });

    private int _debouncePending;

    /// <summary>
    /// Requests a sync now. Extra fires while one is already queued are dropped.
    /// </summary>
    public void Fire() => _channel.Writer.TryWrite(true);

    /// <summary>
    /// Requests a sync after a short delay, coalescing a burst of calls into a
    /// single fire. The delay runs from the first call of the burst, so a
    /// steady stream of calls cannot postpone the sync indefinitely.
    /// </summary>
    public void FireDebounced(TimeSpan delay)
    {
        if (Interlocked.CompareExchange(ref _debouncePending, 1, 0) != 0)
            return;

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(delay).ConfigureAwait(false);
            }
            finally
            {
                // Reset before firing so a call arriving right after the fire
                // opens a fresh debounce window instead of being swallowed.
                Volatile.Write(ref _debouncePending, 0);
                Fire();
            }
        });
    }

    /// <summary>
    /// Waits for a fire or the timeout, whichever comes first. Returns true
    /// when fired, false when the timeout elapsed. Throws only when the
    /// caller's token is canceled.
    /// </summary>
    public async Task<bool> WaitAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(timeout);
        try
        {
            return await _channel.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false; // The interval elapsed with no trigger.
        }
    }
}
