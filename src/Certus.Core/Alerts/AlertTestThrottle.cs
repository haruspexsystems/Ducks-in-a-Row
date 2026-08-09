namespace Certus.Core.Alerts;

/// <summary>
/// A cooldown on operator triggered test sends (issue #161).
///
/// <para>
/// The test button fires outbound SMTP and an HTTP POST on every press. It is
/// already admin only and CSRF protected, so this is not an authorization
/// control; it protects the operator's mail relay and webhook receiver from a
/// held down button, and it stops two admins overlapping.
/// </para>
///
/// <para>Three properties are deliberate and worth stating:</para>
/// <list type="bullet">
/// <item>
/// <b>It arms on entry, not on completion.</b> An SMTP connect can take 30
/// seconds and the webhook client's timeout is 30 seconds, so a cooldown armed
/// at the end would let two concurrent presses both get through while the first
/// was still in flight. Arming at the start makes this a mutual exclusion gate
/// as well as a rate limit. The cost is that a send taking 30 seconds leaves
/// only about 30 seconds of cooldown behind it, which is the right trade: an
/// operator who just watched a test fail wants to fix the config and retry.
/// </item>
/// <item>
/// <b>It is global, not per actor.</b> One admin's test blocks another's for the
/// window. That is correct, because the thing being protected is the relay, not
/// the user.
/// </item>
/// <item>
/// <b>It is per process.</b> Ducks runs as a single Windows service host, so
/// that is the whole installation. It is not a distributed rate limiter and is
/// not trying to be.
/// </item>
/// </list>
/// </summary>
public sealed class AlertTestThrottle
{
    /// <summary>How long after a test send the next one is refused.</summary>
    public const int CooldownSeconds = 60;

    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();

    private DateTimeOffset? _lastAcquiredAt;

    /// <param name="timeProvider">
    /// Injectable so the cooldown can be tested without waiting a minute;
    /// production resolves the default. Same shape as NonceService.
    /// </param>
    public AlertTestThrottle(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Claims the right to send. Returns true and arms the cooldown, or returns
    /// false and reports how long is left. The check and the arm happen under
    /// one lock, so concurrent callers cannot both win.
    /// </summary>
    public bool TryAcquire(out TimeSpan retryAfter)
    {
        var cooldown = TimeSpan.FromSeconds(CooldownSeconds);
        var now = _timeProvider.GetUtcNow();

        lock (_gate)
        {
            if (_lastAcquiredAt is { } last)
            {
                var elapsed = now - last;
                if (elapsed < cooldown)
                {
                    // Rounded up, so a caller told "retry in 1 second" that waits
                    // exactly one second is not refused a second time.
                    var remaining = cooldown - elapsed;
                    retryAfter = TimeSpan.FromSeconds(Math.Ceiling(remaining.TotalSeconds));
                    return false;
                }
            }

            _lastAcquiredAt = now;
            retryAfter = TimeSpan.Zero;
            return true;
        }
    }
}
