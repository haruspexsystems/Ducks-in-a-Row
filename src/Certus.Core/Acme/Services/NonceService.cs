using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Manages ACME replay nonces. Each nonce can be used only once.
/// RFC 8555 §7.2 — nonces prevent replay attacks on signed requests.
///
/// Implementation: an in memory ConcurrentDictionary with periodic expiry.
/// Sufficient for a single instance deployment (Certus v1).
/// </summary>
public sealed class NonceService
{
    private readonly ConcurrentDictionary<string, DateTime> _nonces = new();
    private readonly TimeSpan _maxAge = TimeSpan.FromHours(1);
    private readonly TimeProvider _timeProvider;

    /// <summary>How often expired nonces are swept, independent of traffic volume.</summary>
    private static readonly TimeSpan CleanInterval = TimeSpan.FromMinutes(5);
    private long _lastCleanedTicks;

    /// <summary>
    /// Creates the nonce service. The optional <paramref name="timeProvider"/> lets tests drive
    /// expiry and the sweep; production resolves the default (<see cref="TimeProvider.System"/>)
    /// because the DI registration passes no argument.
    /// </summary>
    public NonceService(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lastCleanedTicks = UtcNow.Ticks;
    }

    /// <summary>Current UTC time from the injected provider.</summary>
    private DateTime UtcNow => _timeProvider.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Generates a new nonce and stores it for later validation.
    /// </summary>
    public string GenerateNonce()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var nonce = Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        _nonces[nonce] = UtcNow;

        MaybeCleanExpired();

        return nonce;
    }

    /// <summary>
    /// Sweeps expired nonces at most once per <see cref="CleanInterval"/>. A time based
    /// trigger means expired but unconsumed nonces cannot accumulate when the live count
    /// oscillates (consuming a nonce removes it), which the old count based trigger allowed.
    /// </summary>
    private void MaybeCleanExpired()
    {
        var nowTicks = UtcNow.Ticks;
        var last = Interlocked.Read(ref _lastCleanedTicks);
        if (nowTicks - last < CleanInterval.Ticks)
            return;
        // Only the caller that wins the swap performs the sweep this interval.
        if (Interlocked.CompareExchange(ref _lastCleanedTicks, nowTicks, last) == last)
            CleanExpired();
    }

    /// <summary>
    /// Validates and consumes a nonce. Returns true if the nonce was valid (exists and not expired).
    /// The nonce is removed after validation — single use.
    /// </summary>
    public bool ValidateAndConsume(string nonce)
    {
        if (string.IsNullOrEmpty(nonce))
            return false;

        if (!_nonces.TryRemove(nonce, out var created))
            return false;

        // Check if the nonce has expired
        if (UtcNow - created > _maxAge)
            return false;

        return true;
    }

    /// <summary>
    /// Gets the current count of active nonces (for diagnostics).
    /// </summary>
    public int ActiveCount => _nonces.Count;

    private void CleanExpired()
    {
        var cutoff = UtcNow - _maxAge;
        var expired = _nonces
            .Where(kvp => kvp.Value < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expired)
            _nonces.TryRemove(key, out _);
    }
}
