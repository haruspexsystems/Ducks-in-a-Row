using System.Collections.Concurrent;
using System.Security.Cryptography;
using Certus.Core.Security;
using Microsoft.Extensions.Options;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Manages ACME replay nonces. Each nonce can be used only once.
/// RFC 8555 §7.2 — nonces prevent replay attacks on signed requests.
///
/// Implementation: an in memory ConcurrentDictionary with periodic expiry and a
/// size cap. Sufficient for a single instance deployment (Certus v1).
///
/// <para>
/// The cap (issue #632, CRA R04): a nonce is stored on every ACME protocol
/// response, so with no bound an unauthenticated client could grow the store at
/// line rate for the hour a nonce lives. The store holds at most
/// <see cref="AcmeRateLimitOptions.MaxStoredNonces"/> entries and evicts the
/// oldest first. Dropping a nonce early is safe: RFC 8555 §6.5 requires a
/// client to recover from <c>badNonce</c> by retrying with the fresh nonce the
/// error carries, so an evicted nonce costs a legitimate client one retry and
/// a flood costs the server nothing beyond the cap.
/// </para>
/// </summary>
public sealed class NonceService
{
    private readonly ConcurrentDictionary<string, DateTime> _nonces = new();

    /// <summary>
    /// Every nonce ever generated, in generation order, until it is evicted.
    /// The dictionary cannot say which entry is oldest, so this is what
    /// "oldest first" is read from. A consumed or expired nonce stays here until
    /// it reaches the head, where removing it from the dictionary is a no-op,
    /// so the queue is trimmed on its own length rather than the dictionary's:
    /// trimming on the live count alone would let a client that generates and
    /// consumes in lockstep grow the queue without bound.
    /// </summary>
    private readonly ConcurrentQueue<string> _order = new();

    private readonly TimeSpan _maxAge = TimeSpan.FromHours(1);
    private readonly TimeProvider _timeProvider;
    private readonly int _maxEntries;

    /// <summary>How often expired nonces are swept, independent of traffic volume.</summary>
    private static readonly TimeSpan CleanInterval = TimeSpan.FromMinutes(5);
    private long _lastCleanedTicks;

    /// <summary>
    /// Creates the nonce service for the hosts, which register it as a singleton
    /// with no arguments. The cap comes from the bound rate limiting options; the
    /// optional <paramref name="timeProvider"/> resolves to the system clock when
    /// nothing is registered.
    /// </summary>
    public NonceService(IOptions<AcmeRateLimitOptions> options, TimeProvider? timeProvider = null)
        : this(options.Value.EffectiveMaxStoredNonces, timeProvider)
    {
    }

    /// <summary>
    /// Creates the nonce service with an explicit cap. Internal so the tests can
    /// drive eviction with a small store, and so the hosts' container never sees
    /// a second public constructor to choose between.
    /// </summary>
    internal NonceService(int maxEntries, TimeProvider? timeProvider = null)
    {
        _maxEntries = Math.Max(1, maxEntries);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lastCleanedTicks = UtcNow.Ticks;
    }

    /// <summary>Current UTC time from the injected provider.</summary>
    private DateTime UtcNow => _timeProvider.GetUtcNow().UtcDateTime;

    /// <summary>The most entries the store holds before it evicts the oldest.</summary>
    public int MaxEntries => _maxEntries;

    /// <summary>
    /// Generates a new nonce and stores it for later validation. When the store
    /// is full the oldest nonces are evicted to make room, so the newest always
    /// gets in.
    /// </summary>
    public string GenerateNonce()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var nonce = Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        _nonces[nonce] = UtcNow;
        _order.Enqueue(nonce);

        EvictOldestBeyondCap();
        MaybeCleanExpired();

        return nonce;
    }

    /// <summary>
    /// Trims the queue, and with it the dictionary, back to the cap. Two callers
    /// racing here may evict one entry more than needed; that costs a client one
    /// badNonce retry and keeps the store free of a lock on the request path.
    /// </summary>
    private void EvictOldestBeyondCap()
    {
        while (_order.Count > _maxEntries && _order.TryDequeue(out var oldest))
            _nonces.TryRemove(oldest, out _);
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
