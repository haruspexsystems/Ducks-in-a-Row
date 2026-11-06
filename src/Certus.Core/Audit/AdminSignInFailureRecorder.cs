using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Audit;

/// <summary>
/// Counts failed dashboard sign ins per source address and hour (issue #634).
/// The web middleware decides what counts as a failure and calls
/// <see cref="RecordAsync"/>; this class only keeps the tally in
/// <see cref="AdminSignInFailure"/> rows.
///
/// <para>Upsert without a lock: one conditional UPDATE adds to the hour's row,
/// and only when no row took the update is one inserted. Two first failures
/// in the same hour can race to the insert; the unique index refuses the
/// second, which then updates instead. A database error never reaches the
/// caller, because a sign in failure must still be answered with its 401 or
/// 403 whatever the state of the database.</para>
/// </summary>
public sealed class AdminSignInFailureRecorder
{
    /// <summary>Declared width of <see cref="AdminSignInFailure.SourceAddress"/>: an IPv6 address with a scope id fits.</summary>
    public const int MaxSourceLength = 64;

    /// <summary>What a connection with no remote address is recorded as.</summary>
    public const string UnknownSource = "unknown";

    private readonly CertusDbContext _db;
    private readonly ILogger<AdminSignInFailureRecorder> _logger;
    private readonly TimeProvider _time;

    public AdminSignInFailureRecorder(
        CertusDbContext db,
        ILogger<AdminSignInFailureRecorder> logger,
        TimeProvider? timeProvider = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Adds one failure to the source's current hour. Never throws.</summary>
    public async Task RecordAsync(string? sourceAddress, int statusCode, CancellationToken cancellationToken = default)
    {
        var source = AdminAuditTrail.Bound(sourceAddress, MaxSourceLength) ?? UnknownSource;
        var now = _time.GetUtcNow().UtcDateTime;
        var bucket = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Utc);

        try
        {
            if (await TryAddToExistingAsync(source, statusCode, bucket, now, cancellationToken).ConfigureAwait(false))
                return;

            _db.AdminSignInFailures.Add(new AdminSignInFailure
            {
                SourceAddress = source,
                StatusCode = statusCode,
                BucketStart = bucket,
                Count = 1,
                FirstAt = now,
                LastAt = now,
            });

            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (DbUpdateException)
            {
                // Another request inserted the hour's row first. Forget the
                // insert and add to that row instead.
                _db.ChangeTracker.Clear();
                await TryAddToExistingAsync(source, statusCode, bucket, now, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Cancellation included: the middleware passes no request token,
            // and a count that could not be written is a warning, not a 500.
            _logger.LogWarning(ex,
                "A failed dashboard sign in from {Source} (status {Status}) could not be counted",
                source, statusCode);
        }
    }

    private async Task<bool> TryAddToExistingAsync(
        string source, int statusCode, DateTime bucket, DateTime now, CancellationToken ct)
    {
        var updated = await _db.AdminSignInFailures
            .Where(f => f.SourceAddress == source && f.StatusCode == statusCode && f.BucketStart == bucket)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(f => f.Count, f => f.Count + 1)
                .SetProperty(f => f.LastAt, now), ct)
            .ConfigureAwait(false);
        return updated > 0;
    }
}
