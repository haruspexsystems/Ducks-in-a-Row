namespace Certus.Core.Security;

/// <summary>
/// Rate limiting configuration for ACME endpoints.
///
/// Every policy partitions on the caller's source IP address. Behind a reverse
/// proxy that is the proxy's address unless Auth:TrustedProxies is configured,
/// which collapses an entire client fleet into one partition; StartupValidator
/// says so at startup and docs/configuration.md explains it.
/// </summary>
public sealed class AcmeRateLimitOptions
{
    public const string SectionName = "Certus:RateLimiting";

    /// <summary>Whether rate limiting is enabled. Defaults to true.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Maximum requests per window for new-account endpoints.</summary>
    public int NewAccountLimit { get; set; } = 10;

    /// <summary>Maximum requests per window for new-order endpoints.</summary>
    public int NewOrderLimit { get; set; } = 30;

    /// <summary>Maximum requests per window for general ACME endpoints.</summary>
    public int GeneralLimit { get; set; } = 100;

    /// <summary>
    /// Maximum requests per window for the authorization and order polling
    /// endpoints. Deliberately far more generous than <see cref="GeneralLimit"/>:
    /// RFC 8555 clients poll both while a challenge validates, and the validation
    /// worker sweeps every few seconds, so one certificate can cost tens of polls.
    ///
    /// The default is 5 requests a second. A client polling once a second
    /// contributes 60 a minute for as long as it is waiting, so the default
    /// carries about five concurrent issuances polling that hard, or ten polling
    /// every two seconds. Authorization and order polling share it, which does
    /// not double the cost because RFC 8555 puts them in sequence: a client polls
    /// the authorization until the challenge settles, then the order after
    /// finalize.
    /// </summary>
    public int PollLimit { get; set; } = 300;

    /// <summary>Rate limit window in seconds. Defaults to 60.</summary>
    public int WindowSeconds { get; set; } = 60;

    /// <summary>
    /// How many segments the sliding window is divided into. Permits are released
    /// one segment at a time rather than all at once at a window boundary, which
    /// is what stops a throttled fleet retrying in lockstep. Higher is smoother
    /// and costs a little more state per partition. Must be at least 1, or the
    /// limiter throws when it is constructed.
    /// </summary>
    public int SegmentsPerWindow { get; set; } = 6;

    /// <summary>
    /// An absolute URL for documentation about these limits. When set, a rate
    /// limited response carries a Link header with rel="help" and the policy name
    /// as its fragment, which RFC 8555 section 6.6 permits so a client can be
    /// pointed at the specific limit it hit. Null by default, so nothing outbound
    /// is baked into the product; point it at your own runbook.
    /// </summary>
    public string? HelpUrl { get; set; }

    /// <summary>
    /// The Retry-After value, in whole seconds, to report on a refusal.
    ///
    /// SlidingWindowRateLimiter reports no RetryAfter metadata of its own
    /// (verified against .NET 10; FixedWindowRateLimiter does, and reports the
    /// whole window), so this is what the refusal falls back to. One segment is
    /// the soonest the limiter releases anything, which is exactly right for
    /// traffic spread across the window and optimistic for a caller that spent
    /// every permit in one instant, since that one waits a full window whichever
    /// limiter is used. Being optimistic is the better error: RFC 8555 section
    /// 6.6 makes Retry-After a hint rather than a guarantee, an early retry costs
    /// one cheap refusal that carries a fresh hint, and a flat full window would
    /// hold back a caller that could already proceed.
    /// </summary>
    public int RetryAfterSeconds =>
        Math.Max(1, (int)Math.Ceiling(
            WindowSeconds / (double)EffectiveSegmentsPerWindow));

    /// <summary>
    /// The segment count actually used, clamped at both ends.
    ///
    /// Below 1 the limiter throws when the first request reaches the policy, so
    /// the floor keeps a misconfiguration from taking ACME down; StartupValidator
    /// warns about the same value. The ceiling is a segment of one second,
    /// because Retry-After is expressed in whole seconds (RFC 7231), so finer
    /// segments cost state without changing anything a client can be told. That
    /// state is held per partition and a partition is a source address, so an
    /// unclamped value is multiplied by the number of callers rather than paid
    /// once, which is what makes the ceiling worth having.
    ///
    /// The limiter and <see cref="RetryAfterSeconds"/> both read this rather than
    /// the raw property, so the window the limiter builds and the interval the
    /// refusal advertises cannot disagree.
    /// </summary>
    public int EffectiveSegmentsPerWindow =>
        Math.Clamp(SegmentsPerWindow, 1, Math.Max(1, WindowSeconds));
}
