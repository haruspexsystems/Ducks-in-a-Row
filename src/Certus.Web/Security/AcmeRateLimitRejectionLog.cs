using System.Collections.Concurrent;
using Certus.Core.Security;

namespace Certus.Web.Security;

/// <summary>
/// Records ACME rate limit refusals to the log, at most one line per policy per
/// cooldown.
///
/// The throttle is the point of the class, not an optimisation. A refusal is the
/// cheap half of load shedding, so a Warning per refused request would let a
/// flood fill the Serilog file at C:\ProgramData\Ducks in a Row\logs and turn the
/// limiter into a disk exhaustion vector: exactly the traffic the limiter exists
/// to survive is the traffic that would write the most. So the first refusal for
/// a policy is logged in full and the rest are counted, with the count reported
/// on the next line that policy writes.
///
/// Nothing logged a refusal before this (issue #263). The limiter's own message
/// is Microsoft.AspNetCore at Debug, and both hosts pin that source to Warning,
/// so working out which of the policies had refused a caller meant reading the
/// client's output rather than the server's.
/// </summary>
public sealed class AcmeRateLimitRejectionLog
{
    /// <summary>
    /// How long one policy stays quiet after logging. A minute matches the
    /// default window, so a sustained flood writes about one line per policy per
    /// window rather than one per request.
    /// </summary>
    public static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, PolicyState> _states = new(StringComparer.Ordinal);
    private readonly ILogger<AcmeRateLimitRejectionLog> _logger;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Creates the log. The optional <paramref name="timeProvider"/> lets tests
    /// drive the cooldown; production resolves the default because the DI
    /// registration passes no argument, matching NonceService.
    /// </summary>
    public AcmeRateLimitRejectionLog(
        ILogger<AcmeRateLimitRejectionLog> logger, TimeProvider? timeProvider = null)
    {
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Records one refusal. Returns true when this call wrote a log line, which is
    /// what the tests assert on; callers ignore it.
    /// </summary>
    public bool Record(
        string? policyName, string method, string path, string? remoteAddress, int? retryAfterSeconds)
    {
        // A refusal with no endpoint metadata has no policy to attribute it to.
        // That should not happen on the ACME surface, where every route carries an
        // attribute, so name it rather than dropping the line.
        var policy = string.IsNullOrEmpty(policyName) ? "(unattributed)" : policyName;

        var state = _states.GetOrAdd(policy, static _ => new PolicyState());
        var nowTicks = _timeProvider.GetUtcNow().UtcDateTime.Ticks;

        long suppressed;
        lock (state)
        {
            if (state.HasLogged && nowTicks - state.WindowStartTicks < Cooldown.Ticks)
            {
                state.Suppressed++;
                return false;
            }

            suppressed = state.Suppressed;
            state.Suppressed = 0;
            state.WindowStartTicks = nowTicks;
            state.HasLogged = true;
        }

        _logger.LogWarning(
            "ACME rate limit refused {Method} {Path} from {RemoteAddress} under policy {Policy} " +
            "(Retry-After {RetryAfterSeconds}s); {SuppressedCount} further refusals under this " +
            "policy were not logged since the last line. Raise {ConfigKey} if legitimate clients " +
            "are being refused.",
            method, path, remoteAddress ?? "(unknown)", policy,
            retryAfterSeconds?.ToString() ?? "(none)", suppressed, ConfigKeyFor(policy));

        return true;
    }

    /// <summary>
    /// The configuration key an operator would raise for this policy, so the log
    /// line names the knob instead of leaving them to find it.
    /// </summary>
    private static string ConfigKeyFor(string policy) => policy switch
    {
        AcmeRateLimitPolicies.NewAccount => AcmeRateLimitOptions.SectionName + ":NewAccountLimit",
        AcmeRateLimitPolicies.NewOrder => AcmeRateLimitOptions.SectionName + ":NewOrderLimit",
        AcmeRateLimitPolicies.Poll => AcmeRateLimitOptions.SectionName + ":PollLimit",
        AcmeRateLimitPolicies.General => AcmeRateLimitOptions.SectionName + ":GeneralLimit",
        _ => AcmeRateLimitOptions.SectionName
    };

    private sealed class PolicyState
    {
        public bool HasLogged;
        public long WindowStartTicks;
        public long Suppressed;
    }
}
