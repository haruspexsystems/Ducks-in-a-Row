using System.Threading.RateLimiting;
using Certus.Core.Security;
using Certus.Web.Routing;
using Microsoft.AspNetCore.RateLimiting;

namespace Certus.Web.Security;

/// <summary>
/// Registers the ACME rate limiter for both hosts.
///
/// This lived as a byte identical block in Certus.Web/Program.cs and
/// Certus.Service/Program.cs. Only the Service host is the deployed one, so a
/// change applied to the copy someone happened to be reading would have silently
/// missed production; issue #263 was filed against the Web copy's line numbers
/// for that reason. It is one method now, called from both, the way
/// CertusAuthExtensions.UseCertusForwardedHeaders already is.
/// </summary>
public static class AcmeRateLimitExtensions
{
    /// <summary>
    /// Binds <see cref="AcmeRateLimitOptions"/> and, when enabled, registers the
    /// four ACME policies. Returns the bound options so the caller can gate
    /// <c>UseRateLimiter</c> on the same values without binding them twice.
    /// </summary>
    public static AcmeRateLimitOptions AddAcmeRateLimiting(
        this IServiceCollection services, IConfiguration configuration)
    {
        // Bind the options so StartupValidator can warn on a value the limiter
        // would throw on; the returned copy gates the pipeline at build time.
        services.Configure<AcmeRateLimitOptions>(
            configuration.GetSection(AcmeRateLimitOptions.SectionName));

        var options = configuration
            .GetSection(AcmeRateLimitOptions.SectionName)
            .Get<AcmeRateLimitOptions>() ?? new AcmeRateLimitOptions();

        if (!options.Enabled)
            return options;

        services.AddSingleton<AcmeRateLimitRejectionLog>();

        services.AddRateLimiter(rlOptions =>
        {
            rlOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            // A bare 429 tells an ACME client nothing; RFC 8555 section 6.6 has an
            // error code for exactly this, and asks for Retry-After.
            rlOptions.OnRejected = AcmeProblemResults.OnRateLimitRejected;

            AddPolicy(rlOptions, AcmeRateLimitPolicies.NewAccount, options.NewAccountLimit, options);
            AddPolicy(rlOptions, AcmeRateLimitPolicies.NewOrder, options.NewOrderLimit, options);
            AddPolicy(rlOptions, AcmeRateLimitPolicies.Poll, options.PollLimit, options);
            AddPolicy(rlOptions, AcmeRateLimitPolicies.General, options.GeneralLimit, options);
        });

        return options;
    }

    /// <summary>
    /// One sliding window policy, partitioned on the caller's source address.
    ///
    /// Sliding rather than fixed because a fixed window lets twice the limit
    /// through across a boundary, and releases every permit at the same instant,
    /// so a throttled fleet retries in lockstep. A sliding window releases one
    /// segment at a time instead. Measured against .NET 10, that trickle only
    /// applies to traffic spread across the window: a caller that spends every
    /// permit in a single instant waits a full window under either limiter.
    ///
    /// QueueLimit stays 0 deliberately. Queueing on a window this long would hold
    /// the connection open until the window replenished rather than refusing, on
    /// an unauthenticated endpoint, which trades an immediate answer the client
    /// can act on for a hang it will probably time out on anyway. Issue #263
    /// raised a non zero queue as an option and this is the decision against it.
    /// </summary>
    private static void AddPolicy(
        RateLimiterOptions rlOptions, string policyName, int permitLimit, AcmeRateLimitOptions options)
    {
        rlOptions.AddPolicy(policyName, httpContext =>
            RateLimitPartition.GetSlidingWindowLimiter(
                httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromSeconds(options.WindowSeconds),
                    SegmentsPerWindow = options.EffectiveSegmentsPerWindow,
                    QueueLimit = 0
                }));
    }
}
