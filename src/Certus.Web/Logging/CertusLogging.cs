using Serilog;
using Serilog.Configuration;
using Serilog.Events;

namespace Certus.Web.Logging;

/// <summary>
/// The log file sink and the per request log line, shared by both hosts for the
/// same reason AcmeRateLimitExtensions is: the two Program.cs pipelines are near
/// duplicates, and only Certus.Web is covered by the integration tests.
///
/// Issue #741: an anonymous flood of rate limited requests wrote one Information
/// line each, and the file sink set no size limit of its own, so Serilog.Sinks.File
/// applied its default of 1 GB per file without rolling. Once the day's file
/// reached that, the service wrote nothing more to its log file until midnight.
/// Both halves are fixed here: a refusal no longer costs a line, and a full file
/// rolls to the next one instead of silencing the log.
/// </summary>
public static class CertusLogging
{
    /// <summary>
    /// The largest one log file grows before the sink rolls to the next, as
    /// ducks-&lt;date&gt;_001.log and so on. A normal day writes a small fraction of this.
    /// </summary>
    public const long FileSizeLimitBytes = 100L * 1024 * 1024;

    /// <summary>
    /// How many log files the sink keeps, counting the files a size roll adds, so
    /// the log never takes more than this times <see cref="FileSizeLimitBytes"/>
    /// (3,000 MB). At one file a day that is 30 days, as before issue #741.
    /// docs/system-requirements.md states the bound.
    /// </summary>
    public const int RetainedFileCountLimit = 30;

    /// <summary>
    /// Writes the daily log file under the data folder's logs directory. The
    /// parameters exist for the tests, which cannot write 100 MB to prove a roll;
    /// both hosts call this with the defaults.
    /// </summary>
    public static LoggerConfiguration CertusLogFile(
        this LoggerSinkConfiguration writeTo,
        string dataDirectory,
        long fileSizeLimitBytes = FileSizeLimitBytes,
        int retainedFileCountLimit = RetainedFileCountLimit)
    {
        ArgumentNullException.ThrowIfNull(writeTo);

        return writeTo.File(
            Path.Combine(dataDirectory, "logs", "ducks-.log"),
            rollingInterval: RollingInterval.Day,
            fileSizeLimitBytes: fileSizeLimitBytes,
            rollOnFileSizeLimit: true,
            retainedFileCountLimit: retainedFileCountLimit);
    }

    /// <summary>
    /// The HttpContext.Items key the rate limiter's rejection handler sets, so the
    /// request logger can tell its refusals from a 429 a controller answers (the
    /// open order cap, the alert test cooldown), which keep their line.
    /// </summary>
    private static readonly object RateLimitRefusalKey = new();

    /// <summary>
    /// Marks the request as refused by the rate limiter. Called from
    /// AcmeProblemResults.OnRateLimitRejected, beside the line that records it.
    /// </summary>
    public static void MarkRateLimitRefusal(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Items[RateLimitRefusalKey] = true;
    }

    /// <summary>
    /// Serilog's request logging with one change: a request the rate limiter
    /// refused is logged at Debug, which the shipped configuration does not write.
    /// The limiter already records refusals through AcmeRateLimitRejectionLog, at
    /// most one line per policy a minute with a count of the rest, so the per
    /// request line only let the cheapest response cost the most disk.
    ///
    /// It stays where UseSerilogRequestLogging was in both pipelines, above the
    /// monitor mode gate and the rate limiter, so every other request is still
    /// logged as before, monitor mode's 404s included.
    /// </summary>
    public static IApplicationBuilder UseCertusRequestLogging(this IApplicationBuilder app) =>
        app.UseSerilogRequestLogging(options => options.GetLevel = GetRequestLevel);

    /// <summary>
    /// The level of the per request line. Serilog's own default with the rate
    /// limiter's refusals added: Error for an exception or a 5xx, Information
    /// otherwise.
    /// </summary>
    public static LogEventLevel GetRequestLevel(HttpContext context, double elapsedMs, Exception? exception)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (exception is not null || context.Response.StatusCode > 499)
            return LogEventLevel.Error;

        return context.Items.ContainsKey(RateLimitRefusalKey)
            ? LogEventLevel.Debug
            : LogEventLevel.Information;
    }
}
