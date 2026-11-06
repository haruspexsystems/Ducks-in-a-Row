using System.Net;
using Certus.Web.Logging;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Serilog;
using Serilog.Events;

namespace Certus.Web.Tests;

/// <summary>
/// Issue #741: an anonymous flood of rate limited requests wrote one Information
/// line each, and the file sink's default 1 GB cap without rolling then stopped
/// the log file for the rest of the day. Reproduced on 1.1.0 main with the dev
/// host and a 512,000 byte cap: the file froze at the cap, and a later request
/// line and the limiter's own refusal Warning reached the console only. These pin
/// both halves of the fix: a refusal writes no line, and a full file rolls.
/// </summary>
public class CertusLoggingTests
{
    [Theory]
    [InlineData(200, LogEventLevel.Information)]
    [InlineData(404, LogEventLevel.Information)]
    [InlineData(401, LogEventLevel.Information)]
    [InlineData(429, LogEventLevel.Information)]
    [InlineData(500, LogEventLevel.Error)]
    [InlineData(503, LogEventLevel.Error)]
    public void RequestLevel_KeepsSerilogsDefault_ForAnUnmarkedRequest(int status, LogEventLevel expected)
    {
        // A 429 a controller answers (the open order cap, the alert test cooldown)
        // keeps its line: only the limiter's own refusals are summarised elsewhere.
        var context = new DefaultHttpContext();
        context.Response.StatusCode = status;

        CertusLogging.GetRequestLevel(context, 1.0, exception: null).Should().Be(expected);
    }

    [Fact]
    public void RequestLevel_IsDebugForARateLimiterRefusal()
    {
        var context = new DefaultHttpContext();
        context.Response.StatusCode = 429;
        CertusLogging.MarkRateLimitRefusal(context);

        CertusLogging.GetRequestLevel(context, 1.0, exception: null).Should().Be(LogEventLevel.Debug);
    }

    [Fact]
    public void RequestLevel_IsErrorForAnException_EvenOnARefusal()
    {
        var context = new DefaultHttpContext();
        context.Response.StatusCode = 429;
        CertusLogging.MarkRateLimitRefusal(context);

        CertusLogging.GetRequestLevel(context, 1.0, new InvalidOperationException())
            .Should().Be(LogEventLevel.Error);
    }

    [Fact]
    public void LogFile_RollsWhenFull_SoALaterEventIsStillWritten()
    {
        var dataDirectory = NewTempDirectory();
        try
        {
            // Well past a 4 KB cap, the shape of a flood, then the event an operator
            // needs. Without the roll the sink drops everything after the cap.
            using (var logger = new LoggerConfiguration()
                       .WriteTo.CertusLogFile(dataDirectory, fileSizeLimitBytes: 4096)
                       .CreateLogger())
            {
                for (var i = 0; i < 200; i++)
                    logger.Information("HTTP GET /acme/WebServer/directory responded 429 in {Elapsed} ms", i);

                logger.Warning("The event after the flood");
            }

            var files = Directory.GetFiles(Path.Combine(dataDirectory, "logs"), "ducks-*.log");
            files.Length.Should().BeGreaterThan(1, "a full file must roll to the next one");
            files.Any(f => File.ReadAllText(f).Contains("The event after the flood"))
                .Should().BeTrue("a full log file must never silence the log (issue #741)");
        }
        finally
        {
            Directory.Delete(dataDirectory, recursive: true);
        }
    }

    [Fact]
    public void LogFile_KeepsNoMoreThanTheRetainedCount()
    {
        var dataDirectory = NewTempDirectory();
        try
        {
            using (var logger = new LoggerConfiguration()
                       .WriteTo.CertusLogFile(dataDirectory, fileSizeLimitBytes: 1024, retainedFileCountLimit: 3)
                       .CreateLogger())
            {
                for (var i = 0; i < 500; i++)
                    logger.Information("Line {Index} of a flood that rolls many times", i);
            }

            Directory.GetFiles(Path.Combine(dataDirectory, "logs"), "ducks-*.log")
                .Length.Should().BeLessThanOrEqualTo(3,
                    "the retained count bounds the disk the log takes, size rolls included");
        }
        finally
        {
            Directory.Delete(dataDirectory, recursive: true);
        }
    }

    [Fact]
    public void TheDefaults_BoundTheLogAtTheFigureTheSystemRequirementsState()
    {
        CertusLogging.FileSizeLimitBytes.Should().Be(100L * 1024 * 1024);
        CertusLogging.RetainedFileCountLimit.Should().Be(30);

        var requirements = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "docs", "system-requirements.md"));
        requirements.Should().Contain("3,000 MB",
            "an operator sizes the data folder from this page, so it must state the log's bound");
    }

    [Fact]
    public void BothHosts_LogThroughCertusLogging()
    {
        // The service's Program.cs is a top level program no test can run, so this is
        // what notices if either host goes back to a bare sink or request logger.
        var src = Path.Combine(FindRepositoryRoot(), "src");

        foreach (var host in new[] { "Certus.Service", "Certus.Web" })
        {
            var program = File.ReadAllText(Path.Combine(src, host, "Program.cs"));

            program.Should().Contain(".WriteTo.CertusLogFile(dataDirectory)", host);
            program.Should().Contain("app.UseCertusRequestLogging();", host);
            program.Should().NotContain(".WriteTo.File(",
                $"{host} must write its log file through CertusLogging, which rolls a full file");
            program.Should().NotContain("UseSerilogRequestLogging(",
                $"{host} must log requests through CertusLogging, which drops the 429 line");
        }
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ARateLimitedFlood_WritesNoRequestLineForItsRefusals()
    {
        using var factory = new OneRequestFactory();
        var client = factory.CreateClient();

        for (var i = 0; i < 20; i++)
        {
            using var response = await client.GetAsync("/acme/WebServer/directory");
            if (i > 0)
                response.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        }

        var log = factory.ReadLog();
        log.Should().Contain("responded 200",
            "the request logger must still write the line for an answered request");
        log.Should().NotContain("responded 429",
            "a refusal is the cheapest response, so it must not cost a log line (issue #741)");
        log.Should().Contain("ACME rate limit refused",
            "the limiter's throttled line is what records the refusals instead");
    }

    private static string NewTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "certus-logging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    /// <summary>
    /// Walks up from the test assembly to the directory holding Certus.sln, and
    /// throws when there is none. The HttpsProtocolPolicyTests pattern.
    /// </summary>
    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException(
            $"Could not find Certus.sln walking up from {AppContext.BaseDirectory}.");
    }

    /// <summary>The ACME general policy at one request a minute.</summary>
    private sealed class OneRequestFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting("Certus:RateLimiting:Enabled", "true");
            builder.UseSetting("Certus:RateLimiting:WindowSeconds", "60");
            builder.UseSetting("Certus:RateLimiting:GeneralLimit", "1");
        }

        /// <summary>
        /// Every log file the host wrote, read while the sink still holds them open.
        /// </summary>
        public string ReadLog() => string.Concat(
            Directory.GetFiles(Path.Combine(TempDataDir, "logs"), "ducks-*.log").Select(path =>
            {
                using var stream = new FileStream(
                    path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }));
    }
}
