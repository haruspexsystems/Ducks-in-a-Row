using Certus.Web.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Certus.Web.Tests;

/// <summary>
/// The guard that keeps a percent encoded line feed in a URL path out of the
/// plain text log file, and a bidirectional override out of the line it would
/// disguise. The integration tests drive it over HTTP; these cover the part
/// that matters most and is hardest to see there, that the refusal itself does
/// not write the rejected path anywhere.
/// </summary>
public class UrlCharacterGuardMiddlewareTests
{
    /// <summary>Records the rendered message of every log entry.</summary>
    private sealed class RecordingLogger : ILogger<UrlCharacterGuardMiddleware>
    {
        public List<string> Messages { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));
    }

    private static (HttpContext Context, RecordingLogger Logger, bool Continued) Invoke(string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();

        var logger = new RecordingLogger();
        var continued = false;

        var middleware = new UrlCharacterGuardMiddleware(
            _ =>
            {
                continued = true;
                return Task.CompletedTask;
            },
            logger);

        middleware.InvokeAsync(context).GetAwaiter().GetResult();
        return (context, logger, continued);
    }

    [Theory]
    // Control characters. These can split a log line.
    [InlineData(0x0A, "line feed, the ADCS attribute pair separator")]
    [InlineData(0x0D, "carriage return")]
    [InlineData(0x09, "tab")]
    [InlineData(0x00, "NUL")]
    [InlineData(0x1B, "escape")]
    [InlineData(0x7F, "DEL")]
    [InlineData(0x85, "the C1 next line, a line terminator in its own right")]
    [InlineData(0x9B, "the C1 control sequence introducer")]
    // Format characters. These cannot split a line, but they disguise one.
    [InlineData(0x202E, "a right to left override")]
    [InlineData(0x2066, "a left to right isolate")]
    [InlineData(0x200B, "a zero width space")]
    [InlineData(0x00AD, "a soft hyphen")]
    // Format characters above the BMP, which arrive as a surrogate pair. A
    // scanner that reads the category from the char sees only Surrogate and
    // misses the class entirely (issue #228, fixed for the other scanners in
    // PR #229). The tag block is the one that matters: it encodes arbitrary
    // ASCII invisibly.
    [InlineData(0xE0001, "a language tag, U+E0001")]
    [InlineData(0xE0041, "a tag latin capital A, which hides text outright")]
    [InlineData(0xE007F, "a cancel tag, U+E007F")]
    [InlineData(0x110BD, "Kaithi number sign, U+110BD")]
    [InlineData(0x1BCA0, "a shorthand format letter overlap, U+1BCA0")]
    public void AnUnsafeCharacterInThePath_IsRefusedWithoutCallingTheNextMiddleware(
        int codePoint, string because)
    {
        var (context, _, continued) = Invoke(
            $"/acme/WebServer{char.ConvertFromUtf32(codePoint)}cdc:evil/directory");

        context.Response.StatusCode.Should().Be(StatusCodes.Status400BadRequest, because);
        continued.Should().BeFalse("a refused request must not reach the rest of the pipeline");
    }

    [Fact]
    public void TheWarningNamesTheWholeRuneNotASurrogateHalf()
    {
        // A pair reported as its leading half (U+DB40) names a character that
        // does not exist on its own and cannot be looked up.
        var (_, logger, _) = Invoke(
            $"/acme/WebServer{char.ConvertFromUtf32(0xE0041)}/directory");

        logger.Messages.Should().ContainSingle();
        logger.Messages[0].Should().Contain("U+E0041");
    }

    [Theory]
    // Ordinary characters outside the BMP are not format characters and must
    // still pass: the guard refuses two named classes, not everything wide.
    [InlineData(0x1F600, "an emoji")]
    [InlineData(0x20000, "a CJK extension B ideograph")]
    public void AnOrdinaryCharacterAboveTheBmp_PassesThrough(int codePoint, string because)
    {
        var (context, _, continued) = Invoke(
            $"/acme/Template{char.ConvertFromUtf32(codePoint)}Name/directory");

        continued.Should().BeTrue(because);
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public void TheWarningNamesTheCodePointAndPositionButNeverThePath()
    {
        // The whole point of refusing is to keep those characters out of the
        // log, so a warning that echoed the path would write the forged line it
        // exists to prevent. Same stance as AdcsRequestAttributes.
        var (_, logger, _) = Invoke("/acme/WebServer\ncdc:evil.attacker.example/directory");

        logger.Messages.Should().ContainSingle();

        var warning = logger.Messages[0];
        warning.Should().Contain("U+000A");
        warning.Should().Contain("position 15");
        warning.Should().NotContain("cdc:");
        warning.Should().NotContainAny("\n", "\r");
    }

    [Theory]
    [InlineData("/acme/WebServer/directory")]
    [InlineData("/api/setup/status")]
    // Reserved and non ASCII characters are ordinary in a template segment: a
    // display name carries spaces, and the guard must not narrow what a
    // legitimate CA can publish.
    [InlineData("/acme/Contoso Web Server v2.1/directory")]
    [InlineData("/acme/Serveur Web étendu/directory")]
    [InlineData("/")]
    public void OrdinaryPaths_PassThrough(string path)
    {
        var (context, logger, continued) = Invoke(path);

        continued.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
        logger.Messages.Should().BeEmpty();
    }
}
