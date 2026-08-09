using System.Globalization;

namespace Certus.Web.Middleware;

/// <summary>
/// Refuses any request whose URL path carries a control character or a Unicode
/// format character, before request logging runs.
///
/// A URL path arrives percent encoded and ASP.NET decodes it before anything
/// reads <c>Request.Path</c>, so <c>%0A</c> on the wire is a real line feed by
/// the time Serilog writes it. The request logger renders the path into the
/// plain text log file, which means an unauthenticated caller could split one
/// log line into three and write the middle one itself:
///
/// <code>
///   GET /acme/WebServer%0A2026-01-01 00:00:00.000 +00:00 [INF] Certificate issued%0A/directory
/// </code>
///
/// Format characters cannot split a line, but a right to left override makes
/// the line render as a different line in a terminal or a log viewer, and a
/// zero width space hides a difference between two paths that read alike.
///
/// Nothing is smuggled to the CA either way. The ACME template segment only
/// selects a template, and a name like these matches nothing the CA publishes
/// (see AdcsRequestAttributes for the attribute string boundary itself). What
/// it costs is the log's integrity, and the log is what
/// <c>docs/hardening.md</c> tells a deployer to read after a suspected
/// enrollment attack.
///
/// The two refused classes are deliberately the same two AdcsRequestAttributes
/// refuses in a template name, for the same reasons. Every template name that
/// reaches this product legitimately came from the CA, so a URL carrying what a
/// template name may not carry is not a URL this product serves.
///
/// Refusing the request rather than escaping the log line fixes it once for
/// every logger and every echo, instead of once per call site: a refused
/// request never reaches a controller, so it also cannot be reflected back in a
/// problem document.
///
/// This runs before <c>UseSerilogRequestLogging</c>, so a refused request is
/// reported by the warning below rather than by the request logger. Like
/// AdcsRequestAttributes, that warning names the code point and its position
/// and never echoes the value, or the refusal would write the very line it
/// exists to prevent.
/// </summary>
public sealed class UrlCharacterGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<UrlCharacterGuardMiddleware> _logger;

    public UrlCharacterGuardMiddleware(
        RequestDelegate next, ILogger<UrlCharacterGuardMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public Task InvokeAsync(HttpContext context)
    {
        // The path only. The query string is deliberately not checked:
        // Request.QueryString.Value is the raw still encoded text, so "%0A"
        // there is three ordinary characters and reaches no log as a newline,
        // and Kestrel's request line parser already refuses a raw control byte
        // anywhere in the request target. Decoding the query here to look for
        // something that cannot arrive would cost every request and find
        // nothing.
        if (FindUnsafeCharacter(context.Request.Path.Value, out var position, out var codePoint))
        {
            _logger.LogWarning(
                "Refused a request whose URL carries a control or formatting character " +
                "(U+{CodePoint:X4}) at position {Position}. Those characters can forge or " +
                "disguise a log line, so the request is refused rather than logged",
                codePoint, position);

            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return context.Response.WriteAsJsonAsync(new
            {
                error = "The request URL contains a control or formatting character.",
            });
        }

        return _next(context);
    }

    /// <summary>
    /// The first control or Unicode format character in <paramref name="value"/>.
    /// Control covers the C0 range, DEL, and the C1 range rather than stopping at
    /// carriage return and line feed: C1 holds its own line terminator (U+0085
    /// NEL), and a log reader or a terminal may act on more of the range than the
    /// file writer does. Format covers the bidirectional overrides U+202A to
    /// U+202E, the isolates U+2066 to U+2069, the zero width space, the soft
    /// hyphen, and the tag block U+E0020 to U+E007F.
    ///
    /// The category is read from the string rather than the char so a format
    /// character above the BMP is caught. Those arrive as a surrogate pair, and
    /// the category of a lone surrogate is Surrogate and never Format, so a per
    /// char lookup misses the whole class. The tag block is the one that matters:
    /// it encodes arbitrary ASCII invisibly, so a path could carry hidden text
    /// through every screen and log that shows it. This is the same defect and
    /// the same fix as issue #228 in AdcsRequestAttributes; a scanner written the
    /// obvious way reintroduces it.
    ///
    /// The control half was never affected, because every control character is
    /// inside the BMP.
    /// </summary>
    private static bool FindUnsafeCharacter(string? value, out int position, out int codePoint)
    {
        position = 0;
        codePoint = 0;

        if (string.IsNullOrEmpty(value))
            return false;

        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (!char.IsControl(c) &&
                CharUnicodeInfo.GetUnicodeCategory(value, i) != UnicodeCategory.Format)
            {
                continue;
            }

            position = i;
            // The rune, not a surrogate half, so the warning names the character
            // an operator can look up.
            codePoint = char.IsHighSurrogate(c) ? char.ConvertToUtf32(value, i) : c;
            return true;
        }

        return false;
    }
}
