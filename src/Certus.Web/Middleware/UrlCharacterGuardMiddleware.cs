using Certus.Core.Acme.Models;
using Certus.Core.Adcs;
using Certus.Core.Security;
using Certus.Web.Routing;

namespace Certus.Web.Middleware;

/// <summary>
/// Refuses any request whose URL path carries a control character, a line
/// separator, or a Unicode format character, before request logging runs.
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
/// Line separators (U+2028 and U+2029) split a line only for a reader that
/// honours them, which the .NET line reader behind this log file does not and a
/// SIEM's own splitter may (issue #234). Format characters cannot split a line at
/// all, but a right to left override makes the line render as a different line in
/// a terminal or a log viewer, and a zero width space hides a difference between
/// two paths that read alike.
///
/// Nothing is smuggled to the CA either way. The ACME template segment only
/// selects a template, and a name like these matches nothing the CA publishes
/// (see AdcsRequestAttributes for the attribute string boundary itself). What
/// it costs is the log's integrity, and the log is what
/// <c>docs/hardening.md</c> tells a deployer to read after a suspected
/// enrollment attack.
///
/// The refused classes are deliberately the same ones AdcsRequestAttributes
/// refuses in a template name, for the same reasons, and since issue #234 that
/// parity is held by sharing one scanner rather than by two comments agreeing.
/// Every template name that reaches this product legitimately came from the CA,
/// so a URL carrying what a template name may not carry is not a URL this
/// product serves.
///
/// Refusing the request rather than escaping the log line fixes it once for
/// every logger and every echo, instead of once per call site: a refused
/// request never reaches a controller, so no controller can reflect the path
/// back into its own answer.
///
/// This runs before <c>UseSerilogRequestLogging</c>, so a refused request is
/// reported by the warning below rather than by the request logger. Like
/// AdcsRequestAttributes, that warning names the code point and its position
/// and never echoes the value, or the refusal would write the very line it
/// exists to prevent.
///
/// On the /acme surface the refusal answers a problem document rather than the
/// plain body, because a bare shape no ACME client understands reads to that
/// client as "unexpected response" and tells its operator nothing. That is the
/// same defect issue #147 fixed for the routing and rate limit refusals, and
/// <see cref="Certus.Web.Routing.AcmeProblemResults"/> is the same envelope
/// those use. The detail carries the code point and the position and nothing
/// else, on exactly the discipline the warning keeps: the caller already knows
/// which bytes it sent, so naming them back discloses nothing, while the path
/// itself never appears. This matters because of issue #235. A certificate
/// template's display name is free text out of Active Directory and may carry
/// an invisible character such as a soft hyphen, issue #17 lets an ACME client
/// address a template by that display name, and the operator on the other end
/// of the 400 can see nothing wrong with the name in any screen that renders
/// it.
///
/// The response carries no Replay-Nonce, because this sits ahead of
/// AcmeNonceMiddleware and has to: the guard's whole job is to run before the
/// request logger. That is unchanged from the bodiless refusal it replaces, and
/// moving the guard later to gain a nonce would put a hostile path back through
/// the logger.
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
        // Control covers the C0 range, DEL, and the C1 range rather than
        // stopping at carriage return and line feed: C1 holds its own line
        // terminator (U+0085 NEL), and a log reader or a terminal may act on
        // more of the range than the file writer does. That reasoning is what
        // reaches U+2028 and U+2029 as well, which the scanner now covers. It
        // also resolves a surrogate pair before reading its category, so the
        // tag block U+E0020 to U+E007F cannot slip past (issue #228).
        if (DeceptiveCharacters.Find(context.Request.Path.Value) is { } found)
        {
            _logger.LogWarning(
                "Refused a request whose URL carries a control, line separator, or " +
                "formatting character (U+{CodePoint:X4}) at position {Position}. Those " +
                "characters can forge or disguise a log line, so the request is refused " +
                "rather than logged",
                found.CodePoint, found.Position);

            if (ProtocolPaths.IsAcmeProtocolPath(context.Request.Path))
            {
                // The template guidance is conditional because the guard does
                // not parse the path and the character can sit in any segment,
                // so telling a client to use the programmatic name would be
                // wrong for a fault in, say, the finalize segment. The position
                // is already here for a reader who needs to locate it.
                return AcmeProblemResults.WriteProblemAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    AcmeErrorType.Malformed,
                    $"The request URL contains a {ClassNoun(found.Class)} character " +
                    $"(U+{found.CodePoint:X4}) at position {found.Position}, so it was " +
                    "refused before routing. If this URL was built from a certificate " +
                    "template's display name, that name carries an invisible character " +
                    "such as a soft hyphen. Address the template by its programmatic " +
                    "name (its Active Directory cn) instead, or ask an administrator to " +
                    "correct the display name.",
                    context.RequestAborted);
            }

            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return context.Response.WriteAsJsonAsync(new
            {
                error =
                    "The request URL contains a control, line separator, or " +
                    "formatting character.",
            });
        }

        return _next(context);
    }

    /// <summary>
    /// The noun that goes in front of "character". The three spellings are the
    /// ones every other guard in the product already uses, and
    /// <see cref="TemplateNameFault.ClassNoun"/> is the shared copy; this one
    /// stays local so a middleware does not take a dependency on an ADCS type
    /// for a single word.
    /// </summary>
    private static string ClassNoun(DeceptiveCharacterClass characterClass) =>
        characterClass switch
        {
            DeceptiveCharacterClass.Control => "control",
            DeceptiveCharacterClass.LineSeparator => "line separator",
            _ => "formatting",
        };
}
