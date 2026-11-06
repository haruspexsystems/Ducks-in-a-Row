using System.Text.RegularExpressions;

namespace Certus.Core.Alerts;

/// <summary>
/// Strips configured secrets out of a notifier's error message before it is
/// shown to anyone (issue #161), and since issue #635 before it is stored or
/// logged: the notifiers redact at the source, and the read path keeps its
/// redaction for rows an older version wrote raw.
///
/// <para>
/// This exists because <see cref="AlertNotificationResult.ErrorMessage"/> is not
/// sanitized at the source and cannot easily be. <see cref="WebhookAlertNotifier"/>
/// builds its failure text from the receiver's entire response body, and on an
/// exception it passes <c>ex.Message</c> through verbatim. A malformed URL, a DNS
/// failure, or a TLS failure all produce messages that contain the webhook URL,
/// and the URL frequently embeds a bearer token: that is exactly how Slack, Teams,
/// and most webhook relays authenticate.
/// </para>
///
/// <para>
/// Applied in two places: the test send response, which is new, and the alert
/// history projection, which has been rendering these strings raw on the
/// certificate detail page since issue #160.
/// </para>
/// </summary>
public static class AlertErrorRedactor
{
    /// <summary>What replaces a secret that was found in the message.</summary>
    private const string Placeholder = "(redacted)";

    /// <summary>
    /// The cap on a redacted message. A webhook receiver can answer a failure
    /// with an arbitrarily large body, and nothing else bounds this string:
    /// AlertSent.ErrorMessage is capped at 1000 characters by the database, but
    /// the test send path never touches the database.
    /// </summary>
    private const int MaxLength = 500;

    /// <summary>
    /// The width of AlertSent.ErrorMessage, which since issue #206 holds every
    /// failed channel's error, so it can be longer than one message's
    /// <see cref="MaxLength"/>. SQLite does not enforce the column width, so the
    /// write bounds the text to this itself, and the read keeps all of it.
    /// </summary>
    public const int MaxStoredLength = 1000;

    /// <summary>
    /// Redacts every configured secret from <paramref name="message"/> and
    /// truncates the result. Null in, null out, so a successful result passes
    /// through untouched. <paramref name="candidateSmtp"/> carries the unsaved
    /// SMTP values of a candidate test send, whose password, username and host
    /// are exactly as sensitive as the configured ones and appear in the same
    /// relay error messages.
    /// </summary>
    public static string? Redact(
        string? message, AlertOptions options, SmtpOptions? candidateSmtp = null) =>
        // Plus one for the ellipsis: a cut message has always kept its first
        // MaxLength characters.
        Truncate(RedactConfigured(message, options, candidateSmtp), MaxLength + 1);

    /// <summary>
    /// <see cref="Redact"/> for a stored AlertSent error read back for display,
    /// capped at the column's <see cref="MaxStoredLength"/> rather than one
    /// message's length, so the second channel's error in a row that names
    /// several is not cut away.
    /// </summary>
    public static string? RedactStored(string? message, AlertOptions options) =>
        Truncate(RedactConfigured(message, options), MaxStoredLength);

    /// <summary>
    /// Cuts <paramref name="text"/> to at most <paramref name="maxLength"/>
    /// characters, the last of them an ellipsis when anything was cut, and never
    /// between the two halves of a surrogate pair.
    /// </summary>
    public static string? Truncate(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= maxLength)
            return text;

        var cut = maxLength - 1;
        if (cut > 0 && char.IsHighSurrogate(text[cut - 1]))
            cut--;

        return string.Concat(text.AsSpan(0, cut), "…");
    }

    /// <summary>
    /// <see cref="Redact"/> without the length cap. For a caller that runs
    /// <see cref="RedactTokens"/> afterwards: the token pass must see a token
    /// whole, and a cap applied first can cut one into a piece too short for
    /// the pass to recognise. Such a caller caps last, with <see cref="Redact"/>.
    /// </summary>
    public static string? RedactConfigured(
        string? message, AlertOptions options, SmtpOptions? candidateSmtp = null)
    {
        if (string.IsNullOrEmpty(message))
            return message;

        var redacted = message;

        // Longest first, so a secret that contains another one (a URL with the
        // secret in its query string) is replaced whole rather than leaving a
        // recognisable fragment behind.
        foreach (var secret in Secrets(options)
                     .Concat(CandidateSecrets(candidateSmtp))
                     .OrderByDescending(s => s.Length))
        {
            redacted = redacted.Replace(secret, Placeholder, StringComparison.Ordinal);
        }

        return redacted;
    }

    /// <summary>
    /// How much of a receiver's response body a log line or a stored error
    /// keeps (issue #635). Enough to tell a 404 page from a JSON refusal, and
    /// short enough that a body echoing the request cannot carry much of it.
    /// </summary>
    public const int ResponseBodyExcerptLength = 200;

    /// <summary>
    /// The webhook URL as it may appear in a log line: scheme, host, and the
    /// port when it is not the scheme's default. Never the path or the query,
    /// and never the userinfo. Slack, Discord and classic Teams connector URLs
    /// carry their secret in the path, Power Automate URLs in the query, and
    /// whoever holds the whole URL can post into the channel. The host is
    /// enough to tell an operator which service failed. A URL that does not
    /// parse is described, not quoted, because the one thing known about it
    /// is that it may hold anything.
    /// </summary>
    public static string DescribeEndpoint(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return "(unparseable URL)";

        var port = uri.IsDefaultPort ? string.Empty : $":{uri.Port}";
        return $"{uri.Scheme}://{uri.Host}{port}";
    }

    /// <summary>
    /// The first <see cref="ResponseBodyExcerptLength"/> characters of a
    /// receiver's response body, with anything that looks like a token
    /// replaced and the whitespace folded so it sits on one log line. The
    /// redaction runs before the cut, so a token the cut would have split
    /// is replaced whole rather than leaving its first half behind.
    /// </summary>
    public static string ExcerptResponseBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return "(empty body)";

        // Bounded before the regexes run: a receiver can answer with
        // megabytes, and only the start of it is kept anyway.
        var head = body.Length > 4 * ResponseBodyExcerptLength
            ? body[..(4 * ResponseBodyExcerptLength)]
            : body;
        var folded = Whitespace.Replace(RedactTokens(head), " ").Trim();

        return folded.Length > ResponseBodyExcerptLength
            ? string.Concat(folded.AsSpan(0, ResponseBodyExcerptLength), "…")
            : folded;
    }

    /// <summary>
    /// Replaces whatever looks like a credential in free text that did not
    /// come from this server's own configuration: a receiver's response body
    /// or an exception message. Four shapes, each a way a token is commonly
    /// written: a named value (<c>token=…</c>, <c>"secret": "…"</c>), an
    /// HTTP authorization scheme and its parameter, a JWT, and any long
    /// opaque run of token characters. The query string of any URL goes too,
    /// whatever it holds. Over redacting a failure body costs a little
    /// legibility; under redacting it puts a token in the log.
    /// </summary>
    public static string RedactTokens(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return text ?? string.Empty;

        // The scheme first, so "Bearer x" loses x rather than the word Bearer
        // when it sits in a named value such as an echoed Authorization header.
        var redacted = AuthorizationScheme.Replace(text, "${scheme} " + Placeholder);
        redacted = NamedValue.Replace(redacted, "${name}${separator}" + Placeholder);
        redacted = QueryString.Replace(redacted, "?" + Placeholder);
        redacted = JsonWebToken.Replace(redacted, Placeholder);
        return OpaqueRun.Replace(redacted, Placeholder);
    }

    private static readonly Regex NamedValue = new(
        @"(?<name>\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|apikey|" +
        @"secret|client[_-]?secret|signature|sig|password|passwd|pwd|authorization|auth|credential|key)\b)" +
        @"(?<separator>""?\s*[:=]\s*""?)(?<value>[^\s""'&,;]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(250));

    private static readonly Regex AuthorizationScheme = new(
        @"(?<scheme>\b(?:Bearer|Basic|Digest|Token))\s+[A-Za-z0-9\-._~+/]+=*",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(250));

    private static readonly Regex QueryString = new(
        @"\?[^\s""'<>]+",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(250));

    private static readonly Regex JsonWebToken = new(
        @"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(250));

    private static readonly Regex OpaqueRun = new(
        @"[A-Za-z0-9_\-+/=]{32,}",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(250));

    private static readonly Regex Whitespace = new(
        @"\s+", RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));

    /// <summary>
    /// The shortest value that is worth replacing. A one or two character host
    /// cannot be a real endpoint, and replacing every occurrence of it would
    /// turn the message into noise without protecting anything the whole URL
    /// entry does not already cover. This is about legibility, not secrecy.
    /// </summary>
    private const int MinimumSecretLength = 4;

    /// <summary>
    /// The shortest webhook path segment or query value that is pooled on its
    /// own. Shorter parts are words every URL of a service shares (services,
    /// webhooks, triggers) or ids that are not secret alone (a Slack workspace
    /// or channel), and pooling them would blank ordinary words out of every
    /// failure message. The secret parts are longer: Slack's is 24 characters,
    /// a Discord token 68, the Teams connector ids 32 and more, and a Power
    /// Automate signature 43.
    /// </summary>
    private const int MinimumUrlPartLength = 16;

    /// <summary>
    /// Every configured value that must not appear in an error message. The SMTP
    /// username is included because it is an account name, and the issue's rule
    /// names it alongside the password.
    ///
    /// <para>
    /// The endpoint host appears separately from the full URL because the
    /// exception messages that reach here rarely quote the URL as configured.
    /// A DNS failure surfaces as "No such host is known. (host:443)" and a
    /// connection failure names the host and port the same way, so matching only
    /// the configured URL string leaves the operator's private endpoint in a
    /// response the dashboard renders. Verified against a live dev host.
    /// </para>
    /// </summary>
    private static IEnumerable<string> Secrets(AlertOptions options)
    {
        var candidates = new List<string?>
        {
            options.Webhook?.Url,
            options.Webhook?.Secret,
            // Only the plaintext configuration file password can be pooled
            // here. A password stored as a protected blob is decrypted
            // nowhere but inside EmailAlertNotifier, which scrubs it from
            // its own failure text at the source (ScrubResolvedPassword)
            // for exactly that reason.
            options.Smtp?.Password,
            options.Smtp?.Username,
            // Readable at the admin only config endpoint since issue #162,
            // but error text renders on wider surfaces (the certificate
            // detail page, the alert history), so the host stays out of
            // failure messages regardless.
            options.Smtp?.Host,
        };

        // Custom header values are the other way a webhook is authenticated, for
        // a receiver that does not verify the HMAC signature, so they are
        // routinely an Authorization bearer token. The config endpoint reports
        // only how many there are for the same reason.
        if (options.Webhook?.Headers is { Count: > 0 } headers)
        {
            candidates.AddRange(headers.Values);
        }

        if (Uri.TryCreate(options.Webhook?.Url, UriKind.Absolute, out var uri))
        {
            // Authority first so "host:port" is replaced whole; the ordering in
            // Redact is longest first, which already guarantees that.
            candidates.Add(uri.Authority);
            candidates.Add(uri.Host);

            // The path and the query, which is where the services put the
            // secret. A receiver's 404 page commonly quotes the path it was
            // asked for, as sent, and a refusal can name just the token, so
            // both go whole and every long segment or query value goes alone.
            candidates.Add(uri.PathAndQuery);
            candidates.Add(uri.AbsolutePath);
            candidates.AddRange(UrlParts(uri).Where(p => p.Length >= MinimumUrlPartLength));

            // Credentials written into the URL itself, whole and the password
            // half alone, as written and unescaped.
            if (uri.UserInfo.Length > 0)
            {
                var password = uri.UserInfo.Split(':', 2) is [_, var half] ? half : null;
                candidates.AddRange(new[] { uri.UserInfo, password }
                    .Where(p => p != null)
                    .SelectMany(p => new[] { p, Uri.UnescapeDataString(p!) }));
            }
        }

        return candidates
            .Where(c => !string.IsNullOrEmpty(c) && c!.Length >= MinimumSecretLength)!;
    }

    /// <summary>
    /// Every path segment and query value of the webhook URL, as sent and
    /// unescaped, since a receiver may quote either form.
    /// </summary>
    private static IEnumerable<string> UrlParts(Uri uri) =>
        uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Concat(uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(pair => pair[(pair.IndexOf('=') + 1)..]))
            .SelectMany(part => new[] { part, Uri.UnescapeDataString(part) });

    /// <summary>
    /// The values a candidate test send supplies that must not appear in its
    /// error text. Password first: for a candidate it arrives in the clear
    /// rather than as a protected blob, so it exists here in a form a relay
    /// error could actually quote.
    /// </summary>
    private static IEnumerable<string> CandidateSecrets(SmtpOptions? candidate)
    {
        if (candidate == null)
            return [];

        return new List<string?>
            {
                candidate.Password,
                candidate.Username,
                candidate.Host,
            }
            .Where(c => !string.IsNullOrEmpty(c) && c!.Length >= MinimumSecretLength)!;
    }
}
