namespace Certus.Core.Alerts;

/// <summary>
/// Strips configured secrets out of a notifier's error message before it is
/// shown to anyone (issue #161).
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
    /// Redacts every configured secret from <paramref name="message"/> and
    /// truncates the result. Null in, null out, so a successful result passes
    /// through untouched. <paramref name="candidateSmtp"/> carries the unsaved
    /// SMTP values of a candidate test send, whose password, username and host
    /// are exactly as sensitive as the configured ones and appear in the same
    /// relay error messages.
    /// </summary>
    public static string? Redact(
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

        return redacted.Length > MaxLength
            ? string.Concat(redacted.AsSpan(0, MaxLength), "…")
            : redacted;
    }

    /// <summary>
    /// The shortest value that is worth replacing. A one or two character host
    /// cannot be a real endpoint, and replacing every occurrence of it would
    /// turn the message into noise without protecting anything the whole URL
    /// entry does not already cover. This is about legibility, not secrecy.
    /// </summary>
    private const int MinimumSecretLength = 4;

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
        }

        return candidates
            .Where(c => !string.IsNullOrEmpty(c) && c!.Length >= MinimumSecretLength)!;
    }

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
