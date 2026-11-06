using Certus.Core.Alerts;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// Secrets must not survive into an error message the dashboard renders
/// (issue #161). The webhook notifier builds its failure text from the
/// receiver's whole response body, and on an exception it passes the exception
/// message through verbatim, so a URL with a token in it reaches the browser
/// unless something strips it.
/// </summary>
public class AlertErrorRedactorTests
{
    private static AlertOptions Configured() => new()
    {
        Smtp = new SmtpOptions { Username = "svc-ducks", Password = "hunter2" },
        Webhook = new WebhookOptions
        {
            Url = "https://hooks.example.com/services/T000/xoxb-secret-token",
            Secret = "shared-secret",
        },
    };

    [Fact]
    public void Redact_ReplacesTheWebhookUrl()
    {
        // The shape a DNS or TLS failure produces: the exception message names
        // the endpoint it could not reach.
        var message =
            "No such host is known (https://hooks.example.com/services/T000/xoxb-secret-token)";

        var redacted = AlertErrorRedactor.Redact(message, Configured());

        redacted.Should().NotContain("hooks.example.com");
        redacted.Should().NotContain("xoxb-secret-token");
        redacted.Should().Contain("(redacted)");
    }

    [Fact]
    public void Redact_ReplacesTheWebhookSecret()
    {
        var redacted = AlertErrorRedactor.Redact(
            "Webhook returned 401: bad signature for shared-secret", Configured());

        redacted.Should().NotContain("shared-secret");
    }

    [Fact]
    public void Redact_ReplacesTheSmtpPasswordAndUsername()
    {
        var redacted = AlertErrorRedactor.Redact(
            "535 authentication failed for svc-ducks with hunter2", Configured());

        redacted.Should().NotContain("svc-ducks");
        redacted.Should().NotContain("hunter2");
    }

    [Fact]
    public void Redact_TruncatesALongReceiverResponseBody()
    {
        // A webhook receiver can answer a failure with an arbitrarily large
        // body, and this path never touches the 1000 character database column.
        var message = new string('x', 5000);

        var redacted = AlertErrorRedactor.Redact(message, Configured());

        redacted!.Length.Should().BeLessThan(600);
        redacted.Should().EndWith("…");
    }

    [Fact]
    public void Redact_NullMessage_ReturnsNull()
    {
        AlertErrorRedactor.Redact(null, Configured()).Should().BeNull();
    }

    [Fact]
    public void Redact_NoSecretsConfigured_ReturnsTheMessageUnchanged()
    {
        const string message = "Webhook returned 500: Internal Server Error";

        var redacted = AlertErrorRedactor.Redact(message, new AlertOptions());

        redacted.Should().Be(message);
    }

    [Fact]
    public void Redact_ReplacesTheEndpointHostAndPort()
    {
        // The message a DNS failure actually produces. It does not quote the URL
        // as configured, so matching only the configured string leaves the
        // operator's private endpoint in a response the dashboard renders. Found
        // by driving a live dev host at an unreachable webhook.
        var redacted = AlertErrorRedactor.Redact(
            "No such host is known. (hooks.example.com:443)", Configured());

        redacted.Should().NotContain("hooks.example.com");
    }

    [Fact]
    public void Redact_ReplacesTheEndpointHostOnItsOwn()
    {
        var redacted = AlertErrorRedactor.Redact(
            "The SSL connection to hooks.example.com could not be established", Configured());

        redacted.Should().NotContain("hooks.example.com");
    }

    [Fact]
    public void Redact_ReplacesWebhookCustomHeaderValues()
    {
        // Custom headers are the other way a webhook is authenticated, for a
        // receiver that does not verify the HMAC signature, so a value here is
        // routinely a bearer token. A receiver that echoes the request headers
        // back in its error body would otherwise put it straight in front of the
        // dashboard.
        var options = new AlertOptions
        {
            Webhook = new WebhookOptions
            {
                Url = "https://hooks.example.com/hook",
                Headers = new Dictionary<string, string> { ["Authorization"] = "Bearer sk-abcdef123456" },
            },
        };

        var redacted = AlertErrorRedactor.Redact(
            "Webhook returned 401: rejected Authorization: Bearer sk-abcdef123456", options);

        redacted.Should().NotContain("sk-abcdef123456");
    }

    [Fact]
    public void Redact_ReplacesTheSmtpHost()
    {
        // Withheld from the config endpoint, so it must not come back through an
        // error message either.
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "relay.internal.example.com" },
        };

        var redacted = AlertErrorRedactor.Redact(
            "No such host is known. (relay.internal.example.com:587)", options);

        redacted.Should().NotContain("relay.internal.example.com");
    }

    [Fact]
    public void Redact_MalformedWebhookUrl_StillRedactsWhatItCan()
    {
        // Uri.TryCreate fails on this, so the host entries are simply absent.
        // The configured string itself is still matched, and nothing throws.
        var options = new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "not a url at all", Secret = "shared-secret" },
        };

        var redacted = AlertErrorRedactor.Redact(
            "Invalid URI: not a url at all, secret shared-secret", options);

        redacted.Should().NotContain("not a url at all");
        redacted.Should().NotContain("shared-secret");
    }

    [Fact]
    public void Redact_VeryShortHost_DoesNotGarbleTheMessage()
    {
        // A one character host cannot be a real endpoint, and replacing every
        // occurrence of it would make the message unreadable while protecting
        // nothing the whole URL entry does not already cover.
        var options = new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://a/hook" },
        };

        var redacted = AlertErrorRedactor.Redact("No such host is known.", options);

        redacted.Should().Be("No such host is known.");
    }

    [Fact]
    public void Redact_UrlContainingTheSecret_LeavesNoRecognisableFragment()
    {
        // Secrets are replaced longest first for exactly this case: replacing
        // the shorter secret first would leave the surrounding URL behind, still
        // naming the host and path.
        var options = new AlertOptions
        {
            Webhook = new WebhookOptions
            {
                Url = "https://hooks.example.com/hook?token=abc123",
                Secret = "abc123",
            },
        };

        var redacted = AlertErrorRedactor.Redact(
            "Connection refused: https://hooks.example.com/hook?token=abc123", options);

        redacted.Should().NotContain("hooks.example.com");
        redacted.Should().NotContain("abc123");
    }

    [Fact]
    public void Redact_CandidateSmtpValues_AreStrippedLikeConfiguredOnes()
    {
        // A candidate test send carries an unsaved host, username and a just
        // typed plaintext password. A relay authentication failure quotes
        // exactly these, and the configured options know nothing about them.
        var options = new AlertOptions();
        var candidate = new SmtpOptions
        {
            Host = "candidate-relay.example.com",
            Username = "candidate-user",
            Password = "candidate-hunter2",
        };

        var redacted = AlertErrorRedactor.Redact(
            "535 authentication failed for candidate-user with candidate-hunter2 " +
            "at candidate-relay.example.com",
            options,
            candidate);

        redacted.Should().NotContain("candidate-user");
        redacted.Should().NotContain("candidate-hunter2");
        redacted.Should().NotContain("candidate-relay.example.com");
    }

    [Fact]
    public void Redact_WithoutACandidate_BehavesExactlyAsBefore()
    {
        var redacted = AlertErrorRedactor.Redact(
            "No such host is known.", new AlertOptions(), candidateSmtp: null);

        redacted.Should().Be("No such host is known.");
    }

    // ---- The log line shape (issue #635) ---------------------------------

    /// <summary>
    /// The webhook URL shapes of the common services, on example.com hosts. Slack,
    /// Discord and a classic Teams connector carry the secret in the path, Power
    /// Automate in the query. The lengths of the secret parts are the services'.
    /// </summary>
    internal const string SlackShapedUrl =
        "https://hooks.example.com/services/T000AAAA0/B000BBBB0/SlackSecretPart24Chars00";

    internal const string DiscordShapedUrl =
        "https://discord.example.com/api/webhooks/123456789012345678/" +
        "DiscordTokenPart_abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWX";

    internal const string TeamsShapedUrl =
        "https://contoso.webhook.example.com/webhookb2/" +
        "00000000-1111-2222-3333-444444444444@55555555-6666-7777-8888-999999999999/" +
        "IncomingWebhook/0123456789abcdef0123456789abcdef/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    internal const string PowerAutomateShapedUrl =
        "https://prod-00.westeurope.logic.example.com:443/workflows/0123456789abcdef0123456789abcdef/" +
        "triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0" +
        "&sig=PowerAutomateSignature_0123456789abcdefghij";

    [Theory]
    [InlineData(SlackShapedUrl, "https://hooks.example.com")]
    [InlineData(DiscordShapedUrl, "https://discord.example.com")]
    [InlineData(TeamsShapedUrl, "https://contoso.webhook.example.com")]
    [InlineData(PowerAutomateShapedUrl, "https://prod-00.westeurope.logic.example.com")]
    [InlineData("https://hooks.example.com/services/T000/B000/SECRETPART", "https://hooks.example.com")]
    [InlineData("https://hooks.example.com/services/T000/B000?token=xoxb-secret", "https://hooks.example.com")]
    [InlineData("https://user:hunter2@hooks.example.com/alerts", "https://hooks.example.com")]
    [InlineData("https://hooks.example.com:8443/alerts#frag", "https://hooks.example.com:8443")]
    [InlineData("http://relay.example.com/", "http://relay.example.com")]
    [InlineData("http://192.0.2.10:8080/hook/SECRETPART", "http://192.0.2.10:8080")]
    public void DescribeEndpoint_KeepsSchemeHostAndPortOnly(string url, string expected)
    {
        AlertErrorRedactor.DescribeEndpoint(url).Should().Be(expected);
    }

    [Theory]
    [InlineData(SlackShapedUrl, "The requested URL /services/T000AAAA0/B000BBBB0/SlackSecretPart24Chars00 was not found on this server.", "SlackSecretPart24Chars00")]
    [InlineData(SlackShapedUrl, "invalid_token SlackSecretPart24Chars00", "SlackSecretPart24Chars00")]
    [InlineData("https://relay.example.com/h/Short0Secret0123", "Cannot POST /h/Short0Secret0123", "/h/Short0Secret0123")]
    [InlineData(PowerAutomateShapedUrl, "signature PowerAutomateSignature_0123456789abcdefghij does not match", "PowerAutomateSignature_0123456789abcdefghij")]
    [InlineData("https://alerts:hunter2pass@relay.example.com/hook", "401: bad credentials for alerts:hunter2pass", "alerts:hunter2pass")]
    [InlineData("https://alerts:hunter2pass@relay.example.com/hook", "401: password hunter2pass was refused", "hunter2pass")]
    public void Redact_ThePathOrALongPartOfTheConfiguredUrl_IsRedacted(string url, string message, string mustBeGone)
    {
        // A receiver's refusal that quotes the path it was asked for, as a
        // stock 404 page does, or names only the token it refused. Neither
        // holds the whole URL or the host, which were the only URL parts
        // pooled before.
        var options = new AlertOptions { Webhook = new WebhookOptions { Url = url } };

        var redacted = AlertErrorRedactor.Redact(message, options);

        redacted.Should().NotContain(mustBeGone);
        redacted.Should().Contain("(redacted)");
    }

    [Fact]
    public void Redact_ShortWordsOfTheConfiguredPath_AreLeftInTheMessage()
    {
        // "services" and the Slack workspace and channel ids are in every URL of
        // that shape and secret in none, and pooling them would blank ordinary
        // words out of every failure message.
        var options = new AlertOptions { Webhook = new WebhookOptions { Url = SlackShapedUrl } };

        var redacted = AlertErrorRedactor.Redact("no_service: the services endpoint for T000AAAA0 is gone", options);

        redacted.Should().Be("no_service: the services endpoint for T000AAAA0 is gone");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a url at all xoxb-secret")]
    public void DescribeEndpoint_UnparseableUrl_IsDescribedNotQuoted(string? url)
    {
        AlertErrorRedactor.DescribeEndpoint(url).Should().Be("(unparseable URL)");
    }

    [Fact]
    public void ExcerptResponseBody_KeepsTheFirst200CharactersOnOneLine()
    {
        var body = string.Join("\n", Enumerable.Repeat("line of ordinary text", 30));

        var excerpt = AlertErrorRedactor.ExcerptResponseBody(body);

        excerpt.Should().NotContain("\n");
        excerpt.Length.Should().Be(AlertErrorRedactor.ResponseBodyExcerptLength + 1, "200 characters and the ellipsis");
        excerpt.Should().EndWith("…");
    }

    [Fact]
    public void ExcerptResponseBody_RedactsATokenTheCutWouldHaveSplit()
    {
        // A token that starts inside the first 200 characters and ends past them:
        // cut first, its first half would survive as a short run.
        var token = new string('k', 40) + "7Zq";
        var body = string.Concat(Enumerable.Repeat("plain words ", 15)) + token + " trailing";

        var excerpt = AlertErrorRedactor.ExcerptResponseBody(body);

        excerpt.Should().NotContain("kkkkkkkk");
        excerpt.Should().Contain("(redacted)");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \n")]
    public void ExcerptResponseBody_EmptyBody_SaysSo(string? body)
    {
        AlertErrorRedactor.ExcerptResponseBody(body).Should().Be("(empty body)");
    }

    [Theory]
    [InlineData("invalid token=xoxb-1234-abcd for this channel", "xoxb-1234-abcd")]
    [InlineData("{\"error\":\"bad_auth\",\"secret\":\"s3cr3t-value\"}", "s3cr3t-value")]
    [InlineData("Authorization: Bearer abc.def-ghi expired", "abc.def-ghi")]
    [InlineData("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c rejected", "eyJhbGciOiJIUzI1NiJ9")]
    [InlineData("see https://relay.example.com/hook?key=abcdef123456 for details", "abcdef123456")]
    [InlineData("opaque 0123456789abcdef0123456789abcdef0123456789abcdef run", "0123456789abcdef0123456789abcdef")]
    public void RedactTokens_ReplacesWhatLooksLikeACredential(string text, string mustBeGone)
    {
        var redacted = AlertErrorRedactor.RedactTokens(text);

        redacted.Should().NotContain(mustBeGone);
        redacted.Should().Contain("(redacted)");
    }

    [Fact]
    public void RedactTokens_LeavesOrdinaryProseAlone()
    {
        const string text = "404 Not Found: the channel was archived on 2026-10-21, status 410 follows.";

        AlertErrorRedactor.RedactTokens(text).Should().Be(text);
    }
}
