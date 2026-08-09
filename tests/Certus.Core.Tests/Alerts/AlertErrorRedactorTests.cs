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
}
