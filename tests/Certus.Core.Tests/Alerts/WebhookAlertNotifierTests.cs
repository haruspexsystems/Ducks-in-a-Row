using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Alerts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Alerts;

public class WebhookAlertNotifierTests
{
    private static ExpiryAlertBatch CreateTestBatch(int thresholdDays = 30) => new(
        thresholdDays,
        [
            new CertificateExpiryInfo(1, "CN=test.example.com", "SERIAL001", "WebServer",
                DateTime.UtcNow.AddDays(25), 25)
        ]);

    [Fact]
    public async Task SendAlert_PostsJsonToWebhookUrl()
    {
        string? capturedBody = null;
        string? capturedUrl = null;

        var handler = new MockHttpHandler((request) =>
        {
            capturedUrl = request.RequestUri?.ToString();
            capturedBody = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });

        var client = new HttpClient(handler);
        var sut = new WebhookAlertNotifier(options, client, NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeTrue();
        capturedUrl.Should().Be("https://hooks.example.com/alerts");
        capturedBody.Should().NotBeNullOrEmpty();

        var payload = JsonSerializer.Deserialize<JsonElement>(capturedBody!);
        payload.GetProperty("event").GetString().Should().Be("certificate.expiring");
        payload.GetProperty("thresholdDays").GetInt32().Should().Be(30);
        payload.GetProperty("certificateCount").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task SendAlert_WithSecret_IncludesHmacSignature()
    {
        string? signatureHeader = null;
        string? body = null;

        var handler = new MockHttpHandler((request) =>
        {
            signatureHeader = request.Headers.TryGetValues("X-Certus-Signature", out var values)
                ? values.First() : null;
            body = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var secret = "my-webhook-secret";
        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts", Secret = secret }
        });

        var client = new HttpClient(handler);
        var sut = new WebhookAlertNotifier(options, client, NullLogger<WebhookAlertNotifier>.Instance);

        await sut.SendExpiryAlertAsync(CreateTestBatch());

        signatureHeader.Should().NotBeNull();
        signatureHeader.Should().StartWith("sha256=");

        // Verify HMAC
        var expectedHash = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(secret),
            Encoding.UTF8.GetBytes(body!));
        var expected = $"sha256={Convert.ToHexString(expectedHash).ToLowerInvariant()}";
        signatureHeader.Should().Be(expected);
    }

    [Fact]
    public async Task SendAlert_WebhookReturnsError_ReturnsFailure()
    {
        var handler = new MockHttpHandler((_) =>
            new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("Internal Server Error")
            });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });

        var client = new HttpClient(handler);
        var sut = new WebhookAlertNotifier(options, client, NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("500");
    }

    [Fact]
    public async Task SendAlert_WithCustomHeaders_IncludesHeaders()
    {
        string? customHeader = null;

        var handler = new MockHttpHandler((request) =>
        {
            customHeader = request.Headers.TryGetValues("X-Custom-Token", out var values)
                ? values.First() : null;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions
            {
                Url = "https://hooks.example.com/alerts",
                Headers = new Dictionary<string, string>
                {
                    ["X-Custom-Token"] = "bearer-token-123"
                }
            }
        });

        var client = new HttpClient(handler);
        var sut = new WebhookAlertNotifier(options, client, NullLogger<WebhookAlertNotifier>.Instance);

        await sut.SendExpiryAlertAsync(CreateTestBatch());

        customHeader.Should().Be("bearer-token-123");
    }

    [Fact]
    public void IsEnabled_WithoutUrl_ReturnsFalse()
    {
        var options = Options.Create(new AlertOptions { Webhook = null });
        var sut = new WebhookAlertNotifier(options, new HttpClient(), NullLogger<WebhookAlertNotifier>.Instance);

        sut.IsEnabled.Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_WithUrl_ReturnsTrue()
    {
        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });
        var sut = new WebhookAlertNotifier(options, new HttpClient(), NullLogger<WebhookAlertNotifier>.Instance);

        sut.IsEnabled.Should().BeTrue();
    }

    [Fact]
    public async Task SendTestAlert_PostsTheDistinctTestEvent()
    {
        // A receiver must be able to tell a test from a real warning without
        // guessing. The event name says so and the boolean says so again, so a
        // handler can filter on either.
        string? body = null;
        var handler = new MockHttpHandler((request) =>
        {
            body = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(handler), NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        result.Success.Should().BeTrue();
        var payload = JsonSerializer.Deserialize<JsonElement>(body!);
        payload.GetProperty("event").GetString().Should().Be("test.alert");
        payload.GetProperty("test").GetBoolean().Should().BeTrue();
        // No certificate list at all, so a receiver that blindly iterates
        // certificates fails loudly rather than filing a fake expiry warning.
        payload.TryGetProperty("certificates", out _).Should().BeFalse();
    }

    [Fact]
    public async Task SendTestAlert_PayloadDoesNotCarryTheTriggeringUser()
    {
        // This body goes to whatever third party relay the operator configured.
        // A directory account name in it would make the test button a small
        // username disclosure channel.
        string? body = null;
        var handler = new MockHttpHandler((request) =>
        {
            body = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(handler), NullLogger<WebhookAlertNotifier>.Instance);

        await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        body.Should().NotContain("alice");
        body.Should().NotContain("CONTOSO");
    }

    [Fact]
    public async Task SendServerCertificateAlert_PostsTheWireDetailAndNeverTheDetail()
    {
        // Issue #485. A denial's Detail names the service's computer account and its
        // domain, which the alert mail keeps for the operator. This body goes to
        // whatever relay the operator configured, so only the account free form may
        // reach it.
        string? body = null;
        var handler = new MockHttpHandler((request) =>
        {
            body = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(handler), NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendServerCertificateAlertAsync(new ServerCertificateAlert(
            Outcome: "Denied",
            Detail: "The CA denied the request. The service enrolls as the computer account " +
                    "DUCKS01$ in domain ad.example.com. Grant it Enroll on the WebServer template.",
            Template: "WebServer",
            DaysRemaining: 9,
            WireDetail: "The CA denied the request. Grant the service's computer account Enroll " +
                        "on the WebServer template."));

        result.Success.Should().BeTrue();
        body.Should().NotContain("DUCKS01").And.NotContain("ad.example.com");
        var payload = JsonSerializer.Deserialize<JsonElement>(body!);
        payload.GetProperty("event").GetString().Should().Be("server.certificate.renewal_failed");
        payload.GetProperty("detail").GetString().Should().Be(
            "The CA denied the request. Grant the service's computer account Enroll " +
            "on the WebServer template.");
        payload.GetProperty("templateName").GetString().Should().Be("WebServer");
        payload.GetProperty("daysRemaining").GetInt32().Should().Be(9);
    }

    [Fact]
    public async Task SendServerCertificateAlert_NoWireDetail_SendsNoDetailRatherThanTheDetail()
    {
        // The safe failure: an alert raised by an arm that did not say what may go on
        // the wire carries the outcome and the template, and none of its text.
        string? body = null;
        var handler = new MockHttpHandler((request) =>
        {
            body = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(handler), NullLogger<WebhookAlertNotifier>.Instance);

        await sut.SendServerCertificateAlertAsync(new ServerCertificateAlert(
            "Denied", Detail: "The service enrolls as the computer account DUCKS01$.",
            Template: "WebServer"));

        body.Should().NotContain("DUCKS01");
        var payload = JsonSerializer.Deserialize<JsonElement>(body!);
        payload.TryGetProperty("detail", out _).Should().BeFalse();
        payload.GetProperty("outcome").GetString().Should().Be("Denied");
    }

    [Fact]
    public async Task SendTestAlert_IsHmacSignedIdenticallyToARealAlert()
    {
        // The point of the test send is to exercise the path a real alert takes.
        // A test that skipped signing would prove nothing about it.
        string? signatureHeader = null;
        string? body = null;

        var handler = new MockHttpHandler((request) =>
        {
            signatureHeader = request.Headers.TryGetValues("X-Certus-Signature", out var values)
                ? values.First() : null;
            body = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        const string secret = "my-webhook-secret";
        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts", Secret = secret }
        });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(handler), NullLogger<WebhookAlertNotifier>.Instance);

        await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        var expectedHash = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body!));
        signatureHeader.Should().Be($"sha256={Convert.ToHexString(expectedHash).ToLowerInvariant()}");
    }

    [Fact]
    public async Task SendTestAlert_IncludesTheConfiguredCustomHeaders()
    {
        string? customHeader = null;
        var handler = new MockHttpHandler((request) =>
        {
            customHeader = request.Headers.TryGetValues("X-Custom-Token", out var values)
                ? values.First() : null;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions
            {
                Url = "https://hooks.example.com/alerts",
                Headers = new Dictionary<string, string> { ["X-Custom-Token"] = "bearer-token-123" }
            }
        });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(handler), NullLogger<WebhookAlertNotifier>.Instance);

        await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        customHeader.Should().Be("bearer-token-123");
    }

    [Fact]
    public async Task SendTestAlert_WhenNotConfigured_ReturnsFailure()
    {
        var options = Options.Create(new AlertOptions { Webhook = null });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(), NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("not configured");
    }

    [Fact]
    public async Task SendLicenceAlert_WhenNotConfigured_ReturnsFailure()
    {
        var options = Options.Create(new AlertOptions { Webhook = null });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(), NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendLicenceAlertAsync(new LicenceAlert(
            LicenceAlertKind.Lapsed, LicenceAlertStages.GraceEnded,
            "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b", "standard", null, null, null));

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("not configured");
    }

    [Fact]
    public async Task SendTestAlert_ReceiverRejects_ReportsTheStatusItAnswered()
    {
        // The dashboard keys off this prefix to tell "the endpoint was reached
        // and answered badly" apart from "the request never arrived", so an
        // operator is not sent off to fix a webhook that is delivering fine.
        var handler = new MockHttpHandler((_) =>
            new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("cannot read certificates of undefined")
            });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });
        var sut = new WebhookAlertNotifier(
            options, new HttpClient(handler), NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendTestAlertAsync(new TestAlert("CONTOSO\\alice", DateTime.UtcNow));

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().StartWith("Webhook returned 500");
    }

    // ---- What reaches the log and the history row (issue #635) ----------

    /// <summary>
    /// The URL with a token in its query, the shape Slack, Teams and most
    /// relays use, and a signing secret and a custom header beside it.
    /// </summary>
    private const string TokenUrl = "https://hooks.example.com/services/T000/B000?token=xoxb-1234-secret-token";

    private static IOptions<AlertOptions> TokenOptions() => Options.Create(new AlertOptions
    {
        Webhook = new WebhookOptions
        {
            Url = TokenUrl,
            Secret = "shared-signing-secret",
            Headers = new Dictionary<string, string> { ["Authorization"] = "Bearer header-bearer-value" },
        },
    });

    [Fact]
    public async Task SendAlert_Success_LogsSchemeAndHostButNeverThePathOrTheQuery()
    {
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK)));
        var sut = new WebhookAlertNotifier(TokenOptions(), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeTrue();
        var line = logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Information).Subject.Message;
        line.Should().EndWith("to https://hooks.example.com");
        line.Should().NotContain("/services");
        line.Should().NotContain("token=");
        line.Should().NotContain("xoxb-1234-secret-token");
    }

    // ---- The secret in the path: Slack, Discord, Teams connectors --------

    /// <summary>
    /// The services' URL shapes. Slack, Discord and a classic Teams connector
    /// carry the secret in the path, Power Automate in the query.
    /// </summary>
    public static TheoryData<string> ServiceShapedUrls => new()
    {
        AlertErrorRedactorTests.SlackShapedUrl,
        AlertErrorRedactorTests.DiscordShapedUrl,
        AlertErrorRedactorTests.TeamsShapedUrl,
        AlertErrorRedactorTests.PowerAutomateShapedUrl,
    };

    [Theory]
    [MemberData(nameof(ServiceShapedUrls))]
    public async Task SendAlert_Success_TheLogNamesTheHostAndNoPartOfThePathOrQuery(string url)
    {
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK)));
        var sut = new WebhookAlertNotifier(UrlOptions(url), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeTrue();
        var line = logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Information).Subject.Message;
        line.Should().Contain("https://" + new Uri(url).Host, "the host still tells the operator which service it was");
        ShouldHoldNoPartOf(line, url);
    }

    [Theory]
    [MemberData(nameof(ServiceShapedUrls))]
    public async Task SendAlert_ReceiverRefuses_TheLogAndTheResultCarryNoPartOfThePathOrQuery(string url)
    {
        // A stock 404 page quotes the path it was asked for, and a refusal can
        // name the token it refused: the longest part of the URL, in each shape.
        var uri = new Uri(url);
        var token = UrlParts(uri).MaxBy(p => p.Length);
        var body = $"<html><body><h1>Not Found</h1><p>The requested URL {uri.PathAndQuery} was not found " +
                   $"on this server.</p><p>invalid_token {token}</p></body></html>";
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ =>
            new HttpResponseMessage(System.Net.HttpStatusCode.NotFound) { Content = new StringContent(body) }));
        var sut = new WebhookAlertNotifier(UrlOptions(url), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().StartWith("Webhook returned 404: ");
        var warning = logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Warning).Subject.Message;
        warning.Should().Contain("https://" + uri.Host);
        ShouldHoldNoPartOf(warning, url);
        ShouldHoldNoPartOf(result.ErrorMessage!, url);
    }

    [Theory]
    [MemberData(nameof(ServiceShapedUrls))]
    public async Task SendAlert_TransportThrows_TheLogAndTheResultCarryNoPartOfThePathOrQuery(string url)
    {
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ =>
            throw new HttpRequestException($"An error occurred while sending the request. ({url})")));
        var sut = new WebhookAlertNotifier(UrlOptions(url), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeFalse();
        var error = logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Error).Subject;
        error.Exception.Should().BeNull();
        ShouldHoldNoPartOf(error.Message, url);
        ShouldHoldNoPartOf(result.ErrorMessage!, url);
    }

    /// <summary>
    /// A path whose start is one long token run and whose end, past a
    /// character the run stops at, is a secret too short to be pooled alone.
    /// </summary>
    private const string FragmentingUrl = "https://relay.example.com/h/abcdefghijklmnopqrstuvwxyz0123@shortsecret12";

    [Fact]
    public async Task SendAlert_ReceiverQuotesThePath_TheShortTailOfItIsRedactedToo()
    {
        // The token pass replaces the long run and leaves "@shortsecret12", which
        // the whole path no longer matches; the configured secrets go first.
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ =>
            new HttpResponseMessage(System.Net.HttpStatusCode.NotFound)
            {
                Content = new StringContent("Cannot POST /h/abcdefghijklmnopqrstuvwxyz0123@shortsecret12"),
            }));
        var sut = new WebhookAlertNotifier(UrlOptions(FragmentingUrl), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.ErrorMessage.Should().NotContain("shortsecret12");
        logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Warning)
            .Subject.Message.Should().NotContain("shortsecret12");
    }

    [Fact]
    public async Task SendAlert_TransportThrowsQuotingThePath_TheShortTailOfItIsRedactedToo()
    {
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ =>
            throw new HttpRequestException($"Connection refused ({FragmentingUrl})")));
        var sut = new WebhookAlertNotifier(UrlOptions(FragmentingUrl), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.ErrorMessage.Should().NotContain("shortsecret12");
        logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Error)
            .Subject.Message.Should().NotContain("shortsecret12");
    }

    /// <summary>
    /// A token no setting names, 60 characters, which only the token pass can
    /// find, and only while it is whole.
    /// </summary>
    private const string UnconfiguredToken = "LeakCheckToken0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";

    [Fact]
    public async Task SendAlert_ReceiverBodyHasATokenAcrossTheLengthCap_ItIsRedactedWhole()
    {
        // An indented page: 478 characters that fold to almost nothing, then the
        // token across character 500, where the 500 character cap falls. Capped
        // before the token pass, 22 characters of it would survive the pass,
        // which needs 32, and land in the excerpt.
        var body = "<p>" + new string(' ', 475) + UnconfiguredToken + " </p>";
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ =>
            new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized) { Content = new StringContent(body) }));
        var sut = new WebhookAlertNotifier(UrlOptions(FragmentingUrl), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.ErrorMessage.Should().NotContain("LeakCheckToken");
        logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Warning)
            .Subject.Message.Should().NotContain("LeakCheckToken");
    }

    [Fact]
    public async Task SendAlert_TransportMessageHasATokenAcrossTheLengthCap_ItIsRedactedWhole()
    {
        var message = string.Concat(Enumerable.Repeat("The request failed. ", 24)) + UnconfiguredToken + " end";
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ => throw new HttpRequestException(message)));
        var sut = new WebhookAlertNotifier(UrlOptions(FragmentingUrl), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.ErrorMessage.Should().NotContain("LeakCheckToken");
        logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Error)
            .Subject.Message.Should().NotContain("LeakCheckToken");
    }

    [Theory]
    [MemberData(nameof(ServiceShapedUrls))]
    public async Task TheRegisteredClient_LogsNoPartOfThePathOrQuery(string url)
    {
        // Resolved through the registration both hosts call, with every log
        // category recorded down to Trace, scopes included. IHttpClientFactory's
        // own handlers log each request URI at Information, the level the
        // service log keeps, and redact only its query.
        var logs = new RecordingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.SetMinimumLevel(LogLevel.Trace).AddProvider(logs));
        services.Configure<AlertOptions>(o => o.Webhook = new WebhookOptions { Url = url });
        services.AddWebhookAlertNotifier();
        services.AddHttpClient(nameof(WebhookAlertNotifier)).ConfigurePrimaryHttpMessageHandler(() =>
            new MockHttpHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK)));

        await using var root = services.BuildServiceProvider();
        using var scope = root.CreateScope();
        var notifier = scope.ServiceProvider.GetServices<IAlertNotifier>()
            .Should().ContainSingle(n => n.Channel == "webhook").Subject;

        var result = await notifier.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeTrue();
        logs.Lines.Should().Contain(l => l.Contains("Webhook alert sent"), "the notifier's own line still says where it went");
        foreach (var line in logs.Lines)
            ShouldHoldNoPartOf(line, url);
    }

    private static IOptions<AlertOptions> UrlOptions(string url) => Options.Create(new AlertOptions
    {
        Webhook = new WebhookOptions { Url = url },
    });

    /// <summary>
    /// Fails if <paramref name="text"/> holds any path segment or query value of
    /// <paramref name="url"/>, as written or unescaped. Parts under four
    /// characters are skipped: "api" and "1.0" occur in ordinary log text.
    /// </summary>
    private static void ShouldHoldNoPartOf(string text, string url)
    {
        foreach (var part in UrlParts(new Uri(url))
                     .SelectMany(p => new[] { p, Uri.UnescapeDataString(p) })
                     .Where(p => p.Length >= 4)
                     .Distinct())
        {
            text.Should().NotContain(part);
        }
    }

    /// <summary>Every path segment and query value of <paramref name="uri"/>, as written.</summary>
    private static IEnumerable<string> UrlParts(Uri uri) =>
        uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Concat(uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(pair => pair[(pair.IndexOf('=') + 1)..]));

    [Fact]
    public async Task SendAlert_WebhookReturnsError_LogsAndStoresTheStatusAndARedactedExcerpt()
    {
        // The receiver echoes the request: the URL it was called on, the
        // signing secret and the custom header, inside a body far longer than
        // the excerpt keeps.
        var echo = $"{{\"error\":\"unauthorized\",\"url\":\"{TokenUrl}\",\"signature\":\"shared-signing-secret\"," +
                   $"\"authorization\":\"Bearer header-bearer-value\"}}" + new string('x', 2000);
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ =>
            new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized) { Content = new StringContent(echo) }));
        var sut = new WebhookAlertNotifier(TokenOptions(), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().StartWith("Webhook returned 401: ");
        result.ErrorMessage!.Length.Should().BeLessThan(
            "Webhook returned 401: ".Length + AlertErrorRedactor.ResponseBodyExcerptLength + 2);

        var warning = logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Warning).Subject.Message;
        foreach (var text in new[] { result.ErrorMessage, warning })
        {
            text.Should().NotContain("xoxb-1234-secret-token");
            text.Should().NotContain("token=");
            text.Should().NotContain("shared-signing-secret");
            text.Should().NotContain("header-bearer-value");
        }
    }

    [Fact]
    public async Task SendAlert_TransportThrows_TheLogAndTheResultCarryNoUrl()
    {
        // HttpRequestException and UriFormatException quote the URL as
        // configured. The exception object itself must not reach the logger,
        // whose exception rendering would write it out verbatim.
        var logger = new RecordingLogger();
        var client = new HttpClient(new MockHttpHandler(_ =>
            throw new HttpRequestException($"Connection refused ({TokenUrl})")));
        var sut = new WebhookAlertNotifier(TokenOptions(), client, logger);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().NotContain("xoxb-1234-secret-token");
        result.ErrorMessage.Should().NotContain("hooks.example.com");

        var error = logger.Lines.Should().ContainSingle(l => l.Level == LogLevel.Error).Subject;
        error.Exception.Should().BeNull("the exception text quotes the URL, so only its type name is logged");
        error.Message.Should().Contain("HttpRequestException");
        error.Message.Should().NotContain("xoxb-1234-secret-token");
        error.Message.Should().NotContain("token=");
    }

    /// <summary>Keeps every line the notifier logs, with its level and exception.</summary>
    private sealed class RecordingLogger : ILogger<WebhookAlertNotifier>
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Lines)
                Lines.Add((logLevel, formatter(state, exception), exception));
        }
    }

    /// <summary>
    /// Keeps every line any category logs, and every scope opened, prefixed
    /// with the category, so the HTTP client factory's own lines are seen too.
    /// </summary>
    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        public List<string> Lines { get; } = [];

        public ILogger CreateLogger(string categoryName) => new CategoryLogger(this, categoryName);

        public void Dispose()
        {
        }

        private void Add(string line)
        {
            lock (Lines)
                Lines.Add(line);
        }

        private sealed class CategoryLogger(RecordingLoggerProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                owner.Add($"{category} scope: {state}");
                return null;
            }

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner.Add($"{category}: {formatter(state, exception)}");
        }
    }

    /// <summary>Simple mock HTTP handler for testing.</summary>
    private class MockHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public MockHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request));
        }
    }
}
