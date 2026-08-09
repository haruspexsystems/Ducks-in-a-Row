using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Certus.Core.Alerts;
using Certus.Core.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// POST /api/alerts/test with a channel actually configured (issue #161).
///
/// <para>
/// This deliberately does not join the shared "ACME Integration" collection.
/// AlertTestThrottle is a singleton, so a cooldown armed by one test class would
/// leak into every other class sharing the host, and the 429 case here would
/// then depend on run order. IClassFixture gives this file its own host and its
/// own throttle.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public class AlertTestSendIntegrationTests : IClassFixture<AlertTestSendWebApplicationFactory>
{
    private readonly AlertTestSendWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public AlertTestSendIntegrationTests(AlertTestSendWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        return JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());
    }

    /// <summary>
    /// The happy path, the 429, and the no-row guarantee in one test.
    ///
    /// One test rather than three, because they share a singleton cooldown and
    /// separate tests would be order dependent: the first to run would arm the
    /// throttle and the rest would see 429s they did not ask for.
    /// </summary>
    [Fact]
    public async Task SendTest_DeliversOnceThenCoolsDown_AndWritesNoHistoryRow()
    {
        var before = await AlertRowCountAsync();
        _factory.Receiver.Reset();

        var first = await _client.PostAsync("/api/alerts/test", null);

        first.StatusCode.Should().Be(HttpStatusCode.OK);
        _factory.Receiver.Requests.Should().Be(1);

        var body = await ParseJsonAsync(first);
        body.TryGetProperty("attemptedAt", out _).Should().BeTrue();

        var results = body.GetProperty("results").EnumerateArray().ToList();
        results.Should().ContainSingle("only the webhook is configured on this host");
        results[0].GetProperty("channel").GetString().Should().Be("webhook");
        results[0].GetProperty("success").GetBoolean().Should().BeTrue();

        // The payload is signed and marked as a test on the real send path, not
        // a shortcut one.
        var payload = JsonSerializer.Deserialize<JsonElement>(_factory.Receiver.LastBody!);
        payload.GetProperty("event").GetString().Should().Be("test.alert");
        payload.GetProperty("test").GetBoolean().Should().BeTrue();
        _factory.Receiver.LastSignature.Should().StartWith("sha256=");

        // The triggering account must not reach a third party endpoint.
        _factory.Receiver.LastBody.Should().NotContain("anonymous");

        // Immediately again: refused, and nothing is attempted.
        var second = await _client.PostAsync("/api/alerts/test", null);

        second.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        _factory.Receiver.Requests.Should().Be(1, "a throttled call attempts nothing");
        second.Headers.TryGetValues("Retry-After", out var retryAfter).Should().BeTrue();
        retryAfter!.First().Should().NotBeNullOrEmpty();

        var refusal = await ParseJsonAsync(second);
        refusal.GetProperty("retryAfterSeconds").GetInt32().Should().BeGreaterThan(0);
        refusal.GetProperty("error").GetString().Should().NotBeNullOrEmpty();

        // AlertsSent has no way to mark a row as a test, and its unique index on
        // (CertificateId, ThresholdDays) means a test row would permanently
        // suppress a real certificate's warning. Nothing may be written.
        (await AlertRowCountAsync()).Should().Be(before);
    }

    private async Task<int> AlertRowCountAsync()
    {
        using var scope = _factory.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<CertusDbContext>()
            .AlertsSent.CountAsync();
    }
}

/// <summary>
/// POST /api/alerts/test with a candidate SMTP body: the test-before-restart
/// path. Its own host and therefore its own throttle, like the class above,
/// because the candidate send arms the shared cooldown.
///
/// <para>
/// The host here has no channel configured at all, which is the interesting
/// starting state: a body-less test is refused outright, while a candidate
/// makes the email channel join anyway, because proving a typed configuration
/// is the whole point when nothing deliverable is running yet.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public class AlertCandidateTestSendIntegrationTests : IClassFixture<CertusWebApplicationFactory>
{
    private readonly HttpClient _client;

    public AlertCandidateTestSendIntegrationTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        return JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());
    }

    private static object Candidate(
        string host = "smtp.test.invalid",
        int port = 2525,
        string tlsMode = "none",
        string from = "ducks@example.com",
        string[]? recipients = null) => new
        {
            smtp = new
            {
                host,
                port,
                tlsMode,
                username = "candidate-user",
                password = "candidate-hunter2",
                fromAddress = from,
                fromName = "Ducks in a Row",
                recipients = recipients ?? new[] { "ops@example.com" },
            },
        };

    /// <summary>
    /// One test for the same reason the class above has one: the 429 at the
    /// end depends on the candidate send arming the singleton cooldown, and
    /// the refusals before it prove they never touch that cooldown.
    /// </summary>
    [Fact]
    public async Task SendTest_CandidateFlow_RefusalsThenSendThenCooldown()
    {
        // No body on a host with nothing configured: refused as always.
        var noBody = await _client.PostAsync("/api/alerts/test", null);
        noBody.StatusCode.Should().Be(HttpStatusCode.Conflict);

        // An incomplete candidate is a 400, not a no-channel 409: the caller
        // asked to test something specific and it cannot be tested.
        var incomplete = await _client.PostAsJsonAsync(
            "/api/alerts/test", Candidate(host: ""));
        incomplete.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var badMode = await _client.PostAsJsonAsync(
            "/api/alerts/test", Candidate(tlsMode: "opportunistic"));
        badMode.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await badMode.Content.ReadAsStringAsync()).Should().Contain("starttls");

        // The full candidate: the email channel joins although the running
        // configuration is not deliverable, the relay does not exist, and the
        // failure comes back redacted of the candidate's own values.
        var send = await _client.PostAsJsonAsync("/api/alerts/test", Candidate());
        send.StatusCode.Should().Be(HttpStatusCode.OK,
            "the request was carried out; the per channel result is the answer");

        var body = await ParseJsonAsync(send);
        var email = body.GetProperty("results").EnumerateArray()
            .Single(r => r.GetProperty("channel").GetString() == "email");
        email.GetProperty("success").GetBoolean().Should().BeFalse();

        var raw = await send.Content.ReadAsStringAsync();
        raw.Should().NotContain("smtp.test.invalid");
        raw.Should().NotContain("candidate-user");
        raw.Should().NotContain("candidate-hunter2");

        // The candidate send armed the shared cooldown; the refusals above
        // did not, or this would have been 429 already.
        var second = await _client.PostAsJsonAsync("/api/alerts/test", Candidate());
        second.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }
}

/// <summary>
/// A host with a webhook configured and its outbound HTTP intercepted.
///
/// The webhook rather than SMTP, because MailKit would need a live relay while
/// the webhook client is a plain HttpClient whose handler can be swapped.
/// </summary>
public sealed class AlertTestSendWebApplicationFactory : CertusWebApplicationFactory
{
    /// <summary>The stand in for the operator's webhook endpoint.</summary>
    public RecordingWebhookHandler Receiver { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        // appsettings.json in Certus.Web has no Certus:Alerts section, so these
        // keys do not collide with anything and UseSetting is read before
        // Program.cs binds AlertOptions.
        builder.UseSetting("Certus:Alerts:Webhook:Url", "https://hooks.test.invalid/hook");
        builder.UseSetting("Certus:Alerts:Webhook:Secret", "test-signing-secret");
        // Off, so the background ExpiryMonitorService this host also registers
        // does not wake up and start POSTing at the recording handler.
        builder.UseSetting("Certus:Alerts:Enabled", "false");

        builder.ConfigureServices(services =>
        {
            // The webhook notifier is registered with AddHttpClient, so the way
            // to intercept it is its named client's primary handler.
            services.AddHttpClient(nameof(WebhookAlertNotifier))
                .ConfigurePrimaryHttpMessageHandler(() => Receiver);
        });
    }
}

/// <summary>
/// Records what the webhook notifier sent. Hand written rather than a mock:
/// Certus.Web.Tests carries no NSubstitute.
/// </summary>
public sealed class RecordingWebhookHandler : HttpMessageHandler
{
    private int _requests;

    public int Requests => Volatile.Read(ref _requests);
    public string? LastBody { get; private set; }
    public string? LastSignature { get; private set; }

    /// <summary>The status the stand in endpoint answers with.</summary>
    public HttpStatusCode ResponseStatus { get; set; } = HttpStatusCode.OK;

    public void Reset()
    {
        Volatile.Write(ref _requests, 0);
        LastBody = null;
        LastSignature = null;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _requests);

        LastBody = request.Content == null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);
        LastSignature = request.Headers.TryGetValues("X-Certus-Signature", out var values)
            ? values.First()
            : null;

        return new HttpResponseMessage(ResponseStatus);
    }
}
