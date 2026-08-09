using Certus.Core.Alerts;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// The operator triggered test send (issue #161).
/// </summary>
public class AlertTestServiceTests
{
    private static AlertTestService Create(
        IEnumerable<IAlertNotifier> notifiers,
        AlertTestThrottle? throttle = null,
        AlertOptions? options = null) =>
        new(notifiers,
            throttle ?? new AlertTestThrottle(new TestTimeProvider()),
            Options.Create(options ?? new AlertOptions()),
            NullLogger<AlertTestService>.Instance);

    [Fact]
    public async Task SendAsync_NoEnabledNotifier_ReturnsNoChannelsEnabled()
    {
        var sut = Create([new RecordingNotifier("email", enabled: false)]);

        var result = await sut.SendAsync("CONTOSO\\alice");

        result.Status.Should().Be(AlertTestStatus.NoChannelsEnabled);
        result.Results.Should().BeEmpty();
    }

    [Fact]
    public async Task SendAsync_NoNotifiersAtAll_ReturnsNoChannelsEnabled()
    {
        var result = await Create([]).SendAsync("CONTOSO\\alice");

        result.Status.Should().Be(AlertTestStatus.NoChannelsEnabled);
    }

    [Fact]
    public async Task SendAsync_NoEnabledNotifier_DoesNotArmTheCooldown()
    {
        // The ordering rule this service exists to own. An operator who presses
        // the button, gets told nothing is configured, fixes the configuration,
        // and presses again must not be refused for a minute by a send that
        // never happened.
        var throttle = new AlertTestThrottle(new TestTimeProvider());
        var disabled = new RecordingNotifier("email", enabled: false);

        await Create([disabled], throttle).SendAsync("CONTOSO\\alice");

        throttle.TryAcquire(out _).Should().BeTrue();
    }

    [Fact]
    public async Task SendAsync_FansOutOverEveryEnabledChannel()
    {
        var email = new RecordingNotifier("email", enabled: true);
        var webhook = new RecordingNotifier("webhook", enabled: true);

        var result = await Create([email, webhook]).SendAsync("CONTOSO\\alice");

        result.Status.Should().Be(AlertTestStatus.Sent);
        result.Results.Select(r => r.Channel).Should().Equal("email", "webhook");
        result.Results.Should().OnlyContain(r => r.Success);
        email.Calls.Should().Be(1);
        webhook.Calls.Should().Be(1);
    }

    [Fact]
    public async Task SendAsync_SkipsDisabledNotifiers()
    {
        var email = new RecordingNotifier("email", enabled: true);
        var webhook = new RecordingNotifier("webhook", enabled: false);

        var result = await Create([email, webhook]).SendAsync("CONTOSO\\alice");

        result.Results.Should().ContainSingle().Which.Channel.Should().Be("email");
        webhook.Calls.Should().Be(0);
    }

    [Fact]
    public async Task SendAsync_CarriesTheActorAndAWallClockTimeToTheNotifier()
    {
        var email = new RecordingNotifier("email", enabled: true);

        await Create([email]).SendAsync("CONTOSO\\alice");

        email.LastAlert!.TriggeredBy.Should().Be("CONTOSO\\alice");
        email.LastAlert.TriggeredAtUtc.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task SendAsync_PartialFailure_ReportsPerChannelResults()
    {
        var email = new RecordingNotifier("email", enabled: true);
        var webhook = new RecordingNotifier("webhook", enabled: true)
        {
            Result = new AlertNotificationResult(false, "Webhook returned 500: nope"),
        };

        var result = await Create([email, webhook]).SendAsync("CONTOSO\\alice");

        // Still Sent: the request was carried out, and the per channel answer is
        // the result. A failure here is the operator's relay, not Ducks.
        result.Status.Should().Be(AlertTestStatus.Sent);
        result.Results.Single(r => r.Channel == "email").Success.Should().BeTrue();

        var failed = result.Results.Single(r => r.Channel == "webhook");
        failed.Success.Should().BeFalse();
        failed.ErrorMessage.Should().Contain("500");
    }

    [Fact]
    public async Task SendAsync_RedactsTheWebhookUrlFromAChannelError()
    {
        var options = new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/xoxb-secret" },
        };
        var webhook = new RecordingNotifier("webhook", enabled: true)
        {
            Result = new AlertNotificationResult(
                false, "No such host is known (https://hooks.example.com/xoxb-secret)"),
        };

        var result = await Create([webhook], options: options).SendAsync("CONTOSO\\alice");

        var error = result.Results.Single().ErrorMessage;
        error.Should().NotContain("hooks.example.com");
        error.Should().NotContain("xoxb-secret");
    }

    [Fact]
    public async Task SendAsync_SecondCallWithinTheWindow_ReturnsThrottledWithRetryAfter()
    {
        var time = new TestTimeProvider();
        var throttle = new AlertTestThrottle(time);
        var email = new RecordingNotifier("email", enabled: true);
        var sut = Create([email], throttle);

        (await sut.SendAsync("CONTOSO\\alice")).Status.Should().Be(AlertTestStatus.Sent);

        time.Now = time.Now.AddSeconds(10);
        var second = await sut.SendAsync("CONTOSO\\bob");

        second.Status.Should().Be(AlertTestStatus.Throttled);
        second.RetryAfterSeconds.Should().Be(AlertTestThrottle.CooldownSeconds - 10);
        second.Results.Should().BeEmpty();
        // Nothing was attempted on the refused call.
        email.Calls.Should().Be(1);
    }

    [Fact]
    public async Task SendAsync_MonitoringDisabled_StillSendsOverTheEnabledChannels()
    {
        // AlertOptions.Enabled gates the expiry monitor, not the notifiers, and
        // proving SMTP works before switching monitoring on is a reasonable
        // thing to want. The dashboard is responsible for not letting the green
        // result read as "alerting is working".
        var email = new RecordingNotifier("email", enabled: true);

        var result = await Create([email], options: new AlertOptions { Enabled = false })
            .SendAsync("CONTOSO\\alice");

        result.Status.Should().Be(AlertTestStatus.Sent);
        email.Calls.Should().Be(1);
    }

    /// <summary>A notifier that records what it was asked to send.</summary>
    private sealed class RecordingNotifier(string channel, bool enabled) : IAlertNotifier
    {
        public string Channel { get; } = channel;
        public bool IsEnabled { get; } = enabled;

        public AlertNotificationResult Result { get; set; } = new(true);
        public int Calls { get; private set; }
        public TestAlert? LastAlert { get; private set; }

        public Task<AlertNotificationResult> SendTestAlertAsync(
            TestAlert alert, CancellationToken cancellationToken = default)
        {
            Calls++;
            LastAlert = alert;
            return Task.FromResult(Result);
        }

        public Task<AlertNotificationResult> SendExpiryAlertAsync(
            ExpiryAlertBatch batch, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AlertNotificationResult> SendServerCertificateAlertAsync(
            ServerCertificateAlert alert, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class TestTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
