using System.Text.Json;
using Certus.Core.Alerts;
using Certus.Core.Crl;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// What an operator actually receives. A CRL warning has to say what lapses and
/// what to do about it, because the outages this feature was reported from
/// happened at a client where nobody knew how to renew a root CRL.
/// </summary>
public class CrlNotificationTests
{
    private static readonly DateTime NextUpdate = new(2026, 12, 31, 21, 0, 0, DateTimeKind.Utc);

    private static CrlAlert RootAlert(string stage, double hoursRemaining = 30 * 24) => new(
        stage,
        "CN=Example Root CA",
        "base",
        "parent",
        NextUpdate,
        hoursRemaining,
        ["ldap:///CN=Example%20Root,CN=CDP,DC=corp,DC=example,DC=com", "http://pki.corp.example.com/root.crl"],
        CrlNumber: "0C");

    #region Email

    [Theory]
    [InlineData("30", 30 * 24, "NOTICE")]
    [InlineData("7", 7 * 24, "WARNING")]
    [InlineData("1", 20, "CRITICAL")]
    public void The_subject_urgency_follows_what_is_left(string stage, double hours, string urgency)
    {
        var message = BuildMail(RootAlert(stage, hours));

        message.Subject.Should().StartWith($"[Ducks in a Row {urgency}]");
        message.Subject.Should().Contain("Example Root CA");
    }

    [Fact]
    public void An_expired_crl_is_critical_and_says_so_in_the_subject()
    {
        var message = BuildMail(RootAlert(CrlAlertRules.ExpiredStage, -3));

        message.Subject.Should().StartWith("[Ducks in a Row CRITICAL]");
        message.Subject.Should().Contain("EXPIRED");
    }

    [Fact]
    public void An_overdue_crl_says_the_ca_missed_its_schedule_rather_than_that_it_expired()
    {
        var message = BuildMail(RootAlert(CrlAlertRules.OverdueStage, 6));

        message.Subject.Should().Contain("not published a new CRL on schedule");
    }

    [Fact]
    public void The_body_says_what_lapses_and_where_the_crl_is_served()
    {
        var body = BodyOf(BuildMail(RootAlert("14", 14 * 24)));

        body.Should().Contain("Every certificate this CA signed stops validating");
        body.Should().Contain("ldap:///CN=Example%20Root");
        body.Should().Contain("http://pki.corp.example.com/root.crl");
    }

    [Fact]
    public void A_parent_crl_is_told_how_to_publish_a_new_one()
    {
        var body = BodyOf(BuildMail(RootAlert("7", 7 * 24)));

        // The remedy for an offline root is a ceremony, and naming the two
        // commands is the difference between a warning and a runbook.
        body.Should().Contain("certutil -crl");
        body.Should().Contain("certutil -dspublish");
    }

    [Fact]
    public void The_configured_cas_own_crl_is_told_to_check_the_service_instead()
    {
        var alert = RootAlert(CrlAlertRules.OverdueStage, 6) with
        {
            Scope = "issuing",
            IssuerName = "CN=Example Issuing CA",
        };

        var body = BodyOf(BuildMail(alert));

        body.Should().Contain("Active Directory Certificate Services service is running");
        body.Should().NotContain("certutil -crl");
    }

    [Fact]
    public void A_copy_left_behind_is_told_to_copy_rather_than_to_publish()
    {
        var alert = RootAlert("7", 7 * 24) with { NewerCrlNumber = "0D" };

        var body = BodyOf(BuildMail(alert));

        body.Should().Contain("A newer CRL exists already");
        body.Should().Contain("number 0D");
    }

    [Fact]
    public void A_warning_from_a_stale_reading_says_when_it_was_read()
    {
        var alert = RootAlert("14", 14 * 24) with
        {
            LastReadAt = new DateTime(2026, 9, 1, 8, 0, 0, DateTimeKind.Utc),
        };

        BodyOf(BuildMail(alert)).Should().Contain("Last read:  2026-09-01 08:00 UTC");
    }

    #endregion

    #region Webhook

    [Theory]
    [InlineData("30", "crl.expiring")]
    [InlineData("overdue", "crl.overdue")]
    [InlineData("expired", "crl.expired")]
    public async Task Each_stage_is_its_own_event(string stage, string expectedEvent)
    {
        var (notifier, captured) = CreateWebhook();

        var result = await notifier.SendCrlAlertAsync(RootAlert(stage));

        result.Success.Should().BeTrue();
        var payload = JsonDocument.Parse(captured.Body!).RootElement;
        payload.GetProperty("event").GetString().Should().Be(expectedEvent);
        payload.GetProperty("stage").GetString().Should().Be(stage);
    }

    [Fact]
    public async Task The_payload_carries_the_issuer_the_sources_and_the_numbers()
    {
        var (notifier, captured) = CreateWebhook();

        await notifier.SendCrlAlertAsync(RootAlert("14", 14 * 24) with { NewerCrlNumber = "0D" });

        var payload = JsonDocument.Parse(captured.Body!).RootElement;
        payload.GetProperty("issuerName").GetString().Should().Be("CN=Example Root CA");
        payload.GetProperty("kind").GetString().Should().Be("base");
        payload.GetProperty("scope").GetString().Should().Be("parent");
        payload.GetProperty("crlNumber").GetString().Should().Be("0C");
        payload.GetProperty("newerCrlNumber").GetString().Should().Be("0D");
        payload.GetProperty("sources").GetArrayLength().Should().Be(2);
        payload.GetProperty("hoursRemaining").GetDouble().Should().Be(336);
    }

    [Fact]
    public async Task The_payload_is_signed_like_every_other_alert()
    {
        var (notifier, captured) = CreateWebhook(secret: "shared-secret");

        await notifier.SendCrlAlertAsync(RootAlert("30"));

        captured.Signature.Should().StartWith("sha256=");
    }

    #endregion

    #region Harness

    private static MimeMessage BuildMail(CrlAlert alert) =>
        EmailAlertNotifier.BuildCrlMessage(
            alert,
            new SmtpOptions
            {
                Host = "smtp.corp.example.com",
                FromAddress = "ducks@corp.example.com",
                FromName = "Ducks in a Row",
                Recipients = ["pki@corp.example.com"],
            },
            [MailboxAddress.Parse("pki@corp.example.com")]);

    private static string BodyOf(MimeMessage message) => message.TextBody ?? string.Empty;

    private static (WebhookAlertNotifier Notifier, CapturedRequest Captured) CreateWebhook(
        string? secret = null)
    {
        var captured = new CapturedRequest();
        var handler = new CapturingHandler(captured);
        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts", Secret = secret },
        });

        return (
            new WebhookAlertNotifier(options, new HttpClient(handler), NullLogger<WebhookAlertNotifier>.Instance),
            captured);
    }

    private sealed class CapturedRequest
    {
        public string? Body { get; set; }
        public string? Signature { get; set; }
    }

    private sealed class CapturingHandler(CapturedRequest captured) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            captured.Body = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);

            captured.Signature = request.Headers.TryGetValues("X-Certus-Signature", out var values)
                ? string.Join(",", values)
                : null;

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        }
    }

    #endregion
}
