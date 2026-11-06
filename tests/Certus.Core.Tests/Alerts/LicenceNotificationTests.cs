using System.Globalization;
using System.Text.Json;
using Certus.Core.Alerts;
using Certus.Core.Modules;
using Certus.Core.Tests.Modules;
using Certus.Modules;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// What an administrator receives about the paid licence (issue #494, licence
/// design section 13.6). The words are the core's own, the urgency is never
/// CRITICAL because no certificate is at stake, and nothing the module supplies
/// beyond a checked licence id, a checked tier and its dates reaches a channel.
/// </summary>
public class LicenceNotificationTests
{
    private const string Id = LicenceAlertRulesTests.Id;
    private const string NotAffected = "Certificate issuance and renewal are not affected.";

    private static readonly DateTimeOffset Ends = new(2027, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset GraceEnds = new(2027, 1, 31, 0, 0, 0, TimeSpan.Zero);

    private static LicenceAlert Alert(
        LicenceAlertKind kind = LicenceAlertKind.Expiring,
        string stage = LicenceAlertStages.Days7,
        int? days = 6,
        string? tier = "standard") =>
        new(kind, stage, Id, tier, Ends, GraceEnds, days);

    public static TheoryData<LicenceAlertKind, string, string> Urgencies => new()
    {
        { LicenceAlertKind.Expiring, LicenceAlertStages.Days30, "NOTICE" },
        { LicenceAlertKind.Expiring, LicenceAlertStages.Days14, "NOTICE" },
        { LicenceAlertKind.Expiring, LicenceAlertStages.Days7, "WARNING" },
        { LicenceAlertKind.Expiring, LicenceAlertStages.Days1, "WARNING" },
        { LicenceAlertKind.Grace, LicenceAlertStages.Expired, "WARNING" },
        { LicenceAlertKind.Lapsed, LicenceAlertStages.Expired, "WARNING" },
        { LicenceAlertKind.Lapsed, LicenceAlertStages.GraceEnded, "WARNING" },
    };

    #region Email

    [Theory]
    [MemberData(nameof(Urgencies))]
    public void TheUrgency_IsNoticeOrWarning_AndNeverCritical(LicenceAlertKind kind, string stage, string urgency)
    {
        var subject = BuildMail(Alert(kind, stage)).Subject;

        subject.Should().StartWith($"[Ducks in a Row {urgency}] ");
        subject.Should().NotContain("CRITICAL");
    }

    [Theory]
    [InlineData(6, "Your licence expires in 6 days")]
    [InlineData(1, "Your licence expires in 1 day")]
    [InlineData(0, "Your licence expires in less than a day")]
    public void TheExpiringSubject_UsesTheModulesDayCount(int days, string expected)
    {
        // The module rounds down to whole days, so the 1 day stage normally carries
        // 0. A licence uploaded with 20 days left says 20, not the stage's 30.
        BuildMail(Alert(days: days)).Subject.Should().EndWith(expected);
    }

    [Fact]
    public void AnExpiringWarningWithNoDayCount_FallsBackToTheStage()
    {
        BuildMail(Alert(stage: LicenceAlertStages.Days30, days: null)).Subject
            .Should().Be("[Ducks in a Row NOTICE] Your licence expires within 30 days");
    }

    [Fact]
    public void TheGraceSubject_SaysWhenPaidFeaturesSwitchOff()
    {
        BuildMail(Alert(LicenceAlertKind.Grace, LicenceAlertStages.Expired, days: 29)).Subject
            .Should().Be("[Ducks in a Row WARNING] Your licence has expired; paid features switch off on 2027-01-31");
    }

    [Fact]
    public void TheLapsedSubject_SaysPaidFeaturesAreOff()
    {
        BuildMail(Alert(LicenceAlertKind.Lapsed, LicenceAlertStages.GraceEnded, days: null)).Subject
            .Should().Be("[Ducks in a Row WARNING] Your licence has lapsed; paid features are off");
    }

    public static TheoryData<LicenceAlertKind, string> EveryAlert => new()
    {
        { LicenceAlertKind.Expiring, LicenceAlertStages.Days30 },
        { LicenceAlertKind.Expiring, LicenceAlertStages.Days1 },
        { LicenceAlertKind.Grace, LicenceAlertStages.Expired },
        { LicenceAlertKind.Lapsed, LicenceAlertStages.Expired },
        { LicenceAlertKind.Lapsed, LicenceAlertStages.GraceEnded },
    };

    [Theory]
    [MemberData(nameof(EveryAlert))]
    public void EveryLicenceMail_EndsWithTheSentenceEveryNegativeLicenceStateEndsWith(
        LicenceAlertKind kind, string stage)
    {
        var lines = BodyOf(BuildMail(Alert(kind, stage)))
            .Split('\n')
            .Select(l => l.TrimEnd('\r'))
            .Where(l => l.Length > 0)
            .ToList();

        lines[^1].Should().Be(NotAffected);
    }

    [Fact]
    public void TheBody_SaysWhatTheCardSays_AndNamesTheLicence()
    {
        var body = BodyOf(BuildMail(Alert()));

        body.Should().Contain("Your licence expires on 2027-01-01, in 6 days.");
        body.Should().Contain($"Licence:      {Id}");
        body.Should().Contain("Tier:         Standard");
        body.Should().Contain("Ends:         2027-01-01");
        body.Should().Contain("Grace until:  2027-01-31");
        body.Should().Contain("Licence card");
    }

    [Fact]
    public void TheGraceBody_SaysBothDates()
    {
        BodyOf(BuildMail(Alert(LicenceAlertKind.Grace, LicenceAlertStages.Expired, days: 29)))
            .Should().Contain("Your licence expired on 2027-01-01. Paid features switch off on 2027-01-31, in 29 days.");
    }

    [Fact]
    public void TheLapsedBody_SaysALapseDeletesNothing()
    {
        var body = BodyOf(BuildMail(Alert(LicenceAlertKind.Lapsed, LicenceAlertStages.GraceEnded, days: null)));

        body.Should().Contain("Your licence lapsed on 2027-01-31. Paid features are off.");
        body.Should().Contain("A lapse deletes nothing");
    }

    [Fact]
    public void AMissingTier_ReadsUnknown()
    {
        BodyOf(BuildMail(Alert(tier: null))).Should().Contain("Tier:         unknown");
    }

    [Fact]
    public void TheDates_AreTheSameInEveryCulture()
    {
        var before = CultureInfo.CurrentCulture;
        try
        {
            // A Buddhist calendar culture would otherwise write the year 2570 for 2027.
            CultureInfo.CurrentCulture = new CultureInfo("th-TH");

            var mail = BuildMail(Alert(LicenceAlertKind.Grace, LicenceAlertStages.Expired));

            mail.Subject.Should().EndWith("2027-01-31");
            BodyOf(mail).Should().Contain("Ends:         2027-01-01");
        }
        finally
        {
            CultureInfo.CurrentCulture = before;
        }
    }

    [Fact]
    public void TheMail_CarriesAHeaderAMailRuleCanRouteOn()
    {
        BuildMail(Alert()).Headers["X-Certus-Alert-Kind"].Should().Be("licence");
    }

    #endregion

    #region Webhook

    [Theory]
    [InlineData(LicenceAlertKind.Expiring, "licence.expiring")]
    [InlineData(LicenceAlertKind.Grace, "licence.grace")]
    [InlineData(LicenceAlertKind.Lapsed, "licence.lapsed")]
    public async Task EachKind_HasItsOwnEvent(LicenceAlertKind kind, string expected)
    {
        var (notifier, captured) = CreateWebhook();

        (await notifier.SendLicenceAlertAsync(Alert(kind, LicenceAlertStages.Expired))).Success.Should().BeTrue();

        var payload = JsonDocument.Parse(captured.Body!).RootElement;
        payload.GetProperty("event").GetString().Should().Be(expected);
        payload.GetProperty("stage").GetString().Should().Be(LicenceAlertStages.Expired);
    }

    [Fact]
    public async Task ThePayload_CarriesExactlyTheFieldsTheDesignNames()
    {
        var (notifier, captured) = CreateWebhook();

        await notifier.SendLicenceAlertAsync(Alert());

        var payload = JsonDocument.Parse(captured.Body!).RootElement;
        payload.EnumerateObject().Select(p => p.Name).Should().Equal(
            "event", "timestamp", "licenceId", "tier", "stage", "validUntil", "graceUntil", "daysRemaining");
        payload.GetProperty("licenceId").GetString().Should().Be(Id);
        payload.GetProperty("tier").GetString().Should().Be("standard");
        payload.GetProperty("validUntil").GetString().Should().Be("2027-01-01T00:00:00Z");
        payload.GetProperty("graceUntil").GetString().Should().Be("2027-01-31T00:00:00Z");
        payload.GetProperty("daysRemaining").GetInt32().Should().Be(6);
    }

    [Fact]
    public async Task ANullTier_IsLeftOutOfThePayload()
    {
        var (notifier, captured) = CreateWebhook();

        await notifier.SendLicenceAlertAsync(Alert(tier: null));

        JsonDocument.Parse(captured.Body!).RootElement.TryGetProperty("tier", out _).Should().BeFalse();
    }

    [Fact]
    public async Task ThePayload_IsSignedLikeEveryOtherAlert()
    {
        var (notifier, captured) = CreateWebhook(secret: "shared-secret");

        await notifier.SendLicenceAlertAsync(Alert());

        captured.Signature.Should().StartWith("sha256=");
    }

    #endregion

    #region No text from the module

    [Fact]
    public async Task NothingTheModuleSupplies_ReachesAChannel_ButTheCheckedFields()
    {
        // Licence design threat T23: a module must not be able to flood or inject
        // into an administrator's channels. Every free form field the module
        // supplies is planted here, run through the real decision, and looked for
        // in what both channels would send.
        var snapshot = LicenceAlertRulesTests.Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, tier: "Gold Edition!")
            with
            {
                LicenseeName = "Planted Licensee",
                LicenseeRef = "PLANTED-REF",
                ReasonCode = "planted-reason",
                BoundForests = ["planted.example"],
                ObservedForest = "planted.example",
                Features = ["planted-feature"],
            };
        var alert = LicenceAlertRules.Evaluate(LicenceAlertRulesTests.Loaded(snapshot)).Alert!;

        var mail = BuildMail(alert);
        var (notifier, captured) = CreateWebhook();
        await notifier.SendLicenceAlertAsync(alert);

        foreach (var sent in new[] { mail.Subject, BodyOf(mail), captured.Body! })
        {
            sent.Should().NotContainEquivalentOf("planted");
            sent.Should().NotContainEquivalentOf("Gold Edition");
        }

        BodyOf(mail).Should().Contain("Tier:         unknown");
        JsonDocument.Parse(captured.Body!).RootElement.TryGetProperty("tier", out _).Should().BeFalse();
    }

    #endregion

    #region Harness

    private static MimeMessage BuildMail(LicenceAlert alert) =>
        EmailAlertNotifier.BuildLicenceMessage(
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
