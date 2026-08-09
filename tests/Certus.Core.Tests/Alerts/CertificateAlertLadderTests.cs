using Certus.Core.Alerts;
using Certus.Core.Data.Entities;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// Tests for the per certificate alert ladder (issue #160).
///
/// This is where the interesting behaviour lives, and it is all pure, so none of
/// it needs a database or a host. The cases that matter most are the ones that
/// stop the block crying wolf: a certificate can legitimately have no alerts for
/// five different reasons, and calling any of them a missed warning would train
/// an operator to ignore the one that is real.
/// </summary>
public class CertificateAlertLadderTests
{
    private static readonly DateTime Now = new(2026, 7, 31, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>
    /// A healthy install: monitoring on, both channels up, the default ladder.
    /// </summary>
    private static AlertLadderContext Context(
        bool enabled = true,
        string[]? channels = null,
        int checkIntervalMinutes = 60,
        int[]? thresholds = null,
        bool isOwnCertificate = false) =>
        new(
            AlertingEnabled: enabled,
            EnabledChannels: channels ?? ["email", "webhook"],
            CheckIntervalMinutes: checkIntervalMinutes,
            ThresholdDays: thresholds ?? [30, 14, 7, 1],
            IsOwnCertificate: isOwnCertificate);

    /// <summary>
    /// A certificate <paramref name="daysToExpiry"/> days out, synced long enough
    /// ago that the first sight grace never applies unless a test asks for it.
    /// </summary>
    private static CertificateAlertFacts Certificate(
        double daysToExpiry = 20,
        string status = "Issued",
        DateTime? firstSyncedAt = null) =>
        new(
            CertificateId: 7,
            Status: status,
            SerialNumber: "ABC123",
            NotAfter: Now.AddDays(daysToExpiry),
            FirstSyncedAt: firstSyncedAt ?? Now.AddYears(-1));

    private static AlertSent Row(int thresholdDays, bool success = true, string? error = null) =>
        new()
        {
            CertificateId = 7,
            ThresholdDays = thresholdDays,
            SentAt = Now.AddDays(-1),
            Channels = "email,webhook",
            Success = success,
            ErrorMessage = error,
        };

    private static CertificateAlertThreshold Rung(CertificateAlertHistory history, int thresholdDays) =>
        history.Thresholds.Single(t => t.ThresholdDays == thresholdDays);

    // ---- Coverage -------------------------------------------------------

    [Fact]
    public void Coverage_HealthyIssuedCertificate_IsMonitored()
    {
        var history = CertificateAlertLadder.Build(Certificate(), [], Context(), Now);

        history.Coverage.Should().Be(AlertCoverage.Monitored);
        history.EnabledChannels.Should().Equal("email", "webhook");
    }

    [Fact]
    public void Coverage_MonitoringDisabled_ReportsDisabled()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(), [], Context(enabled: false), Now);

        history.Coverage.Should().Be(AlertCoverage.AlertingDisabled);
    }

    /// <summary>
    /// The case the issue's own acceptance criteria missed, and the one most
    /// likely to be live on a real install. ExpiryMonitorService returns before
    /// writing anything when no notifier reports itself enabled, so monitoring
    /// switched on with no recipient and no webhook is permanent silence that
    /// looks identical to a quiet, healthy install.
    /// </summary>
    [Fact]
    public void Coverage_EnabledButNoChannels_ReportsNoChannelsConfigured()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(), [], Context(channels: []), Now);

        history.Coverage.Should().Be(AlertCoverage.NoChannelsConfigured);
    }

    /// <summary>
    /// Disabled outranks unconfigured, mirroring the order the monitor applies
    /// its own checks in: the service exits on the enabled flag first.
    /// </summary>
    [Fact]
    public void Coverage_DisabledAndUnconfigured_ReportsDisabledFirst()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(), [], Context(enabled: false, channels: []), Now);

        history.Coverage.Should().Be(AlertCoverage.AlertingDisabled);
    }

    [Fact]
    public void Coverage_Revoked_IsCalledOutSeparatelyFromNotIssued()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(status: "Revoked"), [], Context(), Now);

        history.Coverage.Should().Be(AlertCoverage.Revoked);
    }

    [Theory]
    [InlineData("Pending")]
    [InlineData("Denied")]
    [InlineData("Failed")]
    public void Coverage_RequestThatNeverBecameACertificate_ReportsNotIssued(string status)
    {
        var history = CertificateAlertLadder.Build(
            Certificate(status: status), [], Context(), Now);

        history.Coverage.Should().Be(AlertCoverage.NotIssued);
    }

    [Fact]
    public void Coverage_AlreadyExpired_ReportsAlreadyExpired()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: -1), [], Context(), Now);

        history.Coverage.Should().Be(AlertCoverage.AlreadyExpired);
    }

    /// <summary>
    /// Issue #105: the server's own certificate is suppressed on purpose,
    /// because automatic renewal owns it. Without this the detail page would
    /// report a deliberate design decision as a missed warning.
    /// </summary>
    [Fact]
    public void Coverage_OwnCertificate_ReportsSuppression()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(), [], Context(isOwnCertificate: true), Now);

        history.Coverage.Should().Be(AlertCoverage.OwnCertificate);
    }

    // ---- Threshold state ------------------------------------------------

    [Fact]
    public void Threshold_SuccessfulRow_ReadsAsSentAndCarriesItsDetail()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(), [Row(30)], Context(), Now);

        var rung = Rung(history, 30);
        rung.State.Should().Be(AlertThresholdState.Sent);
        rung.SentAt.Should().Be(Now.AddDays(-1));
        rung.Channels.Should().Be("email,webhook");
        rung.ErrorMessage.Should().BeNull();
    }

    [Fact]
    public void Threshold_FailedRow_ReadsAsFailedAndCarriesItsError()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(), [Row(30, success: false, error: "SMTP host unreachable")], Context(), Now);

        var rung = Rung(history, 30);
        rung.State.Should().Be(AlertThresholdState.Failed);
        rung.ErrorMessage.Should().Be("SMTP host unreachable");
    }

    [Fact]
    public void Threshold_NotYetCrossed_ReadsAsPending()
    {
        // 20 days out, so the 14, 7 and 1 day warnings are all still ahead.
        var history = CertificateAlertLadder.Build(Certificate(daysToExpiry: 20), [], Context(), Now);

        Rung(history, 14).State.Should().Be(AlertThresholdState.Pending);
        Rung(history, 7).State.Should().Be(AlertThresholdState.Pending);
        Rung(history, 1).State.Should().Be(AlertThresholdState.Pending);
    }

    /// <summary>
    /// Crossed, but not long enough ago to expect a row. A 60 minute check
    /// interval means a threshold crossed 10 minutes ago is not evidence of
    /// anything, and calling it missing would fire on every healthy crossing.
    /// </summary>
    [Fact]
    public void Threshold_CrossedWithinOneCheckInterval_ReadsAsAwaitingCheck()
    {
        // 30 day threshold came due 10 minutes ago.
        var certificate = Certificate(daysToExpiry: 30 - (10.0 / 1440));

        var history = CertificateAlertLadder.Build(certificate, [], Context(), Now);

        Rung(history, 30).State.Should().Be(AlertThresholdState.AwaitingCheck);
    }

    [Fact]
    public void Threshold_CrossedLongerAgoThanTheCheckInterval_ReadsAsMissing()
    {
        // 30 day threshold came due two days ago, on a 60 minute interval.
        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: 28), [], Context(), Now);

        Rung(history, 30).State.Should().Be(AlertThresholdState.Missing);
    }

    /// <summary>
    /// The false alarm this guard exists for. A certificate imported today that
    /// is already five days from expiry crossed its 30, 14 and 7 day thresholds
    /// weeks before Ducks had ever heard of it. Measuring the grace from the
    /// crossing alone would mark all three missing the instant it appeared in the
    /// inventory, on an install that has done nothing wrong. ExpiryMonitorService
    /// documents this first sight burst: it fires all three on the next pass.
    /// </summary>
    [Fact]
    public void Threshold_FreshlySyncedCertificateAlreadyInsideTheWindow_IsNotReportedMissing()
    {
        var certificate = Certificate(daysToExpiry: 5, firstSyncedAt: Now.AddMinutes(-5));

        var history = CertificateAlertLadder.Build(certificate, [], Context(), Now);

        Rung(history, 30).State.Should().Be(AlertThresholdState.AwaitingCheck);
        Rung(history, 14).State.Should().Be(AlertThresholdState.AwaitingCheck);
        Rung(history, 7).State.Should().Be(AlertThresholdState.AwaitingCheck);
    }

    [Fact]
    public void Threshold_SyncedLongAgoAndStillNothingRecorded_IsReportedMissing()
    {
        // The same certificate, a day after it was first synced. The burst
        // should have happened by now, so silence is real.
        var certificate = Certificate(daysToExpiry: 5, firstSyncedAt: Now.AddDays(-1));

        var history = CertificateAlertLadder.Build(certificate, [], Context(), Now);

        Rung(history, 30).State.Should().Be(AlertThresholdState.Missing);
    }

    /// <summary>
    /// The case a plain list of what exists cannot show: the 30 day warning
    /// went out, then the service was down across the 14 and 7 day crossings.
    /// The certificate has an alert, so a binary "has anything been sent"
    /// check reads healthy while two warnings were silently skipped.
    /// </summary>
    [Fact]
    public void Threshold_PartialLadder_SurfacesTheSkippedRungs()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: 5, firstSyncedAt: Now.AddYears(-1)),
            [Row(30)],
            Context(),
            Now);

        Rung(history, 30).State.Should().Be(AlertThresholdState.Sent);
        Rung(history, 14).State.Should().Be(AlertThresholdState.Missing);
        Rung(history, 7).State.Should().Be(AlertThresholdState.Missing);
        Rung(history, 1).State.Should().Be(AlertThresholdState.Pending);
    }

    [Fact]
    public void Threshold_NotMonitored_ReadsAsNotApplicableRatherThanMissing()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: 5), [], Context(enabled: false), Now);

        history.Thresholds.Should().OnlyContain(t => t.State == AlertThresholdState.NotApplicable);
    }

    /// <summary>
    /// History outlives coverage. A certificate that was warned about and then
    /// revoked keeps its record, rather than reading as though nothing ever
    /// happened.
    /// </summary>
    [Fact]
    public void Threshold_RecordedRowSurvivesACoverageChange()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: 5, status: "Revoked"), [Row(30)], Context(), Now);

        history.Coverage.Should().Be(AlertCoverage.Revoked);
        Rung(history, 30).State.Should().Be(AlertThresholdState.Sent);
        Rung(history, 14).State.Should().Be(AlertThresholdState.NotApplicable);
    }

    /// <summary>
    /// An operator who alerted at 30 days and later reconfigured to [60, 7]
    /// still has that 30 day row. Dropping it would erase the evidence this
    /// block exists to show.
    /// </summary>
    [Fact]
    public void Threshold_RowForADeconfiguredThreshold_IsStillShown()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: 5), [Row(30)], Context(thresholds: [60, 7]), Now);

        history.Thresholds.Select(t => t.ThresholdDays).Should().BeEquivalentTo(new[] { 60, 30, 7 });
        Rung(history, 30).State.Should().Be(AlertThresholdState.Sent);
    }

    /// <summary>
    /// A nonsensical interval must not collapse the grace to nothing, because
    /// the monitor itself floors its loop at one minute.
    /// </summary>
    [Fact]
    public void Threshold_ZeroCheckInterval_StillLeavesAMinuteOfGrace()
    {
        // Came due 30 seconds ago.
        var certificate = Certificate(daysToExpiry: 30 - (0.5 / 1440));

        var history = CertificateAlertLadder.Build(
            certificate, [], Context(checkIntervalMinutes: 0), Now);

        Rung(history, 30).State.Should().Be(AlertThresholdState.AwaitingCheck);
    }

    // ---- Ordering -------------------------------------------------------

    /// <summary>
    /// Most recent first, as the issue asks, without burying the real events
    /// under thresholds that have not happened yet. A certificate 20 days out
    /// has one sent warning and three still ahead of it; the sent one leads.
    /// </summary>
    [Fact]
    public void Order_EventsComeFirst_ThenUpcomingInTheOrderTheyFallDue()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: 20), [Row(30)], Context(), Now);

        history.Thresholds.Select(t => t.ThresholdDays).Should().Equal(30, 14, 7, 1);
        history.Thresholds[0].State.Should().Be(AlertThresholdState.Sent);
    }

    [Fact]
    public void Order_MultipleEvents_NewestFirst()
    {
        var older = Row(30);
        older.SentAt = Now.AddDays(-10);
        var newer = Row(14);
        newer.SentAt = Now.AddDays(-2);

        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: 5), [older, newer], Context(thresholds: [30, 14]), Now);

        history.Thresholds.Select(t => t.ThresholdDays).Should().Equal(14, 30);
    }

    /// <summary>
    /// A skipped warning sorts into the event stream by when it came due, not to
    /// the bottom with the ones still ahead. It is something that already went
    /// wrong, so it belongs where the reader is looking.
    /// </summary>
    [Fact]
    public void Order_MissingRungsSitAmongTheEventsByTheirDueDate()
    {
        var sent = Row(30);
        sent.SentAt = Now.AddDays(-10);

        // 5 days out: 30 was sent, 14 and 7 came due and were skipped, 1 is
        // still ahead.
        var history = CertificateAlertLadder.Build(
            Certificate(daysToExpiry: 5), [sent], Context(), Now);

        history.Thresholds.Select(t => t.ThresholdDays).Should().Equal(7, 14, 30, 1);
        history.Thresholds[^1].State.Should().Be(AlertThresholdState.Pending);
    }

    // ---- Shape ----------------------------------------------------------

    [Fact]
    public void Build_CarriesTheContextThePageNeedsToExplainItself()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(), [], Context(checkIntervalMinutes: 15), Now);

        history.CertificateId.Should().Be(7);
        history.CheckIntervalMinutes.Should().Be(15);
    }

    [Fact]
    public void Build_NoThresholdsConfiguredAndNothingSent_ReturnsAnEmptyLadder()
    {
        var history = CertificateAlertLadder.Build(
            Certificate(), [], Context(thresholds: []), Now);

        history.Thresholds.Should().BeEmpty();
    }

    /// <summary>
    /// dueAt is the crossing, not the send. The two genuinely differ on the
    /// first sight burst, and the page words itself from both.
    /// </summary>
    [Fact]
    public void Build_DueAtIsDerivedFromExpiryNotFromWhenTheAlertWentOut()
    {
        var certificate = Certificate(daysToExpiry: 5, firstSyncedAt: Now.AddMinutes(-5));

        var history = CertificateAlertLadder.Build(certificate, [Row(30)], Context(), Now);

        var rung = Rung(history, 30);
        rung.DueAt.Should().Be(certificate.NotAfter.AddDays(-30));
        rung.SentAt.Should().Be(Now.AddDays(-1));
        rung.DueAt.Should().BeBefore(rung.SentAt!.Value);
    }
}
