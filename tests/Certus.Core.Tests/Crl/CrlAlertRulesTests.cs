using Certus.Core.Crl;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// The rules are the whole reason this feature is not "run the leaf ladder over
/// CRLs". The numbers in these tests are the ones a real CA produced on lab 2019
/// on 2026-09-23, so the noise case is measured rather than imagined.
/// </summary>
public class CrlAlertRulesTests
{
    private static readonly int[] Ladder = [30, 14, 7, 1];

    /// <summary>A default ADCS base CRL: published weekly, 12.2 hours of overlap.</summary>
    private static readonly DateTimeOffset BasePublished = new(2026, 9, 17, 8, 1, 47, TimeSpan.Zero);
    private static readonly DateTimeOffset BaseNextPublish = new(2026, 9, 24, 8, 11, 47, TimeSpan.Zero);
    private static readonly DateTimeOffset BaseNextUpdate = new(2026, 9, 24, 20, 21, 47, TimeSpan.Zero);

    /// <summary>An offline root's CRL: published by hand, a year of life.</summary>
    private static readonly DateTimeOffset RootPublished = new(2026, 1, 1, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset RootNextUpdate = new(2026, 12, 31, 21, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset RootNextPublish = new(2026, 12, 31, 9, 0, 0, TimeSpan.Zero);

    #region The noise case the whole design exists to avoid

    [Fact]
    public void A_healthy_online_ca_crl_is_worth_no_alert_at_all()
    {
        // Every hour of the CRL's life, from publication to the moment the CA
        // replaces it. On the leaf ladder this window produces four alerts.
        for (var hour = 0; hour < (BaseNextPublish - BasePublished).TotalHours; hour++)
        {
            var now = BasePublished.AddHours(hour);

            var stages = CrlAlertRules.StagesDue(
                now, BasePublished, BaseNextUpdate, BaseNextPublish,
                autoPublished: true, Ladder);

            stages.Should().BeEmpty($"a CA that replaces its CRL on time is not news at hour {hour}");
        }
    }

    [Fact]
    public void A_daily_delta_crl_is_worth_no_alert_either()
    {
        var published = new DateTimeOffset(2026, 9, 22, 8, 1, 48, TimeSpan.Zero);
        var nextPublish = published.AddDays(1);
        var nextUpdate = nextPublish.AddHours(12.2);

        for (var hour = 0; hour < 24; hour++)
        {
            var stages = CrlAlertRules.StagesDue(
                published.AddHours(hour), published, nextUpdate, nextPublish,
                autoPublished: true, Ladder);

            stages.Should().BeEmpty($"the delta is replaced daily, and hour {hour} is inside that");
        }
    }

    #endregion

    #region A CA that misses its own schedule

    [Fact]
    public void An_online_crl_is_overdue_once_the_grace_after_the_scheduled_publish_has_passed()
    {
        var justAfter = BaseNextPublish + TimeSpan.FromHours(2) + TimeSpan.FromMinutes(1);

        var stages = CrlAlertRules.StagesDue(
            justAfter, BasePublished, BaseNextUpdate, BaseNextPublish,
            autoPublished: true, Ladder);

        stages.Should().Equal(CrlAlertRules.OverdueStage);
    }

    [Fact]
    public void The_grace_holds_off_an_alert_while_a_copy_is_still_propagating()
    {
        var justInside = BaseNextPublish + TimeSpan.FromMinutes(90);

        var stages = CrlAlertRules.StagesDue(
            justInside, BasePublished, BaseNextUpdate, BaseNextPublish,
            autoPublished: true, Ladder);

        stages.Should().BeEmpty("a directory or a web server takes time to receive the new CRL");
    }

    [Fact]
    public void The_grace_never_outlasts_the_overlap_it_sits_in()
    {
        // A CA configured with a twenty minute overlap: two hours of grace would
        // put the warning an hour and a half after the outage started.
        var published = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        var nextPublish = published.AddDays(7);
        var nextUpdate = nextPublish.AddMinutes(20);

        var stages = CrlAlertRules.StagesDue(
            nextPublish.AddMinutes(11), published, nextUpdate, nextPublish,
            autoPublished: true, Ladder);

        stages.Should().Equal(CrlAlertRules.OverdueStage);
    }

    [Fact]
    public void An_online_crl_with_no_microsoft_extension_assumes_the_adcs_default_overlap()
    {
        // Ten percent of the window, capped at twelve hours, which is what ADCS
        // itself does when nothing is configured.
        var published = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        var nextUpdate = published.AddDays(7).AddHours(12);
        var expected = nextUpdate - TimeSpan.FromHours(12);

        CrlAlertRules.StagesDue(
            expected.AddMinutes(-1), published, nextUpdate, nextPublish: null,
            autoPublished: true, Ladder)
            .Should().BeEmpty();

        CrlAlertRules.StagesDue(
            expected + TimeSpan.FromHours(3), published, nextUpdate, nextPublish: null,
            autoPublished: true, Ladder)
            .Should().Equal(CrlAlertRules.OverdueStage);
    }

    [Fact]
    public void An_online_crl_that_actually_expired_says_both_things()
    {
        var stages = CrlAlertRules.StagesDue(
            BaseNextUpdate.AddMinutes(1), BasePublished, BaseNextUpdate, BaseNextPublish,
            autoPublished: true, Ladder);

        stages.Should().Equal(CrlAlertRules.OverdueStage, CrlAlertRules.ExpiredStage);
    }

    #endregion

    #region An offline root, where the ladder is the point

    [Fact]
    public void A_root_crl_is_quiet_until_the_widest_threshold()
    {
        var stages = CrlAlertRules.StagesDue(
            RootNextUpdate.AddDays(-31), RootPublished, RootNextUpdate, RootNextPublish,
            autoPublished: false, Ladder);

        stages.Should().BeEmpty();
    }

    [Theory]
    [InlineData(30, "30")]
    [InlineData(14, "14")]
    [InlineData(7, "7")]
    [InlineData(1, "1")]
    public void A_root_crl_warns_at_each_threshold(int daysLeft, string expectedStage)
    {
        var stages = CrlAlertRules.StagesDue(
            RootNextUpdate.AddDays(-daysLeft), RootPublished, RootNextUpdate, RootNextPublish,
            autoPublished: false, Ladder);

        stages.Should().Contain(expectedStage);
    }

    [Fact]
    public void A_root_crl_crossed_late_reports_every_threshold_it_passed()
    {
        // The monitor was off, or the product was only just installed. The burst
        // is deliberate and matches what the leaf monitor does.
        var stages = CrlAlertRules.StagesDue(
            RootNextUpdate.AddDays(-2), RootPublished, RootNextUpdate, RootNextPublish,
            autoPublished: false, Ladder);

        stages.Should().Equal("30", "14", "7");
    }

    [Fact]
    public void A_lapsed_root_crl_reports_the_whole_ladder_and_the_expiry()
    {
        var stages = CrlAlertRules.StagesDue(
            RootNextUpdate.AddHours(1), RootPublished, RootNextUpdate, RootNextPublish,
            autoPublished: false, Ladder);

        stages.Should().Equal("30", "14", "7", "1", CrlAlertRules.ExpiredStage);
    }

    [Fact]
    public void A_threshold_wider_than_the_crls_whole_life_is_skipped()
    {
        // A fortnightly CRL published by hand: warning thirty days before an
        // expiry it was born sixteen days from would fire at publication.
        var published = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        var nextUpdate = published.AddDays(16);

        var atPublication = CrlAlertRules.StagesDue(
            published, published, nextUpdate, nextPublish: null,
            autoPublished: false, Ladder);

        atPublication.Should().BeEmpty();

        var thirteenDaysOn = CrlAlertRules.StagesDue(
            published.AddDays(13), published, nextUpdate, nextPublish: null,
            autoPublished: false, Ladder);

        thirteenDaysOn.Should().Equal("14", "7");
    }

    #endregion

    #region Which rule applies

    [Fact]
    public void The_configured_cas_own_crl_is_always_treated_as_automatic()
    {
        // Even a year long one. The product is talking to that CA, so a timer
        // replaces its CRL whatever the period is.
        CrlAlertRules.IsAutoPublished(CrlScope.Issuing, RootPublished, RootNextUpdate, Ladder)
            .Should().BeTrue();
    }

    [Fact]
    public void A_parent_crl_that_outlives_the_widest_threshold_is_treated_as_manual()
    {
        CrlAlertRules.IsAutoPublished(CrlScope.Parent, RootPublished, RootNextUpdate, Ladder)
            .Should().BeFalse();
    }

    [Fact]
    public void A_short_lived_parent_crl_is_treated_as_automatic()
    {
        // An online CA above the configured one: unusual, and its weekly CRL
        // would produce the four alerts a week the ladder is being kept away
        // from.
        CrlAlertRules.IsAutoPublished(CrlScope.Parent, BasePublished, BaseNextUpdate, Ladder)
            .Should().BeTrue();
    }

    [Fact]
    public void A_widened_ladder_moves_the_line_between_the_two_rules()
    {
        // A CRL published every two months, which is a plausible ceremony and a
        // plausible timer. On the shipped ladder it reads as a ceremony and gets
        // its advance warnings; an operator who asks for ninety days of notice
        // is saying that anything shorter than that is somebody else's timer.
        var published = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        var nextUpdate = published.AddDays(60);

        CrlAlertRules.IsAutoPublished(CrlScope.Parent, published, nextUpdate, Ladder)
            .Should().BeFalse();

        int[] wide = [90, 30];
        CrlAlertRules.IsAutoPublished(CrlScope.Parent, published, nextUpdate, wide)
            .Should().BeTrue();
    }

    [Fact]
    public void A_parent_crl_with_no_next_update_is_treated_as_manual_and_warns_about_nothing()
    {
        CrlAlertRules.IsAutoPublished(CrlScope.Parent, RootPublished, nextUpdate: null, Ladder)
            .Should().BeFalse();

        CrlAlertRules.StagesDue(
            RootPublished.AddYears(5), RootPublished, nextUpdate: null, nextPublish: null,
            autoPublished: false, Ladder)
            .Should().BeEmpty("a CRL that never expires cannot be late");
    }

    #endregion

    [Fact]
    public void An_empty_ladder_still_reports_an_expiry()
    {
        var stages = CrlAlertRules.StagesDue(
            RootNextUpdate.AddDays(1), RootPublished, RootNextUpdate, RootNextPublish,
            autoPublished: false, []);

        stages.Should().Equal(CrlAlertRules.ExpiredStage);
    }
}
