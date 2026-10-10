namespace Certus.Core.Crl;

/// <summary>Which CA in the chain a monitored CRL belongs to.</summary>
public enum CrlScope
{
    /// <summary>
    /// A CRL the configured CA publishes itself. It is online by definition,
    /// because the product is talking to it, so a timer replaces it.
    /// </summary>
    Issuing,

    /// <summary>
    /// A CRL that covers a certificate further up the chain. On the estates this
    /// feature exists for that is an offline root's, published by hand.
    /// </summary>
    Parent,
}

/// <summary>
/// Decides what is worth an alert about one CRL.
///
/// **A CRL cannot be watched the way a certificate is watched, and reusing the
/// leaf ladder would make the product unusable.** Measured on a default lab CA
/// on 2026-09-23: its base CRL lives 180.3 hours and is replaced with 12.2 hours
/// to spare, and its delta lives 36.3 hours and is replaced with the same 12.2
/// hours to spare. The leaf monitor fires every crossed threshold in the same
/// pass, so on [30, 14, 7, 1] each new base CRL would cross 30, 14 and 7 the
/// moment it is published and 1 about six days later, and each delta the same
/// about twelve hours later. That is four alerts a week and four a day from a CA
/// doing exactly what it should.
///
/// So which rule applies depends on who replaces the CRL:
///
/// - **A CA replaces it on a timer.** Nothing before the timer is news. The
///   alert is that the timer was missed, which Microsoft's Next CRL Publish
///   extension dates precisely, and then that it has actually expired.
/// - **A person replaces it**, which is what an offline root means. Then the
///   advance ladder is exactly right, because somebody has to take a root out of
///   a safe, boot it, sign a CRL and publish it, and thirty days of notice is not
///   generous. A missed publish rule would be useless here: Microsoft's own lab
///   guidance leaves twelve hours between the scheduled publication and the
///   expiry, so the warning would arrive the evening before an outage.
///
/// Nothing in a CRL says which of the two it is. The configured CA is known to
/// be online because the product is talking to it. For a CA above it, the
/// discriminator is how long the CRL lives: a CRL that outlives the widest
/// warning threshold was written by somebody who does not intend to come back
/// for a week, which is the shape of a manual ceremony, and a shorter one is a
/// timer. Documented rather than hidden, because an estate that publishes its
/// root CRL monthly with a fourteen day threshold would land on the wrong side
/// of it and get "overdue" instead of a ladder.
/// </summary>
public static class CrlAlertRules
{
    /// <summary>The CA did not replace the CRL when it said it would.</summary>
    public const string OverdueStage = "overdue";

    /// <summary>The CRL is past its nextUpdate. Everything chaining through it now fails.</summary>
    public const string ExpiredStage = "expired";

    /// <summary>
    /// How long after the scheduled publication to wait before calling it
    /// missed, and never more than half the overlap that is left. A CA writes
    /// its new CRL at the moment it says it will, but a copy of it has to reach
    /// a directory or a web server, and that takes minutes to hours.
    /// </summary>
    internal static readonly TimeSpan OverdueGrace = TimeSpan.FromHours(2);

    /// <summary>
    /// What to assume a CA's overlap is when its CRL carries no Next CRL Publish
    /// extension, which is every CRL from a CA that is not Microsoft's. It is
    /// the rule ADCS itself applies when nothing is configured.
    /// </summary>
    internal static readonly TimeSpan MaxAssumedOverlap = TimeSpan.FromHours(12);

    private const double AssumedOverlapFraction = 0.1;

    /// <summary>
    /// Whether the issuer of this CRL replaces it on a timer.
    /// </summary>
    public static bool IsAutoPublished(
        CrlScope scope,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        IReadOnlyList<int> thresholdDays)
    {
        if (scope == CrlScope.Issuing)
            return true;

        if (nextUpdate is null)
            return false;

        var window = nextUpdate.Value - thisUpdate;
        var widest = TimeSpan.FromDays(WidestThreshold(thresholdDays));
        return window <= widest;
    }

    /// <summary>
    /// Every stage that is due for this CRL as at <paramref name="now"/>.
    /// Deciding what has already been sent is the caller's job, from the alert
    /// history, so this is a pure function of the CRL and the clock.
    /// </summary>
    public static IReadOnlyList<string> StagesDue(
        DateTimeOffset now,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        DateTimeOffset? nextPublish,
        bool autoPublished,
        IReadOnlyList<int> thresholdDays)
    {
        // A CRL with no nextUpdate never expires, so there is nothing to warn
        // about. No Windows CA produces one.
        if (nextUpdate is null)
            return [];

        var stages = new List<string>();

        if (autoPublished)
        {
            var expected = ExpectedPublish(thisUpdate, nextUpdate.Value, nextPublish);
            var grace = Grace(expected, nextUpdate.Value);
            if (now >= expected + grace)
                stages.Add(OverdueStage);
        }
        else
        {
            var window = nextUpdate.Value - thisUpdate;
            foreach (var threshold in thresholdDays.OrderByDescending(d => d))
            {
                // A threshold wider than the CRL's whole life would fire the
                // moment it is published, which tells an operator nothing they
                // did not just do themselves.
                var lead = TimeSpan.FromDays(threshold);
                if (lead >= window)
                    continue;

                if (now >= nextUpdate.Value - lead)
                    stages.Add(threshold.ToString());
            }
        }

        // Last, so an operator reading a burst reads it in the order it
        // happened. A monitor that was switched off through the whole ladder
        // sends the lot at once, which is what the leaf monitor does too.
        if (now >= nextUpdate.Value)
            stages.Add(ExpiredStage);

        return stages;
    }

    /// <summary>
    /// When the issuer intended to replace this CRL. The Microsoft extension
    /// says so outright; without it, ADCS's own default overlap is the best
    /// available guess.
    /// </summary>
    internal static DateTimeOffset ExpectedPublish(
        DateTimeOffset thisUpdate,
        DateTimeOffset nextUpdate,
        DateTimeOffset? nextPublish)
    {
        if (nextPublish is not null && nextPublish.Value > thisUpdate && nextPublish.Value <= nextUpdate)
            return nextPublish.Value;

        var window = nextUpdate - thisUpdate;
        var assumedOverlap = window * AssumedOverlapFraction;
        if (assumedOverlap > MaxAssumedOverlap)
            assumedOverlap = MaxAssumedOverlap;

        return nextUpdate - assumedOverlap;
    }

    /// <summary>
    /// The wait after the scheduled publication before calling it missed. Capped
    /// at half the remaining overlap so the warning can never arrive after the
    /// expiry it is warning about, which matters for a CA whose overlap is
    /// minutes rather than hours.
    /// </summary>
    internal static TimeSpan Grace(DateTimeOffset expectedPublish, DateTimeOffset nextUpdate)
    {
        var remaining = nextUpdate - expectedPublish;
        if (remaining <= TimeSpan.Zero)
            return TimeSpan.Zero;

        var half = remaining / 2;
        return half < OverdueGrace ? half : OverdueGrace;
    }

    private static int WidestThreshold(IReadOnlyList<int> thresholdDays) =>
        thresholdDays.Count > 0 ? thresholdDays.Max() : 30;
}
