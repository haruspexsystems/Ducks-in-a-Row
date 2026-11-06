using Certus.Core.Alerts;
using Certus.Modules;

namespace Certus.Core.Modules;

/// <summary>
/// One thing the licence alert check could not accept, and so did not act on.
/// <paramref name="Key"/> is stable for the same cause, so the service logs each
/// one once rather than on every pass. The message never repeats a value the
/// module supplied.
/// </summary>
internal sealed record LicenceAlertProblem(string Key, string Message);

/// <summary>What the licence alert check decided: the alert that is due, if any, and why not.</summary>
internal sealed record LicenceAlertDecision(LicenceAlert? Alert, IReadOnlyList<LicenceAlertProblem> Problems);

/// <summary>
/// Decides which licence alert is due, from the module host's current state
/// (issue #494, licence design section 13.6). The module decides when a notice is
/// due and the core only acts on it; this is the acting half, and it compares no
/// dates and counts no days.
///
/// It lives in the module host's namespace because it reads the contract's
/// status and notice, and only this namespace may refer to the contract
/// (<c>ModuleBoundaryTests.OnlyTheModuleHostTouchesTheContract</c>). What it hands
/// on is a <see cref="LicenceAlert"/>, which holds no contract type, because the
/// notifiers are on the protected surface and must never reach this namespace
/// (<c>IssuancePathNeverReachesTheModuleHost</c>).
///
/// <para><b>The status picks the alert, and the notice is only which stage it
/// is</b> (Sean's decision of 2026-10-14). Mapping the notice straight to an
/// event is what the design said, and it goes wrong twice, both found in the
/// module's own code:</para>
/// <list type="bullet">
/// <item>A trial has no grace period. The module then never reports
/// GraceEnded; it reports Expired while the status is already Lapsed, so the
/// notice alone would announce a grace period that does not exist.</item>
/// <item>The module sets the notice before it checks the forest binding, so a
/// licence bound to another forest can carry "7 days left" while it switches
/// nothing on. Its status, BindingMismatch, sends nothing.</item>
/// </list>
///
/// <para>Every mapping is an allow list. A status or a notice the contract adds
/// later sends nothing until it is placed here deliberately, and is reported as a
/// problem so that the gap shows in the log.</para>
/// </summary>
internal static class LicenceAlertRules
{
    /// <summary>A canonical licence id: a lower case GUID in the "D" format (licence design 7.3).</summary>
    internal const int LicenceIdLength = 36;

    /// <summary>The longest tier a licence may name (licence design 7.3).</summary>
    internal const int MaxTierLength = 32;

    public static LicenceAlertDecision Evaluate(LicenceStatusView view)
    {
        ArgumentNullException.ThrowIfNull(view);

        var problems = new List<LicenceAlertProblem>();

        // The module's verdict counts only while it is loaded, the one rule the card
        // applies too (LicenceViews.TrustedVerdict). A module that has since failed or
        // stopped answering leaves its last snapshot behind, notice and all, and is
        // no longer standing behind it.
        if (!view.LicenceStored || LicenceViews.TrustedVerdict(view) is not { } licence)
            return new LicenceAlertDecision(null, problems);

        var kind = KindFor(licence.Status, problems);
        var stage = StageFor(licence.Notice, problems);

        if (kind is null || stage is null)
            return new LicenceAlertDecision(null, problems);

        if (!IsCanonicalLicenceId(licence.LicenceId))
        {
            problems.Add(new LicenceAlertProblem(
                "licence-id",
                "The paid module reported a licence alert for a licence id that is not a canonical " +
                "licence id, so no alert was sent."));
            return new LicenceAlertDecision(null, problems);
        }

        var tier = licence.Tier;
        if (tier is not null && !IsTierToken(tier))
        {
            // Keyed by licence, so a second licence with the same fault is reported too.
            problems.Add(new LicenceAlertProblem(
                $"tier:{licence.LicenceId}",
                "The paid module reported a licence tier that is not a tier name, so the licence " +
                "alert carries no tier."));
            tier = null;
        }

        var alert = new LicenceAlert(
            kind.Value,
            stage,
            licence.LicenceId!,
            tier,
            licence.ValidUntil,
            licence.GraceUntil,
            licence.DaysRemaining);

        return new LicenceAlertDecision(alert, problems);
    }

    /// <summary>
    /// The statuses that alert. The other known ones are quiet on purpose: None and
    /// NotYetValid have nothing due, Valid is outside the warning period,
    /// BindingMismatch switches nothing on here whatever its dates say, and Invalid
    /// is not a licence at all.
    /// </summary>
    private static LicenceAlertKind? KindFor(LicenceStatus status, List<LicenceAlertProblem> problems)
    {
        switch (status)
        {
            case LicenceStatus.Expiring:
                return LicenceAlertKind.Expiring;
            case LicenceStatus.Grace:
                return LicenceAlertKind.Grace;
            case LicenceStatus.Lapsed:
                return LicenceAlertKind.Lapsed;
            case LicenceStatus.None:
            case LicenceStatus.NotYetValid:
            case LicenceStatus.Valid:
            case LicenceStatus.BindingMismatch:
            case LicenceStatus.Invalid:
                return null;
            default:
                var value = (int)status;
                problems.Add(new LicenceAlertProblem(
                    $"status:{value}",
                    $"The paid module reported a licence status this release does not know ({value}), " +
                    "so no licence alert was sent for it."));
                return null;
        }
    }

    /// <summary>The notices that alert, as the stage the alert and its record carry.</summary>
    private static string? StageFor(NoticeStage notice, List<LicenceAlertProblem> problems)
    {
        switch (notice)
        {
            case NoticeStage.Days30:
                return LicenceAlertStages.Days30;
            case NoticeStage.Days14:
                return LicenceAlertStages.Days14;
            case NoticeStage.Days7:
                return LicenceAlertStages.Days7;
            case NoticeStage.Days1:
                return LicenceAlertStages.Days1;
            case NoticeStage.Expired:
                return LicenceAlertStages.Expired;
            case NoticeStage.GraceEnded:
                return LicenceAlertStages.GraceEnded;
            case NoticeStage.None:
                return null;
            default:
                var value = (int)notice;
                problems.Add(new LicenceAlertProblem(
                    $"notice:{value}",
                    $"The paid module reported a licence notice this release does not know ({value}), " +
                    "so no licence alert was sent for it."));
                return null;
        }
    }

    /// <summary>
    /// A lower case GUID in the "D" format, and nothing else. TryParseExact accepts
    /// upper case, so the value must also equal its own round trip.
    /// </summary>
    internal static bool IsCanonicalLicenceId(string? value) =>
        value is { Length: LicenceIdLength }
        && Guid.TryParseExact(value, "D", out var id)
        && string.Equals(id.ToString("D"), value, StringComparison.Ordinal);

    /// <summary>
    /// 1 to 32 characters of a to z, 0 to 9 and the hyphen. Checked character by
    /// character rather than with a regular expression, because a regular
    /// expression's end anchor also matches before a trailing newline.
    /// </summary>
    internal static bool IsTierToken(string value)
    {
        if (value.Length is < 1 or > MaxTierLength)
            return false;

        foreach (var c in value)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
                return false;
        }

        return true;
    }
}
