namespace Certus.Core.Alerts;

/// <summary>
/// Which licence warning an alert is (issue #494, licence design section 13.6).
/// One per notice the paid module can report. The module decides which one is
/// due; the core only sends each one once per licence.
///
/// These are the values of <see cref="LicenceAlert.Stage"/>, of the webhook's
/// <c>stage</c> field, and of the stored <c>LicenceAlertsSent.Stage</c> column,
/// so they are part of the webhook contract: renaming one changes what a
/// receiver sees and re-arms a stage on every install that already sent it.
/// A test reflects over these constants to prove each fits the column.
/// </summary>
public static class LicenceAlertStages
{
    /// <summary>30 days or fewer before the licence ends.</summary>
    public const string Days30 = "days30";

    /// <summary>14 days or fewer before the licence ends.</summary>
    public const string Days14 = "days14";

    /// <summary>7 days or fewer before the licence ends.</summary>
    public const string Days7 = "days7";

    /// <summary>1 day or less before the licence ends.</summary>
    public const string Days1 = "days1";

    /// <summary>
    /// The licence has ended. With a grace period, paid features stay on until it
    /// ends; a trial has none, so for a trial this is also the lapse.
    /// </summary>
    public const string Expired = "expired";

    /// <summary>The grace period has ended and paid features are off.</summary>
    public const string GraceEnded = "grace_ended";
}
