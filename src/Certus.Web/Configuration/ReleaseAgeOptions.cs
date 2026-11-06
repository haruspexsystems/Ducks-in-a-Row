namespace Certus.Web.Configuration;

/// <summary>
/// The one setting behind the "a newer release may exist" notice on the
/// Settings page (issue #623). Bound from the same "Certus" section as
/// <see cref="Certus.Core.Configuration.CertusOptions"/>, so the key is
/// Certus:ReleaseAgeWarningDays beside the other flat Certus keys.
///
/// It lives in Certus.Web rather than on CertusOptions because the only
/// reader is SettingsController: the service never contacts the internet, so
/// this is a dashboard notice and nothing in Core acts on it.
///
/// The key is deliberately absent from appsettings.json, so the initializer
/// below really is the default (see .claude/rules/host-config.md on explicit
/// JSON nulls overwriting initializers).
/// </summary>
public sealed class ReleaseAgeOptions
{
    /// <summary>The default threshold, in days, per Sean's decision of 2026-10-21 on #623.</summary>
    public const int DefaultWarningDays = 180;

    /// <summary>
    /// How old the installed release may be, in days, before the Settings page
    /// warns that a newer one may exist. 0 disables the warning; a negative
    /// value is treated as 0, because a threshold in the past can mean
    /// nothing else. The date line and the runtime line stay whatever this is.
    /// </summary>
    public int ReleaseAgeWarningDays { get; set; } = DefaultWarningDays;

    /// <summary>The threshold in force: the configured value, never below 0.</summary>
    public int EffectiveWarningDays => Math.Max(0, ReleaseAgeWarningDays);
}
