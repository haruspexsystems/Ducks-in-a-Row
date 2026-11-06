namespace Certus.Modules;

/// <summary>A module's identity: its id, which must equal its folder name, and its version.</summary>
public sealed record ModuleDescription(string Id, string DisplayName, string Version);

/// <summary>
/// Where a licence stands, as the module evaluated it (design section 9.1). Paid features are
/// on in <see cref="Valid"/>, <see cref="Expiring"/> and <see cref="Grace"/>. No status ever
/// stops, delays or changes certificate issuance or renewal (section 2.1).
/// </summary>
public enum LicenceStatus
{
    None,
    NotYetValid,
    Valid,
    Expiring,
    Grace,
    Lapsed,
    BindingMismatch,
    Invalid,
}

/// <summary>Which licence alert is due now, if any (design section 13.6).</summary>
public enum NoticeStage
{
    None,
    Days30,
    Days14,
    Days7,
    Days1,
    Expired,
    GraceEnded,
}

/// <summary>
/// A module's evaluation of one licence file (design section 5). It is for display: the card,
/// the banner, and later the CA capacity check. A module gates its own paid features from its
/// own evaluation and never trusts the core's copy of this.
///
/// <para><b>The boundary rules.</b> The core copies every value into its own types inside the
/// guarded call, caps strings at 200 characters and arrays at 64 entries, and strips control
/// characters. This object never reaches a serializer or a view while it is still the module's.
/// All time logic stays in the module: the core never compares these dates or counts days.</para>
/// </summary>
/// <param name="Status">Where the licence stands.</param>
/// <param name="ReasonCode">Why, from the closed set of design section 8.3.</param>
/// <param name="LicenceId">The licence id, once the signature has verified.</param>
/// <param name="Tier">The tier, once the claims are within bounds.</param>
/// <param name="Features">The tier's features plus add-ons in force now: empty when paid features are off.</param>
/// <param name="MaxCas">The connected CAs the licence covers.</param>
/// <param name="LicenseeName">The contracting party. Personal data for a sole trader, so it is never logged.</param>
/// <param name="LicenseeRef">The customer reference.</param>
/// <param name="ValidFrom">Start of validity.</param>
/// <param name="ValidUntil">End of validity.</param>
/// <param name="WarnFrom">When the warnings start.</param>
/// <param name="GraceUntil">When grace ends.</param>
/// <param name="DaysRemaining">Whole days to the next boundary, computed by the module and shown as given.</param>
/// <param name="BoundForests">The forests the licence is bound to; empty when it is unbound.</param>
/// <param name="ObservedForest">This server's forest, as the module read it.</param>
/// <param name="ClockAnomaly">The server's clock looks more than a day behind the issue time.</param>
/// <param name="UnknownTier">The tier is valid but this module version does not know it.</param>
/// <param name="Notice">Which alert is due now.</param>
/// <param name="WorseThanInstalled">Set by Inspect only: the candidate is worse than the installed licence.</param>
public sealed record LicenceEvaluation(
    LicenceStatus Status,
    string ReasonCode,
    string? LicenceId,
    string? Tier,
    string[] Features,
    int? MaxCas,
    string? LicenseeName,
    string? LicenseeRef,
    DateTimeOffset? ValidFrom,
    DateTimeOffset? ValidUntil,
    DateTimeOffset? WarnFrom,
    DateTimeOffset? GraceUntil,
    int? DaysRemaining,
    string[] BoundForests,
    string? ObservedForest,
    bool ClockAnomaly,
    bool UnknownTier,
    NoticeStage Notice,
    bool WorseThanInstalled);
