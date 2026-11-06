using Certus.Modules;

namespace Certus.Core.Modules;

/// <summary>
/// The licence status the API answers and the Settings card shows (licence design section 13.3).
/// It is the contract's verdict plus the one state only the core can know: a licence is stored, but
/// no module has judged it.
/// </summary>
public enum LicenceDisplayStatus
{
    /// <summary>No licence is stored.</summary>
    None,

    /// <summary>A licence is stored, but no loaded module has evaluated it yet.</summary>
    StoredNotVerified,

    NotYetValid,
    Valid,
    Expiring,
    Grace,
    Lapsed,
    BindingMismatch,

    /// <summary>The module refused the file; the reason code says why.</summary>
    Invalid,
}

/// <summary>
/// A module's contract version beside the core's, each as major.minor, for the Incompatible card
/// text: "built for contract (m). This release needs a module built for contract (n)" (issue #493).
/// </summary>
public sealed record ModuleContractView(string Module, string Core);

/// <summary>
/// Where the module host stands, as the API answers it. <see cref="Contract"/> is filled only for
/// the Incompatible state.
/// </summary>
public sealed record ModuleView(string State, string? Reason, string? Id, string? Version, ModuleContractView? Contract = null);

/// <summary>
/// Which licence files the store holds, so the card can offer "Restore previous licence", and
/// whether the licence folder is refused. A refused folder reads as holding nothing (issue #523), so
/// without <see cref="Untrusted"/> the card would show "no licence" where design section 12.3 asks
/// it to tell an administrator to delete the folder.
/// </summary>
public sealed record LicenceStoreView(bool Active, bool Previous, bool Untrusted = false);

/// <summary>
/// A licence as the API answers it. Every field is a core type, so the licence controller never
/// touches a contract type (deviation Dv15). The display fields are filled only for a verdict that
/// passed the signature; for None, StoredNotVerified and Invalid they are empty, so nothing an
/// unverified file says ever reaches a response (design section 8.4).
/// </summary>
public sealed record LicenceView(
    string Status,
    string? ReasonCode,
    string? LicenceId,
    string? Tier,
    IReadOnlyList<string> Features,
    int? MaxCas,
    string? LicenseeName,
    string? LicenseeRef,
    DateTimeOffset? ValidFrom,
    DateTimeOffset? ValidUntil,
    DateTimeOffset? WarnFrom,
    DateTimeOffset? GraceUntil,
    int? DaysRemaining,
    IReadOnlyList<string> BoundForests,
    string? ObservedForest,
    bool ClockAnomaly,
    bool UnknownTier)
{
    /// <summary>Whether the display fields came from a verified file.</summary>
    public bool IsVerified { get; init; }
}

/// <summary>A candidate from the Settings card, as the module judged it through Inspect.</summary>
public sealed record LicenceCandidateView(LicenceView Licence, bool WorseThanInstalled);

/// <summary>
/// Builds the API's views from the module host's state (licence design sections 13.2 and 13.3).
/// This is the one place the licence API's answers meet a contract type, and it lives in the module
/// host's namespace on purpose: the controller in Certus.Web gets only core types back. None of it
/// is verification. It maps a verdict the module already reached and compares no dates.
/// </summary>
public static class LicenceViews
{
    /// <summary>The module host's state, for the API.</summary>
    public static ModuleView Module(LicenceStatusView view)
    {
        ArgumentNullException.ThrowIfNull(view);
        return new ModuleView(
            view.ModuleState.ToString(), view.ModuleReason, view.ModuleId, view.ModuleVersion,
            view.ModuleState == ModuleState.Incompatible ? view.Contract : null);
    }

    /// <summary>
    /// The installed licence. <paramref name="stored"/> is read from the store at the time of the
    /// request rather than taken from the view, because the view is refreshed only when the module
    /// thread next publishes: a licence removed a moment ago reads None at once, not after the next
    /// evaluation. The module's verdict counts only while the module is loaded. A module that has
    /// since failed or stopped answering is no longer standing behind the evaluation it left, so a
    /// stored licence then reads StoredNotVerified.
    ///
    /// <para>The verdict is the module's latest, so for the moment between a store change and the
    /// re-evaluation it triggers, a replaced licence still answers with the verdict of the one it
    /// replaced (up to a tick for a file dropped into the folder by hand). That is accepted: the
    /// change's own response carries the new licence's verdict, which it asked the module for.</para>
    /// </summary>
    public static LicenceView Current(LicenceStatusView view, bool stored)
    {
        ArgumentNullException.ThrowIfNull(view);

        var evaluation = TrustedVerdict(view);

        // With nothing stored, a loaded module's latest verdict still says which forest this server
        // is in, read off the server and never out of a file, so a customer can quote it when buying
        // a bound licence (design section 10.4, issue #493). Nothing else from that verdict is shown.
        if (!stored)
            return Empty(LicenceDisplayStatus.None) with { ObservedForest = evaluation?.ObservedForest };

        // A verdict of None with a licence on disk means the module last evaluated before the file
        // arrived (an upload, or a file dropped into the folder, not yet picked up), so it has not
        // judged this file.
        if (evaluation is null || evaluation.Status == LicenceStatus.None)
            return Empty(LicenceDisplayStatus.StoredNotVerified);

        return FromVerdict(evaluation);
    }

    /// <summary>
    /// The module's latest verdict, or null when no loaded module stands behind it. A module that
    /// failed or stopped answering leaves its last snapshot in the view; the card and the licence
    /// alerts (issue #494) both ignore it, through this one rule.
    /// </summary>
    internal static LicenceSnapshot? TrustedVerdict(LicenceStatusView view) =>
        view.ModuleState == ModuleState.Loaded ? view.Licence : null;

    /// <summary>
    /// A candidate the module inspected. A verdict of None for bytes that exist is not a usable
    /// verdict, so it reads Invalid rather than as "no licence".
    /// </summary>
    public static LicenceCandidateView Candidate(LicenceSnapshot candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        var view = candidate.Status == LicenceStatus.None
            ? Empty(LicenceDisplayStatus.Invalid) with { ReasonCode = candidate.ReasonCode }
            : FromVerdict(candidate);

        return new LicenceCandidateView(view, candidate.WorseThanInstalled);
    }

    /// <summary>A stored licence no module judged, as the upload answers it with no module loaded.</summary>
    public static LicenceView StoredNotVerified() => Empty(LicenceDisplayStatus.StoredNotVerified);

    /// <summary>
    /// The statuses whose fields come from a file that passed the signature. An allow list, so a
    /// status added later shows nothing until it is placed here deliberately.
    /// </summary>
    internal static bool IsVerifiedStatus(LicenceDisplayStatus status) => status is
        LicenceDisplayStatus.NotYetValid or
        LicenceDisplayStatus.Valid or
        LicenceDisplayStatus.Expiring or
        LicenceDisplayStatus.Grace or
        LicenceDisplayStatus.Lapsed or
        LicenceDisplayStatus.BindingMismatch;

    /// <summary>
    /// Whether a module verdict is one that passed the signature: the allow list above, applied to
    /// the contract's status, so the <c>Licence:</c> log line and the API cannot disagree about what
    /// counts as verified. None, Invalid and anything outside the contract are not.
    /// </summary>
    internal static bool IsVerifiedVerdict(LicenceStatus status) => IsVerifiedStatus(Map(status));

    private static LicenceView FromVerdict(LicenceSnapshot evaluation)
    {
        var status = Map(evaluation.Status);
        if (!IsVerifiedStatus(status))
        {
            // Invalid, or anything unknown: the reason code and the server's own forest only. The
            // forest is read off this server by the module, never out of the file.
            return Empty(status) with
            {
                ReasonCode = evaluation.ReasonCode,
                ObservedForest = evaluation.ObservedForest,
            };
        }

        return new LicenceView(
            status.ToString(),
            evaluation.ReasonCode,
            evaluation.LicenceId,
            evaluation.Tier,
            evaluation.Features,
            evaluation.MaxCas,
            evaluation.LicenseeName,
            evaluation.LicenseeRef,
            evaluation.ValidFrom,
            evaluation.ValidUntil,
            evaluation.WarnFrom,
            evaluation.GraceUntil,
            evaluation.DaysRemaining,
            evaluation.BoundForests,
            evaluation.ObservedForest,
            evaluation.ClockAnomaly,
            evaluation.UnknownTier)
        {
            IsVerified = true,
        };
    }

    /// <summary>
    /// The module's verdict in the API's vocabulary. A value outside the contract's set, which a
    /// module can only produce by casting, reads Invalid: the mapping fails closed.
    /// </summary>
    private static LicenceDisplayStatus Map(LicenceStatus status) => status switch
    {
        LicenceStatus.NotYetValid => LicenceDisplayStatus.NotYetValid,
        LicenceStatus.Valid => LicenceDisplayStatus.Valid,
        LicenceStatus.Expiring => LicenceDisplayStatus.Expiring,
        LicenceStatus.Grace => LicenceDisplayStatus.Grace,
        LicenceStatus.Lapsed => LicenceDisplayStatus.Lapsed,
        LicenceStatus.BindingMismatch => LicenceDisplayStatus.BindingMismatch,
        _ => LicenceDisplayStatus.Invalid,
    };

    private static LicenceView Empty(LicenceDisplayStatus status) => new(
        status.ToString(), null, null, null, [], null, null, null,
        null, null, null, null, null, [], null, false, false);
}
