using Certus.Modules;

namespace Certus.Core.Modules;

/// <summary>Where the module host stands with the paid module (licence design section 13.3).</summary>
public enum ModuleState
{
    /// <summary>No module is installed.</summary>
    NotPresent,

    /// <summary>A module is loaded and answering.</summary>
    Loaded,

    /// <summary>A module is present but could not be loaded or started, or ran over its start budget.</summary>
    Failed,

    /// <summary>A loaded module stopped answering within budget; it gets no more calls until a restart.</summary>
    Unresponsive,

    /// <summary>A module was set aside after failing to start twice; it stays so until its version changes or Retry.</summary>
    Quarantined,

    /// <summary>
    /// A module was built against a contract version this core cannot satisfy: another major, or a
    /// newer minor (design section 5). Only a module built for this release fixes it. Added at the
    /// end so the earlier values keep their numbers (issue #493).
    /// </summary>
    Incompatible,

    /// <summary>
    /// The folder trust gate refused the module's folder, because someone other than SYSTEM,
    /// Administrators or TrustedInstaller can change it (design section 6.3). Nothing in the folder
    /// was read. Repairing the installation fixes it (issue #493).
    /// </summary>
    Refused,
}

/// <summary>Questions about a <see cref="ModuleState"/> that the host and the licence API both ask.</summary>
public static class ModuleStateExtensions
{
    /// <summary>
    /// Whether the module is set aside for any reason, so Retry applies: a start that threw or hung,
    /// a call that ran over its budget, or a quarantine. One definition, so the API's answer to "is
    /// there anything to retry" cannot drift from what the host will actually retry.
    ///
    /// <para><see cref="ModuleState.Incompatible"/> and <see cref="ModuleState.Refused"/> are left out
    /// on purpose. A restart changes neither: the module's contract and its folder's permissions are
    /// the same afterwards. So Retry answers 409 for them rather than restarting the service for
    /// nothing. The Settings card mirrors this rule in <c>isSetAside</c>
    /// (<c>src/frontend/src/lib/licence.ts</c>).</para>
    /// </summary>
    public static bool IsSetAside(this ModuleState state) =>
        state is ModuleState.Failed or ModuleState.Unresponsive or ModuleState.Quarantined;
}

/// <summary>
/// The core's own copy of a module's <see cref="LicenceEvaluation"/> (licence design section 5).
/// The module's object never reaches a serializer or a view; the core copies every value into this
/// record inside the guarded call, caps each string at 200 characters and each array at 64 entries,
/// and strips control characters. All of the time logic stayed in the module; these dates are for
/// display, never compared or counted by the core.
/// </summary>
public sealed record LicenceSnapshot(
    LicenceStatus Status,
    string ReasonCode,
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
    bool UnknownTier,
    NoticeStage Notice,
    bool WorseThanInstalled);

/// <summary>
/// What the host currently believes: the module's state and, when one is loaded and has evaluated,
/// the core's copy of that evaluation. The controller and the banner read this and never touch the
/// module directly.
/// </summary>
public sealed record LicenceStatusView(
    ModuleState ModuleState,
    string? ModuleReason,
    string? ModuleId,
    string? ModuleVersion,
    bool LicenceStored,
    LicenceSnapshot? Licence)
{
    /// <summary>
    /// Why the licence folder is not trusted, or null when it is (licence design section 12.3,
    /// issue #523). While it is set the module is told that no licence is installed and
    /// <see cref="LicenceStored"/> reads false, whatever files sit in the folder, so the card can
    /// tell an administrator to delete the folder and let the service recreate it.
    /// </summary>
    public string? LicenceStoreRefusal { get; init; }

    /// <summary>
    /// The module's contract version beside the core's, set only while the module is
    /// <see cref="ModuleState.Incompatible"/>, because that is the one state whose card text names
    /// them (design section 13.3, issue #493).
    /// </summary>
    public ModuleContractView? Contract { get; init; }
}

/// <summary>The read surface the licence controller and the banner use (design section 6.1).</summary>
public interface ILicenceStatusSource
{
    /// <summary>The current state and evaluation. Never null; a fresh install reads NotPresent.</summary>
    LicenceStatusView Current { get; }
}

/// <summary>
/// The control surface the licence controller uses to inspect a candidate, force a re-evaluation
/// after a store write, and clear a quarantine (design section 13.2). The host implements it.
/// </summary>
public interface IModuleHostControl
{
    /// <summary>
    /// Runs the module's Inspect over a candidate under the call budget and returns the core's copy,
    /// or null when no module is loaded to judge it. It is asynchronous, so it never blocks the
    /// request thread while the module's own thread answers.
    /// </summary>
    Task<LicenceSnapshot?> InspectAsync(ReadOnlyMemory<byte> candidate, CancellationToken cancellationToken = default);

    /// <summary>Re-evaluates the active licence now, for the controller to call after a store change.</summary>
    void Reevaluate();

    /// <summary>
    /// Clears a quarantine for the current module version and asks for a restart, so the next start
    /// is a fresh attempt. Returns false when there is nothing to retry.
    /// </summary>
    bool RequestRetry();
}

/// <summary>
/// Copies a module's <see cref="LicenceEvaluation"/> into the core's <see cref="LicenceSnapshot"/>,
/// capping and sanitising every value (design section 5). It runs inside the guarded call, so the
/// module's object is never handed on.
/// </summary>
internal static class ModuleBoundary
{
    private const int MaxStringLength = 200;
    private const int MaxArrayLength = 64;

    public static LicenceSnapshot Copy(LicenceEvaluation source)
    {
        ArgumentNullException.ThrowIfNull(source);
        return new LicenceSnapshot(
            source.Status,
            Clean(source.ReasonCode) ?? string.Empty,
            Clean(source.LicenceId),
            Clean(source.Tier),
            CleanArray(source.Features),
            source.MaxCas,
            Clean(source.LicenseeName),
            Clean(source.LicenseeRef),
            source.ValidFrom,
            source.ValidUntil,
            source.WarnFrom,
            source.GraceUntil,
            source.DaysRemaining,
            CleanArray(source.BoundForests),
            Clean(source.ObservedForest),
            source.ClockAnomaly,
            source.UnknownTier,
            source.Notice,
            source.WorseThanInstalled);
    }

    private static IReadOnlyList<string> CleanArray(string[]? values)
    {
        if (values is null || values.Length == 0)
            return [];

        var capped = values.Length > MaxArrayLength ? values[..MaxArrayLength] : values;
        var result = new List<string>(capped.Length);
        foreach (var value in capped)
            result.Add(Clean(value) ?? string.Empty);
        return result;
    }

    /// <summary>
    /// <paramref name="value"/> with control characters dropped and capped at <paramref name="maxLength"/>
    /// characters; null stays null. The one sanitiser for text a module or its files supply, shared
    /// with the signature verifier's publisher names (#636).
    /// </summary>
    internal static string? Clean(string? value, int maxLength = MaxStringLength)
    {
        if (value is null)
            return null;

        var builder = new System.Text.StringBuilder(Math.Min(value.Length, maxLength));
        foreach (var c in value)
        {
            if (builder.Length == maxLength)
                break;
            if (!char.IsControl(c))
                builder.Append(c);
        }

        return builder.ToString();
    }
}
