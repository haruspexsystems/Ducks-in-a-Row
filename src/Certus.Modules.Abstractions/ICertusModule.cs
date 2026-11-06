namespace Certus.Modules;

/// <summary>
/// The entry type of a paid module. The core creates it from the type the module's manifest
/// names, on the module's own thread, after the host has started, and never on a request
/// or an issuance path (licence design sections 2.4 and 6.2).
///
/// <para>A module is fully trusted code running as LocalSystem. This contract does not
/// sandbox it. It keeps the boundary narrow: licence bytes go in, and a small evaluation
/// record comes back. The core copies that record before anything reads it (section 5).</para>
/// </summary>
public interface ICertusModule
{
    /// <summary>Who the module says it is. The core checks it against the manifest.</summary>
    ModuleDescription Describe();

    /// <summary>
    /// Starts the module and returns the evaluator the core calls from then on. The call has
    /// a time budget. A module that throws or runs over budget is set aside, and certificate
    /// issuance never notices.
    /// </summary>
    ILicenceEvaluator Start(IModuleContext context);
}

/// <summary>
/// Evaluates licence files. Every decision about a licence is the module's: the core never
/// parses, verifies or does date arithmetic on one (design section 2.4, rule 4).
/// </summary>
public interface ILicenceEvaluator
{
    /// <summary>
    /// The installed licence, or null when none is stored. Called when the file changes and
    /// at least hourly, so stages advance. The module reads its own clock and its own forest
    /// name.
    /// </summary>
    LicenceEvaluation Evaluate(ReadOnlyMemory<byte>? licence);

    /// <summary>
    /// A candidate from the Settings card or the API: the same checks with no side effects.
    /// It also sets <see cref="LicenceEvaluation.WorseThanInstalled"/> by comparing the
    /// candidate with the installed licence (design section 9.5).
    /// </summary>
    LicenceEvaluation Inspect(ReadOnlyMemory<byte> candidate);
}

/// <summary>What the core hands a module at start: a folder of its own and a log.</summary>
public interface IModuleContext
{
    /// <summary>The module's own protected folder under the data directory (design section 12.7).</summary>
    string StateDirectory { get; }

    /// <summary>The module's log. The core caps and sanitises every line (design section 6.5).</summary>
    IModuleLog Log { get; }
}

/// <summary>
/// A module's only way to write to the service log. The core strips control characters and
/// caps the length of every value, because module text is untrusted (log forging).
/// </summary>
public interface IModuleLog
{
    void Write(ModuleLogLevel level, string code, string message);
}

public enum ModuleLogLevel
{
    Information,
    Warning,
    Error,
}
