using Certus.Core.Modules;
using Certus.Modules;

namespace Certus.Service.Tests.Modules;

/// <summary>
/// Hands the module host an in process module in place of the assembly the manifest names. The
/// host's own discovery, gate, manifest and metadata checks still run over a real folder first, so
/// only the final step, creating the entry type, is replaced.
/// </summary>
internal sealed class FixedActivator(ICertusModule module) : IModuleActivator
{
    public ICertusModule Create(ModuleValidation validation) => module;
}

/// <summary>Fixed evaluations. Every name and value here is a test fixture, never a real licence.</summary>
internal static class TestEvaluations
{
    public static LicenceEvaluation For(LicenceStatus status) => new(
        status,
        status == LicenceStatus.Valid ? "ok" : status.ToString().ToLowerInvariant(),
        "TEST-LICENCE-1",
        "standard",
        status is LicenceStatus.Lapsed or LicenceStatus.BindingMismatch ? [] : ["placeholder"],
        1,
        "Example Test Licensee",
        "TEST-REF",
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch.AddYears(60),
        null,
        null,
        30,
        ["corp.example.com"],
        status == LicenceStatus.BindingMismatch ? "other.example.com" : "corp.example.com",
        false,
        false,
        NoticeStage.None,
        false);

    public static LicenceEvaluation None() => new(
        LicenceStatus.None, "none", null, null, [], null, null, null, null, null, null, null, null, [], null,
        false, false, NoticeStage.None, false);
}

/// <summary>A module that answers every evaluation with one fixed status.</summary>
internal sealed class ScriptedModule(LicenceStatus status) : ICertusModule
{
    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context) => new Evaluator(status);

    private sealed class Evaluator(LicenceStatus status) : ILicenceEvaluator
    {
        public LicenceEvaluation Evaluate(ReadOnlyMemory<byte>? licence) =>
            licence is null ? TestEvaluations.None() : TestEvaluations.For(status);

        public LicenceEvaluation Inspect(ReadOnlyMemory<byte> candidate) => TestEvaluations.For(status);
    }
}

/// <summary>
/// A module that throws from every entry point the host calls once it has started: Evaluate and
/// Inspect. Describe has to answer, because the host refuses a module whose description disagrees
/// with its manifest before it ever calls Start.
/// </summary>
internal sealed class ThrowingModule : ICertusModule
{
    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context) => new Evaluator();

    private sealed class Evaluator : ILicenceEvaluator
    {
        public LicenceEvaluation Evaluate(ReadOnlyMemory<byte>? licence) => throw new InvalidOperationException("evaluate");

        public LicenceEvaluation Inspect(ReadOnlyMemory<byte> candidate) => throw new InvalidOperationException("inspect");
    }
}

/// <summary>
/// A module whose Start blocks until it is released. Never released, it is a hung module; released
/// by a test, it is a slow one. Disposing releases it, so the module thread it holds ends with the
/// test rather than with the process.
/// </summary>
internal sealed class BlockingStartModule : ICertusModule, IDisposable
{
    private readonly ManualResetEventSlim _release = new(false);
    private readonly ManualResetEventSlim _entered = new(false);

    /// <summary>Set once the host has called Start, so a test knows the module thread is held.</summary>
    public bool WaitUntilEntered(TimeSpan timeout) => _entered.Wait(timeout);

    public void Release() => _release.Set();

    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context)
    {
        _entered.Set();
        _release.Wait();
        return new ScriptedModule(LicenceStatus.Valid).Start(context);
    }

    public void Dispose()
    {
        // Released, never disposed: the module thread may still be waking from the wait.
        _release.Set();
    }
}

/// <summary>
/// A module whose licence is expiring and whose notice says the 7 day alert is due (issue #494).
/// The licence id is a canonical GUID, because the alert check refuses anything else, and the
/// licensee is a fixture name the alert must never carry.
/// </summary>
internal sealed class NoticeModule : ICertusModule
{
    public const string LicenceId = "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b";
    public const string Licensee = "Example Test Licensee";

    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context) => new Evaluator();

    private static LicenceEvaluation Expiring() => new(
        LicenceStatus.Expiring, "ok", LicenceId, "standard", ["placeholder"], 1, Licensee, "TEST-REF",
        DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(60), null, null, 6,
        [], null, false, false, NoticeStage.Days7, false);

    private sealed class Evaluator : ILicenceEvaluator
    {
        public LicenceEvaluation Evaluate(ReadOnlyMemory<byte>? licence) =>
            licence is null ? TestEvaluations.None() : Expiring();

        public LicenceEvaluation Inspect(ReadOnlyMemory<byte> candidate) => Expiring();
    }
}
