using System.Runtime.CompilerServices;
using Certus.Core.Modules;
using Certus.Modules;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Modules;

/// <summary>Hands the host a stub in place of a real on-disk module, so the host's thread, budget and crash behaviour are exercised directly.</summary>
internal sealed class StubActivator(ICertusModule module) : IModuleActivator
{
    public ICertusModule Create(ModuleValidation validation) => module;
}

/// <summary>A module that answers with a fixed evaluation for Evaluate and another for Inspect.</summary>
internal sealed class ScriptedModule(LicenceEvaluation evaluate, LicenceEvaluation? inspect = null) : ICertusModule
{
    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context) => new Evaluator(evaluate, inspect ?? evaluate);

    private sealed class Evaluator(LicenceEvaluation evaluate, LicenceEvaluation inspect) : ILicenceEvaluator
    {
        public LicenceEvaluation Evaluate(ReadOnlyMemory<byte>? licence) => evaluate;
        public LicenceEvaluation Inspect(ReadOnlyMemory<byte> candidate) => inspect;
    }
}

/// <summary>A module whose Evaluate reflects whether a licence is stored: None when absent, Valid when present.</summary>
internal sealed class EchoModule : ICertusModule
{
    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context) => new Evaluator();

    private sealed class Evaluator : ILicenceEvaluator
    {
        public LicenceEvaluation Evaluate(ReadOnlyMemory<byte>? licence) =>
            licence is null ? Evaluations.None() : Evaluations.Valid();

        public LicenceEvaluation Inspect(ReadOnlyMemory<byte> candidate) => Evaluations.Valid();
    }
}

/// <summary>A module that starts, then throws from Evaluate and Inspect, counting every call it gets.</summary>
internal sealed class ThrowingEvaluatorModule : ICertusModule
{
    private int _evaluations;
    private int _inspections;

    public int EvaluateCalls => Volatile.Read(ref _evaluations);

    public int InspectCalls => Volatile.Read(ref _inspections);

    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context) => new Evaluator(this);

    private sealed class Evaluator(ThrowingEvaluatorModule owner) : ILicenceEvaluator
    {
        public LicenceEvaluation Evaluate(ReadOnlyMemory<byte>? licence)
        {
            Interlocked.Increment(ref owner._evaluations);
            throw new InvalidOperationException("evaluate");
        }

        public LicenceEvaluation Inspect(ReadOnlyMemory<byte> candidate)
        {
            Interlocked.Increment(ref owner._inspections);
            throw new InvalidOperationException("inspect");
        }
    }
}

/// <summary>A module that evaluates normally and throws from Inspect.</summary>
internal sealed class InspectThrowingModule : ICertusModule
{
    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context) => new Evaluator();

    private sealed class Evaluator : ILicenceEvaluator
    {
        public LicenceEvaluation Evaluate(ReadOnlyMemory<byte>? licence) => Evaluations.Valid();

        public LicenceEvaluation Inspect(ReadOnlyMemory<byte> candidate) => throw new InvalidOperationException("inspect");
    }
}

/// <summary>A module whose Start throws.</summary>
internal sealed class ThrowingStartModule : ICertusModule
{
    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");
    public ILicenceEvaluator Start(IModuleContext context) => throw new InvalidOperationException("boom");
}

/// <summary>A module whose Start never returns, so the start budget is what ends the call.</summary>
internal sealed class HangingStartModule : ICertusModule
{
    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context)
    {
        Thread.Sleep(Timeout.Infinite);
        return null!;
    }
}

/// <summary>A module that starts normally, counting its starts and keeping the state folder it was given.</summary>
internal sealed class CountingModule : ICertusModule
{
    private int _starts;

    public int StartCalls => Volatile.Read(ref _starts);

    public string? StateDirectory { get; private set; }

    public ModuleDescription Describe() => new("paid", "Paid modules", "1.0.0");

    public ILicenceEvaluator Start(IModuleContext context)
    {
        StateDirectory = context.StateDirectory;
        Interlocked.Increment(ref _starts);
        return new EchoModule().Start(context);
    }
}

internal static class Evaluations
{
    public static LicenceEvaluation Valid(string tier = "standard", bool worse = false, string[]? features = null) =>
        new(LicenceStatus.Valid, "ok", "LIC-1", tier, features ?? ["placeholder"], 3, "Acme BV", "CUST-1",
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(60), null, null, 30, [], null, false, false,
            NoticeStage.None, worse);

    public static LicenceEvaluation None() =>
        new(LicenceStatus.None, "none", null, null, [], null, null, null, null, null, null, null, null, [], null,
            false, false, NoticeStage.None, false);
}

/// <summary>Builds a running module host over temp folders, driven by a FakeTimeProvider.</summary>
internal sealed class HostFixture : IDisposable
{
    /// <summary>How long a wait leaves between two looks at the host's view.</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(25);

    public readonly string Root = Path.Combine(Path.GetTempPath(), $"certus-host-{Guid.NewGuid():N}");
    public readonly FakeTimeProvider Time = new();
    public readonly FakeHostApplicationLifetime Lifetime = new();
    public readonly FakeServiceRestarter Restarter = new();
    public readonly LicenceFileStore Store;
    public readonly ModuleJournal Journal;
    public readonly ModuleHost Host;

    /// <summary>The host's data directory, which holds the licence folder and the modules folder.</summary>
    public string DataDirectory => Path.Combine(Root, "data");

    /// <param name="contract">The contract version the installed module's entry references; the current one when null.</param>
    /// <param name="trustAll">
    /// The Development override of the folder trust gate. The temp folders sit outside the install
    /// folder, so false makes the gate refuse the module.
    /// </param>
    /// <param name="signaturePolicy">
    /// A signature policy to apply in place of the one the host picks from the override, so the
    /// signature refusal can be driven over the temp folder (issue #636). Null leaves the host's
    /// choice, which under trust all is no check.
    /// </param>
    /// <param name="logger">A logger to capture the host's lines; null discards them.</param>
    public HostFixture(
        ICertusModule module, bool installModule = true, Version? contract = null, bool trustAll = true,
        ModuleSignaturePolicy? signaturePolicy = null, Microsoft.Extensions.Logging.ILogger<ModuleHost>? logger = null)
    {
        Directory.CreateDirectory(Root);
        var dataDir = DataDirectory;
        Store = new LicenceFileStore(Path.Combine(dataDir, "licence"));
        Journal = new ModuleJournal(Path.Combine(dataDir, "modules"));
        var modulesRoot = Path.Combine(Root, "modules");

        if (installModule)
        {
            var folder = Path.Combine(modulesRoot, "paid");
            Directory.CreateDirectory(folder);
            var image = Certus.Tests.Shared.ModuleAssemblyBuilder.Module(contract: contract);
            File.WriteAllBytes(Path.Combine(folder, "paid.dll"), image);
            ModuleFolders.WriteManifest(folder, "paid", "paid.dll", "Paid.Module", "1.0",
                [("paid.dll", ModuleFolders.Sha(image))]);
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Certus:Modules:DevelopmentPath"] = modulesRoot,
            ["Certus:Modules:DevelopmentTrustAll"] = trustAll ? "true" : "false",
        }).Build();
        var environment = new FakeHostEnvironment { EnvironmentName = Environments.Development };

        Host = new ModuleHost(logger ?? NullLogger<ModuleHost>.Instance, Lifetime, config, environment, Store, Journal,
            Restarter, new StubActivator(module), Time, new ModuleHostOptions(dataDir) { SignaturePolicy = signaturePolicy });
    }

    public async Task StartAsync()
    {
        await Host.StartAsync(CancellationToken.None);
        Lifetime.FireStarted();
    }

    /// <summary>
    /// Waits until <paramref name="condition"/> holds. It returns true or throws a
    /// <see cref="TimeoutException"/> that names the condition and the host's view, and never
    /// returns false; the bool stays so that every caller's BeTrue assertion reads as before.
    ///
    /// <para>There is no fixed deadline (issue #529). Once the module thread answers, the host
    /// carries on in a continuation queued on the thread pool's global queue, so on a saturated
    /// pool a fixed wall clock bound measures the pool rather than the host. Measured on four
    /// cores with 200 blocking work items held for 25 seconds: the 20 second bound this used to
    /// have failed the Loaded wait with "Expected boolean to be True, but found False" while that
    /// continuation was still queued, and this wait passed under the same load, and under a
    /// 45 second hold as well. The bound elapsing is now a question, answered by
    /// <c>PoolAwareWait</c>, and a real failure still reports in about 31 seconds.</para>
    ///
    /// <para>The test that failed on 2026-10-10, NoModule_IsNotPresent_AndReportsAStoredLicence, is
    /// not that mechanism: its only publish runs from a Task.Run queued on the test thread's own
    /// queue, and the same starvation did not delay it under either wait. So the failure names the
    /// host's view, which says whether the host never published or published a refused licence
    /// folder.</para>
    /// </summary>
    public Task<bool> WaitForAsync(Func<bool> condition, [CallerArgumentExpression(nameof(condition))] string what = "") =>
        WaitCoreAsync(condition, between: null, what);

    public Task<bool> WaitForStateAsync(ModuleState state) =>
        WaitForAsync(() => Host.Current.ModuleState == state, $"ModuleState == {state}");

    /// <summary>
    /// Advances the fake clock by <paramref name="step"/> between looks until
    /// <paramref name="condition"/> holds, for a state only the clock can bring about, such as a
    /// budget running out. A step taken before the host has armed its budget moves nothing and a
    /// later one does, so advancing on every look rides out the race between the host posting a
    /// call and the clock moving. Fails as <see cref="WaitForAsync"/> does.
    /// </summary>
    public Task<bool> AdvanceUntilAsync(TimeSpan step, Func<bool> condition,
        [CallerArgumentExpression(nameof(condition))] string what = "") =>
        WaitCoreAsync(condition, () => Time.Advance(step), what);

    private async Task<bool> WaitCoreAsync(Func<bool> condition, Action? between, string what)
    {
        // The caller's lambda can span lines, so its text is put on one line for the message.
        var oneLine = string.Join(' ', what.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

        using var stop = new CancellationTokenSource();
        try
        {
            return await Certus.Tests.Shared.PoolAwareWait.Bounded(PollAsync(condition, between, stop.Token), $"`{oneLine}` to hold");
        }
        catch (TimeoutException ex)
        {
            // One last look on this thread before calling it a failure. PoolAwareWait's probe proves
            // that a completion already queued has run, but a poll is not one: its next look needs a
            // timer fire and then a continuation, both queued behind the probe, so under sustained
            // load the condition can already hold while the poll has not yet seen it.
            if (condition())
                return true;

            // The view is what tells the two causes apart: a host that never published still shows
            // its initial view, and one that did shows what it published, a licence folder it
            // refused included. No inner exception: it would only print the same sentence twice.
            throw new TimeoutException($"{ex.Message} The host's view: {Describe(Host.Current)}.");
        }
        finally
        {
            stop.Cancel(); // a wait that gave up stops looking
        }
    }

    private static async Task<bool> PollAsync(Func<bool> condition, Action? between, CancellationToken ct)
    {
        while (!condition())
        {
            between?.Invoke();
            await Task.Delay(PollInterval, ct);
        }

        return true;
    }

    private static string Describe(LicenceStatusView view) =>
        $"state={view.ModuleState} reason={view.ModuleReason ?? "none"} module={view.ModuleId ?? "none"} " +
        $"licenceStored={view.LicenceStored} storeRefusal={view.LicenceStoreRefusal ?? "none"} " +
        $"licence={(view.Licence is { } licence ? $"{licence.Status}/{licence.ReasonCode}" : "none")}";

    public void Dispose()
    {
        Host.Dispose();
        try { Directory.Delete(Root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
