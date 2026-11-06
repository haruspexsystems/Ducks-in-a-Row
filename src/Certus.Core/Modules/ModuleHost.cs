using System.Collections.Concurrent;
using Certus.Core.Security;
using Certus.Core.Setup;
using Certus.Modules;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Modules;

/// <summary>Where the host keeps a module's state folder and reads the data directory from.</summary>
public sealed record ModuleHostOptions(string DataDirectory)
{
    /// <summary>
    /// The signature policy to apply in place of the one the host would pick (Haruspex, or
    /// Unchecked under the Development trust all override). Production registration leaves it
    /// null; a test sets it to prove the refusal path with a certificate chain of its own, since
    /// the temp folders a test can make never pass the folder trust gate without that override.
    /// </summary>
    public ModuleSignaturePolicy? SignaturePolicy { get; init; }
}

/// <summary>
/// Creates the entry module from a validated folder. The default loads the entry assembly through
/// the module's own <see cref="ModuleLoadContext"/> and creates the type the manifest names; a test
/// substitutes an in-process stub, so the host's thread, budget and crash behaviour are exercised
/// without an assembly on disk.
/// </summary>
public interface IModuleActivator
{
    ICertusModule Create(ModuleValidation validation);
}

/// <summary>The production activator: load the signed entry assembly and create the named type.</summary>
internal sealed class DefaultModuleActivator : IModuleActivator
{
    public ICertusModule Create(ModuleValidation validation)
    {
        ArgumentNullException.ThrowIfNull(validation);
        var (_, assembly) = ModuleLoader.Load(validation.Manifest!, validation.EntryAssemblyPath!);
        var type = assembly.GetType(validation.Manifest!.EntryType, throwOnError: true, ignoreCase: false)!;
        return (ICertusModule)Activator.CreateInstance(type)!;
    }
}

/// <summary>
/// Loads and runs the one paid module, and tells the rest of the core where the licence stands
/// (licence design sections 2.4, 6.1 to 6.5). Nothing here is on the certificate issuance or
/// renewal path: issuance never calls the host, and the host never blocks a request or a thread
/// pool thread on module code. Module code runs only on one dedicated thread, started after the
/// application has started, and every call into it has a time budget. A module that throws is set
/// aside Failed, one that runs over budget Unresponsive, and one that kills the process is bounded
/// to two restarts by the load journal before it is Quarantined.
/// </summary>
public sealed class ModuleHost : IHostedService, ILicenceStatusSource, IModuleHostControl, IDisposable
{
    private static readonly TimeSpan StartBudget = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CallBudget = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan Tick = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ReevaluateAtLeastEvery = TimeSpan.FromHours(1);
    private static readonly TimeSpan HealthyAfter = TimeSpan.FromMinutes(10);

    private static readonly Version CoreContract =
        typeof(ICertusModule).Assembly.GetName().Version ?? new Version(1, 0, 0, 0);

    private readonly ILogger<ModuleHost> _logger;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly IConfiguration _configuration;
    private readonly IHostEnvironment _environment;
    private readonly LicenceFileStore _store;
    private readonly ModuleJournal _journal;
    private readonly IServiceRestarter _restarter;
    private readonly IModuleActivator _activator;
    private readonly TimeProvider _time;
    private readonly string _dataDirectory;
    private readonly ModuleSignaturePolicy? _signaturePolicy;

    private readonly Pump _pump = new("certus-module");
    private readonly SemaphoreSlim _callGate = new(1, 1);
    private readonly CancellationTokenSource _stopping = new();
    private readonly object _viewLock = new();

    private volatile bool _unresponsive;

    // Set when an evaluation throws. Like _unresponsive it is for good until a restart: a module set
    // aside Failed gets no further call, so no later evaluation can publish a verdict under a state
    // that still reads Failed, and Inspect cannot answer for a module the API reports as set aside.
    private volatile bool _failed;
    private LicenceStatusView _view = new(ModuleState.NotPresent, null, null, null, false, null);
    private ILicenceEvaluator? _evaluator;
    private ModuleManifest? _loaded;
    private byte[]? _lastEvaluated;
    private TaskCompletionSource _wake = Fresh();

    public ModuleHost(
        ILogger<ModuleHost> logger,
        IHostApplicationLifetime lifetime,
        IConfiguration configuration,
        IHostEnvironment environment,
        LicenceFileStore store,
        ModuleJournal journal,
        IServiceRestarter restarter,
        IModuleActivator activator,
        TimeProvider time,
        ModuleHostOptions options)
    {
        _logger = logger;
        _lifetime = lifetime;
        _configuration = configuration;
        _environment = environment;
        _store = store;
        _journal = journal;
        _restarter = restarter;
        _activator = activator;
        _time = time;
        _dataDirectory = options.DataDirectory;
        _signaturePolicy = options.SignaturePolicy;
    }

    // ILicenceStatusSource
    public LicenceStatusView Current
    {
        get { lock (_viewLock) return _view; }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        // No module file is opened before the host has started (design 6.1). The work begins on
        // ApplicationStarted, on the module's own thread, and StartAsync returns at once.
        _lifetime.ApplicationStarted.Register(() =>
        {
            _pump.Start();
            _ = Task.Run(() => RunAsync(_stopping.Token));
        });
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        // A clean stop of a running module is evidence it did not crash the process, so record it as
        // healthy. That stops a run of unrelated restarts (settings changes, a service restart) from
        // accumulating attempts and falsely quarantining a sound module; only a crash leaves an
        // attempt with no healthy entry after it.
        LicenceStatusView view;
        lock (_viewLock)
            view = _view;
        if (view is { ModuleState: ModuleState.Loaded, ModuleId: { } id, ModuleVersion: { } version })
            _journal.RecordHealthy(id, version, _time.GetUtcNow());

        await _stopping.CancelAsync();
        Wake();
    }

    // IModuleHostControl
    public async Task<LicenceSnapshot?> InspectAsync(ReadOnlyMemory<byte> candidate, CancellationToken cancellationToken = default)
    {
        if (_disposed || _unresponsive || _failed || _evaluator is null)
            return null;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // The copy runs on the module thread inside the budgeted call, so the module's object
            // never crosses the thread boundary.
            var outcome = await InvokeAsync(() => ModuleBoundary.Copy(_evaluator.Inspect(candidate)), CallBudget).ConfigureAwait(false);
            if (outcome.TimedOut)
            {
                PublishState(ModuleState.Unresponsive, "the module stopped answering within its budget", _loaded?.Id, _loaded?.Version);
                return null;
            }

            return outcome.Snapshot;
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
        {
            return null; // shutting down, or the caller gave up
        }
    }

    public void Reevaluate()
    {
        if (!_disposed)
            Wake();
    }

    public bool RequestRetry()
    {
        LicenceStatusView view;
        lock (_viewLock)
            view = _view;

        // Retry a module that is set aside for any reason, including a start that threw or hung
        // (which carry no _loaded), not only a quarantine.
        if (!view.ModuleState.IsSetAside())
            return false;

        if (view.ModuleId is { } id)
            _journal.ClearModule(id);

        return _restarter.TryScheduleRestart();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            var modulesRoot = ModulesRoot();
            var trustAll = TrustAll();

            var discovery = ModuleLoader.Discover(modulesRoot);
            if (discovery.Outcome == ModuleDiscoveryOutcome.None)
            {
                PublishState(ModuleState.NotPresent, discovery.Reason);
                Log("Modules: none");
                await IdleLoop(ct);
                return;
            }

            if (discovery.Outcome == ModuleDiscoveryOutcome.Multiple)
            {
                PublishState(ModuleState.Failed, discovery.Reason);
                Log($"Modules: refused reason={discovery.Reason}");
                await IdleLoop(ct);
                return;
            }

            // The signature check is skipped only under the Development trust all override, which
            // already disables the folder trust gate for the unsigned test module Certus-Commercial
            // publishes. Everywhere else the module must be signed by Haruspex (issue #636).
            var signatures = _signaturePolicy ?? (trustAll ? ModuleSignaturePolicy.Unchecked : ModuleSignaturePolicy.Haruspex);

            var validation = ModuleLoader.Validate(AppContext.BaseDirectory, discovery.FolderPath!, trustAll, CoreContract, signatures);
            if (!validation.IsReady)
            {
                // The card needs Incompatible and Refused told apart from Failed without reading the
                // reason text (design section 13.3, issue #493). None of these costs a strike in the
                // journal, so none of them can turn into Quarantined.
                switch (validation.Outcome)
                {
                    case ModuleValidationOutcome.Incompatible:
                        PublishState(ModuleState.Incompatible, validation.Reason, validation.ModuleId, validation.ModuleVersion,
                            new ModuleContractView(Short(validation.ModuleContract!), Short(CoreContract)));
                        break;
                    case ModuleValidationOutcome.Refused:
                        PublishState(ModuleState.Refused, validation.Reason);
                        break;
                    case ModuleValidationOutcome.SignatureRefused:
                        // Failed, not Refused: Retry is right here, because an administrator who
                        // reinstalls the module changes what the next check sees, where a restart
                        // changes nothing about a folder's permissions. The refusal is written to the
                        // journal as a record of its own kind, so it is on disk beside the attempts
                        // but never counts as one, and the card keeps naming the file at every start
                        // rather than switching to "set aside after two failed starts".
                        PublishState(ModuleState.Failed, validation.Reason, validation.ModuleId, validation.ModuleVersion);
                        var signature = validation.Signature!;
                        _logger.LogError(
                            "Modules: refused id={ModuleId} reason=signature file={File} expectedPublisher='{Expected}' foundPublisher='{Found}': the file {Detail}",
                            validation.ModuleId, signature.FileName, signatures.CommonName, signature.FoundPublisher ?? "none", signature.Reason);
                        RecordRefusal(validation);
                        await IdleLoop(ct);
                        return;
                    default:
                        PublishState(ModuleState.Failed, validation.Reason);
                        break;
                }

                Log($"Modules: refused reason={validation.Reason}");
                await IdleLoop(ct);
                return;
            }

            var manifest = validation.Manifest!;

            // The state folder is readied and verified before the quarantine check and the
            // journal's attempt, so a module refused for it runs no code and costs no strike.
            var stateDirectory = System.IO.Path.Combine(_dataDirectory, "modules", manifest.Id);
            if (ReadyStateFolder(stateDirectory) is { } distrust)
            {
                PublishState(ModuleState.Failed,
                    $"the module's state folder is not trusted, so the module was not started: {distrust}. " +
                    "An administrator must delete that folder; the service then recreates it",
                    manifest.Id, manifest.Version);
                Log($"Modules: refused id={manifest.Id} reason=state-folder-untrusted");
                _logger.LogError("The state folder {Folder} of module {ModuleId} is not trusted, so the module was not started: {Reason}",
                    stateDirectory, manifest.Id, distrust);
                await IdleLoop(ct);
                return;
            }

            if (_journal.IsQuarantined(manifest.Id, manifest.Version))
            {
                PublishState(ModuleState.Quarantined, "set aside after two failed starts; press Retry to try again", manifest.Id, manifest.Version);
                Log($"Modules: refused id={manifest.Id} reason=quarantined");
                await IdleLoop(ct);
                return;
            }

            _journal.RecordAttempt(manifest.Id, manifest.Version, _time.GetUtcNow());

            var start = await InvokeAsync(() => StartModule(validation, stateDirectory), StartBudget);
            if (start.TimedOut)
            {
                PublishState(ModuleState.Unresponsive, "the module did not start within its budget", manifest.Id, manifest.Version);
                Log($"Modules: refused id={manifest.Id} reason=start-timeout");
                await IdleLoop(ct);
                return;
            }

            if (start.Error is not null)
            {
                PublishState(ModuleState.Failed, "the module failed to start", manifest.Id, manifest.Version);
                Log($"Modules: refused id={manifest.Id} reason=start-threw type={start.Error.GetType().Name}");
                await IdleLoop(ct);
                return;
            }

            _evaluator = (ILicenceEvaluator)start.Result!;
            _loaded = manifest;
            var startedAt = _time.GetUtcNow();
            PublishState(ModuleState.Loaded, null, manifest.Id, manifest.Version);
            Log($"Modules: loaded id={manifest.Id} version={manifest.Version} contract={CoreContract.Major}.{CoreContract.Minor}");

            await EvaluateAsync();
            await LiveLoop(ct, startedAt);
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
        {
            // Shutting down: the stop token was cancelled, or its source was disposed under us.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "The module host stopped with an unexpected error");
            PublishState(ModuleState.Failed, "the module host failed");
        }
    }

    /// <summary>
    /// Writes a signature refusal to the journal. It runs after the state and the log line are
    /// published and swallows a folder failure, because it is the one journal write that happens
    /// before <see cref="ReadyStateFolder"/> has readied the data modules folder: a folder that
    /// cannot be created must not turn the clear refusal into "the module host failed".
    /// </summary>
    private void RecordRefusal(ModuleValidation validation)
    {
        try
        {
            _journal.RecordRefusal(validation.ModuleId!, validation.ModuleVersion!, _time.GetUtcNow(), validation.Reason!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "The refusal of module {ModuleId} could not be written to the load journal", validation.ModuleId);
        }
    }

    /// <summary>
    /// Loads the module and starts it with the state folder <see cref="ReadyStateFolder"/> already
    /// verified. Runs on the pump thread, under the start budget.
    /// </summary>
    private object StartModule(ModuleValidation validation, string stateDirectory)
    {
        var manifest = validation.Manifest!;
        var module = _activator.Create(validation);

        var described = module.Describe();
        if (!string.Equals(described.Id, manifest.Id, StringComparison.Ordinal)
            || !string.Equals(described.Version, manifest.Version, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("the module describes itself differently from its manifest");
        }

        var context = new ModuleContext(stateDirectory, new ModuleLog(_logger, manifest.Id));
        return module.Start(context);
    }

    /// <summary>
    /// Readies a module's state folder, %DataDirectory%\modules\&lt;id&gt;\, which section 12.7 of
    /// the licence design puts under the licence folder's rules (section 12.3, issue #523). The
    /// modules folder and then the state folder are each created with the protected DACL when
    /// absent, and each is verified either way and never repaired. The modules folder is part of
    /// the check because its owner could replace the state folder inside it, and it is verified
    /// before anything is created inside it, so a junction planted in its place is refused rather
    /// than followed. Returns null when both are trusted, or why not, naming the folder.
    /// </summary>
    private static string? ReadyStateFolder(string stateDirectory)
    {
        var modulesFolder = System.IO.Path.GetDirectoryName(stateDirectory)!;
        return ReadyFolder(modulesFolder) ?? ReadyFolder(stateDirectory);

        static string? ReadyFolder(string folder)
        {
            try
            {
                ProtectedFolder.EnsureExists(folder);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return $"'{folder}' could not be created ({ex.Message})";
            }

            var trust = FolderTrust.CheckDataPath(folder);
            return trust.IsTrusted ? null : $"'{folder}' is refused, because {trust.Reason ?? "it is not trusted"}";
        }
    }

    private async Task EvaluateAsync()
    {
        if (_evaluator is null)
            return;

        var licence = _store.ReadActive();
        // A missing licence must reach the module as null, not as an empty ReadOnlyMemory. A null
        // byte[] converts to an empty, non-null ReadOnlyMemory, which a module would read as a zero
        // byte licence (Invalid) rather than as none installed, so build the value explicitly.
        ReadOnlyMemory<byte>? memory = null;
        if (licence is not null)
            memory = licence;

        // The module's evaluation is copied into the core's own snapshot on the module thread, inside
        // the budgeted call, so the module's object never crosses the thread boundary.
        var outcome = await InvokeAsync(() => ModuleBoundary.Copy(_evaluator.Evaluate(memory)), CallBudget);

        if (outcome.TimedOut)
        {
            PublishState(ModuleState.Unresponsive, "the module stopped answering within its budget", _loaded?.Id, _loaded?.Version);
            Log($"Modules: unresponsive id={_loaded?.Id}");
            return;
        }

        if (outcome.Error is not null)
        {
            _failed = true;
            PublishState(ModuleState.Failed, "the module failed while evaluating the licence", _loaded?.Id, _loaded?.Version);
            Log($"Modules: failed id={_loaded?.Id} type={outcome.Error.GetType().Name}");
            return;
        }

        // Record the evaluated bytes only after a success, so a timed out or faulted evaluation is
        // retried on the next tick rather than skipped as unchanged.
        _lastEvaluated = licence;
        var snapshot = outcome.Snapshot!;
        PublishLicence(snapshot);
        Log(LicenceLine(snapshot));
    }

    /// <summary>
    /// The <c>Licence:</c> log line (deviation Dv4). It always carries the status and the module's
    /// reason code, which is how a refused file explains itself in the log (acceptance criterion 2
    /// of #413: tampering fails "with a logged reason"). The tier, the end date and the licence id
    /// appear only for a verdict that passed the signature, judged by the same allow list the API
    /// uses, so nothing an unverified file says is logged. Every value the module supplied is reduced
    /// to one token, so none can add a field of its own to the line, and the date is written in the
    /// invariant culture, so the year is the licence's whatever the server's calendar.
    /// </summary>
    internal static string LicenceLine(LicenceSnapshot snapshot)
    {
        var reason = Token(snapshot.ReasonCode);
        if (!LicenceViews.IsVerifiedVerdict(snapshot.Status))
            return $"Licence: status={snapshot.Status} reason={reason}";

        var validUntil = snapshot.ValidUntil?.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) ?? "none";
        return $"Licence: status={snapshot.Status} reason={reason} tier={Token(snapshot.Tier)} " +
               $"validUntil={validUntil} lid={Token(snapshot.LicenceId)}";
    }

    /// <summary>A value as one log token: letters, digits, '.', '-' and '_' kept, anything else '_'.</summary>
    private static string Token(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "none";

        return string.Create(value.Length, value, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                var c = source[i];
                span[i] = char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_';
            }
        });
    }

    /// <summary>The idle loop for the states that carry no evaluator: keep the store's verdict current, and wait for stop.</summary>
    private async Task IdleLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await WaitForTickOrWake(ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            PublishStore();
        }
    }

    /// <summary>The live loop: re-evaluate on a licence change or at least hourly, and record healthy once.</summary>
    private async Task LiveLoop(CancellationToken ct, DateTimeOffset startedAt)
    {
        var lastEvaluatedAt = _time.GetUtcNow();
        var healthyRecorded = false;

        while (!ct.IsCancellationRequested && !_unresponsive && !_failed)
        {
            try
            {
                await WaitForTickOrWake(ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (_unresponsive || _failed)
                return;

            if (!healthyRecorded && _time.GetUtcNow() - startedAt >= HealthyAfter && _loaded is { } loaded)
            {
                _journal.RecordHealthy(loaded.Id, loaded.Version, _time.GetUtcNow());
                healthyRecorded = true;
            }

            // ReadActive reads nothing from a folder that is not trusted, so a folder that stops being
            // trusted reads as a change to no licence and is evaluated as one.
            var current = _store.ReadActive();
            var changed = !BytesEqual(current, _lastEvaluated);
            if (changed || _time.GetUtcNow() - lastEvaluatedAt >= ReevaluateAtLeastEvery)
            {
                await EvaluateAsync();
                lastEvaluatedAt = _time.GetUtcNow();
            }
            else
            {
                PublishStore();
            }
        }
    }

    private async Task WaitForTickOrWake(CancellationToken ct)
    {
        var wake = Volatile.Read(ref _wake);
        var delay = Task.Delay(Tick, _time, ct);
        await Task.WhenAny(delay, wake.Task).ConfigureAwait(false);
        if (wake.Task.IsCompleted)
            Interlocked.Exchange(ref _wake, Fresh());
        ct.ThrowIfCancellationRequested();
    }

    private void Wake() => Volatile.Read(ref _wake).TrySetResult();

    /// <summary>
    /// Posts <paramref name="work"/> to the module thread and awaits it under <paramref name="budget"/>.
    /// At most one call is outstanding. A budget overrun marks the module Unresponsive for good: the
    /// dedicated thread keeps running the hung call, but no pool thread is held and no further call is
    /// posted.
    /// </summary>
    private async Task<CallOutcome> InvokeAsync(Func<object?> work, TimeSpan budget)
    {
        if (_unresponsive)
            return CallOutcome.Timeout;

        await _callGate.WaitAsync(_stopping.Token).ConfigureAwait(false);
        try
        {
            if (_unresponsive)
                return CallOutcome.Timeout;

            var task = _pump.PostAsync(work);
            try
            {
                var result = await task.WaitAsync(budget, _time, _stopping.Token).ConfigureAwait(false);
                return CallOutcome.Ok(result);
            }
            catch (TimeoutException)
            {
                // The dedicated thread keeps running the hung call. Observe its eventual fault so an
                // abandoned, later-throwing call does not surface as an unobserved task exception.
                _unresponsive = true;
                Observe(task);
                return CallOutcome.Timeout;
            }
            catch (OperationCanceledException)
            {
                throw; // a clean shutdown, not a module fault
            }
            catch (Exception ex)
            {
                return CallOutcome.Faulted(ex);
            }
        }
        finally
        {
            _callGate.Release();
        }
    }

    /// <summary>
    /// Publishes a module state. <paramref name="contract"/> is set on every publish rather than
    /// carried forward, because it describes only the Incompatible state it arrives with.
    /// </summary>
    private void PublishState(ModuleState state, string? reason, string? id = null, string? version = null, ModuleContractView? contract = null) =>
        Publish(view => view with
        {
            ModuleState = state,
            ModuleReason = reason,
            ModuleId = id ?? view.ModuleId,
            ModuleVersion = version ?? view.ModuleVersion,
            Contract = contract,
        });

    /// <summary>A contract version as the card and the log show it: major and minor only (design section 5).</summary>
    private static string Short(Version version) => $"{version.Major}.{version.Minor}";

    private void PublishLicence(LicenceSnapshot snapshot) => Publish(view => view with { Licence = snapshot });

    /// <summary>Refreshes only what the view says about the licence store.</summary>
    private void PublishStore() => Publish(view => view);

    /// <summary>
    /// Applies <paramref name="change"/> to the view together with the licence store's current
    /// verdict, so every publish carries the store as it is now (issue #523). A folder that is not
    /// trusted holds no licence, and its reason is logged once each time it changes rather than on
    /// every tick.
    /// </summary>
    private void Publish(Func<LicenceStatusView, LicenceStatusView> change)
    {
        var store = _store.Verify();
        var refusal = store.IsReady ? null : store.RefusalReason ?? "the licence folder is not trusted";
        var stored = refusal is null && _store.HasActive;

        string? before;
        lock (_viewLock)
        {
            before = _view.LicenceStoreRefusal;
            _view = change(_view) with { LicenceStored = stored, LicenceStoreRefusal = refusal };
        }

        if (refusal is not null && !string.Equals(before, refusal, StringComparison.Ordinal))
        {
            _logger.LogError(
                "The licence folder {Folder} is not trusted, so the paid module is told that no licence is installed: {Reason}. " +
                "An administrator must delete the folder; the service then recreates it",
                _store.Folder, refusal);
        }
    }

    private void Log(string line) => _logger.LogInformation("{Line}", line);

    private string ModulesRoot()
    {
        if (_environment.IsDevelopment() && _configuration["Certus:Modules:DevelopmentPath"] is { Length: > 0 } dev)
            return System.IO.Path.GetFullPath(dev);
        return System.IO.Path.Combine(AppContext.BaseDirectory, "modules");
    }

    private bool TrustAll() =>
        _environment.IsDevelopment()
        && string.Equals(_configuration["Certus:Modules:DevelopmentTrustAll"], "true", StringComparison.OrdinalIgnoreCase);

    private static bool BytesEqual(byte[]? a, byte[]? b)
    {
        if (ReferenceEquals(a, b)) return true;
        if (a is null || b is null) return false;
        return a.AsSpan().SequenceEqual(b);
    }

    private static TaskCompletionSource Fresh() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static void Observe(Task task) =>
        _ = task.ContinueWith(
            static t => _ = t.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

    private bool _disposed;

    public void Dispose()
    {
        // The host is registered under several service types that all resolve to this one
        // instance, and the container disposes each, so Dispose runs more than once.
        if (_disposed)
            return;
        _disposed = true;

        try
        {
            _stopping.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _pump.Dispose();
        // _stopping and _callGate are deliberately not disposed: the fire and forget load task and
        // an in flight Inspect may still touch them during shutdown, and the host lives for the life
        // of the process, so GC reclaims them without a disposed object race.
    }

    /// <summary>The outcome of one budgeted call into module code.</summary>
    private readonly record struct CallOutcome(object? Result, Exception? Error, bool TimedOut)
    {
        public static CallOutcome Ok(object? result) => new(result, null, false);
        public static CallOutcome Faulted(Exception error) => new(null, error, false);
        public static CallOutcome Timeout { get; } = new(null, null, true);

        public LicenceSnapshot? Snapshot => Result as LicenceSnapshot;
    }

    /// <summary>
    /// The module's dedicated thread: a pump that runs one posted delegate at a time and never
    /// touches the thread pool. Started with <see cref="Thread.UnsafeStart()"/> so no caller's
    /// execution context flows onto it.
    /// </summary>
    private sealed class Pump : IDisposable
    {
        private readonly BlockingCollection<Item> _queue = new(new ConcurrentQueue<Item>());
        private readonly Thread _thread;

        public Pump(string name) =>
            _thread = new Thread(Loop) { IsBackground = true, Name = name };

        public void Start() => _thread.UnsafeStart();

        public Task<object?> PostAsync(Func<object?> work)
        {
            var tcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            try
            {
                _queue.Add(new Item(work, tcs));
            }
            catch (InvalidOperationException)
            {
                tcs.TrySetCanceled();
            }

            return tcs.Task;
        }

        public void Dispose() => _queue.CompleteAdding();

        private void Loop()
        {
            foreach (var item in _queue.GetConsumingEnumerable())
            {
                try
                {
                    item.Tcs.TrySetResult(item.Work());
                }
                catch (Exception ex)
                {
                    item.Tcs.TrySetException(ex);
                }
            }
        }

        private readonly record struct Item(Func<object?> Work, TaskCompletionSource<object?> Tcs);
    }
}
