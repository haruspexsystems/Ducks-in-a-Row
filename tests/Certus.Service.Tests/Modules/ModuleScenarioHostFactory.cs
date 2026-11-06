using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Certus.Core.Modules;
using Certus.Modules;
using Certus.Tests.Shared;
using Certus.Web.Controllers.Settings;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Service.Tests.Modules;

/// <summary>The states of the module the invariant is proved across (licence design section 18.1).</summary>
public enum ModuleScenario
{
    NoModule,
    Valid,
    Expired,
    Lapsed,
    BindingMismatch,
    ThrowsEverywhere,
    Hangs,
    Incompatible,
    RefusedByGate,
    Quarantined,
}

/// <summary>
/// Boots the real service host with the paid module in one <see cref="ModuleScenario"/>, before the
/// host starts: a module folder the host's own discovery, gate, manifest and metadata checks run
/// over, a stored licence, and for the quarantine a load journal that already holds two failed
/// starts. Only the last step, creating the module's entry type, is an in process stub.
///
/// <para>The module host gets a <see cref="FakeTimeProvider"/> of its own, and nothing else in the
/// host does, so a test moves the module host's ticks and budgets without freezing the clocks the
/// issuance path reads.</para>
/// </summary>
public sealed class ModuleScenarioHostFactory : ServiceHostFactory
{
    /// <summary>The bytes stored as the active licence. A fixture, not a licence.</summary>
    public static readonly byte[] LicenceBytes = "header.TEST-LICENCE-BYTES.signature"u8.ToArray();

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly ModuleScenario _scenario;
    private readonly ICertusModule _module;
    private readonly Action<IWebHostBuilder>? _configure;
    private readonly string? _instanceMode;

    /// <param name="scenario">The module's state.</param>
    /// <param name="module">The module to load in place of the scenario's default.</param>
    /// <param name="configure">More configuration, applied last, so its settings win.</param>
    /// <param name="instanceMode">The instance mode, full when null.</param>
    public ModuleScenarioHostFactory(
        ModuleScenario scenario,
        ICertusModule? module = null,
        Action<IWebHostBuilder>? configure = null,
        string? instanceMode = null)
    {
        _scenario = scenario;
        _configure = configure;
        _instanceMode = instanceMode;
        _module = module ?? scenario switch
        {
            ModuleScenario.Valid => new ScriptedModule(LicenceStatus.Valid),
            ModuleScenario.Expired => new ScriptedModule(LicenceStatus.Grace),
            ModuleScenario.Lapsed => new ScriptedModule(LicenceStatus.Lapsed),
            ModuleScenario.BindingMismatch => new ScriptedModule(LicenceStatus.BindingMismatch),
            ModuleScenario.ThrowsEverywhere => new ThrowingModule(),
            ModuleScenario.Hangs => new BlockingStartModule(),
            // The remaining states never reach Start; a sound module proves it is the state, not
            // the module, that keeps it from loading.
            _ => new ScriptedModule(LicenceStatus.Valid),
        };
    }

    public ModuleScenario Scenario => _scenario;

    protected override string? InstanceMode => _instanceMode ?? base.InstanceMode;

    /// <summary>The module host's own clock.</summary>
    public FakeTimeProvider ModuleTime { get; } = new(DateTimeOffset.UtcNow);

    /// <summary>
    /// Where the module folder is installed. Not the data directory's own <c>modules</c> folder,
    /// which holds the load journal and the modules' state folders.
    /// </summary>
    public string ModulesRoot => Path.Combine(DataDirectory, "installed-modules");

    protected override void SeedDataDirectory(string dataDirectory)
    {
        new LicenceFileStore(Path.Combine(dataDirectory, "licence")).Save(LicenceBytes);

        if (_scenario != ModuleScenario.NoModule)
            InstallModuleFolder(Path.Combine(ModulesRoot, "paid"), incompatible: _scenario == ModuleScenario.Incompatible);

        if (_scenario == ModuleScenario.Quarantined)
        {
            // Two starts with no healthy run between them: the journal's quarantine rule.
            var journal = new ModuleJournal(Path.Combine(dataDirectory, "modules"));
            journal.RecordAttempt("paid", "1.0.0", DateTimeOffset.UtcNow.AddMinutes(-2));
            journal.RecordAttempt("paid", "1.0.0", DateTimeOffset.UtcNow.AddMinutes(-1));
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.UseSetting("Certus:Modules:DevelopmentPath", ModulesRoot);
        // The gate is what refuses the module in one state; everywhere else the temporary folder
        // stands in for the protected install folder, which a test cannot create.
        builder.UseSetting(
            "Certus:Modules:DevelopmentTrustAll",
            _scenario == ModuleScenario.RefusedByGate ? "false" : "true");

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IModuleActivator>();
            services.AddSingleton<IModuleActivator>(new FixedActivator(_module));

            services.RemoveAll<ModuleHost>();
            services.AddSingleton(sp => ActivatorUtilities.CreateInstance<ModuleHost>(sp, (TimeProvider)ModuleTime));
        });

        _configure?.Invoke(builder);
    }

    /// <summary>GET api/settings/licence, asserting it answered without a server error.</summary>
    public static async Task<LicenceStatusResponse> GetLicenceAsync(HttpClient http)
    {
        var response = await http.GetAsync("/api/settings/licence");
        ((int)response.StatusCode).Should().BeLessThan(500, await response.Content.ReadAsStringAsync());
        return (await response.Content.ReadFromJsonAsync<LicenceStatusResponse>(Json))!;
    }

    /// <summary>
    /// Waits until the module host reports <paramref name="state"/>. Answers the last status read
    /// either way, so the caller's assertion names the state it actually saw.
    ///
    /// <para>Only a wait for Unresponsive moves the module host's clock, so a hung start runs out
    /// of budget. Every other state is reached in real time, and moving the clock there is a race:
    /// a poll that lands while Start or the first Evaluate is still running pushes the clock past
    /// that call's budget, and a sound module is set aside Unresponsive. That race failed
    /// HostServesAcme_BeforeTheModuleFinishesLoading once in a full suite run on 2026-10-12, and
    /// failed it every time with a 300 ms pause added after the module's release.</para>
    /// </summary>
    public async Task<LicenceStatusResponse> WaitForModuleStateAsync(HttpClient http, string state, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            var status = await GetLicenceAsync(http);
            if (status.Module.State == state || DateTime.UtcNow > deadline)
                return status;

            if (state == nameof(ModuleState.Unresponsive))
                ModuleTime.Advance(TimeSpan.FromSeconds(11)); // past the start budget, short of a tick's worth of drift
            await Task.Delay(100);
        }
    }

    /// <summary>Moves the module host through <paramref name="ticks"/> of its 30 second ticks.</summary>
    public async Task AdvanceModuleTicksAsync(int ticks)
    {
        for (var i = 0; i < ticks; i++)
        {
            ModuleTime.Advance(TimeSpan.FromSeconds(31));
            await Task.Delay(100);
        }
    }

    protected override void Dispose(bool disposing)
    {
        // Release a held Start first, so the module thread it pins ends with the test.
        if (disposing && _module is IDisposable disposable)
            disposable.Dispose();
        base.Dispose(disposing);
    }

    /// <summary>
    /// Writes a module folder the host's checks accept: an emitted entry assembly that references the
    /// contract and the framework and nothing else (issue #538 refuses anything more), and a manifest
    /// with its hash. For the incompatible state the entry references contract major 2, exactly what
    /// a module built against a later contract carries.
    /// </summary>
    private static void InstallModuleFolder(string folder, bool incompatible)
    {
        Directory.CreateDirectory(folder);
        var bytes = ModuleAssemblyBuilder.Module(contract: incompatible ? new Version(2, 0, 0, 0) : null);
        File.WriteAllBytes(Path.Combine(folder, "paid.dll"), bytes);

        var sha = Convert.ToHexStringLower(SHA256.HashData(bytes));
        File.WriteAllText(
            Path.Combine(folder, "module.json"),
            "{\"id\":\"paid\",\"displayName\":\"Paid modules\",\"version\":\"1.0.0\"," +
            "\"entryAssembly\":\"paid.dll\",\"entryType\":\"Paid.Module\",\"contract\":\"1.0\"," +
            $"\"files\":[{{\"path\":\"paid.dll\",\"sha256\":\"{sha}\"}}]}}");
    }
}
