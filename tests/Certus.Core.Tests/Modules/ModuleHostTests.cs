using Certus.Core.Modules;
using Certus.Modules;
using Certus.Core.Tests.Security;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The module host's load path and calling model (licence design sections 6.1 to 6.5). Module code
/// runs on the host's own thread through the stub activator, and the budgets are driven by a
/// FakeTimeProvider, so a hang is deterministic rather than a real wait.
/// </summary>
public class ModuleHostTests
{
    [Fact]
    public async Task LoadsTheModule_AndPublishesItsEvaluation()
    {
        using var fixture = new HostFixture(new ScriptedModule(Evaluations.Valid()));
        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Loaded)).Should().BeTrue();
        (await fixture.WaitForAsync(() => fixture.Host.Current.Licence is not null)).Should().BeTrue();

        var licence = fixture.Host.Current.Licence!;
        licence.Status.Should().Be(LicenceStatus.Valid);
        licence.Features.Should().Contain("placeholder");
    }

    [Fact]
    public void TheLicenceLine_ForARefusedFile_CarriesTheReason_AndNothingTheFileSays()
    {
        // Acceptance criterion 2 of #413: a tampered file fails "with a logged reason", and
        // deviation Dv4: nothing unverified is logged, so no id, tier or date from the file.
        var refused = ModuleBoundary.Copy(new LicenceEvaluation(
            LicenceStatus.Invalid, "bad-signature", "LIC-FROM-THE-FILE", "standard", ["placeholder"], 3,
            "Name From The File", "REF", null, DateTimeOffset.UnixEpoch.AddYears(60), null, null, null,
            ["corp.example.com"], "corp.example.com", false, false, NoticeStage.None, false));

        ModuleHost.LicenceLine(refused).Should().Be("Licence: status=Invalid reason=bad-signature");
    }

    [Fact]
    public void TheLicenceLine_ForAVerifiedLicence_CarriesTheReason_TheTier_AndTheId()
    {
        var line = ModuleHost.LicenceLine(ModuleBoundary.Copy(Evaluations.Valid()));

        line.Should().StartWith("Licence: status=Valid reason=ok tier=standard validUntil=").And.EndWith(" lid=LIC-1");
    }

    [Fact]
    public void TheLicenceLine_WithNoLicence_SaysSo()
    {
        ModuleHost.LicenceLine(ModuleBoundary.Copy(Evaluations.None())).Should().Be("Licence: status=None reason=none");
    }

    [Fact]
    public async Task AStartThatThrows_IsFailed()
    {
        using var fixture = new HostFixture(new ThrowingStartModule());
        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Failed)).Should().BeTrue();
    }

    [Fact]
    public async Task AnEvaluationThatThrows_SetsTheModuleAside_AndItGetsNoFurtherCall()
    {
        var module = new ThrowingEvaluatorModule();
        using var fixture = new HostFixture(module);
        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Failed)).Should().BeTrue();
        module.EvaluateCalls.Should().Be(1);

        // Set aside means set aside: no Inspect for the licence API, and no later evaluation that
        // could publish a verdict while the state still reads Failed.
        (await fixture.Host.InspectAsync("candidate"u8.ToArray())).Should().BeNull();
        fixture.Store.Save("a-licence"u8.ToArray());
        fixture.Host.Reevaluate();
        fixture.Time.Advance(TimeSpan.FromHours(2));
        await Task.Delay(200);

        module.InspectCalls.Should().Be(0);
        module.EvaluateCalls.Should().Be(1);
        fixture.Host.Current.ModuleState.Should().Be(ModuleState.Failed);
    }

    [Fact]
    public async Task AnInspectThatThrows_AnswersNoVerdict_AndLeavesTheModuleLoaded()
    {
        // A candidate the module chokes on is the uploader's problem, not a reason to switch paid
        // features off: the inspect reads null (which the licence API answers 503) and the module
        // keeps its state and its evaluation of the installed licence.
        using var fixture = new HostFixture(new InspectThrowingModule());
        await fixture.StartAsync();
        (await fixture.WaitForStateAsync(ModuleState.Loaded)).Should().BeTrue();
        (await fixture.WaitForAsync(() => fixture.Host.Current.Licence is not null)).Should().BeTrue();

        (await fixture.Host.InspectAsync("candidate"u8.ToArray())).Should().BeNull();

        fixture.Host.Current.ModuleState.Should().Be(ModuleState.Loaded);
        fixture.Host.Current.Licence!.Status.Should().Be(LicenceStatus.Valid);
    }

    [Fact]
    public void TheLicenceLine_CannotBeGivenExtraFields_ByWhatTheModuleReturns()
    {
        // Every value is reduced to one token, so a reason with spaces cannot append a forged
        // status=Valid that a search of the log would then match.
        var forged = ModuleBoundary.Copy(new LicenceEvaluation(
            LicenceStatus.Invalid, "x status=Valid", null, null, [], null, null, null, null, null, null, null,
            null, [], null, false, false, NoticeStage.None, false));

        ModuleHost.LicenceLine(forged).Should().Be("Licence: status=Invalid reason=x_status_Valid");
    }

    [Fact]
    public void TheLicenceLine_WritesTheDate_TheSameInEveryCulture()
    {
        var before = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            // A Buddhist calendar culture would otherwise log the year 2573 for 2030.
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("th-TH");
            ModuleHost.LicenceLine(ModuleBoundary.Copy(Evaluations.Valid())).Should().Contain("validUntil=2030-01-01");
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = before;
        }
    }

    [Fact]
    public async Task NoModule_IsNotPresent_AndReportsAStoredLicence()
    {
        using var fixture = new HostFixture(new ThrowingStartModule(), installModule: false);
        fixture.Store.Save("a-licence"u8.ToArray()); // stored, but no module to verify it

        await fixture.StartAsync();

        // The initial view is already NotPresent, so wait for the host to actually run and report
        // the stored licence rather than catching the pre-start view.
        (await fixture.WaitForAsync(() =>
            fixture.Host.Current is { ModuleState: ModuleState.NotPresent, LicenceStored: true })).Should().BeTrue();
    }

    [Fact]
    public async Task AModuleBuiltForAnotherContract_IsIncompatible_WithBothContracts_AndRunsNoCode()
    {
        // Issue #493: the card names the module's version and both contract numbers, and Retry is
        // refused because a restart cannot change the contract a module was built for.
        var module = new CountingModule();
        using var fixture = new HostFixture(module, contract: new Version(2, 0, 0, 0));
        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Incompatible)).Should().BeTrue();

        var current = fixture.Host.Current;
        current.ModuleId.Should().Be("paid");
        current.ModuleVersion.Should().Be("1.0.0");
        current.Contract.Should().Be(new ModuleContractView("2.0", "1.0"));
        current.ModuleReason.Should().Contain("contract major 2");
        module.StartCalls.Should().Be(0);
        File.Exists(fixture.Journal.JournalPath).Should().BeFalse("a refusal before the start costs no strike");
        fixture.Host.RequestRetry().Should().BeFalse();
        fixture.Restarter.Requests.Should().Be(0);
    }

    [Fact]
    public async Task AModuleWhoseSignatureDoesNotVerify_IsFailed_Journaled_AndLoggedInOneLine()
    {
        // Issue #636: the fixture's module is unsigned, and the policy expects the suite's own
        // publisher. The module runs no code, the card gets the file name, the journal keeps a
        // refused entry that is not a strike, Retry is offered, and the log names both publishers.
        using var chain = new SignatureFixture();
        var module = new CountingModule();
        var log = new RecordingLogger();
        using var fixture = new HostFixture(module, signaturePolicy: chain.Policy, logger: log);
        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Failed)).Should().BeTrue();

        var current = fixture.Host.Current;
        current.ModuleReason.Should().Be(
            "the paid module's signature could not be verified: 'module.json' has no signature file (module.json.p7 is missing)");
        current.ModuleId.Should().Be("paid");
        current.ModuleVersion.Should().Be("1.0.0");
        module.StartCalls.Should().Be(0);

        var entries = fixture.Journal.Entries();
        entries.Should().ContainSingle().Which.Kind.Should().Be(ModuleJournalEntry.Refused);
        fixture.Journal.IsQuarantined("paid", "1.0.0").Should().BeFalse();
        fixture.Host.RequestRetry().Should().BeTrue("reinstalling the module changes what the next check sees");

        log.Errors.Should().ContainSingle().Which.Should()
            .Contain("file=module.json")
            .And.Contain($"expectedPublisher='{SignatureFixture.Publisher}'")
            .And.Contain("foundPublisher='none'");
    }

    private sealed class RecordingLogger : Microsoft.Extensions.Logging.ILogger<ModuleHost>
    {
        public List<string> Errors { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= Microsoft.Extensions.Logging.LogLevel.Error)
                lock (Errors)
                    Errors.Add(formatter(state, exception));
        }
    }

    [Fact]
    public async Task AModuleTheFolderGateRefuses_IsRefused_AndNothingInItIsRead()
    {
        var module = new CountingModule();
        using var fixture = new HostFixture(module, trustAll: false);
        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Refused)).Should().BeTrue();

        var current = fixture.Host.Current;
        current.ModuleReason.Should().Contain("not trusted");
        current.ModuleId.Should().BeNull("the gate refuses before the manifest is read");
        current.ModuleVersion.Should().BeNull();
        current.Contract.Should().BeNull();
        module.StartCalls.Should().Be(0);
        File.Exists(fixture.Journal.JournalPath).Should().BeFalse();
        fixture.Host.RequestRetry().Should().BeFalse();
    }

    [Fact]
    public async Task AQuarantinedVersion_IsNotLoaded()
    {
        using var fixture = new HostFixture(new ScriptedModule(Evaluations.Valid()));
        // Two attempts with no healthy one between them quarantine this version.
        fixture.Journal.RecordAttempt("paid", "1.0.0", DateTimeOffset.UnixEpoch);
        fixture.Journal.RecordAttempt("paid", "1.0.0", DateTimeOffset.UnixEpoch.AddSeconds(1));

        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Quarantined)).Should().BeTrue();
    }

    [Fact]
    public async Task Inspect_RunsTheModule_AndCopiesTheResult()
    {
        using var fixture = new HostFixture(new ScriptedModule(Evaluations.Valid(), Evaluations.Valid(worse: true)));
        await fixture.StartAsync();
        (await fixture.WaitForStateAsync(ModuleState.Loaded)).Should().BeTrue();

        var snapshot = await fixture.Host.InspectAsync("candidate"u8.ToArray());

        snapshot.Should().NotBeNull();
        snapshot!.WorseThanInstalled.Should().BeTrue();
    }

    [Fact]
    public async Task AStartThatHangs_IsUnresponsive()
    {
        using var fixture = new HostFixture(new HangingStartModule());
        await fixture.StartAsync();

        // Advance past the start budget until the host gives up on the hung call. Advancing on every
        // look rides out the race between the host posting the call and the clock moving, and the
        // wait has no fixed wall clock bound of its own (issue #529).
        (await fixture.AdvanceUntilAsync(TimeSpan.FromSeconds(11),
            () => fixture.Host.Current.ModuleState == ModuleState.Unresponsive)).Should().BeTrue();
    }

    [Fact]
    public async Task Reevaluate_PicksUpALicenceDroppedAfterStart()
    {
        using var fixture = new HostFixture(new EchoModule());
        fixture.Store.ReadActive().Should().BeNull("no licence is stored before the test saves one");
        await fixture.StartAsync();
        (await fixture.WaitForStateAsync(ModuleState.Loaded)).Should().BeTrue();
        (await fixture.WaitForAsync(() => fixture.Host.Current.Licence is not null)).Should().BeTrue(
            $"state={fixture.Host.Current.ModuleState} reason={fixture.Host.Current.ModuleReason}");
        fixture.Host.Current.Licence!.Status.Should().Be(LicenceStatus.None,
            $"the module should see no licence; reason={fixture.Host.Current.Licence!.ReasonCode}");

        fixture.Store.Save("a-licence"u8.ToArray());
        fixture.Host.Reevaluate();

        (await fixture.WaitForAsync(() => fixture.Host.Current.Licence?.Status == LicenceStatus.Valid)).Should().BeTrue();
    }

    [Fact]
    public async Task AnUntrustedLicenceFolder_IsNoLicence_AndTheReasonIsPublished()
    {
        // Issue #523: the host read licence.json without the folder check the store's Open makes.
        // The licence is stored, then the folder is opened to Everyone, the shape a folder planted
        // before #489 can have. The module must be told there is no licence.
        using var fixture = new HostFixture(new EchoModule());
        fixture.Store.Save("a-licence"u8.ToArray());
        FileAcl.GrantEveryoneWriteToFolder(fixture.Store.Folder);

        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Loaded)).Should().BeTrue();
        (await fixture.WaitForAsync(() => fixture.Host.Current.Licence is not null)).Should().BeTrue();
        fixture.Host.Current.Licence!.Status.Should().Be(LicenceStatus.None, "the module was told no licence is installed");
        fixture.Host.Current.LicenceStored.Should().BeFalse();
        fixture.Host.Current.LicenceStoreRefusal.Should().Contain("write");
    }

    [Fact]
    public async Task AnUntrustedStateFolder_RefusesTheModule_BeforeAnyOfItsCodeRuns()
    {
        var module = new CountingModule();
        using var fixture = new HostFixture(module);
        var state = Path.Combine(fixture.DataDirectory, "modules", "paid");
        Certus.Core.Security.ProtectedFolder.EnsureExists(state);
        FileAcl.GrantEveryoneWriteToFolder(state);

        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Failed)).Should().BeTrue();
        fixture.Host.Current.ModuleReason.Should().Contain("state folder is not trusted");
        module.StartCalls.Should().Be(0);
        fixture.Journal.Entries().Should().BeEmpty("a module refused before it runs costs no strike");
    }

    [Fact]
    public async Task AnUntrustedModulesFolder_RefusesTheModule()
    {
        // The modules folder's owner could replace the state folder inside it, so the state folder
        // is no better than the folder that holds it.
        var module = new CountingModule();
        using var fixture = new HostFixture(module);
        var modules = Path.Combine(fixture.DataDirectory, "modules");
        Certus.Core.Security.ProtectedFolder.EnsureExists(modules);
        FileAcl.GrantEveryoneWriteToFolder(modules);

        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Failed)).Should().BeTrue();
        fixture.Host.Current.ModuleReason.Should().Contain("state folder is not trusted");
        module.StartCalls.Should().Be(0);
    }

    [Fact]
    public async Task AModulesFolderThatIsAJunction_IsRefused_AndNothingIsCreatedThroughIt()
    {
        // Found by the review of this change: the state folder used to be created before the
        // modules folder was checked, so a junction planted in its place made the service create
        // the state folder at the junction's target first and refuse it afterwards.
        var module = new CountingModule();
        using var fixture = new HostFixture(module);
        var target = Path.Combine(fixture.Root, "elsewhere");
        Directory.CreateDirectory(target);
        Directory.CreateDirectory(fixture.DataDirectory);
        ReparsePoints.TryCreateJunction(Path.Combine(fixture.DataDirectory, "modules"), target)
            .Should().BeTrue("the test needs a junction to check");

        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Failed)).Should().BeTrue();
        fixture.Host.Current.ModuleReason.Should().Contain("reparse point");
        Directory.Exists(Path.Combine(target, "paid")).Should().BeFalse("nothing is created through a junction");
        module.StartCalls.Should().Be(0);
    }

    [Fact]
    public async Task ATrustedStateFolder_IsHandedToTheModule()
    {
        // The positive control for the two refusals above: the host creates the folder protected,
        // verifies it, and starts the module with it.
        var module = new CountingModule();
        using var fixture = new HostFixture(module);

        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Loaded)).Should().BeTrue();
        module.StartCalls.Should().Be(1);
        module.StateDirectory.Should().Be(Path.Combine(fixture.DataDirectory, "modules", "paid"));
        Directory.Exists(module.StateDirectory).Should().BeTrue();
    }
}
