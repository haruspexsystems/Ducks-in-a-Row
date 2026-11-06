using System.Reflection;
using System.Security.AccessControl;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json;
using Certus.Core.Modules;
using Certus.Modules;
using Certus.Web.Authentication;
using Certus.Web.Controllers.Settings;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Certus.Web.Tests;

/// <summary>
/// The licence API (licence design section 13.2, issue #413) as unit tests: the controller with a
/// real licence store in a folder of its own and a fake module host, so each route's effect on the
/// store, on the module and on the audit log is asserted directly. The 415 and 413 that the
/// framework answers, the CSRF header and the AdminOnly policy are proved through the real pipeline
/// separately; here the attributes that carry them are pinned, and the action's own read cap, which
/// is what holds under TestServer, is exercised.
/// </summary>
public sealed class LicenceControllerTests : IDisposable
{
    private const string Admin = @"CORP\licence-admin";

    // A marker no response or log line may ever repeat: the API never echoes the upload.
    private static readonly byte[] LicenceA = "header.LICENCE-A-UPLOADED-BYTES.signature"u8.ToArray();
    private static readonly byte[] LicenceB = "header.LICENCE-B-UPLOADED-BYTES.signature"u8.ToArray();

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-licapi-{Guid.NewGuid():N}");
    private readonly LicenceFileStore _store;
    private readonly FakeModuleHost _host = new();
    private readonly RecordingLogger _log = new();

    public LicenceControllerTests()
    {
        Directory.CreateDirectory(_root);
        _store = new LicenceFileStore(Path.Combine(_root, "licence"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    // ---- GET ----

    [Fact]
    public void Get_NoModuleAndNoLicence_ReadsNone()
    {
        var response = OkBody<LicenceStatusResponse>(NewController().Get());

        response.Module.State.Should().Be("NotPresent");
        response.Stored.Should().Be(new LicenceStoreView(false, false));
        response.Licence.Status.Should().Be("None");
    }

    [Fact]
    public void Get_AStoredLicenceWithNoModule_ReadsStoredNotVerified()
    {
        _store.Save(LicenceA);

        var response = OkBody<LicenceStatusResponse>(NewController().Get());

        response.Licence.Status.Should().Be("StoredNotVerified");
        response.Stored.Active.Should().BeTrue();
        response.Licence.LicenceId.Should().BeNull();
    }

    [Fact]
    public void Get_ALoadedModule_ReportsItsVerdict()
    {
        _store.Save(LicenceA);
        _host.LoadWith(Verdict(LicenceStatus.Valid));

        var response = OkBody<LicenceStatusResponse>(NewController().Get());

        response.Module.Should().Be(new ModuleView("Loaded", null, "paid", "1.0.0+test"));
        response.Licence.Status.Should().Be("Valid");
        response.Licence.LicenceId.Should().Be("lid-1");
        response.Licence.Tier.Should().Be("standard");
        response.Licence.ObservedForest.Should().Be("corp.example.com");
    }

    [Fact]
    public void Get_ALoadedModuleWithNothingStored_ShowsTheServersForest()
    {
        // Issue #493, design section 10.4: the forest is read off the server, so it is shown before
        // any licence is installed, for a customer to quote when buying a bound one.
        _host.LoadWith(Verdict(LicenceStatus.None, "None"));

        var response = OkBody<LicenceStatusResponse>(NewController().Get());

        response.Licence.Status.Should().Be("None");
        response.Licence.ObservedForest.Should().Be("corp.example.com");
        response.Licence.LicenceId.Should().BeNull();
    }

    [Fact]
    public void Get_AnIncompatibleModule_CarriesBothContracts_OnTheWire()
    {
        _host.Current = new LicenceStatusView(ModuleState.Incompatible, "the module needs contract major 2, and the core carries 1",
            "paid", "2.0.0", false, null)
        {
            Contract = new ModuleContractView("2.0", "1.0"),
        };

        var response = OkBody<LicenceStatusResponse>(NewController().Get());

        response.Module.State.Should().Be("Incompatible");
        response.Module.Version.Should().Be("2.0.0");
        var json = JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        json.Should().Contain("\"contract\":{\"module\":\"2.0\",\"core\":\"1.0\"}");
    }

    [Fact]
    public void Get_AnUntrustedLicenceFolder_SaysSo_RatherThanReadingAsNoLicence()
    {
        if (!OperatingSystem.IsWindows())
            return; // the service runs only on Windows, and off it there are no ACLs to refuse

        // Issue #523 made a refused folder read as holding nothing. Issue #493 has GET say why, so
        // the card can tell an administrator to delete the folder (design section 12.3).
        var folder = Path.Combine(_root, "squatted");
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "licence.json"), LicenceA);
        GrantEveryoneWrite(folder);
        var store = new LicenceFileStore(folder);

        var response = OkBody<LicenceStatusResponse>(NewController(store: store).Get());

        response.Stored.Should().Be(new LicenceStoreView(Active: false, Previous: false, Untrusted: true));
        response.Licence.Status.Should().Be("None");
    }

    [Fact]
    public void Get_ATrustedOrAbsentLicenceFolder_IsNotUntrusted()
    {
        OkBody<LicenceStatusResponse>(NewController().Get()).Stored.Untrusted.Should().BeFalse();

        _store.Save(LicenceA);
        OkBody<LicenceStatusResponse>(NewController().Get()).Stored.Untrusted.Should().BeFalse();
    }

    // ---- inspect ----

    [Fact]
    public async Task Inspect_ReturnsTheModulesVerdict_AndChangesNothing()
    {
        _host.LoadWith(Verdict(LicenceStatus.None));
        _host.InspectResult = Verdict(LicenceStatus.Valid);

        var response = OkBody<LicenceInspectResponse>(await NewController(LicenceA).Inspect(CancellationToken.None));

        response.Candidate!.Licence.Status.Should().Be("Valid");
        response.Candidate.WorseThanInstalled.Should().BeFalse();
        _host.Inspected.Should().ContainSingle().Which.Should().Equal(LicenceA);
        _store.HasActive.Should().BeFalse();
        _host.Reevaluations.Should().Be(0);
        _log.AuditLines.Should().BeEmpty();
    }

    [Fact]
    public async Task Inspect_WithNoModuleToJudgeIt_AnswersANullCandidate()
    {
        var response = OkBody<LicenceInspectResponse>(await NewController(LicenceA).Inspect(CancellationToken.None));

        response.Candidate.Should().BeNull();
        response.Module.State.Should().Be("NotPresent");
    }

    [Fact]
    public async Task Inspect_OverTheCap_Answers413_WithoutAskingTheModule()
    {
        var result = await NewController(new byte[LicenceController.MaxLicenceBytes + 1]).Inspect(CancellationToken.None);

        StatusOf(result).Should().Be(StatusCodes.Status413PayloadTooLarge);
        _host.Inspected.Should().BeEmpty();
    }

    // ---- PUT ----

    [Fact]
    public async Task Put_WithNoModule_StoresTheBytesVerbatim_AsStoredNotVerified()
    {
        var response = OkBody<LicenceStatusResponse>(await NewController(LicenceA).Put(confirm: false, CancellationToken.None));

        response.Licence.Status.Should().Be("StoredNotVerified");
        response.Stored.Active.Should().BeTrue();
        _store.ReadActive().Should().Equal(LicenceA);
        _host.Reevaluations.Should().Be(1);

        // Nothing unverified is logged: no licence id or tier for a file no module judged.
        _log.AuditLines.Should().ContainSingle().Which.Should()
            .Contain("action=install ").And.Contain($"by={Admin}")
            .And.Contain("status=StoredNotVerified").And.Contain("lid=none").And.Contain("tier=none");
    }

    [Fact]
    public async Task Put_WithAModule_InstallsAndAnswersTheCandidatesVerdict()
    {
        _host.LoadWith(Verdict(LicenceStatus.None));
        _host.InspectResult = Verdict(LicenceStatus.Valid);

        var response = OkBody<LicenceStatusResponse>(await NewController(LicenceA).Put(confirm: false, CancellationToken.None));

        response.Licence.Status.Should().Be("Valid");
        response.Licence.LicenceId.Should().Be("lid-1");
        _store.ReadActive().Should().Equal(LicenceA);
        _host.Reevaluations.Should().Be(1);
        _log.AuditLines.Should().ContainSingle().Which.Should()
            .Contain("action=install ").And.Contain("lid=lid-1").And.Contain("tier=standard");
    }

    [Fact]
    public async Task Put_ACandidateWorseThanTheInstalledLicence_Answers409_AndWritesNothing()
    {
        _store.Save(LicenceA);
        _host.LoadWith(Verdict(LicenceStatus.Valid));
        _host.InspectResult = Verdict(LicenceStatus.Lapsed, worse: true);

        var result = await NewController(LicenceB).Put(confirm: false, CancellationToken.None);

        var conflict = result.Should().BeOfType<ConflictObjectResult>().Subject;
        var body = conflict.Value.Should().BeOfType<LicenceDowngradeResponse>().Subject;
        body.Code.Should().Be("WouldDowngrade");
        body.Candidate.Licence.Status.Should().Be("Lapsed");
        _store.ReadActive().Should().Equal(LicenceA);
        _store.HasPrevious.Should().BeFalse();
        _host.Reevaluations.Should().Be(0);
        _log.AuditLines.Should().BeEmpty();
    }

    [Fact]
    public async Task Put_AWorseCandidateWithConfirm_Installs_AndKeepsTheOneItReplaced()
    {
        _store.Save(LicenceA);
        _host.LoadWith(Verdict(LicenceStatus.Valid));
        _host.InspectResult = Verdict(LicenceStatus.Lapsed, worse: true);

        var response = OkBody<LicenceStatusResponse>(await NewController(LicenceB).Put(confirm: true, CancellationToken.None));

        response.Licence.Status.Should().Be("Lapsed");
        response.Stored.Should().Be(new LicenceStoreView(true, true));
        _store.ReadActive().Should().Equal(LicenceB);
        _log.AuditLines.Should().ContainSingle().Which.Should().Contain("action=install-downgrade");
    }

    [Fact]
    public async Task Put_ExactlyTheCap_IsAccepted()
    {
        var bytes = new byte[LicenceController.MaxLicenceBytes];
        Array.Fill(bytes, (byte)'a');

        var result = await NewController(bytes).Put(confirm: false, CancellationToken.None);

        StatusOf(result).Should().Be(StatusCodes.Status200OK);
        _store.ReadActive().Should().Equal(bytes);
    }

    [Fact]
    public async Task Put_OneByteOverTheCap_Answers413_AndNeverReachesTheModuleOrTheStore()
    {
        var result = await NewController(new byte[LicenceController.MaxLicenceBytes + 1]).Put(confirm: false, CancellationToken.None);

        StatusOf(result).Should().Be(StatusCodes.Status413PayloadTooLarge);
        _host.Inspected.Should().BeEmpty();
        _store.HasActive.Should().BeFalse();
    }

    [Fact]
    public async Task Put_ABodyFarOverTheCap_IsReadOnlyToOneBytePastIt()
    {
        var body = new CountingStream(new byte[LicenceController.MaxLicenceBytes * 4]);
        var controller = NewController();
        controller.HttpContext.Request.Body = body;

        var result = await controller.Put(confirm: false, CancellationToken.None);

        StatusOf(result).Should().Be(StatusCodes.Status413PayloadTooLarge);
        body.BytesRead.Should().Be(LicenceController.MaxLicenceBytes + 1);
    }

    [Fact]
    public async Task Put_AnEmptyBody_Answers400()
    {
        var result = await NewController([]).Put(confirm: false, CancellationToken.None);

        StatusOf(result).Should().Be(StatusCodes.Status400BadRequest);
        _store.HasActive.Should().BeFalse();
    }

    [Fact]
    public async Task Put_ACallerThatGoesAwayDuringTheInspect_WritesNothing()
    {
        // A cancelled inspect reads null, the same as "no module"; storing then would install a file
        // the module was never allowed to judge.
        using var cts = new CancellationTokenSource();
        _host.LoadWith(Verdict(LicenceStatus.Valid));
        _host.OnInspect = () => cts.Cancel();
        _host.InspectResult = null;

        var act = () => NewController(LicenceA).Put(confirm: false, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        _store.HasActive.Should().BeFalse();
        _host.Reevaluations.Should().Be(0);
        _log.AuditLines.Should().BeEmpty();
    }

    [Fact]
    public async Task Put_ALoadedModuleThatCannotJudgeTheFile_Answers503_AndWritesNothing()
    {
        // Its Inspect threw, which reads null like "no module"; storing then would skip the
        // downgrade check against the licence it would replace.
        _store.Save(LicenceA);
        _host.LoadWith(Verdict(LicenceStatus.Valid));
        _host.InspectResult = null;

        var result = await NewController(LicenceB).Put(confirm: false, CancellationToken.None);

        StatusOf(result).Should().Be(StatusCodes.Status503ServiceUnavailable);
        _store.ReadActive().Should().Equal(LicenceA);
        _store.HasPrevious.Should().BeFalse();
        _host.Reevaluations.Should().Be(0);
        _log.AuditLines.Should().BeEmpty();
    }

    [Theory]
    [InlineData(ModuleState.NotPresent)]
    [InlineData(ModuleState.Failed)]
    [InlineData(ModuleState.Unresponsive)]
    [InlineData(ModuleState.Quarantined)]
    [InlineData(ModuleState.Incompatible)]
    [InlineData(ModuleState.Refused)]
    public async Task Put_WithNoModuleLoaded_StoresWithoutAVerdict(ModuleState state)
    {
        _host.Current = new LicenceStatusView(state, null, null, null, false, null);

        var response = OkBody<LicenceStatusResponse>(await NewController(LicenceA).Put(confirm: false, CancellationToken.None));

        response.Licence.Status.Should().Be("StoredNotVerified");
        _store.ReadActive().Should().Equal(LicenceA);
    }

    [Fact]
    public async Task Put_WhereTheLicenceFolderCannotBeCreated_Answers409_AndWritesNothing()
    {
        // A file where the licence folder should be: the store refuses rather than repairs.
        var refused = Path.Combine(_root, "refused");
        await File.WriteAllTextAsync(refused, "not a folder");
        var store = new LicenceFileStore(refused);

        var result = await NewController(LicenceA, store).Put(confirm: false, CancellationToken.None);

        StatusOf(result).Should().Be(StatusCodes.Status409Conflict);
        _host.Inspected.Should().BeEmpty();
        _log.AuditLines.Should().BeEmpty();
        _log.Lines.Should().Contain(l => l.Contains("was refused"));
    }

    [Fact]
    public async Task Put_IntoAFolderThatGrantsOthersWrite_Answers409_AndWritesNothing()
    {
        if (!OperatingSystem.IsWindows())
            return; // the service runs only on Windows, and off it there are no ACLs to refuse

        // A folder that already exists and lets Everyone write: a squatter's shape (design 12.3).
        // The store verifies and never repairs it, so the upload is refused and nothing lands.
        var folder = Path.Combine(_root, "squatted");
        Directory.CreateDirectory(folder);
        GrantEveryoneWrite(folder);
        var store = new LicenceFileStore(folder);

        var result = await NewController(LicenceA, store).Put(confirm: false, CancellationToken.None);

        StatusOf(result).Should().Be(StatusCodes.Status409Conflict);
        store.HasActive.Should().BeFalse();
        _host.Inspected.Should().BeEmpty();
        _log.AuditLines.Should().BeEmpty();
    }

    [Fact]
    public async Task DeleteAndRestore_RefuseAnUntrustedFolderToo()
    {
        var refused = Path.Combine(_root, "refused");
        await File.WriteAllTextAsync(refused, "not a folder");
        var store = new LicenceFileStore(refused);

        StatusOf(NewController(store: store).Delete()).Should().Be(StatusCodes.Status409Conflict);
        StatusOf(await NewController(store: store).RestorePrevious()).Should().Be(StatusCodes.Status409Conflict);
        _host.Reevaluations.Should().Be(0);
    }

    [Fact]
    public async Task NoResponseOrLogLine_EverRepeatsTheUploadedBytes()
    {
        _host.LoadWith(Verdict(LicenceStatus.None));
        _host.InspectResult = Verdict(LicenceStatus.Invalid, "bad-signature");

        var inspect = await NewController(LicenceA).Inspect(CancellationToken.None);
        var put = await NewController(LicenceA).Put(confirm: false, CancellationToken.None);
        var get = NewController().Get();

        var marker = "LICENCE-A-UPLOADED-BYTES";
        foreach (var result in new[] { inspect, put, get })
            Json(((ObjectResult)result).Value).Should().NotContain(marker);
        _log.Lines.Should().NotContain(l => l.Contains(marker));
    }

    // ---- DELETE ----

    [Fact]
    public void Delete_RemovesTheActiveLicence_KeepsItAsPrevious_AndAudits()
    {
        _store.Save(LicenceA);
        _host.LoadWith(Verdict(LicenceStatus.Valid));

        var response = OkBody<LicenceStatusResponse>(NewController().Delete());

        response.Licence.Status.Should().Be("None");
        response.Stored.Should().Be(new LicenceStoreView(false, true));
        _store.HasActive.Should().BeFalse();
        _host.Reevaluations.Should().Be(1);
        _log.AuditLines.Should().ContainSingle().Which.Should()
            .Contain("action=remove").And.Contain("lid=lid-1").And.Contain("tier=standard");
    }

    [Fact]
    public void Delete_WithNothingInstalled_Answers404()
    {
        StatusOf(NewController().Delete()).Should().Be(StatusCodes.Status404NotFound);
        _host.Reevaluations.Should().Be(0);
        _log.AuditLines.Should().BeEmpty();
    }

    // ---- restore-previous ----

    [Fact]
    public async Task RestorePrevious_PutsThePreviousLicenceBack_AndAnswersItsVerdict()
    {
        _store.Save(LicenceA);
        _store.Save(LicenceB);
        _host.LoadWith(Verdict(LicenceStatus.Lapsed));
        _host.InspectResult = Verdict(LicenceStatus.Valid);

        var response = OkBody<LicenceStatusResponse>(await NewController().RestorePrevious());

        _store.ReadActive().Should().Equal(LicenceA);
        _host.Inspected.Should().ContainSingle().Which.Should().Equal(LicenceA);
        response.Licence.Status.Should().Be("Valid");
        _host.Reevaluations.Should().Be(1);
        _log.AuditLines.Should().ContainSingle().Which.Should().Contain("action=restore-previous").And.Contain("lid=lid-1");
    }

    [Fact]
    public async Task RestorePrevious_WithNoModule_ReadsStoredNotVerified()
    {
        _store.Save(LicenceA);
        _store.DeleteActive();

        var response = OkBody<LicenceStatusResponse>(await NewController().RestorePrevious());

        response.Licence.Status.Should().Be("StoredNotVerified");
        _store.ReadActive().Should().Equal(LicenceA);
    }

    [Fact]
    public async Task RestorePrevious_WithNothingKept_Answers404()
    {
        StatusOf(await NewController().RestorePrevious()).Should().Be(StatusCodes.Status404NotFound);
        _log.AuditLines.Should().BeEmpty();
    }

    // ---- retry-module ----

    [Theory]
    [InlineData(ModuleState.Failed)]
    [InlineData(ModuleState.Unresponsive)]
    [InlineData(ModuleState.Quarantined)]
    public void RetryModule_ForAModuleSetAside_AsksForARetry(ModuleState state)
    {
        _host.Current = new LicenceStatusView(state, "set aside", "paid", "1.0.0+test", false, null);

        var result = NewController().RetryModule();

        StatusOf(result).Should().Be(StatusCodes.Status200OK);
        _host.Retries.Should().Be(1);
        Json(((ObjectResult)result).Value).Should().Contain("\"restartScheduled\":true");
        _log.AuditLines.Should().ContainSingle().Which.Should().Contain("action=retry-module");
    }

    [Fact]
    public void RetryModule_WhereNoRestarterIsAvailable_SaysToRestartByHand()
    {
        _host.Current = new LicenceStatusView(ModuleState.Quarantined, "set aside", "paid", "1.0.0+test", false, null);
        _host.RetrySchedules = false;

        var result = NewController().RetryModule();

        Json(((ObjectResult)result).Value).Should().Contain("\"restartScheduled\":false").And.Contain("Restart the service");
    }

    [Theory]
    [InlineData(ModuleState.NotPresent)]
    [InlineData(ModuleState.Loaded)]
    [InlineData(ModuleState.Incompatible)] // a restart cannot change the contract a module was built for
    [InlineData(ModuleState.Refused)]      // nor the permissions on its folder
    public void RetryModule_ForAModuleNotSetAside_Answers409_AndAsksForNothing(ModuleState state)
    {
        _host.Current = new LicenceStatusView(state, null, null, null, false, null);

        StatusOf(NewController().RetryModule()).Should().Be(StatusCodes.Status409Conflict);
        _host.Retries.Should().Be(0);
        _log.AuditLines.Should().BeEmpty();
    }

    // ---- the attributes the pipeline acts on ----

    [Fact]
    public void TheController_IsAdminOnly()
    {
        typeof(LicenceController).GetCustomAttribute<AuthorizeAttribute>()!.Policy
            .Should().Be(CertusPolicies.AdminOnly);
        typeof(LicenceController).GetCustomAttribute<RouteAttribute>()!.Template
            .Should().Be("api/settings/licence");
    }

    [Theory]
    [InlineData(nameof(LicenceController.Put))]
    [InlineData(nameof(LicenceController.Inspect))]
    public void TheUploadRoutes_TakeOnlyAJws_AndCapTheRequest(string action)
    {
        var method = typeof(LicenceController).GetMethod(action)!;

        method.GetCustomAttribute<ConsumesAttribute>()!.ContentTypes.Should().Equal("application/jose+json");
        IRequestSizeLimitMetadata limit = method.GetCustomAttribute<RequestSizeLimitAttribute>()!;
        limit.MaxRequestBodySize.Should().Be(20480);
        LicenceController.MaxRequestBytes.Should().Be(20480);
        LicenceController.MaxLicenceBytes.Should().Be(16384);
    }

    // ---- helpers ----

    /// <summary>Lets Everyone write to <paramref name="folder"/>: a squatter's shape, which the store refuses (design 12.3).</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void GrantEveryoneWrite(string folder)
    {
        var directory = new DirectoryInfo(folder);
        var security = directory.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Write,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        directory.SetAccessControl(security);
    }

    private LicenceController NewController(byte[]? body = null, LicenceFileStore? store = null)
    {
        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, Admin)], "Test")),
        };
        httpContext.Request.Body = new MemoryStream(body ?? []);

        return new LicenceController(_host, _host, store ?? _store, _log)
        {
            ControllerContext = new ControllerContext { HttpContext = httpContext },
        };
    }

    private static T OkBody<T>(IActionResult result) =>
        result.Should().BeOfType<OkObjectResult>().Subject.Value.Should().BeOfType<T>().Subject;

    private static int? StatusOf(IActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode,
        StatusCodeResult s => s.StatusCode,
        _ => null,
    };

    private static string Json(object? value) =>
        JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private static LicenceSnapshot Verdict(LicenceStatus status, string reason = "ok", bool worse = false) => new(
        status,
        reason,
        "lid-1",
        "standard",
        ["placeholder"],
        2,
        "Example BV",
        "REF-1",
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        null,
        null,
        42,
        ["corp.example.com"],
        "corp.example.com",
        false,
        false,
        NoticeStage.None,
        worse);

    /// <summary>The module host as the controller sees it: a status to read and a control surface.</summary>
    private sealed class FakeModuleHost : ILicenceStatusSource, IModuleHostControl
    {
        public LicenceStatusView Current { get; set; } = new(ModuleState.NotPresent, null, null, null, false, null);

        public LicenceSnapshot? InspectResult { get; set; }

        public Action? OnInspect { get; set; }

        public List<byte[]> Inspected { get; } = [];

        public int Reevaluations { get; private set; }

        public int Retries { get; private set; }

        public bool RetrySchedules { get; set; } = true;

        public void LoadWith(LicenceSnapshot verdict) =>
            Current = new LicenceStatusView(ModuleState.Loaded, null, "paid", "1.0.0+test", true, verdict);

        public Task<LicenceSnapshot?> InspectAsync(ReadOnlyMemory<byte> candidate, CancellationToken cancellationToken = default)
        {
            Inspected.Add(candidate.ToArray());
            OnInspect?.Invoke();
            return Task.FromResult(InspectResult);
        }

        public void Reevaluate() => Reevaluations++;

        public bool RequestRetry()
        {
            Retries++;
            return RetrySchedules;
        }
    }

    private sealed class RecordingLogger : ILogger<LicenceController>
    {
        public List<string> Lines { get; } = [];

        public IEnumerable<string> AuditLines => Lines.Where(l => l.StartsWith("Licence audit:", StringComparison.Ordinal));

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Add(formatter(state, exception));
    }

    /// <summary>A body that counts what the action actually read from it.</summary>
    private sealed class CountingStream(byte[] content) : MemoryStream(content)
    {
        public long BytesRead { get; private set; }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await base.ReadAsync(buffer, cancellationToken);
            BytesRead += read;
            return read;
        }
    }
}
