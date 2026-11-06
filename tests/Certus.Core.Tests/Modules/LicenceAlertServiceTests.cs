using Certus.Core.Alerts;
using Certus.Core.Data;
using Certus.Core.Modules;
using Certus.Modules;
using Certus.Tests.Shared;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The licence alert service end to end on a real database (issue #494): each
/// (licence id, stage) goes once to every enabled channel, a renewal starts
/// again, a broken channel stops nothing, and nothing is recorded while there is
/// no channel to send to.
/// </summary>
public class LicenceAlertServiceTests : IDisposable
{
    private const string OtherId = "0192a3b4-c5d6-7e8f-9a0b-ffffffffffff";

    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _services;
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 12, 24, 9, 0, 0, TimeSpan.Zero));
    private readonly RecordingNotifier _email = new("email");
    private readonly RecordingNotifier _webhook = new("webhook");
    private readonly FakeLicenceSource _source = new();
    private readonly RecordingLogger _log = new();

    public LicenceAlertServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        services.AddScoped<IAlertNotifier>(_ => _email);
        services.AddScoped<IAlertNotifier>(_ => _webhook);
        _services = services.BuildServiceProvider();

        using var scope = _services.CreateScope();
        scope.ServiceProvider.GetRequiredService<CertusDbContext>().Database.EnsureCreated();
    }

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    private LicenceAlertService CreateService(IServiceProvider? services = null) => new(
        (services ?? _services).GetRequiredService<IServiceScopeFactory>(),
        _source,
        _log,
        _clock);

    private CertusDbContext OpenDb() =>
        _services.CreateScope().ServiceProvider.GetRequiredService<CertusDbContext>();

    private void Report(
        LicenceStatus status,
        NoticeStage notice,
        string licenceId = LicenceAlertRulesTests.Id,
        ModuleState state = ModuleState.Loaded) =>
        _source.Current = new LicenceStatusView(state, null, "paid", "1.0.0+test", true,
            LicenceAlertRulesTests.Snapshot(status, notice, licenceId: licenceId));

    [Fact]
    public async Task ADueStage_GoesOnceToEveryEnabledChannel_AndIsRecordedOnce()
    {
        Report(LicenceStatus.Expiring, NoticeStage.Days7);

        await CreateService().CheckAsync();

        _email.Alerts.Should().ContainSingle();
        _webhook.Alerts.Should().ContainSingle().Which.Should().Be(_email.Alerts[0]);
        _email.Alerts[0].Kind.Should().Be(LicenceAlertKind.Expiring);
        _email.Alerts[0].Stage.Should().Be(LicenceAlertStages.Days7);

        var row = (await OpenDb().LicenceAlertsSent.ToListAsync()).Should().ContainSingle().Which;
        row.LicenceId.Should().Be(LicenceAlertRulesTests.Id);
        row.Stage.Should().Be(LicenceAlertStages.Days7);
        row.Channels.Should().Be("email,webhook");
        row.Success.Should().BeTrue();
        row.SentAt.Should().Be(_clock.GetUtcNow().UtcDateTime);
    }

    [Fact]
    public async Task ADisabledChannel_IsNeitherCalled_NorListed()
    {
        _webhook.Enabled = false;
        Report(LicenceStatus.Expiring, NoticeStage.Days7);

        await CreateService().CheckAsync();

        _email.Alerts.Should().ContainSingle();
        _webhook.Alerts.Should().BeEmpty();
        (await OpenDb().LicenceAlertsSent.SingleAsync()).Channels.Should().Be("email");
    }

    [Fact]
    public async Task TheSameStage_IsNotSentAgain_OnTheNextPass_OrAfterARestart()
    {
        Report(LicenceStatus.Expiring, NoticeStage.Days7);
        var service = CreateService();

        await service.CheckAsync();
        await service.CheckAsync();
        await CreateService().CheckAsync(); // a restart: a new instance over the same database

        _email.Alerts.Should().ContainSingle();
        (await OpenDb().LicenceAlertsSent.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task TheNextStage_OfTheSameLicence_IsSent()
    {
        var service = CreateService();

        Report(LicenceStatus.Expiring, NoticeStage.Days7);
        await service.CheckAsync();
        Report(LicenceStatus.Expiring, NoticeStage.Days1);
        await service.CheckAsync();

        _email.Alerts.Select(a => a.Stage).Should().Equal(LicenceAlertStages.Days7, LicenceAlertStages.Days1);
        (await OpenDb().LicenceAlertsSent.CountAsync()).Should().Be(2);
    }

    [Fact]
    public async Task ARenewedLicence_StartsAgain_AndRestoringTheEarlierOne_RepeatsNothing()
    {
        var service = CreateService();

        Report(LicenceStatus.Expiring, NoticeStage.Days7);
        await service.CheckAsync();
        Report(LicenceStatus.Expiring, NoticeStage.Days7, licenceId: OtherId); // renewed: a new id
        await service.CheckAsync();
        Report(LicenceStatus.Expiring, NoticeStage.Days7); // the earlier licence restored
        await service.CheckAsync();
        await CreateService().CheckAsync();

        _email.Alerts.Select(a => a.LicenceId).Should().Equal(LicenceAlertRulesTests.Id, OtherId);
    }

    [Fact]
    public async Task AChannelThatThrows_StopsNeitherTheOthers_NorThePass()
    {
        _email.Throw = new InvalidOperationException("relay exploded");
        Report(LicenceStatus.Grace, NoticeStage.Expired);

        var pass = () => CreateService().CheckAsync();

        await pass.Should().NotThrowAsync();
        _webhook.Alerts.Should().ContainSingle().Which.Kind.Should().Be(LicenceAlertKind.Grace);
        var row = await OpenDb().LicenceAlertsSent.SingleAsync();
        row.Success.Should().BeFalse();
        row.Channels.Should().Be("email,webhook");
        _log.Warnings.Should().Contain(w => w.Contains("email") && w.Contains("threw"));
    }

    [Fact]
    public async Task AFailedDelivery_IsRecorded_AndNotRetried()
    {
        // Sean's decision of 2026-10-14, the stance the CRL alerts take: a warning
        // that repeats every pass while a relay is down is worse than one missed
        // once, and the next stage follows.
        _email.Result = new AlertNotificationResult(false, "relay down");
        _webhook.Result = new AlertNotificationResult(false, "receiver down");
        Report(LicenceStatus.Expiring, NoticeStage.Days7);

        await CreateService().CheckAsync();
        await CreateService().CheckAsync();

        _email.Alerts.Should().ContainSingle();
        (await OpenDb().LicenceAlertsSent.SingleAsync()).Success.Should().BeFalse();
        _log.Warnings.Should().Contain(w => w.Contains("relay down"));
        _log.Warnings.Should().Contain(w => w.Contains("did not reach every channel"),
            "a delivery that failed must not be logged as sent");
        _log.Informations.Should().NotContain(w => w.Contains("alert sent"));
    }

    [Fact]
    public async Task ATierThatIsNotATierName_IsReportedForEachLicence()
    {
        var service = CreateService();

        _source.Current = new LicenceStatusView(ModuleState.Loaded, null, "paid", "1.0.0+test", true,
            LicenceAlertRulesTests.Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, tier: "Gold!"));
        await service.CheckAsync();
        await service.CheckAsync();
        _source.Current = new LicenceStatusView(ModuleState.Loaded, null, "paid", "1.0.0+test", true,
            LicenceAlertRulesTests.Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, licenceId: OtherId, tier: "Gold!"));
        await service.CheckAsync();

        _log.Warnings.Count(w => w.Contains("not a tier name")).Should().Be(2,
            "one report per licence, not one per process");
    }

    [Fact]
    public async Task WithNoChannel_NothingIsRecorded_SoAChannelAddedLaterStillGetsTheStage()
    {
        _email.Enabled = false;
        _webhook.Enabled = false;
        Report(LicenceStatus.Expiring, NoticeStage.Days14);
        var service = CreateService();

        await service.CheckAsync();
        (await OpenDb().LicenceAlertsSent.CountAsync()).Should().Be(0);

        _email.Enabled = true;
        await service.CheckAsync();

        _email.Alerts.Should().ContainSingle().Which.Stage.Should().Be(LicenceAlertStages.Days14);
        (await OpenDb().LicenceAlertsSent.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task AModuleThatStoppedAnswering_SendsNothingFromItsLastVerdict()
    {
        Report(LicenceStatus.Expiring, NoticeStage.Days7, state: ModuleState.Unresponsive);

        await CreateService().CheckAsync();

        _email.Alerts.Should().BeEmpty();
        (await OpenDb().LicenceAlertsSent.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task ALicenceBoundToAnotherForest_SendsNoExpiryWarning()
    {
        Report(LicenceStatus.BindingMismatch, NoticeStage.Days7);

        await CreateService().CheckAsync();

        _email.Alerts.Should().BeEmpty();
    }

    [Fact]
    public async Task ATrialEnding_SendsTheLapsedAlert()
    {
        Report(LicenceStatus.Lapsed, NoticeStage.Expired);

        await CreateService().CheckAsync();

        var alert = _email.Alerts.Should().ContainSingle().Which;
        alert.Kind.Should().Be(LicenceAlertKind.Lapsed);
        alert.Stage.Should().Be(LicenceAlertStages.Expired);
    }

    [Fact]
    public async Task AValueThisReleaseDoesNotKnow_IsLoggedOnce_NotOnEveryPass()
    {
        _source.Current = new LicenceStatusView(ModuleState.Loaded, null, "paid", "1.0.0+test", true,
            LicenceAlertRulesTests.Snapshot(LicenceStatus.Expiring, (NoticeStage)42));
        var service = CreateService();

        await service.CheckAsync();
        await service.CheckAsync();
        await service.CheckAsync();

        _email.Alerts.Should().BeEmpty();
        _log.Warnings.Should().ContainSingle().Which.Should().Contain("(42)");

        _source.Current = new LicenceStatusView(ModuleState.Loaded, null, "paid", "1.0.0+test", true,
            LicenceAlertRulesTests.Snapshot((LicenceStatus)99, NoticeStage.Days7));
        await service.CheckAsync();

        _log.Warnings.Should().HaveCount(2, "a different unknown value is a different problem");
    }

    [Fact]
    public async Task ALicenceIdThatIsNotCanonical_SendsNothing_AndIsNotWrittenToTheLog()
    {
        const string planted = "PLANTED-LICENCE-ID";
        _source.Current = new LicenceStatusView(ModuleState.Loaded, null, "paid", "1.0.0+test", true,
            LicenceAlertRulesTests.Snapshot(LicenceStatus.Expiring, NoticeStage.Days7, licenceId: planted));
        var service = CreateService();

        await service.CheckAsync();
        await service.CheckAsync();

        _email.Alerts.Should().BeEmpty();
        _log.Warnings.Should().ContainSingle().Which.Should().NotContain(planted);
    }

    [Fact]
    public async Task AQuietPass_NeverTouchesTheDatabase()
    {
        // No database is registered here at all, so a pass that reached for one
        // would throw. A pass with nothing due must cost an in-memory read only.
        var bare = new ServiceCollection();
        bare.AddScoped<IAlertNotifier>(_ => _email);
        using var provider = bare.BuildServiceProvider();
        Report(LicenceStatus.Valid, NoticeStage.None);

        var pass = () => CreateService(provider).CheckAsync();

        await pass.Should().NotThrowAsync();
    }

    [Fact]
    public async Task StoppingWhileAChannelIsSending_RecordsNothing_SoTheStageIsNotLost()
    {
        using var stopping = new CancellationTokenSource();
        _email.OnSend = () =>
        {
            stopping.Cancel();
            stopping.Token.ThrowIfCancellationRequested();
        };
        Report(LicenceStatus.Expiring, NoticeStage.Days7);

        var pass = () => CreateService().CheckAsync(stopping.Token);

        await pass.Should().ThrowAsync<OperationCanceledException>();
        (await OpenDb().LicenceAlertsSent.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task TheLoop_KeepsGoingAfterAFailedPass_AndStopsWhenAsked()
    {
        // Real milliseconds through the seams, not a fake clock: a fake clock turns
        // a broken loop into a hung run (CLAUDE.md, test timing). Every wait is
        // bounded by PoolAwareWait, so a regression reports rather than hangs.
        var source = new CountingSource(throwOnFirstRead: true, signalAfter: 3);
        var service = new LicenceAlertService(
            _services.GetRequiredService<IServiceScopeFactory>(), source, _log, TimeProvider.System)
        {
            StartupDelay = TimeSpan.FromMilliseconds(1),
            Interval = TimeSpan.FromMilliseconds(20),
        };

        await service.StartAsync(CancellationToken.None);
        await PoolAwareWait.Bounded(source.Reached.Task, "three passes of the licence alert loop");
        await PoolAwareWait.Bounded(Completed(service.StopAsync(CancellationToken.None)), "the loop to stop");

        _log.Errors.Should().ContainSingle("the first pass threw and the loop logged it and went on");
    }

    private static async Task<bool> Completed(Task task)
    {
        await task;
        return true;
    }

    private sealed class RecordingNotifier(string channel) : IAlertNotifier
    {
        public string Channel => channel;
        public bool Enabled { get; set; } = true;
        public bool IsEnabled => Enabled;
        public AlertNotificationResult Result { get; set; } = new(true);
        public Exception? Throw { get; set; }
        public Action? OnSend { get; set; }
        public List<LicenceAlert> Alerts { get; } = [];

        public Task<AlertNotificationResult> SendLicenceAlertAsync(
            LicenceAlert alert, CancellationToken cancellationToken = default)
        {
            Alerts.Add(alert);
            OnSend?.Invoke();
            if (Throw is not null)
                throw Throw;
            return Task.FromResult(Result);
        }

        public Task<AlertNotificationResult> SendExpiryAlertAsync(
            ExpiryAlertBatch batch, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AlertNotificationResult> SendServerCertificateAlertAsync(
            ServerCertificateAlert alert, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AlertNotificationResult> SendCrlAlertAsync(
            CrlAlert alert, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AlertNotificationResult> SendTestAlertAsync(
            TestAlert alert, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class FakeLicenceSource : ILicenceStatusSource
    {
        public LicenceStatusView Current { get; set; } =
            new(ModuleState.NotPresent, null, null, null, false, null);
    }

    /// <summary>A status source that counts its reads, throws on the first, and signals after a number of them.</summary>
    private sealed class CountingSource(bool throwOnFirstRead, int signalAfter) : ILicenceStatusSource
    {
        private int _reads;

        public TaskCompletionSource<bool> Reached { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public LicenceStatusView Current
        {
            get
            {
                var reads = Interlocked.Increment(ref _reads);
                if (reads >= signalAfter)
                    Reached.TrySetResult(true);
                if (throwOnFirstRead && reads == 1)
                    throw new InvalidOperationException("the first read fails");
                return new LicenceStatusView(ModuleState.NotPresent, null, null, null, false, null);
            }
        }
    }

    private sealed class RecordingLogger : ILogger<LicenceAlertService>
    {
        private readonly object _lock = new();

        public List<string> Informations { get; } = [];
        public List<string> Warnings { get; } = [];
        public List<string> Errors { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (_lock)
            {
                if (logLevel == LogLevel.Information)
                    Informations.Add(formatter(state, exception));
                else if (logLevel == LogLevel.Warning)
                    Warnings.Add(formatter(state, exception));
                else if (logLevel >= LogLevel.Error)
                    Errors.Add(formatter(state, exception));
            }
        }
    }
}
