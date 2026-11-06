using Certus.Core.Alerts;
using Certus.Core.Data;
using Certus.Core.Modules;
using Certus.Modules;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The licence alert service over a real module host (issue #494): a notice the
/// module reports crosses the boundary copy, reaches the service through the
/// host's published view, and leaves as an alert carrying none of the module's
/// free text. Every other fixture in the repository reports NoticeStage.None, so
/// this is the first test in which a notice travels the whole way.
/// </summary>
public class LicenceAlertHostTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _services;
    private readonly Notifier _notifier = new();

    public LicenceAlertHostTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var services = new ServiceCollection();
        services.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        services.AddScoped<IAlertNotifier>(_ => _notifier);
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

    private static LicenceEvaluation Expiring(NoticeStage notice) =>
        new(LicenceStatus.Expiring, "None", LicenceAlertRulesTests.Id, "standard", ["placeholder"], 3,
            "Planted Licensee Name", "PLANTED-REF",
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 12, 2, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 31, 0, 0, 0, TimeSpan.Zero),
            6, [], null, false, false, notice, false);

    private LicenceAlertService CreateService(ILicenceStatusSource source) => new(
        _services.GetRequiredService<IServiceScopeFactory>(),
        source,
        NullLogger<LicenceAlertService>.Instance);

    [Fact]
    public async Task ANoticeTheModuleReports_ArrivesAsOneAlert_WithNoneOfTheModulesText()
    {
        using var fixture = new HostFixture(new ScriptedModule(Expiring(NoticeStage.Days7)));
        fixture.Store.Save("a-licence"u8.ToArray());
        await fixture.StartAsync();

        (await fixture.WaitForAsync(() => fixture.Host.Current.Licence is { Notice: NoticeStage.Days7 }))
            .Should().BeTrue("the module's verdict should be published");

        var service = CreateService(fixture.Host);
        await service.CheckAsync();
        await service.CheckAsync();

        var alert = _notifier.Alerts.Should().ContainSingle().Which;
        alert.Should().Be(new LicenceAlert(
            LicenceAlertKind.Expiring,
            LicenceAlertStages.Days7,
            LicenceAlertRulesTests.Id,
            "standard",
            new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 31, 0, 0, 0, TimeSpan.Zero),
            6));
        alert.ToString().Should().NotContain("Planted").And.NotContain("PLANTED");

        using var scope = _services.CreateScope();
        (await scope.ServiceProvider.GetRequiredService<CertusDbContext>().LicenceAlertsSent.CountAsync())
            .Should().Be(1);
    }

    [Fact]
    public async Task AModuleThatFailed_SendsNothing()
    {
        using var fixture = new HostFixture(new ThrowingEvaluatorModule());
        fixture.Store.Save("a-licence"u8.ToArray());
        await fixture.StartAsync();

        (await fixture.WaitForStateAsync(ModuleState.Failed))
            .Should().BeTrue("a module whose evaluation throws is set aside");

        await CreateService(fixture.Host).CheckAsync();

        _notifier.Alerts.Should().BeEmpty();
    }

    private sealed class Notifier : IAlertNotifier
    {
        public string Channel => "webhook";
        public bool IsEnabled => true;
        public List<LicenceAlert> Alerts { get; } = [];

        public Task<AlertNotificationResult> SendLicenceAlertAsync(
            LicenceAlert alert, CancellationToken cancellationToken = default)
        {
            Alerts.Add(alert);
            return Task.FromResult(new AlertNotificationResult(true));
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
}
