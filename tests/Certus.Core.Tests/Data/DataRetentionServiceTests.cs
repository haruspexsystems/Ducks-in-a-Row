using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Data.Retention;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Tests.Data;

/// <summary>
/// The hosted side of the retention rule (issue #637): AddDataRetention wires a
/// pass that really runs the job on a fresh scope, and a host with every period
/// at 0 starts and finishes the service without touching the database. Neither
/// test waits on the clock, so neither needs a bounded wait.
/// </summary>
public class DataRetentionServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;

    public DataRetentionServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = new CertusDbContext(Options());
        db.Database.EnsureCreated();
    }

    public void Dispose()
    {
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task RunOnce_RunsTheJobOnAFreshScope_WithTheBoundPeriods()
    {
        using var provider = BuildProvider(new Dictionary<string, string?>
        {
            ["Certus:Retention:FinishedOrderDays"] = "30",
        });
        await using (var db = new CertusDbContext(Options()))
        {
            var account = new AcmeAccount
            {
                AccountId = "retention-host-account",
                JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
                JwkThumbprint = "retention-host-thumbprint",
            };
            db.AcmeAccounts.Add(account);
            db.AcmeOrders.Add(new AcmeOrder
            {
                OrderId = "retention-host-order",
                Account = account,
                Status = "invalid",
                TemplateId = "WebServer",
                CreatedAt = DateTime.UtcNow.AddDays(-45),
                ExpiresAt = DateTime.UtcNow.AddDays(-38),
            });
            await db.SaveChangesAsync();
        }

        var service = provider.GetServices<IHostedService>().OfType<DataRetentionService>().Single();
        var report = await service.RunOnceAsync();

        report.InvalidOrdersRemoved.Should().Be(1, "38 days past expiry is over the bound 30 day period");
        await using var verify = new CertusDbContext(Options());
        (await verify.AcmeOrders.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task Execute_WithEveryPeriodAtZero_FinishesAtOnce()
    {
        using var provider = BuildProvider(new Dictionary<string, string?>
        {
            ["Certus:Retention:FinishedOrderDays"] = "0",
            ["Certus:Retention:DeactivatedAccountDays"] = "0",
            ["Certus:Retention:AlertHistoryDays"] = "0",
            ["Certus:Retention:AuditTrailDays"] = "0",
        });
        var service = provider.GetServices<IHostedService>().OfType<DataRetentionService>().Single();

        await service.StartAsync(CancellationToken.None);

        // ExecuteAsync returns before its first delay when everything is off.
        // BackgroundService may still hand the body to the pool, so the task
        // is awaited with a real clock bound rather than inspected at once: a
        // regression that reached the daily timer would wait five minutes on
        // the system clock, and the bound turns that into a failure in ten
        // seconds instead of a hang.
        service.ExecuteTask.Should().NotBeNull();
        var finished = await Task.WhenAny(service.ExecuteTask!, Task.Delay(TimeSpan.FromSeconds(10)));
        finished.Should().BeSameAs(service.ExecuteTask,
            "a host with every class turned off must not keep a daily timer alive");
        service.ExecuteTask!.IsCompletedSuccessfully.Should().BeTrue();
        await service.StopAsync(CancellationToken.None);
    }

    private DbContextOptions<CertusDbContext> Options() =>
        new DbContextOptionsBuilder<CertusDbContext>().UseSqlite(_connection).Options;

    private ServiceProvider BuildProvider(Dictionary<string, string?> settings)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.None));
        services.AddDbContext<CertusDbContext>(o => o.UseSqlite(_connection));
        services.AddDataRetention(configuration);
        return services.BuildServiceProvider();
    }
}
