using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Health;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Certus.Core.Tests.Health;

public class CertusHealthCheckTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly IAdcsClient _mockClient;

    public CertusHealthCheckTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _mockClient = Substitute.For<IAdcsClient>();
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns(new CaInfo("TestCA", "ca.test.com", "Test CA", true));
    }

    private CertusHealthCheck CreateCheck(CaHealthCache? caHealthCache = null)
    {
        return new CertusHealthCheck(
            _db, _mockClient, caHealthCache ?? new CaHealthCache(), NullLogger<CertusHealthCheck>.Instance);
    }

    [Fact]
    public async Task CheckHealth_AllOk_ReturnsHealthy()
    {
        var check = CreateCheck();
        var context = new HealthCheckContext();

        var result = await check.CheckHealthAsync(context);

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Data.Should().ContainKey("database");
        result.Data.Should().ContainKey("ca");
    }

    [Fact]
    public async Task CheckHealth_CaNotAccessible_ReturnsDegraded()
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns(new CaInfo("TestCA", "ca.test.com", null, false));

        var check = CreateCheck();
        var context = new HealthCheckContext();

        var result = await check.CheckHealthAsync(context);

        result.Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public async Task CheckHealth_CaThrows_ReturnsDegraded()
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns<CaInfo>(_ => throw new InvalidOperationException("DCOM error"));

        var check = CreateCheck();
        var context = new HealthCheckContext();

        var result = await check.CheckHealthAsync(context);

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Data["ca"].Should().BeOfType<string>().Which.Should().Contain("DCOM error");
    }

    [Fact]
    public async Task CheckHealth_HealthyPath_ReportsDatabaseConnected()
    {
        var check = CreateCheck();
        var context = new HealthCheckContext();

        var result = await check.CheckHealthAsync(context);

        result.Data["database"].Should().Be("connected");
    }

    [Fact]
    public async Task CheckHealth_DatabaseUnavailable_ReturnsUnhealthy()
    {
        // Disposing the context makes the count queries throw, simulating a DB failure.
        // The CA mock stays accessible, so only the database is down.
        _db.Dispose();
        var check = CreateCheck();
        var context = new HealthCheckContext();

        var result = await check.CheckHealthAsync(context);

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task CheckHealth_DatabaseUnavailableAndCaDown_ReturnsUnhealthy()
    {
        // Database failure must outrank CA degradation: when both are down the
        // result is Unhealthy, not Degraded.
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns(new CaInfo("TestCA", "ca.test.com", null, false));
        _db.Dispose();
        var check = CreateCheck();
        var context = new HealthCheckContext();

        var result = await check.CheckHealthAsync(context);

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task CheckHealth_Cancelled_PropagatesCancellation()
    {
        // A cancelled probe must surface as cancellation, not be swallowed and
        // reported as a database or CA failure.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns<CaInfo>(_ => throw new OperationCanceledException());

        var check = CreateCheck();
        var context = new HealthCheckContext();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => check.CheckHealthAsync(context, cts.Token));
    }

    [Fact]
    public async Task CheckHealth_RepeatedWithinTtl_ProbesCaOnce()
    {
        // A shared cache with a long window collapses repeated readiness checks into a
        // single CA probe, so the anonymous endpoint cannot hammer the CA.
        var cache = new CaHealthCache(TimeSpan.FromMinutes(5));

        await CreateCheck(cache).CheckHealthAsync(new HealthCheckContext());
        await CreateCheck(cache).CheckHealthAsync(new HealthCheckContext());

        await _mockClient.Received(1).GetCaInfoAsync(Arg.Any<CancellationToken>());
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }
}
