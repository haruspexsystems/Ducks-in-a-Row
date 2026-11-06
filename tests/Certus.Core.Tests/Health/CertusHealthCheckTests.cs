using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Health;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
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

    /// <summary>
    /// A monitor whose probe answers a fixed number, so the dev box's real disk
    /// never decides a test. Null stands for a volume that cannot be read.
    /// </summary>
    internal static DataFolderFreeSpaceMonitor FreeSpace(long? freeBytes = 50L * 1024 * 1024 * 1024, long thresholdMegabytes = 1024) =>
        new(Path.GetTempPath(),
            Options.Create(new CertusOptions { FreeSpaceWarningMegabytes = thresholdMegabytes }),
            NullLogger<DataFolderFreeSpaceMonitor>.Instance,
            probe: _ => freeBytes);

    private CertusHealthCheck CreateCheck(CaHealthCache? caHealthCache = null, DataFolderFreeSpaceMonitor? freeSpace = null)
    {
        return new CertusHealthCheck(
            _db, _mockClient, caHealthCache ?? new CaHealthCache(), freeSpace ?? FreeSpace(),
            NullLogger<CertusHealthCheck>.Instance);
    }

    [Fact]
    public async Task CheckHealth_DataFolderVolumeLow_ReturnsDegradedWithTheReason()
    {
        var check = CreateCheck(freeSpace: FreeSpace(freeBytes: 100L * 1024 * 1024, thresholdMegabytes: 1024));

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Be("Free space on the data folder's volume is low");
        result.Data["dataFolderFreeSpace"].Should().Be("100 MB free, below the 1024 MB warning threshold");
    }

    [Fact]
    public async Task CheckHealth_DataFolderVolumeFine_ReportsTheNumberAndStaysHealthy()
    {
        var check = CreateCheck(freeSpace: FreeSpace(freeBytes: 2048L * 1024 * 1024, thresholdMegabytes: 1024));

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Data["dataFolderFreeSpace"].Should().Be("2048 MB free");
    }

    [Fact]
    public async Task CheckHealth_DataFolderVolumeUnreadable_IsNotDegraded()
    {
        // A failed read says nothing about the disk; degrading on it would send
        // an operator looking for space that is there.
        var check = CreateCheck(freeSpace: FreeSpace(freeBytes: null));

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Data["dataFolderFreeSpace"].Should().Be("unknown");
    }

    [Fact]
    public async Task CheckHealth_CaDownAndVolumeLow_TheCaReasonWins_AndTheDiskIsStillInTheData()
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns(new CaInfo("TestCA", "ca.test.com", null, false));
        var check = CreateCheck(freeSpace: FreeSpace(freeBytes: 0, thresholdMegabytes: 1024));

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Be("CA is not accessible");
        result.Data["dataFolderFreeSpace"].Should().BeOfType<string>().Which.Should().Contain("below");
    }

    [Fact]
    public async Task CheckHealth_DatabaseDownAndVolumeLow_IsUnhealthy()
    {
        _db.Dispose();
        var check = CreateCheck(freeSpace: FreeSpace(freeBytes: 0));

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        result.Status.Should().Be(HealthStatus.Unhealthy);
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
    public async Task CheckHealth_CaUnavailableThrown_ReadsExactlyAsNotAccessible()
    {
        // Issue #440: GetCaInfoAsync throws this for an unreachable CA rather
        // than answering "not accessible", and so does the unconfigured client.
        // The health endpoint must read exactly as it did before, with no error
        // text and no warning every probe.
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns<CaInfo>(_ => throw new CaUnavailableException("unreachable"));

        var check = CreateCheck();

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Be("CA is not accessible");
        result.Data["ca"].Should().Be("not accessible");
    }

    [Fact]
    public async Task CheckHealth_CaRefusesTheAccount_IsDegradedWithTheReason_AndNoWarning()
    {
        _mockClient.GetCaInfoAsync(Arg.Any<CancellationToken>())
            .Returns<CaInfo>(_ => throw new CaAccessDeniedException(
                CaAccessDeniedException.ConnectPermissionMessage, new UnauthorizedAccessException()));
        var logger = Substitute.For<ILogger<CertusHealthCheck>>();

        var check = new CertusHealthCheck(_db, _mockClient, new CaHealthCache(), FreeSpace(), logger);

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Data["ca"].Should().BeOfType<string>().Which.Should().Contain("Request Certificates");
        // AdcsClient has logged the refusal at Error; a warning here on every
        // 30 second probe would only repeat it.
        logger.ReceivedCalls()
            .Where(call => call.GetMethodInfo().Name == nameof(ILogger.Log)
                           && call.GetArguments()[0] is LogLevel.Warning)
            .Should().BeEmpty();
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
