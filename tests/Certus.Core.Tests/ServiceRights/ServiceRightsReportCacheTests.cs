using Certus.Core.ServiceRights;

namespace Certus.Core.Tests.ServiceRights;

/// <summary>
/// The Settings page's kept report, issue #440: served while fresh, rerun when
/// asked, never served for a different configuration.
/// </summary>
public class ServiceRightsReportCacheTests
{
    private static ServiceRightsReport Report(string ca) => new(
        ca,
        new ServiceRightsIdentity("x", false, null, null, null, 0),
        [],
        Simulated: true,
        DateTimeOffset.UtcNow);

    [Fact]
    public async Task AFreshReport_IsServedWithoutRunningAgain()
    {
        var cache = new ServiceRightsReportCache(TimeSpan.FromMinutes(10));
        var runs = 0;
        Task<ServiceRightsReport> Run(CancellationToken _) { runs++; return Task.FromResult(Report("a")); }

        await cache.GetOrRunAsync("a", Run, force: false, CancellationToken.None);
        await cache.GetOrRunAsync("a", Run, force: false, CancellationToken.None);

        runs.Should().Be(1);
    }

    [Fact]
    public async Task Forcing_AlwaysRuns()
    {
        var cache = new ServiceRightsReportCache(TimeSpan.FromMinutes(10));
        var runs = 0;
        Task<ServiceRightsReport> Run(CancellationToken _) { runs++; return Task.FromResult(Report("a")); }

        await cache.GetOrRunAsync("a", Run, force: false, CancellationToken.None);
        await cache.GetOrRunAsync("a", Run, force: true, CancellationToken.None);

        runs.Should().Be(2);
    }

    [Fact]
    public async Task AReportForAnotherConfiguration_IsNeverServed()
    {
        var cache = new ServiceRightsReportCache(TimeSpan.FromMinutes(10));

        await cache.GetOrRunAsync("a", _ => Task.FromResult(Report("a")), force: false, CancellationToken.None);
        var second = await cache.GetOrRunAsync("b", _ => Task.FromResult(Report("b")), force: false, CancellationToken.None);

        second.CaConnectionString.Should().Be("b");
    }

    [Fact]
    public async Task AnAgedReport_IsRunAgain()
    {
        var cache = new ServiceRightsReportCache(TimeSpan.Zero);
        var runs = 0;
        Task<ServiceRightsReport> Run(CancellationToken _) { runs++; return Task.FromResult(Report("a")); }

        await cache.GetOrRunAsync("a", Run, force: false, CancellationToken.None);
        await cache.GetOrRunAsync("a", Run, force: false, CancellationToken.None);

        runs.Should().Be(2);
    }
}
