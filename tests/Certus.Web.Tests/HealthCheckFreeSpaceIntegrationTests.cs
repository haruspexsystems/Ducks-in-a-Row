using System.Net;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// The readiness endpoint reports degraded when the data folder's volume is
/// below the free space threshold (issue #632). The threshold is set far above
/// any disk, so the real probe on the dev box's temp volume reads as low; the
/// shared factory runs at the default and stays healthy.
/// </summary>
[Trait("Category", "Integration")]
public class HealthCheckFreeSpaceIntegrationTests
{
    [Fact]
    public async Task HealthEndpoint_VolumeBelowTheThreshold_ReportsDegraded()
    {
        using var factory = new LowDiskFactory();
        var client = factory.CreateClient();

        var response = await client.GetAsync("/health");

        // The default health writer answers 200 for Degraded and writes the status.
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Contain("Degraded");
    }

    [Fact]
    public async Task HealthEndpoint_ThresholdOff_ReportsHealthy()
    {
        using var factory = new LowDiskFactory(thresholdMegabytes: "0");
        var client = factory.CreateClient();

        var response = await client.GetAsync("/health");

        (await response.Content.ReadAsStringAsync()).Should().Contain("Healthy");
    }

    private sealed class LowDiskFactory : CertusWebApplicationFactory
    {
        private readonly string _thresholdMegabytes;

        // Nine petabytes: no volume this suite will ever run on has that free.
        public LowDiskFactory(string thresholdMegabytes = "9000000000")
        {
            _thresholdMegabytes = thresholdMegabytes;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting("Certus:FreeSpaceWarningMegabytes", _thresholdMegabytes);
        }
    }
}
