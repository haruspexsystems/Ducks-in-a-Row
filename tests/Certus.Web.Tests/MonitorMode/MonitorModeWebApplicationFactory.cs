using Certus.Core.Configuration;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests.MonitorMode;

/// <summary>
/// The development host in monitor mode (issue #470), through the Development only key
/// the production host never reads. Everything else is the shared factory's.
/// </summary>
public class MonitorModeWebApplicationFactory : CertusWebApplicationFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting(CertusInstanceMode.DevelopmentKey, CertusInstanceMode.MonitorValue);
    }
}

/// <summary>
/// Monitor mode with the real authorization stack (the deny by default policy and the
/// admin requirement) and the header driven test scheme, for the tests that prove the
/// administration API gate never tells a caller outside the admin group which routes
/// exist.
/// </summary>
public class MonitorModeAuthWebApplicationFactory : AuthWebApplicationFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting(CertusInstanceMode.DevelopmentKey, CertusInstanceMode.MonitorValue);
    }
}
