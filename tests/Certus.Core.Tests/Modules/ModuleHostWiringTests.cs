using Certus.Core.Modules;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// AddCertusModuleHost is the one line each host calls (licence design section 6.1). It registers
/// the host once, and the read and control surfaces resolve to that same instance.
/// </summary>
public class ModuleHostWiringTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-wiring-{Guid.NewGuid():N}");

    public ModuleHostWiringTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private ServiceProvider Build()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment());
        services.AddSingleton<IHostApplicationLifetime>(new FakeHostApplicationLifetime());
        services.AddSingleton<Certus.Core.Setup.IServiceRestarter>(new FakeServiceRestarter());
        services.AddCertusModuleHost(_root);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void TheReadAndControlSurfaces_AreTheSameHostInstance()
    {
        using var provider = Build();

        var host = provider.GetRequiredService<ModuleHost>();
        provider.GetRequiredService<ILicenceStatusSource>().Should().BeSameAs(host);
        provider.GetRequiredService<IModuleHostControl>().Should().BeSameAs(host);
    }

    [Fact]
    public void TheHostIsRegisteredAsExactlyOneHostedService()
    {
        using var provider = Build();

        provider.GetServices<IHostedService>().OfType<ModuleHost>().Should().ContainSingle();
    }

    [Fact]
    public void BeforeTheHostStarts_TheStatusIsNotPresent()
    {
        using var provider = Build();

        provider.GetRequiredService<ILicenceStatusSource>().Current.ModuleState.Should().Be(ModuleState.NotPresent);
    }
}
