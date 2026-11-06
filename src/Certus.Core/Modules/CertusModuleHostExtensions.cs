using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Modules;

/// <summary>
/// Wires the module host into a host's services (licence design section 6.1). Both the service and
/// the web host call this once, before Build, with the data directory they already resolved. It
/// registers the host as a singleton and a hosted service, the licence store, the load journal, and
/// the read and control surfaces the licence controller and the banner use. The host's constructor
/// takes only core and framework types, and its StartAsync returns at once, so no module file is
/// opened before the application has started.
/// </summary>
public static class CertusModuleHostExtensions
{
    public static IServiceCollection AddCertusModuleHost(this IServiceCollection services, string dataDirectory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IModuleActivator, DefaultModuleActivator>();
        services.TryAddSingleton(new ModuleHostOptions(dataDirectory));
        services.TryAddSingleton(new LicenceFileStore(System.IO.Path.Combine(dataDirectory, "licence")));
        services.TryAddSingleton(sp => new ModuleJournal(
            System.IO.Path.Combine(dataDirectory, "modules"),
            sp.GetRequiredService<ILogger<ModuleJournal>>()));
        services.TryAddSingleton<ModuleHost>();
        services.TryAddSingleton<ILicenceStatusSource>(sp => sp.GetRequiredService<ModuleHost>());
        services.TryAddSingleton<IModuleHostControl>(sp => sp.GetRequiredService<ModuleHost>());
        services.AddHostedService(sp => sp.GetRequiredService<ModuleHost>());

        return services;
    }
}
