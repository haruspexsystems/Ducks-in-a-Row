using Certus.Core.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Adcs;

/// <summary>
/// Puts <see cref="MonitorModeAdcsClient"/> in front of whichever CA client a host
/// registered (issue #470). Both hosts call it once, after their CA client branch, so the
/// mock, the real COM client and the unconfigured one are all covered by the same line.
/// </summary>
public static class MonitorModeServiceCollectionExtensions
{
    /// <summary>
    /// In monitor mode, wraps every registered <see cref="IAdcsClient"/> and
    /// <see cref="IAdcsClientFactory"/>, keeping each registration's lifetime. In full mode
    /// it changes nothing.
    ///
    /// Call it after the CA client registrations. It throws when it finds nothing to wrap,
    /// because a call placed above them would otherwise guard nothing and say nothing.
    /// </summary>
    public static IServiceCollection AddMonitorModeCaWriteGuard(
        this IServiceCollection services, CertusInstanceMode instanceMode)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(instanceMode);

        if (!instanceMode.IsMonitor)
            return services;

        Decorate<IAdcsClient>(services, (inner, sp) =>
            new MonitorModeAdcsClient(inner, sp.GetRequiredService<ILogger<MonitorModeAdcsClient>>()));
        Decorate<IAdcsClientFactory>(services, (inner, sp) =>
            new MonitorModeAdcsClientFactory(inner, sp.GetRequiredService<ILogger<MonitorModeAdcsClient>>()));

        return services;
    }

    private static void Decorate<TService>(
        IServiceCollection services, Func<TService, IServiceProvider, TService> wrap)
        where TService : class
    {
        var wrapped = 0;
        for (var i = 0; i < services.Count; i++)
        {
            var descriptor = services[i];
            if (descriptor.ServiceType != typeof(TService) || descriptor.IsKeyedService)
                continue;

            services[i] = ServiceDescriptor.Describe(
                typeof(TService),
                sp => wrap((TService)CreateInner(descriptor, sp), sp),
                descriptor.Lifetime);
            wrapped++;
        }

        if (wrapped == 0)
        {
            throw new InvalidOperationException(
                $"Monitor mode found no {typeof(TService).Name} registration to guard. " +
                $"{nameof(AddMonitorModeCaWriteGuard)} must be called after the CA client is registered.");
        }
    }

    private static object CreateInner(ServiceDescriptor descriptor, IServiceProvider services)
    {
        if (descriptor.ImplementationInstance is { } instance)
            return instance;
        if (descriptor.ImplementationFactory is { } factory)
            return factory(services);
        return ActivatorUtilities.CreateInstance(services, descriptor.ImplementationType!);
    }
}
