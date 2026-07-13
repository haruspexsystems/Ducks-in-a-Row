using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Adcs;

/// <summary>
/// Extension methods for registering ADCS services in DI.
/// Used by the Certus.Service project (the production host).
/// </summary>
public static class AdcsServiceExtensions
{
    /// <summary>
    /// Registers the real ADCS COM interop client as IAdcsClient.
    /// The CA connection string is read from CertusOptions.
    /// </summary>
    public static IServiceCollection AddAdcsClient(this IServiceCollection services)
    {
        services.AddSingleton<IAdcsClient>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<CertusOptions>>().Value;
            var logger = sp.GetRequiredService<ILogger<AdcsClient>>();

            if (string.IsNullOrEmpty(options.CaConnectionString))
            {
                throw new InvalidOperationException(
                    "CaConnectionString is not configured. " +
                    "Set Certus:CaConnectionString in appsettings.json to \"CAHostName\\CAName\".");
            }

            return new AdcsClient(options.CaConnectionString, logger);
        });

        return services;
    }

    /// <summary>
    /// Registers the mock ADCS client as IAdcsClient.
    /// Used for development and testing without a real CA. Only selected when
    /// Certus:UseMockCa is explicitly true; an empty CA connection string no
    /// longer falls back to the mock.
    /// </summary>
    public static IServiceCollection AddMockAdcsClient(this IServiceCollection services)
    {
        services.AddSingleton<IAdcsClient>(new MockAdcsClient());
        return services;
    }

    /// <summary>
    /// Registers the unconfigured ADCS client as IAdcsClient. Bound when no CA
    /// connection string is set and the mock was not explicitly requested:
    /// every CA operation surfaces as 503 ca-unavailable until the setup
    /// wizard connects a CA.
    /// </summary>
    public static IServiceCollection AddUnconfiguredAdcsClient(this IServiceCollection services)
    {
        services.AddSingleton<IAdcsClient>(new UnconfiguredAdcsClient());
        return services;
    }
}
