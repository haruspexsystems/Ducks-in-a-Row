using Certus.Core.Acme.Services;
using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Core.Data.Retention;

/// <summary>
/// Registers the retention rule and the per account erasure path (issue #637)
/// in a host. Both hosts call this once, so the two stay registered together:
/// <see cref="RetentionOptions"/> bound from <c>Certus:Retention</c>, the
/// scoped <see cref="DataRetentionJob"/> and <see cref="AccountErasureService"/>,
/// and the hosted <see cref="DataRetentionService"/> that runs the job daily.
/// </summary>
public static class DataRetentionServiceCollectionExtensions
{
    public static IServiceCollection AddDataRetention(
        this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<RetentionOptions>(configuration.GetSection(RetentionOptions.SectionName));
        services.AddScoped<DataRetentionJob>();
        services.AddScoped<AccountErasureService>();
        services.AddHostedService<DataRetentionService>();

        return services;
    }
}
