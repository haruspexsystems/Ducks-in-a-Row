using Microsoft.Extensions.DependencyInjection;

namespace Certus.Core.Audit;

/// <summary>
/// Registers the administrator audit trail's writers (issue #634). Both hosts
/// call this once, through the web layer's registration, so the trail exists
/// wherever the dashboard API does. Both are scoped: they write through the
/// request's <c>CertusDbContext</c>, which is what puts an audit row in the
/// same transaction as the change it records.
/// </summary>
public static class AdminAuditServiceCollectionExtensions
{
    public static IServiceCollection AddAdminAuditTrail(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<IAdminAuditTrail, AdminAuditTrail>();
        services.AddScoped<AdminSignInFailureRecorder>();

        return services;
    }
}
