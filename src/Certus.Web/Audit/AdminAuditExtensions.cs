using Certus.Core.Audit;
using Microsoft.AspNetCore.Mvc;

namespace Certus.Web.Audit;

/// <summary>
/// Wires the administrator audit trail into a host (issue #634). One call in
/// each Program.cs, beside <c>AddCertusAuth</c>, so neither host can carry the
/// dashboard API without the trail: the Core writers, the per request
/// description, and the MVC filter that turns <see cref="AdminAuditAttribute"/>
/// into rows. The sign in failure middleware is added by
/// <c>UseCertusAuth</c>, which knows whether authentication is on at all.
/// </summary>
public static class AdminAuditExtensions
{
    public static IServiceCollection AddAdminAudit(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAdminAuditTrail();
        services.AddScoped<AdminAuditDescription>();
        services.Configure<MvcOptions>(options => options.Filters.Add<AdminAuditFilter>());

        return services;
    }
}
