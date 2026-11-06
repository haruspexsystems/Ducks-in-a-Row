using Certus.Core.Configuration;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// The auth test host with <c>Auth:RequireKerberos</c> on (issue #633). The
/// test scheme stays header driven; <see cref="TestAuthHandler.AuthTypeHeader"/>
/// names the package the identity reports, which is what the Kerberos only
/// middleware reads from a real Windows identity.
/// </summary>
public sealed class KerberosOnlyWebApplicationFactory : AuthWebApplicationFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting(
            $"{AuthOptions.SectionName}:{nameof(AuthOptions.RequireKerberos)}", "true");
    }
}
