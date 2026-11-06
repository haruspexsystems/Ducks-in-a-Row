using System.Security.Claims;
using System.Text.Encodings.Web;
using Certus.Core.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Service.Tests;

/// <summary>
/// The service host with its real authorization wiring: the fallback policy that denies by
/// default, the AdminOnly policy with its admin group requirement, and the CSRF header guard. Only
/// the Negotiate handler is replaced, by a header driven test scheme, because TestServer cannot do
/// a SPNEGO handshake. The same approach as Certus.Web.Tests' AuthWebApplicationFactory, here
/// against the service host, so the licence API's pipeline is proved where it ships.
/// </summary>
public sealed class AuthServiceHostFactory : ServiceHostFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureServices(services =>
        {
            // The base names Auth:Mode=Disabled so the host can boot without Negotiate. Flipping the
            // options back puts the policies, the fallback and the CSRF middleware in place, since
            // UseCertusAuth and the policy setup both read the options rather than the setting.
            services.PostConfigure<AuthOptions>(o => o.Mode = AuthOptions.ModeNegotiate);

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                options.DefaultChallengeScheme = TestAuthHandler.SchemeName;
            }).AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
        });
    }
}

/// <summary>
/// X-Test-User: admin yields a member of BUILTIN\Administrators, any other value an authenticated
/// user who is not an administrator, and no header an anonymous request.
/// </summary>
public sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "TestAuth";
    public const string UserHeader = "X-Test-User";
    public const string AdminUser = "admin";

    public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var user = Request.Headers[UserHeader].FirstOrDefault();
        if (string.IsNullOrEmpty(user))
            return Task.FromResult(AuthenticateResult.NoResult());

        var claims = new List<Claim> { new(ClaimTypes.Name, user) };
        if (user == AdminUser)
            claims.Add(new(ClaimTypes.Role, @"BUILTIN\Administrators"));

        var identity = new ClaimsIdentity(claims, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}
