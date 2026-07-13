using System.Security.Claims;
using System.Text.Encodings.Web;
using Certus.Core.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Web.Tests;

/// <summary>
/// Factory for authentication integration tests: runs with the full auth stack
/// enabled (Auth:Mode=Negotiate wiring — a fallback policy that denies by default,
/// admin group requirement, CSRF header guard, anonymous carve-outs) but with
/// the Negotiate handler replaced by a header-driven test scheme, because
/// TestServer cannot perform a real SPNEGO handshake. The live handshake is
/// exercised by the security agent's re-probe against the lab.
/// </summary>
public class AuthWebApplicationFactory : CertusWebApplicationFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureServices(services =>
        {
            // Runs after the base factory's PostConfigure (registration order),
            // flipping the host from the Disabled escape hatch to the real
            // auth wiring.
            services.PostConfigure<AuthOptions>(o =>
                o.Mode = AuthOptions.ModeNegotiate);

            // Replace Negotiate as the default scheme; policies, the fallback,
            // and the AdminGroupHandler claims path all still run for real.
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                options.DefaultChallengeScheme = TestAuthHandler.SchemeName;
            }).AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(
                TestAuthHandler.SchemeName, _ => { });
        });
    }
}

/// <summary>
/// Test authentication driven by a request header: X-Test-User: admin yields a principal in
/// the builtin Administrators role, any other value an authenticated non-admin,
/// and no header an anonymous request (which the fallback policy turns into a
/// 401 challenge).
/// </summary>
public sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "TestAuth";
    public const string UserHeader = "X-Test-User";
    public const string AdminUser = "admin";

    private const string AdminRole = @"BUILTIN\Administrators";

    public TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
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
            claims.Add(new(ClaimTypes.Role, AdminRole));

        var identity = new ClaimsIdentity(claims, SchemeName);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
