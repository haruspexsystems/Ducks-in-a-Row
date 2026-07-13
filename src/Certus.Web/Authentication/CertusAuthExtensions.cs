using System.Net;
using Certus.Core.Configuration;
using Certus.Web.Middleware;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;

namespace Certus.Web.Authentication;

/// <summary>
/// Shared authentication and authorization wiring for both hosts
/// (Certus.Service and Certus.Web). The two Program.cs pipelines are near
/// duplicates; keeping this in one extension prevents auth being added to one
/// host and forgotten in the other (issue #27, SEC-F1).
/// </summary>
public static class CertusAuthExtensions
{
    /// <summary>
    /// Registers Windows Integrated Authentication (Negotiate) and a
    /// deny-by-default authorization policy: any endpoint without explicit
    /// authorization metadata requires an authenticated admin, so a forgotten
    /// endpoint fails closed. The public surface (ACME, /health, SPA shell,
    /// reduced setup status) is carved out with [AllowAnonymous].
    /// The Negotiate handler is registered only when Auth:Mode is not Disabled,
    /// read straight from configuration here (not via IOptions), because a host
    /// must decide before it builds whether the handler exists at all. Test hosts
    /// set Auth:Mode=Disabled in configuration to keep it off TestServer; see
    /// CertusWebApplicationFactory.
    /// </summary>
    public static IServiceCollection AddCertusAuth(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<AuthOptions>(configuration.GetSection(AuthOptions.SectionName));

        // The Negotiate handler is registered from the configuration as read
        // here: it intercepts every request (IAuthenticationRequestHandler) and
        // requires Kestrel, so it must not exist on hosts that disable auth
        // (TestServer included). WebApplication also auto-adds the authentication
        // middleware whenever an authentication scheme is registered, so the
        // handler runs even when UseCertusAuth skips UseAuthentication — the only
        // safe way to keep it off TestServer is to not register it. Auth tests
        // (AuthWebApplicationFactory) add their own header-driven scheme instead.
        var registration = configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>()
            ?? new AuthOptions();
        if (!registration.IsDisabled)
        {
            services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
                .AddNegotiate();
        }

        services.AddSingleton<IAuthorizationHandler, AdminGroupHandler>();
        services.AddAuthorization();
        services.AddOptions<AuthorizationOptions>()
            .Configure<IOptions<AuthOptions>>((authz, auth) =>
            {
                if (auth.Value.IsDisabled)
                {
                    // Development escape hatch: controllers still carry
                    // [Authorize(Policy = CertusPolicies.AdminOnly)], so the
                    // policy must exist; it degrades to allow-all and no
                    // fallback policy is installed.
                    authz.AddPolicy(CertusPolicies.AdminOnly,
                        p => p.RequireAssertion(_ => true));
                    return;
                }

                authz.AddPolicy(CertusPolicies.AdminOnly, p => p
                    .RequireAuthenticatedUser()
                    .AddRequirements(new AdminGroupRequirement()));
                authz.FallbackPolicy = authz.GetPolicy(CertusPolicies.AdminOnly);
            });

        // HSTS hardening (SEC-J1): a one year max age with includeSubDomains, replacing
        // the framework default of 30 days. It lives here next to UseCertusTransportSecurity,
        // which consumes it, so both hosts get the same policy and a new host cannot forget
        // it (the same reason auth itself is centralized in this extension).
        services.AddHsts(hstsOptions =>
        {
            hstsOptions.MaxAge = TimeSpan.FromDays(365);
            hstsOptions.IncludeSubDomains = true;
        });

        return services;
    }

    /// <summary>
    /// Adds authentication, authorization, and the CSRF header guard to the
    /// pipeline. Call after UseRouting and before the rate limiter and endpoint
    /// mapping. Refuses to run with authentication disabled outside the
    /// Development environment.
    /// </summary>
    public static WebApplication UseCertusAuth(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<IOptions<AuthOptions>>().Value;

        if (options.IsDisabled)
        {
            if (!app.Environment.IsDevelopment())
            {
                throw new InvalidOperationException(
                    "Auth:Mode=Disabled is a development-only escape hatch and is " +
                    "not allowed outside the Development environment.");
            }

            // No authentication; authorization still runs because endpoints
            // carry [Authorize] metadata (the policy is allow-all here).
            app.UseAuthorization();
            return app;
        }

        app.UseAuthentication();
        app.UseAuthorization();

        // CSRF rides on ambient credentials; without authentication there is
        // nothing to ride, so the guard is active only alongside it.
        app.UseMiddleware<CsrfHeaderMiddleware>();
        return app;
    }

    /// <summary>
    /// Enforces HTTPS (HSTS plus HTTP-to-HTTPS redirection) outside Development
    /// when Auth:RequireHttps is true. Config-gated so the lab can stage the
    /// transport change separately (SEC-J2).
    /// </summary>
    public static WebApplication UseCertusTransportSecurity(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<IOptions<AuthOptions>>().Value;

        if (!options.RequireHttps || app.Environment.IsDevelopment())
            return app;

        app.UseHsts();
        app.UseHttpsRedirection();
        return app;
    }

    /// <summary>
    /// Builds forwarded header options from the configured trusted proxy list, or
    /// null when no proxies are configured so forwarded headers stay ignored. The
    /// X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto headers are honored
    /// only from a listed proxy, so HttpContext.Connection.RemoteIpAddress reflects the
    /// real client (what the ACME rate limiter keys on) and request.Host / request.Scheme
    /// reflect the public origin (what AcmeUrl builds ACME URLs from). An unlisted peer
    /// cannot spoof any of the three.
    /// </summary>
    public static ForwardedHeadersOptions? BuildForwardedHeadersOptions(AuthOptions options)
    {
        var forwardedOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor
                | ForwardedHeaders.XForwardedHost
                | ForwardedHeaders.XForwardedProto
        };

        // Clear the framework defaults so the configured proxies are the complete
        // allowlist. An unlisted peer's forwarded header is ignored and its
        // connection address stays the client.
        forwardedOptions.KnownNetworks.Clear();
        forwardedOptions.KnownProxies.Clear();

        foreach (var entry in options.TrustedProxies)
        {
            if (IPAddress.TryParse(entry, out var ip))
                forwardedOptions.KnownProxies.Add(ip);
        }

        return forwardedOptions.KnownProxies.Count == 0 ? null : forwardedOptions;
    }

    /// <summary>
    /// Applies forwarded header handling when Auth:TrustedProxies is configured, so
    /// the rate limiter and request logging see the real client behind a known
    /// reverse proxy. Call first in the pipeline, before anything reads
    /// RemoteIpAddress. Does nothing when no trusted proxies are configured.
    /// </summary>
    public static WebApplication UseCertusForwardedHeaders(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<IOptions<AuthOptions>>().Value;
        var forwardedOptions = BuildForwardedHeadersOptions(options);
        if (forwardedOptions is not null)
            app.UseForwardedHeaders(forwardedOptions);

        return app;
    }
}
