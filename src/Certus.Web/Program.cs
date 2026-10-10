using Certus.Core.Acme.Attestation;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Services;
using Certus.Core.ActiveDirectory;
using Certus.Core.Adcs;
using Microsoft.Extensions.Options;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Crl;
using Certus.Core.Data;
using Certus.Core.Health;
using Certus.Core.Security;
using Certus.Web.Security;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Core.ServiceRights;
using Certus.Web;
using Certus.Web.Authentication;
using Certus.Web.Middleware;
using Certus.Web.Routing;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting Ducks in a Row (dev host) v{Version}", typeof(Program).Assembly.GetName().Version);

    var builder = WebApplication.CreateBuilder(args);

    // Serilog
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .WriteTo.Console()
        .WriteTo.File(
            Path.Combine(CertusPaths.DataDirectory, "logs", "ducks-.log"),
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 30));

    // Configuration
    builder.Services.Configure<CertusOptions>(
        builder.Configuration.GetSection(CertusOptions.SectionName));

    // Certus:DatabasePath ships as null in appsettings and the binder applies that
    // null over the option initializer, so resolve it back to the default for every
    // IOptions<CertusOptions> consumer (StartupValidator, SetupService).
    builder.Services.PostConfigure<CertusOptions>(o => o.NormalizeDatabasePath());

    // Database
    var certusOptions = builder.Configuration
        .GetSection(CertusOptions.SectionName)
        .Get<CertusOptions>() ?? new CertusOptions();

    // Same resolution for the copy used to build the connection string below: an
    // empty Data Source opens a throwaway temporary database per connection.
    certusOptions.NormalizeDatabasePath();

    builder.Services.AddDbContext<CertusDbContext>(options =>
        options.UseSqlite($"Data Source={certusOptions.DatabasePath}"));

    // Write the write ahead log back into the database when the host stops
    // (issue #215). Registered before the other AddHostedService calls in this
    // file on purpose: hosted services stop in reverse registration order, so
    // first here means this one stops after those background workers have
    // finished writing. Keep this line above the AddHostedService calls further
    // down. It orders this against those workers only, not against hosted
    // services the framework registers of its own accord.
    builder.Services.AddHostedService<SqliteShutdownCheckpoint>();

    // ADCS client — Certus.Web is used for development and integration testing and has
    // no real ADCS COM client wired (that is Certus.Service's job). A configured CA
    // string cannot be honored here, so fail fast before it would register no
    // IAdcsClient and crash opaquely when the certificate sync hosted service is
    // constructed. Otherwise use the mock client.
    //
    // The options overload, not the connection string one: the wizard writes the CA to
    // the settings overlay, which this host does not load as a configuration source, so
    // checking configuration alone passes on a fully configured install and lets the dev
    // host open the service's database (issue #305). Ahead of builder.Build() and well
    // ahead of DatabaseInitializer.Initialize below, so nothing is touched first.
    WebHostGuards.EnsureNoRealCaConfigured(certusOptions);
    Log.Warning("Certus.Web is the development host — using the mock ADCS client (certificates are fake)");
    builder.Services.AddSingleton<IAdcsClient>(new MockAdcsClient());
    // The CRL half of the mock CA. It publishes no distribution point, so this
    // host makes no outbound request for one.
    builder.Services.AddSingleton<ICaCrlReader>(new MockCrlReader());

    // ACME services
    builder.Services.Configure<AcmeOptions>(
        builder.Configuration.GetSection(AcmeOptions.SectionName));
    builder.Services.AddSingleton<NonceService>();
    builder.Services.AddSingleton<JwsService>();
    // Backs the "up" link target of a certificate download (RFC 8555 §7.4.2).
    // Singleton because the whole point is caching the CA chain across requests.
    builder.Services.AddSingleton<AcmeIssuerChainCache>();
    builder.Services.AddScoped<AccountService>();
    builder.Services.AddScoped<OrderService>();
    builder.Services.AddSingleton<EnabledTemplatesPolicy>();
    builder.Services.AddSingleton<AllowedDomainsPolicy>();
    builder.Services.AddScoped<DomainPolicyAuditService>();
    builder.Services.AddSingleton<TemplateService>();

    // External account binding (RFC 8555 §7.3.4). The enforcement policy hot
    // reads the wizard status file; credentials live in the database with
    // their MAC secrets encrypted at rest through the shared Data Protection
    // wiring (see CertusDataProtectionExtensions for the keyring and DPAPI
    // details). Integration tests replace the provider with the ephemeral one.
    builder.Services.AddSingleton<EabEnforcementPolicy>();
    // The dashboard revocation scope, hot read from the same status file.
    builder.Services.AddSingleton<RevocationScopePolicy>();
    builder.Services.AddScoped<EabCredentialService>();
    builder.Services.AddCertusSecretProtection(certusOptions);

    // Setup wizard
    // The dev host always runs the mock, so setup support is mock throughout,
    // and it cannot restart itself — the wizard shows the manual restart step.
    builder.Services.AddSingleton<IAdcsClientFactory, MockAdcsClientFactory>();
    builder.Services.AddSingleton<ICaDiscoveryService, MockCaDiscoveryService>();
    builder.Services.AddSingleton<IAdPrincipalLookup, MockAdPrincipalLookup>();
    builder.Services.AddSingleton<IServiceRestarter, NoOpServiceRestarter>();
    builder.Services.AddSingleton<IHttpsCertificateStore, NoOpHttpsCertificateStore>();
    builder.Services.AddScoped<TlsCertificateEnroller>();
    builder.Services.AddScoped<SetupService>();

    // The service rights check (issue #440), against the simulated probe: the
    // dev host answers for an example estate, never for the developer's account.
    builder.Services.AddSingleton<IServiceRightsProbe, MockServiceRightsProbe>();
    builder.Services.AddScoped<ServiceRightsCheck>();
    builder.Services.AddSingleton<ServiceRightsReportCache>();

    // Automatic renewal of the server's own HTTPS certificate (issue #105).
    // Registered here too, mirroring the service host, because the settings
    // controller lives in this assembly and must resolve wherever it can be
    // routed. Inert on this host: the mock CA blocks renewal and the no op
    // certificate store finds nothing to renew or suppress.
    builder.Services.AddScoped<HttpsCertificateRenewalService>();
    builder.Services.AddSingleton<ServerCertificateIdentity>();
    builder.Services.AddSingleton<HttpsCertificateAutoRenewalService>();
    builder.Services.AddHostedService(sp =>
        sp.GetRequiredService<HttpsCertificateAutoRenewalService>());

    // External URL reachability probe (issue #89). Its handler accepts self
    // signed certificates and is deliberately not the challenge egress
    // handler: the external URL legitimately points at this very server,
    // which AddressGuard exists to block.
    builder.Services.AddHttpClient<IExternalUrlProbe, ExternalUrlProbe>(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(5);
    })
    .ConfigurePrimaryHttpMessageHandler(() => ExternalUrlProbe.CreateHandler());

    // Dashboard services
    builder.Services.AddScoped<CertificateQueryService>();
    builder.Services.AddScoped<DashboardMetricsService>();
    builder.Services.AddScoped<CertificateRevocationService>();
    // The TLS capability gate under both the revoke endpoint and the detail
    // response's disabled button reason.
    builder.Services.AddScoped<RevocationEligibilityService>();
    // Singleton so concurrent scoped requests share the per serial locks
    // (issue #203); the scoped service above acquires it per revocation.
    builder.Services.AddSingleton<CertificateRevocationGate>();

    // Certificate sync background service. Registered as a singleton the API
    // controllers can reach (manual sync endpoint) and as the hosted service
    // that runs the interval loop — one shared instance, one sync gate. The
    // trigger lets the ACME issuance path and the endpoint wake the loop ahead
    // of its interval.
    builder.Services.AddSingleton<CertificateSyncTrigger>();
    builder.Services.AddSingleton<CertificateSyncService>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<CertificateSyncService>());

    // Expiry alert services. ThresholdDays binds onto an empty default, so
    // PostConfigure supplies the standard thresholds when the section is
    // absent and normalizes whatever was configured (see AlertOptions).
    //
    // Mirrors the service host (issue #162). Note this host never calls
    // AddSettingsOverlay, so settings.json is not a configuration source here
    // at all; reading it explicitly is what lets a value saved from the
    // dashboard take effect on the dev host too, rather than only in the
    // shipped service.
    var outrankedAlertKeys = SettingsOverlay.FindOutrankedKeys(
        builder.Configuration, AlertOptions.OutrankableKeys);
    builder.Services.Configure<AlertOptions>(
        builder.Configuration.GetSection(AlertOptions.SectionName));
    builder.Services.AddOptions<AlertOptions>()
        // IOptions<CertusOptions> rather than the manually bound copy above:
        // this resolves after every PostConfigure<CertusOptions> has run, which
        // is how the web test factory redirects the overlay away from
        // ProgramData.
        .PostConfigure<IOptions<CertusOptions>>((alerts, certusOptions) =>
        {
            var saved = SettingsOverlay.TryLoadAlerts(
                SettingsOverlay.ResolvePath(certusOptions.Value), out var failure);

            if (failure != null)
            {
                Log.Error(
                    failure,
                    "The settings overlay could not be read, so alert configuration saved " +
                    "from the dashboard is not in force; the values in appsettings.json are " +
                    "being used instead");
            }

            alerts.ApplyOverlay(saved, outrankedAlertKeys);
            alerts.NormalizeThresholdDays();
        });
    // The read and write path for the dashboard-owned slice of the alert
    // configuration. Singleton: it holds no state beyond the outranked key set,
    // which is fixed once the process has started.
    builder.Services.AddSingleton<AlertConfigStore>();
    builder.Services.AddScoped<AlertQueryService>();
    builder.Services.AddScoped<IAlertNotifier, EmailAlertNotifier>();
    builder.Services.AddHttpClient<WebhookAlertNotifier>(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(30);
    });
    builder.Services.AddScoped<IAlertNotifier>(sp =>
        sp.GetRequiredService<WebhookAlertNotifier>());
    builder.Services.AddHostedService<ExpiryMonitorService>();
    // The test send (issue #161). The throttle is a singleton because its whole
    // job is to hold the last send time across requests; the service that
    // consumes it is scoped like every other notifier consumer.
    builder.Services.AddSingleton<AlertTestThrottle>();
    builder.Services.AddScoped<AlertTestService>();

    // CRL monitoring (issue #447). No ILdapCrlFetcher is registered here:
    // System.DirectoryServices is Windows only and this host does not reference
    // Certus.Adcs at all. The mock CA names no distribution point, so nothing
    // asks for one.
    builder.Services.AddHttpClient<HttpCrlFetcher>((sp, client) =>
    {
        var alerts = sp.GetRequiredService<IOptions<AlertOptions>>().Value;
        client.Timeout = TimeSpan.FromSeconds(Math.Max(1, alerts.Crl.FetchTimeoutSeconds));
    });
    builder.Services.AddScoped<ICrlDistributionPointFetcher>(sp =>
    {
        var alerts = sp.GetRequiredService<IOptions<AlertOptions>>().Value;
        return new CrlDistributionPointFetcher(
            sp.GetRequiredService<HttpCrlFetcher>(),
            alerts.Crl.MaxCrlBytes,
            sp.GetService<ILdapCrlFetcher>());
    });
    builder.Services.AddHostedService<CrlMonitorService>();

    // Challenge validators — HTTP-01, DNS-01, TLS-ALPN-01.
    // Egress is screened by AddressGuard so a validator cannot be pointed at loopback,
    // link local, or operator blocked addresses (server side request forgery).
    builder.Services.Configure<ChallengeValidationOptions>(
        builder.Configuration.GetSection(ChallengeValidationOptions.SectionName));
    builder.Services.AddSingleton<AddressGuard>();

    builder.Services.AddHttpClient<Http01ChallengeValidator>(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(10);
    })
    .ConfigurePrimaryHttpMessageHandler(sp =>
        ChallengeHttpHandlerFactory.Create(
            sp.GetRequiredService<AddressGuard>(),
            sp.GetRequiredService<IOptions<ChallengeValidationOptions>>().Value));
    builder.Services.AddTransient<IChallengeValidator>(sp =>
        sp.GetRequiredService<Http01ChallengeValidator>());

    builder.Services.AddSingleton<DnsClient.ILookupClient>(_ =>
        new DnsClient.LookupClient(new DnsClient.LookupClientOptions
        {
            UseCache = false, // Avoid stale DNS cache during challenge validation
            Timeout = TimeSpan.FromSeconds(10)
        }));
    builder.Services.AddTransient<Dns01ChallengeValidator>();
    builder.Services.AddTransient<IChallengeValidator>(sp =>
        sp.GetRequiredService<Dns01ChallengeValidator>());

    builder.Services.AddTransient<TlsAlpn01ChallengeValidator>();
    builder.Services.AddTransient<IChallengeValidator>(sp =>
        sp.GetRequiredService<TlsAlpn01ChallengeValidator>());

    // device-attest-01 (draft-ietf-acme-device-attest-08). The verifier registry
    // is keyed on the CBOR fmt string; apple is the only format in v1 and its
    // verifier pins the embedded Apple root. The validator and its dependencies
    // are scoped, unlike the network validators above, because the trust anchor
    // store and the device gate read the database. Dark until an administrator
    // creates a device attestation profile: without one, no device order is
    // accepted, so no device-attest-01 challenge ever exists to validate.
    builder.Services.AddSingleton<IAttestationFormatVerifier, AppleAttestationVerifier>();
    builder.Services.AddScoped<AttestationTrustAnchorStore>();
    builder.Services.AddScoped<DeviceAttestationPolicyService>();
    builder.Services.AddScoped<DeviceAttest01ChallengeValidator>();
    builder.Services.AddScoped<IChallengeValidator>(sp =>
        sp.GetRequiredService<DeviceAttest01ChallengeValidator>());
    // The dashboard admin API for the device attestation tables (the profiles,
    // allowlists, and custom trust anchors the protocol path reads per request).
    builder.Services.AddScoped<DeviceAttestationAdminService>();

    // Background challenge validation worker
    builder.Services.AddHostedService<ChallengeValidationService>();

    // Background worker for orders the CA holds for manager approval (issue
    // #319). A template with CT_FLAG_PEND_ALL_REQUESTS answers every finalize
    // with "pending", and before this worker existed nothing revisited such an
    // order: the certificate an operator approved was never delivered and the
    // order never reached a terminal status either. Registered in both hosts
    // like the challenge worker; the options section is deliberately absent from
    // appsettings.json so the C# initializer is the default.
    builder.Services.Configure<PendingIssuanceOptions>(
        builder.Configuration.GetSection(PendingIssuanceOptions.SectionName));
    builder.Services.AddHostedService<PendingIssuanceService>();

    // MVC controllers
    builder.Services.AddControllers();

    // Authentication and authorization (issue #27, SEC-F1) — Negotiate plus a
    // deny by default fallback policy; public routes are carved out explicitly
    builder.Services.AddCertusAuth(builder.Configuration);

    // Security: startup validator
    builder.Services.AddSingleton<StartupValidator>();

    // Rate limiting for ACME endpoints. Registered in one place for both hosts:
    // this block used to be duplicated byte for byte here and in the other host's
    // Program.cs, so a change made to whichever copy was in front of you could
    // silently miss the deployed one (issue #263).
    var rateLimitOptions = builder.Services.AddAcmeRateLimiting(builder.Configuration);

    // Health check with database and CA connectivity verification. The CA probe is
    // cached briefly (CaHealthCache) so the anonymous readiness endpoint cannot drive a
    // fresh CA round trip on every request.
    builder.Services.AddSingleton<CaHealthCache>();
    builder.Services.AddHealthChecks()
        .AddCheck<CertusHealthCheck>("certus", tags: new[] { "ready" });

    var app = builder.Build();

    // Startup validation — reject fatal misconfigurations (including the SEC-F1
    // refusal) before any database I/O happens.
    using (var scope = app.Services.CreateScope())
    {
        var validator = scope.ServiceProvider.GetRequiredService<StartupValidator>();
        validator.Validate();

        // Force construction so a misconfigured challenge egress denylist fails at startup
        // rather than on the first challenge validation.
        _ = scope.ServiceProvider.GetRequiredService<AddressGuard>();

        // Construct the attestation verifier registry now: this runs the embedded
        // Apple root's SHA-256 pin check, so a tampered or mispackaged root fails
        // at startup rather than on the first device attestation.
        var attestationFormats = string.Join(", ",
            scope.ServiceProvider.GetServices<IAttestationFormatVerifier>().Select(v => v.Format));
        Log.Information("Device attestation formats registered: {Formats}", attestationFormats);

        // The revocation scope, named on every boot the same way the template
        // exposure is: the mode decides what the dashboard may revoke, and an
        // admin reading the log should not have to open Settings to know it.
        var revocationScope = scope.ServiceProvider
            .GetRequiredService<RevocationScopePolicy>().GetSnapshot();
        Log.Information(
            "Revocation scope: {Mode} ({CustomCount} custom templates)",
            RevocationScopePolicy.ModeName(revocationScope.Mode),
            revocationScope.CustomTemplates.Count);
    }

    // Ensure the database directory exists and the schema is current. The
    // initializer migrates, adopts a pre migration database whose schema
    // matches the model, or fails fast with the documented reset message
    // (issue #77).
    if (certusOptions.DatabasePath != CertusPaths.InMemoryDatabase)
    {
        var dbDir = Path.GetDirectoryName(certusOptions.DatabasePath);
        if (!string.IsNullOrEmpty(dbDir))
            Directory.CreateDirectory(dbDir);
    }

    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        DatabaseInitializer.Initialize(db, certusOptions.EnableWalMode, app.Logger);
    }

    // Detached on purpose, and after the migration rather than inside the
    // validation scope above, which is documented as running before any I/O.
    // This is the one boot line that says a template nobody can address is the
    // one exposed over ACME (issue #235), and it is the only startup diagnostic
    // that needs the CA. StartupValidator stays what it is: synchronous, I/O
    // free, and answerable from configuration alone. Running it detached means
    // a CA at the end of an RPC timeout costs boot nothing, an unconfigured
    // install costs nothing, and a healthy install pays only the template cache
    // fill the first ACME request would have paid anyway.
    // Both singletons are resolved here rather than inside the lambda. A
    // resolution failure on the boot thread fails loudly like every other
    // GetRequiredService in this file; the same failure inside a detached task
    // would be swallowed as an unobserved exception, and the diagnostic would
    // silently stop existing with nothing logged at any level.
    var templateNameReportTemplates = app.Services.GetRequiredService<TemplateService>();
    var templateNameReportPolicy = app.Services.GetRequiredService<EnabledTemplatesPolicy>();
    _ = Task.Run(() => TemplateNameStartupReport.LogAsync(
        templateNameReportTemplates,
        templateNameReportPolicy,
        app.Logger,
        app.Lifetime.ApplicationStopping));

    // Forwarded headers — correct RemoteIpAddress from a known reverse proxy
    // before the rate limiter and request logging read it. Does nothing when
    // Auth:TrustedProxies is empty.
    app.UseCertusForwardedHeaders();

    // Security headers middleware — X-Content-Type-Options, X-Frame-Options, etc.
    app.UseMiddleware<SecurityHeadersMiddleware>();

    // Refuse control and formatting characters in the URL, before the request
    // logger renders the path into the log file (a percent encoded line feed
    // would otherwise forge log lines from an unauthenticated request) and
    // before the redirect below builds a Location header out of that path.
    // After the security headers, which are set on the way in, so the refusal
    // carries them too.
    app.UseMiddleware<UrlCharacterGuardMiddleware>();

    // HTTPS enforcement (HSTS + redirect) outside Development, gated by Auth:RequireHttps
    app.UseCertusTransportSecurity();

    app.UseSerilogRequestLogging();

    // ACME nonce middleware — injects Replay-Nonce on all /acme/ responses
    app.UseMiddleware<AcmeNonceMiddleware>();

    app.UseRouting();

    // Authentication, authorization, and the CSRF header guard (issue #27)
    app.UseCertusAuth();

    // Rate limiting — must be after routing so policies can match endpoints
    if (rateLimitOptions.Enabled)
    {
        app.UseRateLimiter();
    }

    // Serve React dashboard static files from wwwroot
    app.UseDefaultFiles();
    app.UseStaticFiles();

    // Liveness probe — process is up; runs no checks (no DB or CA). No auth.
    app.MapHealthChecks("/health/live",
        new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();

    // Readiness probe — runs the DB and CA connectivity checks. No auth.
    app.MapHealthChecks("/health").AllowAnonymous();

    // Map ACME and dashboard controllers
    app.MapControllers();

    // Unknown /api/ and /acme/ paths must never fall back to the SPA shell:
    // index.html would mask the 401/404 (issue #27). Both fallbacks also work
    // out why the request missed, because they are unconstrained catch-alls
    // and so suppress the 405/415 ASP.NET would otherwise answer (issue #147).
    // See ProtocolFallbackExtensions for the whole story.
    app.MapApiFallback();
    app.MapAcmeProtocolFallback();

    // SPA fallback — serve index.html for any unmatched routes
    // (must be after MapControllers so API/ACME routes take priority)
    app.MapFallbackToFile("index.html").AllowAnonymous();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Ducks in a Row terminated unexpectedly");

    // A fatal startup error (including the SEC-F1 refusal in StartupValidator and
    // the auth guard in UseCertusAuth) must surface as a nonzero exit code so an
    // orchestrator or the service control manager sees a failed start rather than
    // a clean exit (issue #27, SEC-F1).
    Environment.ExitCode = 1;
}
finally
{
    Log.CloseAndFlush();
}

// Required for WebApplicationFactory integration tests
public partial class Program;
