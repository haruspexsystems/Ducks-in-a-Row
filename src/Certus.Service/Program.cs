using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Certus.Adcs;
using Certus.Core.Acme.Attestation;
using Certus.Core.Acme.Crypto;
using Certus.Core.ActiveDirectory;
using Certus.Core.Adcs;
using Certus.Core.Acme.Services;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Health;
using Certus.Core.Security;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Service;
using Certus.Web;
using Certus.Web.Authentication;
using Certus.Web.Routing;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting Ducks in a Row service v{Version}",
        typeof(Program).Assembly.GetName().Version);

    var options = new WebApplicationOptions
    {
        Args = args,
        ContentRootPath = WindowsServiceHelpers.IsWindowsService()
            ? AppContext.BaseDirectory
            : default
    };

    var builder = WebApplication.CreateBuilder(options);

    // Windows Service support
    builder.Host.UseWindowsService();

    // Runtime settings overlay (settings.json in the data directory), written
    // by the setup wizard: CA connection string and external URL. It lives in
    // the data directory so MSI upgrades cannot overwrite it, and is inserted
    // after appsettings so environment variables and command line still win.
    builder.Configuration.AddSettingsOverlay(CertusPaths.DataDirectory);

    // HTTPS: resolve the certificate for the Kestrel HTTPS endpoint.
    // Precedence: an explicit Kestrel certificate path, then the CA issued
    // certificate the setup wizard recorded by thumbprint (loaded from
    // LocalMachine\My), then the generated self signed fallback. A recorded
    // thumbprint that cannot be honored (certificate removed, expired, or
    // missing its private key) logs a warning and falls through to the self
    // signed certificate — a broken certificate must never stop the service,
    // because the wizard and the settings page are the way to fix it.
    var httpsSection = builder.Configuration.GetSection("Kestrel:Endpoints:Https:Certificate");
    var certPath = httpsSection["Path"];
    var configuredThumbprint = builder.Configuration["Certus:HttpsCertificateThumbprint"];

    // Capture which certificate this boot serves. The Log.* calls in this
    // block run on the console only bootstrap logger, before the file sink
    // attaches, so the outcome is logged again after Build() to reach the
    // field log file.
    (string Source, string? Thumbprint, string Detail) httpsCertSelection =
        ("KestrelConfig", null, certPath ?? "");

    X509Certificate2? storeCertificate = null;
    if (string.IsNullOrEmpty(certPath) && !string.IsNullOrWhiteSpace(configuredThumbprint))
    {
        using var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        machineStore.Open(OpenFlags.ReadOnly);
        var matches = machineStore.Certificates.Find(
            X509FindType.FindByThumbprint, configuredThumbprint.Trim(), validOnly: false);

        if (matches.Count == 0)
        {
            Log.Warning(
                "Certus:HttpsCertificateThumbprint {Thumbprint} is configured but no such " +
                "certificate exists in LocalMachine\\My; falling back to the self signed certificate",
                configuredThumbprint);
        }
        else if (!matches[0].HasPrivateKey)
        {
            Log.Warning(
                "The configured HTTPS certificate {Thumbprint} has no private key; " +
                "falling back to the self signed certificate",
                configuredThumbprint);
        }
        else if (matches[0].NotAfter.ToUniversalTime() <= DateTime.UtcNow)
        {
            Log.Warning(
                "The configured HTTPS certificate {Thumbprint} expired {NotAfter:u}; " +
                "falling back to the self signed certificate",
                configuredThumbprint, matches[0].NotAfter.ToUniversalTime());
        }
        else
        {
            storeCertificate = matches[0];
            builder.WebHost.ConfigureKestrel(kestrel =>
                kestrel.ConfigureHttpsDefaults(https => https.ServerCertificate = storeCertificate));
            httpsCertSelection = ("Store", storeCertificate.Thumbprint, storeCertificate.Subject);
            Log.Information(
                "HTTPS is using certificate {Thumbprint} ({Subject}, valid until {NotAfter:u}) " +
                "from LocalMachine\\My",
                storeCertificate.Thumbprint, storeCertificate.Subject,
                storeCertificate.NotAfter.ToUniversalTime());
        }
    }

    if (string.IsNullOrEmpty(certPath) && storeCertificate is null)
    {
        // Generate a self-signed certificate for lab/development use
        var dataDir = CertusPaths.DataDirectory;
        Directory.CreateDirectory(dataDir);
        var selfSignedPath = Path.Combine(dataDir, "ducks-selfsigned.pfx");
        const string selfSignedPassword = "certus-dev";
        const int selfSignedRenewalWindowDays = 30;

        httpsCertSelection = ("SelfSigned", null, selfSignedPath);

        // Regenerate when the pfx is missing, unreadable, or within the renewal
        // window of expiry. The earlier code generated only when the file was
        // missing, so an expired certificate was reused indefinitely.
        var regenerate = !File.Exists(selfSignedPath);
        if (!regenerate)
        {
            try
            {
                using var existing = X509CertificateLoader.LoadPkcs12FromFile(
                    selfSignedPath, selfSignedPassword, X509KeyStorageFlags.EphemeralKeySet);
                regenerate = existing.NotAfter.ToUniversalTime()
                    <= DateTime.UtcNow.AddDays(selfSignedRenewalWindowDays);
                if (!regenerate)
                    httpsCertSelection = ("SelfSigned", existing.Thumbprint, selfSignedPath);
            }
            catch (CryptographicException)
            {
                // Corrupt or unreadable pfx: regenerate it.
                regenerate = true;
            }
        }

        if (regenerate)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=Ducks in a Row Self-Signed", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

            // Add SAN for localhost so browsers and tools accept it
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddDnsName(Environment.MachineName);
            request.CertificateExtensions.Add(sanBuilder.Build());

            using var cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));
            File.WriteAllBytes(selfSignedPath,
                cert.Export(X509ContentType.Pfx, selfSignedPassword));
            httpsCertSelection = ("SelfSigned", cert.Thumbprint, selfSignedPath);
            Log.Information(
                "Generated self-signed HTTPS certificate at {Path} (valid until {NotAfter:u})",
                selfSignedPath, cert.NotAfter.ToUniversalTime());
        }

        // Point Kestrel at the generated certificate
        builder.Configuration["Kestrel:Endpoints:Https:Certificate:Path"] = selfSignedPath;
        builder.Configuration["Kestrel:Endpoints:Https:Certificate:Password"] = selfSignedPassword;

        // Surface the fallback on every boot, not just first generation, so an
        // operator never unknowingly runs production on the self-signed cert.
        Log.Warning(
            "HTTPS is using the generated self-signed certificate at {Path}. Configure " +
            "Kestrel:Endpoints:Https:Certificate:Path with a trusted certificate for production use.",
            selfSignedPath);
    }

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
    // empty Data Source opens a throwaway temporary database per connection, which
    // makes the startup migration fail with "no such table: __EFMigrationsHistory".
    certusOptions.NormalizeDatabasePath();

    builder.Services.AddDbContext<CertusDbContext>(dbOptions =>
        dbOptions.UseSqlite($"Data Source={certusOptions.DatabasePath}"));

    // ADCS client — tri state. Real COM interop when a CA is configured; the
    // mock only when explicitly requested; otherwise an unconfigured client
    // whose operations surface as 503 ca-unavailable until the setup wizard
    // connects a CA. An empty CA string used to fall back to the mock
    // silently, which let a production install complete setup against a fake
    // CA without noticing. The wizard's probe factory, CA discovery, and the
    // EAB owner principal lookup are registered in the same branch so every
    // directory facing concern switches together.
    if (certusOptions.UseMockCa)
    {
        builder.Services.AddMockAdcsClient();
        builder.Services.AddSingleton<IAdcsClientFactory, MockAdcsClientFactory>();
        builder.Services.AddSingleton<ICaDiscoveryService, MockCaDiscoveryService>();
        builder.Services.AddSingleton<IAdPrincipalLookup, MockAdPrincipalLookup>();
        Log.Warning(
            "Certus:UseMockCa=true — using the mock ADCS client. Certificates are fake; " +
            "never use this in production");
    }
    else
    {
        builder.Services.AddSingleton<IAdcsClientFactory, AdcsClientFactory>();
        builder.Services.AddSingleton<ICaDiscoveryService, AdcsCaDiscoveryService>();
        builder.Services.AddSingleton<IAdPrincipalLookup, AdPrincipalLookup>();

        if (!string.IsNullOrEmpty(certusOptions.CaConnectionString))
        {
            builder.Services.AddAdcsClient();
            Log.Information("Using real ADCS client for CA: {Ca}", certusOptions.CaConnectionString);
        }
        else
        {
            builder.Services.AddUnconfiguredAdcsClient();
            Log.Warning(
                "No CA connection string configured — the service is unconfigured and CA " +
                "operations return 503 until setup completes");
        }
    }

    // ACME services
    builder.Services.Configure<AcmeOptions>(
        builder.Configuration.GetSection(AcmeOptions.SectionName));
    builder.Services.AddSingleton<NonceService>();
    builder.Services.AddSingleton<JwsService>();
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
    // details).
    builder.Services.AddSingleton<EabEnforcementPolicy>();
    // The dashboard revocation scope, hot read from the same status file.
    builder.Services.AddSingleton<RevocationScopePolicy>();
    builder.Services.AddScoped<EabCredentialService>();
    builder.Services.AddCertusSecretProtection(certusOptions);

    // Setup wizard. The probe factory and CA discovery are registered with
    // the ADCS client tri state above. The restarter applies completed setup
    // by restarting this service. The certificate store and enroller back
    // the wizard's one click TLS certificate provisioning.
    builder.Services.AddSingleton<IServiceRestarter, WindowsServiceRestarter>();
    builder.Services.AddSingleton<IHttpsCertificateStore, MachineHttpsCertificateStore>();
    builder.Services.AddScoped<TlsCertificateEnroller>();
    builder.Services.AddScoped<SetupService>();

    // Automatic renewal of the server's own HTTPS certificate (issue #105).
    // The renewal core is shared with the settings page button. The hosted
    // service is registered as a singleton as well, the CertificateSyncService
    // pattern, so the settings API reads its last attempt off the instance the
    // loop writes. ServerCertificateIdentity keeps this certificate out of the
    // product's own expiry alerting.
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
    // What an administrator saved from the dashboard is laid over the bound
    // values here rather than left to the configuration binder (issue #162).
    // The overlay is a JSON source like appsettings.json, and .NET merges array
    // keys index by index, so a saved ThresholdDays shorter than the shipped
    // one would silently keep the old tail; ApplyOverlay replaces arrays
    // wholesale. The outranked set is computed once, before DI, because it is
    // a property of the configuration layering and cannot change at runtime.
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
            UseCache = false,
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
    // Registered in both hosts to mirror EabCredentialService: the admin
    // controllers live in the Certus.Web assembly, which the service host also
    // loads, so the service must resolve wherever the controller can be routed.
    builder.Services.AddScoped<DeviceAttestationAdminService>();

    // Background challenge validation worker
    builder.Services.AddHostedService<ChallengeValidationService>();

    // MVC controllers — discover from both Service and Web assemblies
    builder.Services.AddControllers()
        .AddApplicationPart(typeof(Certus.Web.Controllers.Acme.DirectoryController).Assembly);

    // Authentication and authorization (issue #27, SEC-F1) — Negotiate plus a
    // deny by default fallback policy; public routes are carved out explicitly
    builder.Services.AddCertusAuth(builder.Configuration);

    // Security: startup validator
    builder.Services.AddSingleton<StartupValidator>();

    // Rate limiting for ACME endpoints. Bind the options so StartupValidator can
    // warn on a non positive limit or window; the local copy below gates the
    // pipeline at build time.
    builder.Services.Configure<AcmeRateLimitOptions>(
        builder.Configuration.GetSection(AcmeRateLimitOptions.SectionName));

    var rateLimitOptions = builder.Configuration
        .GetSection(AcmeRateLimitOptions.SectionName)
        .Get<AcmeRateLimitOptions>() ?? new AcmeRateLimitOptions();

    if (rateLimitOptions.Enabled)
    {
        builder.Services.AddRateLimiter(rlOptions =>
        {
            rlOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            // A bare 429 tells an ACME client nothing; RFC 8555 §6.6 has an
            // error code for exactly this, and §6.6 asks for Retry-After.
            rlOptions.OnRejected = AcmeProblemResults.OnRateLimitRejected;

            rlOptions.AddPolicy("acme-new-account", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = rateLimitOptions.NewAccountLimit,
                        Window = TimeSpan.FromSeconds(rateLimitOptions.WindowSeconds),
                        QueueLimit = 0
                    }));

            rlOptions.AddPolicy("acme-new-order", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = rateLimitOptions.NewOrderLimit,
                        Window = TimeSpan.FromSeconds(rateLimitOptions.WindowSeconds),
                        QueueLimit = 0
                    }));

            rlOptions.AddPolicy("acme-general", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = rateLimitOptions.GeneralLimit,
                        Window = TimeSpan.FromSeconds(rateLimitOptions.WindowSeconds),
                        QueueLimit = 0
                    }));
        });
    }

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

    // Forwarded headers — correct RemoteIpAddress from a known reverse proxy
    // before the rate limiter and request logging read it. Does nothing when
    // Auth:TrustedProxies is empty.
    app.UseCertusForwardedHeaders();

    // Security headers middleware — X-Content-Type-Options, X-Frame-Options, etc.
    app.UseMiddleware<Certus.Web.Middleware.SecurityHeadersMiddleware>();

    // Refuse control and formatting characters in the URL, before the request
    // logger renders the path into the log file (a percent encoded line feed
    // would otherwise forge log lines from an unauthenticated request) and
    // before the redirect below builds a Location header out of that path.
    // After the security headers, which are set on the way in, so the refusal
    // carries them too.
    app.UseMiddleware<Certus.Web.Middleware.UrlCharacterGuardMiddleware>();

    // HTTPS enforcement (HSTS + redirect) outside Development, gated by Auth:RequireHttps
    app.UseCertusTransportSecurity();

    app.UseSerilogRequestLogging();

    // ACME nonce middleware — injects Replay-Nonce on all /acme/ responses
    app.UseMiddleware<Certus.Web.Middleware.AcmeNonceMiddleware>();

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
    app.MapFallbackToFile("index.html").AllowAnonymous();

    // Diagnostic for stale binary detection (issue #10–#12 baseline) and for
    // confirming the issue #15 fix is deployed:
    //   - All v1 and v2 [ComImport] interface declarations have been removed
    //     from Certus.Adcs.ComInterop. AdcsClient dispatches every CCertRequest
    //     and CCertView method through IDispatch via C# `dynamic`, so vtable
    //     layout is not load-bearing. The diagnostic confirms the typed
    //     declarations stay absent.
    try
    {
        var adcsAsm = typeof(AdcsClient).Assembly;
        var adcsPath = adcsAsm.Location;
        var adcsWritten = File.Exists(adcsPath)
            ? File.GetLastWriteTimeUtc(adcsPath).ToString("o")
            : "(unknown)";
        var icr1 = adcsAsm.GetType("Certus.Adcs.ComInterop.ICertRequest");
        var icr2 = adcsAsm.GetType("Certus.Adcs.ComInterop.ICertRequest2");
        var icv1 = adcsAsm.GetType("Certus.Adcs.ComInterop.ICertView");
        var icv2 = adcsAsm.GetType("Certus.Adcs.ComInterop.ICertView2");
        Log.Information(
            "ComInterop diagnostic: Certus.Adcs.dll Path={Path} LastWriteUtc={LastWrite} " +
            "ICertRequestRemoved={V1ReqRemoved} ICertRequest2Removed={V2ReqRemoved} " +
            "ICertViewRemoved={V1ViewRemoved} ICertView2Removed={V2ViewRemoved} " +
            "DispatchModel=full-IDispatch",
            adcsPath,
            adcsWritten,
            icr1 is null,
            icr2 is null,
            icv1 is null,
            icv2 is null);
    }
    catch (Exception diagEx)
    {
        Log.Warning(diagEx, "ComInterop diagnostic failed");
    }

    // Repeat the certificate selection through the file backed logger; the
    // original selection lines above ran on the console only bootstrap logger.
    Log.Information(
        "HTTPS certificate for this boot: {CertSource} thumbprint {Thumbprint} ({CertDetail})",
        httpsCertSelection.Source, httpsCertSelection.Thumbprint ?? "unknown",
        httpsCertSelection.Detail);
    Log.Information("Certus Service started successfully");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Certus Service terminated unexpectedly");

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
