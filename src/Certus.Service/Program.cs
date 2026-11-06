using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Adcs;
using Certus.Adcs.ServiceRights;
using Certus.Core.Acme.Attestation;
using Certus.Core.Acme.Crypto;
using Certus.Core.ActiveDirectory;
using Certus.Core.Adcs;
using Certus.Core.Acme.Services;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Crl;
using Certus.Core.Data;
using Certus.Core.Data.Retention;
using Certus.Core.Health;
using Certus.Core.Modules;
using Certus.Core.Security;
using Certus.Web.Security;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Core.ServiceRights;
using Certus.Service;
using Certus.Web;
using Certus.Web.Audit;
using Certus.Web.Authentication;
using Certus.Web.Routing;
using Certus.Web.Configuration;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using Certus.Web.Logging;
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

    // The data directory, resolved once and before the settings overlay below
    // is added, so the overlay it holds can never move it. Outside Development
    // this is always the installer's choice or the %ProgramData% default; see
    // CertusDataDirectory for the one Development override and why tests need it.
    var dataDirectory = CertusDataDirectory.Resolve(builder.Configuration, builder.Environment);

    // The instance mode (issue #470), resolved here for the same reason as the data
    // directory: before the settings overlay is added, so the overlay can never
    // supply it. In production it comes from the registry value the installer writes,
    // which only a local administrator can change. A value that cannot be honoured
    // registers everything below as monitor mode, the side that never writes to the
    // CA, and StartupValidator refuses to start once the file logger exists.
    var instanceMode = CertusInstanceMode.Resolve(builder.Configuration, builder.Environment);

    // Lock the data folder down before anything reads or writes it (issue #489).
    // The installer does this too, but on a server first installed by a version
    // before the fix its folder, and the files already in it, carry the old
    // permissive entries; enforcing here re-propagates the protected DACL to every
    // child. On a fresh install it is a no-op. A test host's own folder keeps the
    // test's access, because the protected DACL names the process identity.
    ProtectedFolder.EnsureProtected(dataDirectory);

    // Runtime settings overlay (settings.json in the data directory), written
    // by the setup wizard: CA connection string and external URL. It lives in
    // the data directory so MSI upgrades cannot overwrite it, and is inserted
    // after appsettings so environment variables and command line still win.
    // An overlay the service cannot trust is not added; the verdict is logged
    // once the file logger exists, after Build (issue #489).
    var overlayTrust = builder.Configuration.AddSettingsOverlay(dataDirectory);

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

    // Anything about the pinned certificate an operator has to act on, carried to
    // the post Build block so it reaches the field log file (issue #471).
    string? httpsCertificateNotice = null;

    X509Certificate2? storeCertificate = null;
    if (string.IsNullOrEmpty(certPath) && !string.IsNullOrWhiteSpace(configuredThumbprint))
    {
        // Archived certificates are included because a renewal by Windows
        // autoenrolment archives the certificate it supersedes, and that archived
        // certificate is the only record of which subject and template to follow.
        // A plain open hides archived certificates (measured; see HttpsCertificateFollow,
        // which also says what about autoenrolment is still a belief).
        using var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        machineStore.Open(OpenFlags.ReadOnly | OpenFlags.IncludeArchived);
        var storeCertificates = machineStore.Certificates;

        var choice = HttpsCertificateFollow.Choose(
            configuredThumbprint,
            storeCertificates.Select(HttpsCertificateFollow.Describe).ToList(),
            DateTimeOffset.UtcNow);

        storeCertificate = choice.ServeThumbprint is null
            ? null
            : storeCertificates.First(c => string.Equals(
                c.Thumbprint, choice.ServeThumbprint, StringComparison.OrdinalIgnoreCase));
        foreach (var certificate in storeCertificates)
        {
            if (!ReferenceEquals(certificate, storeCertificate))
                certificate.Dispose();
        }

        switch (choice.Outcome)
        {
            case HttpsCertificateChoiceOutcome.Pinned:
                break;

            case HttpsCertificateChoiceOutcome.Followed:
            {
                // Record the successor where the settings page and the automatic
                // renewal read it, but only in the overlay, and only when the overlay
                // is what pinned the old one: a thumbprint set in an environment
                // variable or on the command line outranks the overlay and is left
                // for whoever set it.
                var repinNote = "settings.json was not changed, because it does not hold the old " +
                                "thumbprint; update Certus:HttpsCertificateThumbprint where it is set";
                const string thumbprintKey = "Certus:HttpsCertificateThumbprint";
                if (overlayTrust.IsTrusted
                    && SettingsOverlay.FindOutrankedKeys(builder.Configuration, [thumbprintKey]).Count == 0)
                {
                    var overlayPath = Path.Combine(dataDirectory, CertusPaths.SettingsOverlayFileName);
                    if (HttpsCertificateFollow.TryRepin(
                            overlayPath, choice.PinnedThumbprint, choice.ServeThumbprint!, out var repinFailure))
                    {
                        repinNote = "settings.json now records the new thumbprint";
                    }
                    else if (repinFailure is not null)
                    {
                        repinNote = $"recording the new thumbprint in settings.json failed: {repinFailure}";
                    }
                }

                // This boot serves the successor, so it is what the served thumbprint
                // reads as for the settings page and the automatic renewal, whatever
                // the overlay says.
                builder.Configuration[thumbprintKey] = choice.ServeThumbprint;
                httpsCertificateNotice =
                    $"{choice.Reason} {char.ToUpperInvariant(repinNote[0])}{repinNote[1..]}. " +
                    "A service that runs across a certificate's expiry keeps serving it until it restarts.";
                break;
            }

            case HttpsCertificateChoiceOutcome.ArchivedNoSuccessor:
                httpsCertificateNotice = choice.Reason;
                break;

            default:
                httpsCertificateNotice = choice.Reason + " Falling back to the self signed certificate.";
                break;
        }

        if (httpsCertificateNotice is not null)
            Log.Warning("{HttpsCertificateNotice}", httpsCertificateNotice);

        if (storeCertificate is not null)
        {
            httpsCertSelection = ("Store", storeCertificate.Thumbprint, storeCertificate.Subject);
            Log.Information(
                "HTTPS is using certificate {Thumbprint} ({Subject}, valid until {NotAfter:u}) " +
                "from LocalMachine\\My",
                storeCertificate.Thumbprint, storeCertificate.Subject,
                storeCertificate.NotAfter.ToUniversalTime());
        }
    }

    // The self signed fallback for lab and first boot use (issue #635). It is
    // loaded, or generated, when the host resolves Kestrel's options rather than
    // here, because the file is encrypted with the Data Protection keyring and
    // the keyring is a service of the built container. Measured on 2026-10-21:
    // that resolution happens inside Build(), after the data folder lock and
    // the file logger, before the placement refusals run, so the delegate below
    // checks the refusals itself. SelfSignedHttpsCertificate logs the thumbprint
    // it serves, and the outcome is kept for the post Build summary line.
    var usesSelfSignedFallback = string.IsNullOrEmpty(certPath) && storeCertificate is null;
    SelfSignedHttpsCertificate.Outcome? selfSignedFallback = null;
    if (usesSelfSignedFallback)
    {
        var selfSignedPath = Path.Combine(dataDirectory, SelfSignedHttpsCertificate.FileName);
        httpsCertSelection = ("SelfSigned", null, selfSignedPath);

        // Surface the fallback on every boot, not just first generation, so an
        // operator never unknowingly runs production on the self signed certificate.
        Log.Warning(
            "HTTPS is using the generated self signed certificate at {Path}. Configure " +
            "Kestrel:Endpoints:Https:Certificate:Path with a trusted certificate for production use.",
            selfSignedPath);
    }

    // Serilog
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .WriteTo.Console()
        .WriteTo.CertusLogFile(dataDirectory));

    // Configuration
    builder.Services.Configure<CertusOptions>(
        builder.Configuration.GetSection(CertusOptions.SectionName));

    // Certus:DatabasePath ships as null in appsettings and the binder applies that
    // null over the option initializer, so resolve it back to the default for every
    // IOptions<CertusOptions> consumer (StartupValidator, SetupService).
    builder.Services.PostConfigure<CertusOptions>(o => o.NormalizeDatabasePath());

    // Certus:ReleaseAgeWarningDays (issue #623), read by the Settings About
    // block only. Bound from the same section so the key sits beside the
    // other flat Certus keys; the binder ignores what each class lacks.
    builder.Services.Configure<ReleaseAgeOptions>(
        builder.Configuration.GetSection(CertusOptions.SectionName));

    builder.Services.AddSingleton(instanceMode);

    // Database
    var certusOptions = builder.Configuration
        .GetSection(CertusOptions.SectionName)
        .Get<CertusOptions>() ?? new CertusOptions();

    // Same resolution for the copy used to build the connection string below: an
    // empty Data Source opens a throwaway temporary database per connection, which
    // makes the startup migration fail with "no such table: __EFMigrationsHistory".
    certusOptions.NormalizeDatabasePath();

    // The database and the settings overlay belong in the data folder, the one folder
    // this host locks (issue #506). Decided here, from the copy every path below is built
    // from, and refused once the file logger exists, right after Build: nothing touches
    // the database folder before then.
    var placementRefusals = new[]
    {
        DataFolderPlacement.RefuseDatabase(certusOptions.DatabasePath, dataDirectory),
        DataFolderPlacement.RefuseSettingsOverlay(certusOptions.SettingsOverlayPath, dataDirectory),
    }.OfType<string>().ToArray();

    // The HTTPS defaults, once, for whichever certificate was chosen above: TLS
    // 1.2 and 1.3 only (issue #484), plus the certificate when the host resolved
    // one in code (the store certificate, or the self signed fallback). Only the
    // store branch used to configure HTTPS at all, so the self signed and
    // configured path endpoints never had a floor to inherit. One call, because
    // ConfigureHttpsDefaults keeps only the last delegate it was given. The
    // fallback is not loaded when the placement is refused: the host throws right
    // after Build, and loading it would create a keyring beside a database the
    // host is about to refuse (issue #506).
    builder.WebHost.ConfigureKestrel(kestrel =>
    {
        var serverCertificate = storeCertificate;
        if (usesSelfSignedFallback && placementRefusals.Length == 0)
        {
            var services = kestrel.ApplicationServices;
            selfSignedFallback = SelfSignedHttpsCertificate.Load(
                dataDirectory,
                services.GetRequiredService<IDataProtectionProvider>(),
                DateTimeOffset.UtcNow,
                services.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(SelfSignedHttpsCertificate)));
            serverCertificate = selfSignedFallback.Certificate;
        }

        HttpsProtocolPolicy.Apply(kestrel, serverCertificate);
    });

    // Built rather than formatted, so a path holding a semicolon cannot add a second
    // connection string keyword and open a database other than the one checked above.
    var connectionString = new SqliteConnectionStringBuilder { DataSource = certusOptions.DatabasePath }.ToString();
    builder.Services.AddDbContext<CertusDbContext>(dbOptions => dbOptions.UseSqlite(connectionString));

    // Write the write ahead log back into the database when the host stops
    // (issue #215). Registered before the other AddHostedService calls in this
    // file on purpose: hosted services stop in reverse registration order, so
    // first here means this one stops after the certificate sync, the expiry
    // monitor, and the challenge validation worker have finished writing.
    // Moving this line below any of them would checkpoint while they are still
    // committing. It orders this against those workers only; the framework
    // registers its own hosted services elsewhere, and a late write from one of
    // them would simply be checkpointed at process exit instead.
    builder.Services.AddHostedService<SqliteShutdownCheckpoint>();

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
        builder.Services.AddSingleton<ICaCrlReader>(new MockCrlReader());
        builder.Services.AddSingleton<IAdcsClientFactory, MockAdcsClientFactory>();
        builder.Services.AddSingleton<ICaDiscoveryService, MockCaDiscoveryService>();
        builder.Services.AddSingleton<IAdPrincipalLookup, MockAdPrincipalLookup>();
        builder.Services.AddSingleton<IServiceRightsProbe, MockServiceRightsProbe>();
        Log.Warning(
            "Certus:UseMockCa=true — using the mock ADCS client. Certificates are fake; " +
            "never use this in production");
    }
    else
    {
        builder.Services.AddSingleton<IAdcsClientFactory, AdcsClientFactory>();
        builder.Services.AddSingleton<ICaDiscoveryService, AdcsCaDiscoveryService>();
        builder.Services.AddSingleton<IAdPrincipalLookup, AdPrincipalLookup>();
        // Above the configured/unconfigured split, like the probe factory: the
        // wizard checks the service's rights before any CA is configured.
        builder.Services.AddSingleton<IServiceRightsProbe, AdcsServiceRightsProbe>();

        if (!string.IsNullOrEmpty(certusOptions.CaConnectionString))
        {
            builder.Services.AddAdcsClient();
            builder.Services.AddAdcsCrlReader();
            Log.Information("Using real ADCS client for CA: {Ca}", certusOptions.CaConnectionString);
        }
        else
        {
            builder.Services.AddUnconfiguredAdcsClient();
            builder.Services.AddSingleton<ICaCrlReader, UnconfiguredCrlReader>();
            Log.Warning(
                "No CA connection string configured — the service is unconfigured and CA " +
                "operations return 503 until setup completes");
        }
    }

    // Monitor mode's last line (issue #470): wraps whichever CA client and client
    // factory the branch above registered, so neither can submit or revoke. The
    // factory matters as much as the client, because the HTTPS enroller and the
    // wizard build their own clients through it. Full mode changes nothing here.
    builder.Services.AddMonitorModeCaWriteGuard(instanceMode);

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

    // The service rights check (issue #440): the wizard's and the Settings
    // page's answer to what this server's account may do on the CA. The probe
    // is registered with the ADCS client tri state above.
    builder.Services.AddScoped<ServiceRightsCheck>();
    builder.Services.AddSingleton<ServiceRightsReportCache>();

    // The paid module host (issue #413): after the app has started it loads the one paid
    // module on its own thread and exposes where the licence stands, never touching the
    // issuance path. Wired in both hosts; BothHostsWireTheModuleHostOnce checks it. The data
    // directory is the one resolved above, so the licence store and the module state and
    // journal live beside the database.
    builder.Services.AddCertusModuleHost(dataDirectory);

    // Automatic renewal of the server's own HTTPS certificate (issue #105).
    // The renewal core is shared with the settings page button. The hosted
    // service is registered as a singleton as well, the CertificateSyncService
    // pattern, so the settings API reads its last attempt off the instance the
    // loop writes. ServerCertificateIdentity keeps this certificate out of the
    // product's own expiry alerting.
    builder.Services.AddScoped<HttpsCertificateRenewalService>();
    builder.Services.AddSingleton<ServerCertificateIdentity>();
    builder.Services.AddSingleton<HttpsCertificateAutoRenewalService>();
    // The singleton stays in monitor mode, because SettingsController reads it; only
    // the loop goes, since every renewal is an enrolment (issue #470).
    if (!instanceMode.IsMonitor)
    {
        builder.Services.AddHostedService(sp =>
            sp.GetRequiredService<HttpsCertificateAutoRenewalService>());
    }

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
    builder.Services.AddWebhookAlertNotifier();
    builder.Services.AddHostedService<ExpiryMonitorService>();
    // The test send (issue #161). The throttle is a singleton because its whole
    // job is to hold the last send time across requests; the service that
    // consumes it is scoped like every other notifier consumer.
    builder.Services.AddSingleton<AlertTestThrottle>();
    builder.Services.AddScoped<AlertTestService>();

    // CRL monitoring (issue #447). It reads the CA's own CRLs over COM and the
    // rest from the distribution points named in the chain, so the fetcher needs
    // both halves: the typed HttpClient here and the directory reader that
    // AddAdcsCrlReader bound above. Registered whether or not a channel is
    // configured, because the card it fills is the whole feature on a free
    // install with no SMTP.
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

    // Licence alerts (issue #494). Registered in both modes, because an alert is
    // not a write to the CA. It reads the module host's verdict and never runs
    // module code; the host and the status source come from AddCertusModuleHost.
    builder.Services.AddHostedService<LicenceAlertService>();

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
    // Not in monitor mode (issue #470): ACME is off there, so there is nothing to
    // validate, and a validated order is one step from a CA write.
    if (!instanceMode.IsMonitor)
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
    // Not in monitor mode (issue #470): its leaf guard can revoke. An order the CA
    // held when the mode was switched waits in processing and is finished by the
    // first sweep after a switch back to full mode.
    if (!instanceMode.IsMonitor)
        builder.Services.AddHostedService<PendingIssuanceService>();

    // MVC controllers — discover from both Service and Web assemblies
    builder.Services.AddControllers()
        .AddApplicationPart(typeof(Certus.Web.Controllers.Acme.DirectoryController).Assembly);

    // Authentication and authorization (issue #27, SEC-F1) — Negotiate plus a
    // deny by default fallback policy; public routes are carved out explicitly
    builder.Services.AddCertusAuth(builder.Configuration);

    // The administrator audit trail (issue #634): every mutating dashboard API
    // action writes a row and a Warning log line that no setting can turn off.
    builder.Services.AddAdminAudit();

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
    // The data folder's volume is watched for free space (issue #632); the check
    // reports degraded below Certus:FreeSpaceWarningMegabytes and deletes nothing.
    builder.Services.AddDataFolderFreeSpaceMonitor(dataDirectory);
    // The daily retention pass and the per account erasure path (issue #637).
    // Periods come from Certus:Retention; 0 keeps a class for ever.
    builder.Services.AddDataRetention(builder.Configuration);
    builder.Services.AddHealthChecks()
        .AddCheck<CertusHealthCheck>("certus", tags: new[] { "ready" });

    var app = builder.Build();

    // First after Build, so the refusal reaches the log file through the catch below,
    // and before anything reads, creates or migrates in the database folder.
    if (placementRefusals.Length > 0)
        throw new InvalidOperationException(string.Join(" ", placementRefusals));

    // Which mode is in force (issue #470), through the file logger, which did not
    // exist when the mode was resolved.
    instanceMode.LogAtStartup(app.Logger);

    // The two configuration files a standard user could once take over (issue
    // #489). An untrusted one reads as absent wherever it is read, so the
    // service runs on without it, unconfigured for the overlay and with no
    // template exposed for the status file. This is the line that says so,
    // through the file logger, which did not exist when the overlay was added.
    var statusPath = SetupStatus.GetStatusPath(certusOptions);
    foreach (var (path, verdict, consequence) in new[]
    {
        (Path.Combine(dataDirectory, CertusPaths.SettingsOverlayFileName), overlayTrust,
            "none of its settings, the CA connection string among them, are in force"),
        (statusPath, TrustedFile.Check(statusPath),
            "the setup state in it is not in force, so no template is exposed over ACME"),
    })
    {
        if (verdict.IsTrusted)
            continue;
        app.Logger.LogCritical(
            "{Path} is being ignored because it cannot be trusted: {Reason}. Until it is " +
            "replaced, {Consequence}. Check what it contains, then delete it and run the setup " +
            "wizard again, or reset its owner and permissions as Troubleshooting describes under " +
            "\"The service ignores a configuration file\".",
            path, verdict.Reason, consequence);
    }

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

    // Bring the schema up to date. The database is in the data folder, which
    // EnsureProtected created and locked before anything else ran (issue #506).
    // The initializer migrates, adopts a pre migration database whose schema
    // matches the model, or fails fast with the documented reset message
    // (issue #77).
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
        instanceMode,
        app.Logger,
        app.Lifetime.ApplicationStopping));

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

    // One line per request, except a rate limited one (issue #741): see
    // CertusLogging.UseCertusRequestLogging, and keep it above the monitor mode gate.
    app.UseCertusRequestLogging();

    // Monitor mode (issue #470): every ACME protocol URL answers 404, here so the
    // request is still logged and nothing after this point runs for a refused
    // request, so no nonce is stored for it. Adds nothing in full mode.
    app.UseMonitorModeAcmeGate();

    app.UseRouting();

    // Authentication, authorization, and the CSRF header guard (issue #27)
    app.UseCertusAuth();

    // Monitor mode (issue #470): the ACME administration API answers 404, after
    // authorization so an anonymous caller still gets 401 like any other /api path.
    // Adds nothing in full mode.
    app.UseMonitorModeAdminApiGate();

    // Rate limiting — must be after routing so policies can match endpoints
    if (rateLimitOptions.Enabled)
    {
        app.UseRateLimiter();
    }

    // ACME nonce middleware: injects Replay-Nonce on /acme/ responses a
    // controller action produces. After the rate limiter on purpose (issue
    // #632): a 429 never reaches it, so a throttled flood stores no nonce, and
    // after routing so it can tell the protocol fallback's 404 apart from an
    // action's answer. Keep it below UseRateLimiter.
    app.UseMiddleware<Certus.Web.Middleware.AcmeNonceMiddleware>();

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
        httpsCertSelection.Source,
        httpsCertSelection.Thumbprint ?? selfSignedFallback?.Certificate.Thumbprint ?? "unknown",
        httpsCertSelection.Detail);

    // The fixed password PFX an earlier release kept goes on every boot, not
    // only when the fallback is served (issue #635): a server that moved to a
    // CA issued certificate still has the file, and the file is the key.
    SelfSignedHttpsCertificate.RemoveLegacyFile(dataDirectory, app.Logger);
    if (httpsCertificateNotice is not null)
        Log.Warning("{HttpsCertificateNotice}", httpsCertificateNotice);

    // And the TLS protocols beside it (issue #484). The floor can be replaced in
    // settings.json, and this line is the only place that shows whether it was.
    foreach (var endpoint in HttpsProtocolPolicy.Describe(app.Configuration))
    {
        if (HttpsProtocolPolicy.AdmitsBelowFloor(endpoint.Protocols))
        {
            Log.Warning(
                "Kestrel:Endpoints:{Endpoint}:SslProtocols lets the HTTPS endpoint negotiate " +
                "{Protocols}, below the TLS 1.2 floor this service otherwise sets. Remove the " +
                "setting to restore TLS 1.2 and TLS 1.3 only (issue #484)",
                endpoint.Name,
                endpoint.Protocols == System.Security.Authentication.SslProtocols.None
                    ? "None, which lets Windows choose, and a default install then accepts TLS 1.0 and TLS 1.1"
                    : endpoint.Protocols.ToString());
        }
        else
        {
            // As a string: the file sink renders an enum as JSON, in quotes.
            Log.Information(
                "HTTPS protocols for endpoint {Endpoint}: {Protocols} ({ProtocolSource})",
                endpoint.Name, endpoint.Protocols.ToString(),
                endpoint.NamedOnEndpoint
                    ? $"named in Kestrel:Endpoints:{endpoint.Name}:SslProtocols"
                    : "the service's floor");
        }
    }

    Log.Information("Ducks in a Row service started successfully");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Ducks in a Row service terminated unexpectedly");

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
