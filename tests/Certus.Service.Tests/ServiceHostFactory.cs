using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Acme.Services;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Setup;
using Certus.Core.Tests.Acme.Attestation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Certus.Service.Tests;

/// <summary>
/// Boots the real Windows service host, DucksInARow.Service, in a TestServer, where
/// Certus.Web.Tests boots the development host. The two hosts register different services
/// (the real ADCS client switch, the Windows service restarter, the machine certificate
/// store, the settings overlay), so a claim about the product has to be proven here.
///
/// <para>Everything the host writes lands in one temporary data directory, which the
/// factory deletes on disposal:</para>
/// <list type="bullet">
/// <item>The Development data directory override (<see cref="CertusDataDirectory"/>)
/// moves the settings overlay, the self signed certificate and the log files there.
/// Without it the host would load the machine's overlay, so a dev box with a configured
/// install would hand it a real CA connection string.</item>
/// <item>The database and the wizard status file go there through their own keys.</item>
/// <item>Data Protection is ephemeral, and the machine certificate store is replaced with
/// the no-op one, so nothing reaches DPAPI or LocalMachine\My.</item>
/// </list>
///
/// <para>Every setting reaches the host through <c>UseSetting</c>, which
/// WebApplicationFactory hands the entry point as command line arguments. Those outrank
/// the service's own appsettings.json, which matters here because two of them (Auth:Mode
/// and Auth:RequireHttps) are set there too; a test proves the precedence rather than
/// assuming it.</para>
/// </summary>
public class ServiceHostFactory : WebApplicationFactory<ServiceHostEntryPoint>
{
    /// <summary>The template the seeded wizard status file enables, the mock CA's WebServer.</summary>
    public const string Template = "WebServer";

    /// <summary>The temporary data directory this host writes everything to.</summary>
    public string DataDirectory { get; } =
        Path.Combine(Path.GetTempPath(), "ducks-service-tests-" + Guid.NewGuid().ToString("N"));

    /// <summary>
    /// The host's database, inside <see cref="DataDirectory"/>. Virtual so a test can put it
    /// somewhere the service host refuses (issue #506).
    /// </summary>
    public virtual string DatabasePath => Path.Combine(DataDirectory, "ducks.db");

    /// <summary>
    /// The settings overlay path the host is given, the data directory's own file. Virtual
    /// for the same reason as <see cref="DatabasePath"/>.
    /// </summary>
    public virtual string SettingsOverlayPath => Path.Combine(DataDirectory, CertusPaths.SettingsOverlayFileName);

    // The Serilog logger of every host this factory built, each holding its log file
    // open. See Dispose.
    private readonly List<Serilog.ILogger> _hostLoggers = [];

    /// <summary>
    /// Writes files the host reads while it boots, before it boots. The base seeds nothing
    /// beyond the wizard status file.
    /// </summary>
    protected virtual void SeedDataDirectory(string dataDirectory)
    {
    }

    /// <summary>
    /// Whether the factory names <see cref="DataDirectory"/> through <c>UseSetting</c>,
    /// which outranks every other configuration source. A test that needs the folder named
    /// by a weaker source sets this false and names it itself.
    /// </summary>
    protected virtual bool NamesDataDirectoryAsSetting => true;

    /// <summary>
    /// The instance mode the host boots in (issue #470), through the Development key,
    /// which outranks the registry. Full unless a subclass says otherwise, and named
    /// rather than left unset, because an unset key falls back to the machine's
    /// registry, which a test must never depend on. Null leaves the key to a weaker
    /// source, for the one test that needs that.
    /// </summary>
    protected virtual string? InstanceMode => CertusInstanceMode.FullValue;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // The override is honoured only here, and WebApplicationFactory's default is this
        // environment anyway; saying it keeps the dependency visible.
        builder.UseEnvironment(Environments.Development);

        if (NamesDataDirectoryAsSetting)
            builder.UseSetting(CertusDataDirectory.DevelopmentKey, DataDirectory);
        builder.UseSetting(Key(nameof(CertusOptions.DatabasePath)), DatabasePath);
        builder.UseSetting(Key(nameof(CertusOptions.SettingsOverlayPath)), SettingsOverlayPath);
        builder.UseSetting(Key(nameof(CertusOptions.UseMockCa)), "true");
        if (InstanceMode is not null)
            builder.UseSetting(CertusInstanceMode.DevelopmentKey, InstanceMode);
        builder.UseSetting("Certus:RateLimiting:Enabled", "false");

        // Both are in the service's appsettings.json as Negotiate and true. AddCertusAuth
        // reads Auth:Mode from configuration before the container is built, and the
        // Negotiate handler cannot run under TestServer, so these have to win there.
        builder.UseSetting($"{AuthOptions.SectionName}:{nameof(AuthOptions.Mode)}", AuthOptions.ModeDisabled);
        builder.UseSetting($"{AuthOptions.SectionName}:{nameof(AuthOptions.RequireHttps)}", "false");

        // The template policy fails closed (issue #101): with no wizard status file, no
        // template is exposed over ACME.
        Directory.CreateDirectory(DataDirectory);
        new SetupStatus { EnabledTemplates = [Template] }
            .Save(Path.Combine(DataDirectory, SetupStatus.FileName));
        SeedDataDirectory(DataDirectory);

        builder.ConfigureServices(services =>
        {
            services.AddDataProtection().UseEphemeralDataProtectionProvider();

            services.RemoveAll<IHttpsCertificateStore>();
            services.AddSingleton<IHttpsCertificateStore, NoOpHttpsCertificateStore>();

            // The device flow runs through the background validation worker, and its
            // production sweep of five seconds would put dead time into every test.
            services.PostConfigure<ChallengeValidationOptions>(o => o.PollIntervalSeconds = 0.2);
        });
    }

    /// <summary>
    /// Seeds an enabled device attestation profile in open mode for <see cref="Template"/>,
    /// and the synthetic root as a custom trust anchor (the embedded Apple root refuses
    /// synthetic chains, which is its job).
    /// </summary>
    public async Task SeedOpenDeviceProfileAsync(X509Certificate2 root)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        db.DeviceAttestationProfiles.Add(new DeviceAttestationProfile
        {
            TemplateId = Template,
            Enabled = true,
            GateMode = DeviceAttestationGateModes.Open,
            CsrIdentifierBinding = CsrIdentifierBindingModes.CnOrSan,
        });
        db.AttestationTrustAnchors.Add(new AttestationTrustAnchor
        {
            Format = "apple",
            Name = "synthetic test root",
            CertificatePem = SyntheticAttestationBuilder.ToPem(root),
            Sha256Fingerprint = Convert.ToHexString(SHA256.HashData(root.RawData)).ToLowerInvariant(),
            Enabled = true,
        });
        await db.SaveChangesAsync();
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);
        // Building the host made its logger the static Serilog logger, and only one
        // host boots at a time, so this is a logger this factory has to close. A list,
        // because a factory derived with WithWebHostBuilder builds its host through this
        // method too, and keeping only the latest lost the parent's own logger.
        lock (_hostLoggers)
            _hostLoggers.Add(Serilog.Log.Logger);
        return host;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing)
            return;

        // The host's file logger and its pooled database connections both hold files in
        // the data directory open. Serilog closes a host's logger only through the static
        // one, which a later host's boot replaces, so a host that outlived another's boot
        // kept its file open until the process ended (measured in Certus.Web.Tests on
        // 2026-10-02). So close the loggers this factory's hosts built; closing one twice
        // is harmless.
        lock (_hostLoggers)
        {
            foreach (var logger in _hostLoggers)
                (logger as IDisposable)?.Dispose();
        }
        SqliteConnection.ClearAllPools();

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                Directory.Delete(DataDirectory, recursive: true);
                return;
            }
            catch (DirectoryNotFoundException)
            {
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException && attempt < 5)
            {
                Thread.Sleep(200);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best effort: a stray temporary folder is harmless.
                return;
            }
        }
    }

    private static string Key(string option) => $"{CertusOptions.SectionName}:{option}";
}
