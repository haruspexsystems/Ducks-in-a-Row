using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Setup;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// Custom WebApplicationFactory that gives each factory its own SQLite database
/// file in its temp data directory, so every scope in the host opens its own
/// connection to it (see ConfigureWebHost for why it is not a shared in memory
/// connection any more).
/// Rate limiting is disabled in tests to avoid false 429 failures.
/// Authentication is disabled (the escape hatch used only in Development); the auth
/// stack itself is covered by <see cref="AuthWebApplicationFactory"/>.
/// The data directory is redirected to a per-factory temp folder so the setup
/// status file (ducks-setup.json, written next to the database) does not
/// touch C:\ProgramData or leak state between runs. The temp folder is seeded
/// with a draft shaped status file enabling the mock CA's WebServer template,
/// because the template policy fails closed (issue #101); subclasses that need
/// a different set overwrite the seed (or delete it) after calling
/// base.ConfigureWebHost.
/// Auth:Mode is overridden through configuration, not DI, because AddCertusAuth
/// reads it straight from IConfiguration to decide whether to register the
/// Negotiate handler (which throws under TestServer). appsettings.json omits
/// Auth:Mode (the code default is Negotiate), so UseSetting supplies Disabled
/// without a key collision and is read before Program.cs.
/// </summary>
public class CertusWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _tempDataDir = Path.Combine(
        Path.GetTempPath(), "certus-tests-" + Guid.NewGuid().ToString("N"));

    // The Serilog logger of every host this factory built, each holding its log file
    // open. See Dispose.
    private readonly List<Serilog.ILogger> _hostLoggers = [];

    /// <summary>
    /// The per factory data directory the host is redirected to. Subclasses
    /// use it to seed files the service reads from the data directory, such
    /// as the wizard status file (ducks-setup.json).
    /// </summary>
    protected string TempDataDir => _tempDataDir;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Disable rate limiting for integration tests. The rate-limit Enabled
        // flag is absent from appsettings.json, so UseSetting (host configuration)
        // supplies it without a collision and is read before Program.cs.
        builder.UseSetting("Certus:RateLimiting:Enabled", "false");

        // Disable authentication for integration tests. AddCertusAuth reads
        // Auth:Mode straight from configuration to decide whether to register the
        // Negotiate handler, which throws under TestServer (it needs Kestrel).
        // appsettings.json omits Auth:Mode (the code default is Negotiate), so
        // UseSetting supplies Disabled without a key collision and is read before
        // Program.cs, exactly like the rate-limit flag above. The auth stack is
        // covered by AuthWebApplicationFactory, which flips the mode back to
        // Negotiate through DI and supplies a test scheme.
        builder.UseSetting(
            $"{AuthOptions.SectionName}:{nameof(AuthOptions.Mode)}", AuthOptions.ModeDisabled);

        // Keep the settings overlay out of the real data directory for the
        // manually bound options copy too. The PostConfigure below redirects
        // SettingsOverlayPath for every IOptions<CertusOptions> consumer, but
        // Program.cs binds its own copy from configuration before DI is built,
        // and the startup CA guard reads the overlay through that copy (issue
        // #305). Without this line the guard would read the real
        // ProgramData overlay, so a developer machine with a configured
        // installation on it would fail every web test at host startup.
        // Configuration, not DI, for the same reason as the two settings above.
        builder.UseSetting(
            $"{CertusOptions.SectionName}:{nameof(CertusOptions.SettingsOverlayPath)}",
            Path.Combine(_tempDataDir, "settings.json"));

        // Keep the development host's log files out of the machine's data directory
        // too. Its Serilog file sink writes under the resolved data directory, which
        // only this Development override moves (CertusDataDirectory, issue #413).
        // Without it every run of this suite wrote into
        // C:\ProgramData\Ducks in a Row\logs, beside an installed service's own logs.
        builder.UseSetting(CertusDataDirectory.DevelopmentKey, _tempDataDir);

        // Full mode, named rather than left unset (issue #470): with the key unset the
        // host would read the machine's registry, and a developer box with a monitor
        // mode install would turn every test here into a monitor mode test. The monitor
        // mode factories set it again after this, and the later value wins.
        builder.UseSetting(CertusInstanceMode.DevelopmentKey, CertusInstanceMode.FullValue);

        Directory.CreateDirectory(_tempDataDir);

        // The template policy fails closed (issue #101): with no wizard status
        // file, no template is exposed over ACME. Seed a draft shaped status
        // file enabling the mock CA's WebServer template so the ACME flow
        // tests can run. SetupCompleted stays false so the wizard tests still
        // exercise real completion; completing writes the same ["WebServer"]
        // set back, so the enabled set is identical whichever order the shared
        // collection runs in. Subclass factories that need different wizard
        // state overwrite this file (or delete it) after base.ConfigureWebHost.
        new SetupStatus { EnabledTemplates = ["WebServer"] }
            .Save(Path.Combine(_tempDataDir, SetupStatus.FileName));

        builder.ConfigureServices(services =>
        {
            // Remove the existing DbContext registration (added by Program.cs)
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<CertusDbContext>));
            if (descriptor != null)
                services.Remove(descriptor);

            // A file database rather than a shared in memory connection.
            //
            // "Data Source=:memory:" only survives while a connection stays
            // open, so it forces every scope in the host onto one shared
            // SqliteConnection. That connection then has to carry the
            // background workers and the request pipeline at once, and a
            // worker writing while a request writes intermittently fails with
            // "database is locked". The certificate sync is the worker that
            // makes it bite: OrderService.RevokeCertificateAsync fires the sync
            // trigger the moment a revocation lands, so the sync starts writing
            // exactly while the next request is in flight.
            //
            // A file gives every scope its own connection and lets SQLite's own
            // locking, with the driver's default busy timeout, arbitrate the
            // race. DeviceAttestWebApplicationFactory already did this for the
            // same reason; this lifts it to the shared factory so every web
            // test gets it. The file lives in the temp data directory this
            // factory already cleans up.
            var databasePath = Path.Combine(_tempDataDir, "web-tests.db");
            services.AddDbContext<CertusDbContext>(options =>
                options.UseSqlite($"Data Source={databasePath}"));

            services.PostConfigure<CertusOptions>(o =>
            {
                // The file the DbContext above opens, so anything that reads the
                // option rather than the context names the same database.
                o.DatabasePath = databasePath;
                // Keep the setup wizard's settings overlay out of the real
                // ProgramData data directory.
                o.SettingsOverlayPath = Path.Combine(_tempDataDir, "settings.json");
            });

            // Keep the Data Protection keyring off the disk: the hosts persist
            // keys next to the database, and the manually bound options copy in
            // Program.cs resolves that to the real data directory before this
            // factory can redirect it. The ephemeral provider replaces the file
            // backed keyring entirely, so EAB secrets round trip in memory and
            // nothing under ProgramData is touched.
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
        });
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
        if (disposing)
        {
            // The pooled connections to the file and the host's file logger both
            // hold files in the folder open, so the delete below fails until they
            // are closed. Serilog closes a host's logger only through the static
            // one, and hosts here can overlap: three classes in the ACME collection
            // boot their own host while the collection's host is alive, and the
            // later boot replaces the static logger. The earlier host's file then
            // stayed open until the process ended, and its folder was left behind
            // (measured on 2026-10-02). So each factory closes the loggers its own
            // hosts built; closing one twice is harmless.
            lock (_hostLoggers)
            {
                foreach (var logger in _hostLoggers)
                    (logger as IDisposable)?.Dispose();
            }
            SqliteConnection.ClearAllPools();
            for (var attempt = 1; attempt <= 5; attempt++)
            {
                try
                {
                    Directory.Delete(_tempDataDir, recursive: true);
                    break;
                }
                catch (DirectoryNotFoundException)
                {
                    break;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Best effort: a stray temp folder is harmless.
                    if (attempt < 5)
                        Thread.Sleep(200);
                }
            }
        }
    }
}
