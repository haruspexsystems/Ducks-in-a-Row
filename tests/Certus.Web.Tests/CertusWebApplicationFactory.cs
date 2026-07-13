using Certus.Core.Configuration;
using Certus.Core.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Custom WebApplicationFactory that provides a shared in-memory SQLite database
/// for integration testing. The shared connection stays open for the lifetime
/// of the factory, ensuring all scopes share the same database instance.
/// Rate limiting is disabled in tests to avoid false 429 failures.
/// Authentication is disabled (the escape hatch used only in Development); the auth
/// stack itself is covered by <see cref="AuthWebApplicationFactory"/>.
/// The data directory is redirected to a per-factory temp folder so the setup
/// status file (ducks-setup.json, written next to the database) does not
/// touch C:\ProgramData or leak state between runs.
/// Auth:Mode is overridden through configuration, not DI, because AddCertusAuth
/// reads it straight from IConfiguration to decide whether to register the
/// Negotiate handler (which throws under TestServer). appsettings.json omits
/// Auth:Mode (the code default is Negotiate), so UseSetting supplies Disabled
/// without a key collision and is read before Program.cs.
/// </summary>
public class CertusWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly SqliteConnection _connection = CreateOpenConnection();

    private readonly string _tempDataDir = Path.Combine(
        Path.GetTempPath(), "certus-tests-" + Guid.NewGuid().ToString("N"));

    /// <summary>
    /// The per factory data directory the host is redirected to. Subclasses
    /// use it to seed files the service reads from the data directory, such
    /// as the wizard status file (ducks-setup.json).
    /// </summary>
    protected string TempDataDir => _tempDataDir;

    private static SqliteConnection CreateOpenConnection()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        return connection;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // The shared SQLite connection (Data Source=:memory:) is created once in the
        // field initializer so WithWebHostBuilder, which re-invokes ConfigureWebHost,
        // cannot orphan an earlier connection.

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

        Directory.CreateDirectory(_tempDataDir);

        builder.ConfigureServices(services =>
        {
            // Remove the existing DbContext registration (added by Program.cs)
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<CertusDbContext>));
            if (descriptor != null)
                services.Remove(descriptor);

            // Re-register with our shared connection
            services.AddDbContext<CertusDbContext>(options =>
                options.UseSqlite(_connection));

            services.PostConfigure<CertusOptions>(o =>
            {
                o.DatabasePath = Path.Combine(_tempDataDir, "certus.db");
                // Keep the setup wizard's settings overlay out of the real
                // ProgramData data directory.
                o.SettingsOverlayPath = Path.Combine(_tempDataDir, "settings.json");
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _connection.Dispose();
            try
            {
                Directory.Delete(_tempDataDir, recursive: true);
            }
            catch (IOException)
            {
                // Best effort: a stray temp folder is harmless.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
