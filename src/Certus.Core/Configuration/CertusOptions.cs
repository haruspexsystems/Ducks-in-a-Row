namespace Certus.Core.Configuration;

/// <summary>
/// Root configuration options for Certus.
/// Bound from appsettings.json "Certus" section.
/// </summary>
public sealed class CertusOptions
{
    public const string SectionName = "Certus";

    /// <summary>
    /// The ADCS CA connection string in the format "CAHostName\CAName".
    /// When empty and <see cref="UseMockCa"/> is false, the service runs
    /// unconfigured: it serves the setup wizard while CA operations return
    /// 503 until a CA is connected.
    /// </summary>
    public string? CaConnectionString { get; set; }

    /// <summary>
    /// Explicitly select the mock ADCS client (development and demos only;
    /// certificates are fake). This is the only way to get the mock: an empty
    /// <see cref="CaConnectionString"/> no longer falls back to it, so a
    /// production install can never run against the mock unnoticed.
    /// Mutually exclusive with <see cref="CaConnectionString"/>.
    /// </summary>
    public bool UseMockCa { get; set; }

    /// <summary>
    /// Path to the SQLite database file.
    /// Defaults to ducks.db in the effective data directory
    /// (%ProgramData%\Ducks in a Row unless the installer chose another).
    /// </summary>
    public string DatabasePath { get; set; } = CertusPaths.DefaultDatabasePath;

    /// <summary>
    /// Resolve an unset <see cref="DatabasePath"/> back to the default under the
    /// data directory. The appsettings files ship the key as null so the code can
    /// choose the default, but the configuration binder applies that null over the
    /// property initializer above. An empty value leaves SQLite with "Data Source="
    /// which opens a private temporary database for each connection: the startup
    /// migration then fails because the history table one connection creates is
    /// invisible to the next, and nothing ever persists. Call this after binding so
    /// the DbContext, StartupValidator, and SetupService all see a real file path. A
    /// literal ":memory:" is left untouched so a caller can select an in memory
    /// database on purpose.
    /// </summary>
    public void NormalizeDatabasePath()
    {
        if (string.IsNullOrWhiteSpace(DatabasePath))
        {
            DatabasePath = CertusPaths.DefaultDatabasePath;
        }
    }

    /// <summary>
    /// Where the setup wizard persists the settings overlay. Null means the
    /// default (<see cref="CertusPaths.SettingsOverlayPath"/> in the data
    /// directory) — which is where the service host loads it from, so leave
    /// this unset in production. Tests redirect it to keep runs hermetic.
    /// </summary>
    public string? SettingsOverlayPath { get; set; }

    /// <summary>
    /// The base URL that ACME clients will use to reach this server.
    /// Used to construct ACME directory URLs.
    /// </summary>
    public string? ExternalUrl { get; set; }

    /// <summary>
    /// Thumbprint of the HTTPS certificate to serve from the LocalMachine\My
    /// store. Written by the setup wizard when it enrolls a certificate for
    /// this server from the connected CA. When unset, or when no matching
    /// certificate with a private key is found, the host falls back to the
    /// generated self signed certificate.
    /// </summary>
    public string? HttpsCertificateThumbprint { get; set; }

    /// <summary>
    /// The smallest sync interval the certificate sync service will honor. A
    /// configured <see cref="SyncIntervalMinutes"/> below this is floored to it.
    /// </summary>
    public const int MinSyncIntervalMinutes = 1;

    /// <summary>
    /// How often (in minutes) to sync the certificate inventory from the ADCS CA database.
    /// Defaults to 5 minutes so out of band CA changes (revocations in particular)
    /// reach the dashboard promptly.
    /// </summary>
    public int SyncIntervalMinutes { get; set; } = 5;

    /// <summary>
    /// Whether to enable SQLite WAL (Write-Ahead Logging) mode for better
    /// concurrent read/write performance. Defaults to true.
    /// Disable only if running on a filesystem that doesn't support WAL (e.g., some network shares).
    /// </summary>
    public bool EnableWalMode { get; set; } = true;
}
