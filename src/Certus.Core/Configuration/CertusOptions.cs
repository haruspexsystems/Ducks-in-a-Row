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
    /// The CA name half of <see cref="CaConnectionString"/>, for display in
    /// the dashboard headers (issue #157). The whole string when it has no
    /// backslash or an empty name half, null when nothing is configured
    /// (appsettings ships the key as explicit JSON null). Pure string
    /// parsing: it never contacts the CA, so the name renders exactly when
    /// the CA is unreachable and the header needs it most.
    /// </summary>
    public string? CaDisplayName
    {
        get
        {
            var value = CaConnectionString?.Trim();
            if (string.IsNullOrEmpty(value))
                return null;
            var separator = value.IndexOf('\\');
            if (separator < 0)
                return value;
            var name = value[(separator + 1)..].Trim();
            return name.Length > 0 ? name : value;
        }
    }

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
    /// Whether the server's own HTTPS certificate is re enrolled automatically
    /// as it nears expiry (issue #105). The renewal never restarts the host by
    /// itself: it swaps the overlay thumbprint and the dashboard offers the
    /// restart that applies it.
    ///
    /// None of the three renewal keys below appear in appsettings.json on
    /// purpose. Keys that ship there as an explicit JSON null have that null
    /// applied over the C# initializer by the configuration binder (see
    /// <see cref="NormalizeDatabasePath"/> for what that once cost), so
    /// leaving them out is what makes these initializers the real defaults.
    /// </summary>
    public bool HttpsCertificateAutoRenewalEnabled { get; set; } = true;

    /// <summary>
    /// How close to expiry (in days) the server's own HTTPS certificate is
    /// renewed. Defaults to 30, matching the self signed certificate's
    /// renewal window in the service host. The effective window is capped at
    /// a third of the certificate's own validity, so a short lived template
    /// does not renew on every check.
    /// </summary>
    public int HttpsCertificateRenewalWindowDays { get; set; } = 30;

    /// <summary>
    /// How often (in hours) the renewal check runs. Daily by default: the
    /// certificate lives for a year or two, and a failed attempt has the whole
    /// renewal window to retry in.
    /// </summary>
    public int HttpsCertificateRenewalCheckIntervalHours { get; set; } = 24;

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
    /// How far back the certificate sync reaches for pending, denied, and
    /// failed requests, in days. Issued and revoked certificates are always
    /// synced in full; only these three request dispositions are bounded,
    /// because they accumulate without limit on a busy CA while an admin only
    /// ever chases a request that is stuck now.
    /// Set to 0 to skip those three passes entirely and sync only issued and
    /// revoked certificates, which is the behaviour before issue #151.
    /// </summary>
    public int RequestHistoryDays { get; set; } = 30;

    /// <summary>
    /// Whether the database uses SQLite WAL (Write-Ahead Logging) mode, for
    /// better concurrent read/write performance. Defaults to true. Turn it off
    /// on a filesystem that cannot support WAL, which needs shared memory and so
    /// rules out most network shares, or when a backup agent, scanner, or
    /// replication tool needs a database with no permanent sidecar files.
    ///
    /// Journal mode lives in the database file, not in configuration. This
    /// option is a request made once per start against a file that already has
    /// an answer, and it is applied in both directions: turning it off converts
    /// an existing database back to rollback journalling and removes the
    /// <c>-wal</c> and <c>-shm</c> sidecars. Before issue #283 only the on
    /// direction was applied, so turning the option off changed nothing at all
    /// on an existing install.
    ///
    /// Either direction can be refused, because changing journal mode needs the
    /// database file exclusively and anything else holding it open prevents
    /// that. A refusal is logged as a warning and retried on the next start; it
    /// never stops the service. Read <c>SQLite journal mode</c> in the startup
    /// log for what the database actually is, rather than inferring it from this
    /// setting: the log line reports the mode the database itself reports.
    ///
    /// Moving the data directory to a share needs the conversion to happen
    /// first, while the database is still somewhere WAL works. A database
    /// already in WAL mode will not open on a filesystem that cannot support
    /// WAL, so there is no start on which this option could convert it. The
    /// order is: set this to false, restart, confirm the logged mode is
    /// <c>delete</c>, stop the service, move the data directory, start.
    ///
    /// The off state is <c>delete</c> specifically, which is SQLite's own
    /// default, so a converted database is indistinguishable from one created
    /// with this option already off. A database somebody had deliberately put in
    /// <c>truncate</c> or <c>persist</c> is converted to <c>delete</c> as well.
    /// </summary>
    public bool EnableWalMode { get; set; } = true;
}
