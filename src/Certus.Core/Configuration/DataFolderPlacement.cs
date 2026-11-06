namespace Certus.Core.Configuration;

/// <summary>
/// Keeps the database and the settings overlay in the data folder, and refuses to start
/// the service when configuration puts either of them anywhere else (issue #506).
///
/// <para>The data folder is the one folder whose permissions the service decides: the
/// installer locks it to SYSTEM and Administrators, and the service re-applies that lock
/// on every start (<see cref="Security.ProtectedFolder.EnsureProtected"/>). The database
/// does not travel alone. <c>ducks-setup.json</c> and the Data Protection keyring, which
/// protects the EAB secrets and the saved SMTP password, both follow the database's
/// folder. Of the three, only the status file is checked before it is read, so a database
/// folder that someone other than an administrator can write puts ACME state and stored
/// secrets in their hands. Locking an administrator's chosen folder on every start was
/// weighed and rejected: it would strip any grant the administrator meant to keep, and on
/// a network share it would name the file server's own SYSTEM rather than this server.
/// Moving the whole data folder (the installer's DATAFOLDER, or the DataDirectory registry
/// value) remains the supported way to keep the data on another disk.</para>
///
/// <para>The settings overlay is refused for a different reason. The service reads it from
/// the data folder only, before the options that name it are bound, while the wizard and
/// the Settings page write to <see cref="CertusOptions.SettingsOverlayPath"/>. Any other
/// value splits the two: settings saved from the dashboard land in a file the next start
/// ignores.</para>
///
/// <para>Only the Windows service host applies this. The development host and the tests
/// keep these keys to put their files in a temporary folder.</para>
/// </summary>
public static class DataFolderPlacement
{
    /// <summary>The Troubleshooting heading both refusals point at.</summary>
    public const string TroubleshootingHeading =
        "The service will not start: a file is outside the data folder";

    /// <summary>
    /// Why the service refuses <paramref name="databasePath"/>, or null when the database
    /// is in <paramref name="dataDirectory"/>. Pass the path after
    /// <see cref="CertusOptions.NormalizeDatabasePath"/>. The in memory database has no
    /// folder and is allowed. A path that is not fully qualified is refused rather than
    /// resolved, because it would land wherever the process happened to start.
    /// </summary>
    public static string? RefuseDatabase(string databasePath, string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        if (databasePath == CertusPaths.InMemoryDatabase)
            return null;

        var dataFolder = FullFolder(dataDirectory);
        var echoedDataFolder = Echo(dataFolder);
        var full = FullPathOrNull(databasePath);
        if (full is null || Path.GetFileName(full).Length == 0)
        {
            return $"Certus:DatabasePath is '{Echo(databasePath)}', which is not a full path to a " +
                $"file. The database must be in the data folder, '{echoedDataFolder}'. " +
                DatabaseRemedy(echoedDataFolder);
        }

        var folder = Path.TrimEndingDirectorySeparator(Path.GetDirectoryName(full) ?? full);
        if (SamePath(folder, dataFolder))
            return null;

        return $"Certus:DatabasePath is '{Echo(databasePath)}', which puts the database in " +
            $"'{Echo(folder)}', outside the data folder '{echoedDataFolder}'. The database, the " +
            "ducks-setup.json beside it and the keys folder that protects stored secrets must " +
            "be in the data folder, the one folder the service keeps locked to SYSTEM and " +
            "Administrators. " + DatabaseRemedy(echoedDataFolder);
    }

    /// <summary>
    /// Why the service refuses <paramref name="overlayPath"/>, or null when it is unset or
    /// names the settings file in <paramref name="dataDirectory"/>, the only one the
    /// service reads.
    /// </summary>
    public static string? RefuseSettingsOverlay(string? overlayPath, string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        if (overlayPath is null)
            return null;

        var expected = Path.Combine(FullFolder(dataDirectory), CertusPaths.SettingsOverlayFileName);
        var echoedExpected = Echo(expected);
        var full = FullPathOrNull(overlayPath);
        if (full is not null && SamePath(full, expected))
            return null;

        return $"Certus:SettingsOverlayPath is '{Echo(overlayPath)}', but the service reads its " +
            $"settings only from '{echoedExpected}', so settings saved from the dashboard would land in a " +
            "file the next start ignores. Remove Certus:SettingsOverlayPath wherever it is set " +
            "(appsettings.json, an environment variable or the command line), and if the file it " +
            $"names holds settings you need, copy them into '{echoedExpected}' as an administrator. " +
            $"Troubleshooting covers this under \"{TroubleshootingHeading}\".";
    }

    private static string DatabaseRemedy(string dataFolder) =>
        "Stop the service, check who owns the files, then as an administrator copy ducks.db " +
        "(with ducks.db-wal and ducks.db-shm if they are there), ducks-setup.json and the keys " +
        $"folder into '{dataFolder}' and delete the originals. Remove Certus:DatabasePath " +
        "wherever it is set (settings.json, appsettings.json, an environment variable or the " +
        "command line), then start the service. To keep the data on another disk, move the " +
        $"whole data folder instead. Troubleshooting covers both under \"{TroubleshootingHeading}\".";

    private static string FullFolder(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static string? FullPathOrNull(string path)
    {
        if (!Path.IsPathFullyQualified(path))
            return null;

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    // Windows paths compare without regard to case. A short (8.3) name or a \\?\ prefix
    // is not expanded, so it reads as a different folder and is refused: the message names
    // both paths, which makes the fix obvious.
    private static bool SamePath(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    // Configuration values reach the log through this message, so nothing in one may break
    // the line it is written on.
    private static string Echo(string value) =>
        string.Concat(value.Select(c => char.IsControl(c) ? '?' : c));
}
