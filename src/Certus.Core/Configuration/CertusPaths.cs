using System.Security;
using Microsoft.Win32;

namespace Certus.Core.Configuration;

/// <summary>
/// Shared filesystem paths and sentinels for Certus, defined once so the
/// in-memory database marker and the data directory resolution are not
/// repeated as literals across configuration, validation, and host wiring.
///
/// The data directory holds everything the service writes at runtime: the
/// SQLite database, logs, the setup status file, the settings overlay, and
/// the self signed HTTPS certificate. The installer lets the administrator
/// choose it and records the choice in the registry; without that value the
/// default under %ProgramData% is used.
/// </summary>
public static class CertusPaths
{
    /// <summary>
    /// SQLite connection sentinel selecting a private in-memory database. Data is
    /// lost on restart; used by tests and warned about by StartupValidator.
    /// </summary>
    public const string InMemoryDatabase = ":memory:";

    /// <summary>
    /// The HKLM registry key the MSI installer writes its choices to.
    /// </summary>
    public const string InstallerRegistryKey = @"SOFTWARE\Haruspex Systems\Ducks in a Row";

    /// <summary>
    /// The registry value under <see cref="InstallerRegistryKey"/> holding the
    /// administrator chosen data directory.
    /// </summary>
    public const string DataDirectoryValueName = "DataDirectory";

    /// <summary>
    /// The file name of the runtime settings overlay written by the setup
    /// wizard into the data directory.
    /// </summary>
    public const string SettingsOverlayFileName = "settings.json";

    /// <summary>
    /// The default data directory under %ProgramData% on Windows. A property
    /// rather than a const because Environment.GetFolderPath resolves at
    /// runtime. Renamed from "Certus" with the product rebrand; existing
    /// installs get a clean break (the old directory is left untouched and
    /// documented for removal).
    /// </summary>
    public static string DefaultDataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Ducks in a Row");

    /// <summary>
    /// The effective data directory: the installer chosen directory from the
    /// registry when present, otherwise <see cref="DefaultDataDirectory"/>.
    /// The registry is read once per process: every consumer (database path,
    /// logs, overlay, setup files) must see one consistent directory, and the
    /// value only changes at install time anyway.
    /// </summary>
    public static string DataDirectory =>
        InstallerDataDirectory.Value ?? DefaultDataDirectory;

    private static readonly Lazy<string?> InstallerDataDirectory = new(ReadInstallerDataDirectory);

    /// <summary>
    /// The default SQLite database path, inside the effective data directory.
    /// </summary>
    public static string DefaultDatabasePath => Path.Combine(DataDirectory, "ducks.db");

    /// <summary>
    /// The runtime settings overlay path, inside the effective data directory.
    /// </summary>
    public static string SettingsOverlayPath => Path.Combine(DataDirectory, SettingsOverlayFileName);

    private static string? ReadInstallerDataDirectory()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(InstallerRegistryKey);
            return NormalizeDataDirectory(key?.GetValue(DataDirectoryValueName) as string);
        }
        catch (SecurityException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Normalize a registry sourced directory value. MSI directory properties
    /// resolve with a trailing backslash; strip it so Path.Combine produces
    /// clean paths. Null, empty, and whitespace collapse to null (use default).
    /// </summary>
    internal static string? NormalizeDataDirectory(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var trimmed = value.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }
}
