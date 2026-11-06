using System.Security;
using Certus.Core.Adcs;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Certus.Core.Configuration;

/// <summary>What the whole instance is allowed to do with its CA (issue #470).</summary>
public enum InstanceMode
{
    /// <summary>Issuance over ACME, revocation and every read. The default.</summary>
    Full,

    /// <summary>
    /// Reads only: the inventory sync, expiry alerts and CRL watching. No ACME, no
    /// issuance and no revocation, so the service never writes to the CA.
    /// </summary>
    Monitor,
}

/// <summary>
/// The instance mode this process runs in, resolved once at startup (issue #470).
///
/// It lives in the registry value <see cref="CertusPaths.ModeValueName"/> next to
/// <see cref="CertusPaths.DataDirectoryValueName"/>, which the installer writes and
/// only a local administrator can change. It is deliberately never read from
/// configuration in production: appsettings.json is replaced by every upgrade, and
/// settings.json (the overlay) is written by the dashboard, while this switch must stay
/// out of the browser's reach, the stance #148 takes for the SMTP password. A restart
/// applies a change.
///
/// The vocabulary is <c>monitor</c> and <c>full</c>, compared after trimming and
/// without regard to case. An absent or blank value means full, so monitor mode is an
/// explicit opt in and an install that never chose stays exactly as it was. Any other
/// value is refused rather than guessed at: the issue's first draft read every
/// unrecognised value as full, which would let a mistyped "monitr" silently re-enable
/// issuance and revocation on a CA whose team had been promised neither. A value that
/// cannot be honoured is reported through <see cref="InvalidReason"/>; the host
/// registers its services as for monitor mode, the side that never writes, and
/// <see cref="Certus.Core.Security.StartupValidator"/> refuses to start. The refusal waits for the
/// validator because before the host is built only the console logger exists, and a
/// Windows service would write the reason nowhere anyone could read it.
///
/// In Development, and only there, <see cref="DevelopmentKey"/> overrides the registry
/// when it is set. That is what lets a test boot either mode, so every test factory sets
/// it, which also keeps the tests deterministic on a developer box whose registry
/// carries a value from a real install. When the key is not set the registry is read,
/// exactly as <see cref="CertusDataDirectory"/> falls back: an earlier draft read
/// nothing in Development, so a monitor mode install started in Development (the only
/// environment that allows Auth:Mode=Disabled, so the one a troubleshooting
/// administrator reaches for) ran in full mode with no warning. Each host resolves this
/// before it adds the settings overlay, so the overlay can never supply it.
/// </summary>
public sealed class CertusInstanceMode
{
    /// <summary>The configuration key a Development host reads its mode from.</summary>
    public const string DevelopmentKey = "Certus:Development:Mode";

    /// <summary>The value that selects monitor mode.</summary>
    public const string MonitorValue = "monitor";

    /// <summary>The value that selects full mode, which an absent value also means.</summary>
    public const string FullValue = "full";

    /// <summary>Where the mode came from, for the startup log line.</summary>
    public const string RegistrySource = @"HKLM\" + CertusPaths.InstallerRegistryKey + @"\" + CertusPaths.ModeValueName;

    private CertusInstanceMode(InstanceMode mode, string source, string? invalidReason)
    {
        Mode = mode;
        Source = source;
        InvalidReason = invalidReason;
    }

    /// <summary>Full mode, as an install that never chose runs.</summary>
    public static CertusInstanceMode Full { get; } = new(InstanceMode.Full, "default", null);

    /// <summary>Monitor mode, for tests and for hosts built outside the resolver.</summary>
    public static CertusInstanceMode Monitor { get; } = new(InstanceMode.Monitor, "default", null);

    /// <summary>
    /// The mode the host runs in. Monitor when the configured value cannot be honoured,
    /// so that whatever runs before the startup refusal never writes to the CA.
    /// </summary>
    public InstanceMode Mode { get; }

    /// <summary>True in monitor mode, including the refused case.</summary>
    public bool IsMonitor => Mode == InstanceMode.Monitor;

    /// <summary>The registry value, or the Development key, the mode was read from.</summary>
    public string Source { get; }

    /// <summary>Why the configured value cannot be honoured, or null when it can.</summary>
    public string? InvalidReason { get; }

    /// <summary>The wire form the dashboard API reports: <c>full</c> or <c>monitor</c>.</summary>
    public string WireName => IsMonitor ? MonitorValue : FullValue;

    /// <summary>
    /// The mode for this host: <see cref="DevelopmentKey"/> when the host runs in
    /// Development and the key is set, otherwise the registry.
    /// </summary>
    public static CertusInstanceMode Resolve(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        if (environment.IsDevelopment() && !string.IsNullOrWhiteSpace(configuration[DevelopmentKey]))
            return Parse(configuration[DevelopmentKey], DevelopmentKey);

        return ReadRegistry();
    }

    /// <summary>
    /// Reads one configured value. Null, empty and blank mean full; otherwise the
    /// trimmed value must be <see cref="MonitorValue"/> or <see cref="FullValue"/>,
    /// ignoring case, and anything else is invalid.
    /// </summary>
    public static CertusInstanceMode Parse(string? value, string source)
    {
        if (string.IsNullOrWhiteSpace(value))
            return new CertusInstanceMode(InstanceMode.Full, source, null);

        var trimmed = value.Trim();
        if (string.Equals(trimmed, MonitorValue, StringComparison.OrdinalIgnoreCase))
            return new CertusInstanceMode(InstanceMode.Monitor, source, null);
        if (string.Equals(trimmed, FullValue, StringComparison.OrdinalIgnoreCase))
            return new CertusInstanceMode(InstanceMode.Full, source, null);

        return Invalid(source, $"its value '{Echo(trimmed)}' is neither '{MonitorValue}' nor '{FullValue}'");
    }

    /// <summary>
    /// The registry half of <see cref="Resolve"/>, apart from the read itself so the
    /// shapes a real registry can hand back are testable without one. A value that is
    /// there but is not a string, or could not be read, is refused rather than taken as
    /// absent: absent means full, and reading a monitor install as full because a read
    /// failed is the one direction this switch must never fail in.
    /// </summary>
    internal static CertusInstanceMode FromRegistryValue(object? raw, string? readError)
    {
        if (readError is not null)
            return Invalid(RegistrySource, $"it could not be read: {Echo(readError)}");

        return raw switch
        {
            null => Parse(null, RegistrySource),
            string text => Parse(text, RegistrySource),
            // A REG_DWORD 1 is the shape an installer property most naturally takes,
            // and reading it "as string" would have found nothing, so full mode.
            _ => Invalid(RegistrySource,
                $"it is a {DescribeKind(raw)} value, and only a string (REG_SZ) is read"),
        };
    }

    /// <summary>
    /// Writes the one startup line that says which mode is in force. Monitor mode is
    /// logged as a warning so it stands out in a log an operator skims.
    /// </summary>
    public void LogAtStartup(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);

        if (InvalidReason is not null)
            return; // StartupValidator refuses to start and says why.

        if (IsMonitor)
        {
            logger.LogWarning(
                "Monitor mode ({Source}): this server never issues or revokes. ACME is off, " +
                "and nothing it does writes to the CA",
                Source);
        }
        else
        {
            logger.LogInformation("Full mode ({Source}): ACME issuance and revocation are on", Source);
        }
    }

    private static CertusInstanceMode Invalid(string source, string reason) =>
        new(InstanceMode.Monitor, source, reason);

    private static CertusInstanceMode ReadRegistry()
    {
        if (!OperatingSystem.IsWindows())
            return Full;

        object? raw;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CertusPaths.InstallerRegistryKey);
            raw = key?.GetValue(CertusPaths.ModeValueName);
        }
        catch (Exception ex) when (ex is SecurityException or IOException or UnauthorizedAccessException)
        {
            return FromRegistryValue(null, ex.Message);
        }

        return FromRegistryValue(raw, null);
    }

    private static string DescribeKind(object raw) => raw switch
    {
        int => "REG_DWORD",
        long => "REG_QWORD",
        string[] => "REG_MULTI_SZ",
        byte[] => "REG_BINARY",
        _ => raw.GetType().Name,
    };

    /// <summary>
    /// A configured value as it may appear in the refusal and the log line: control
    /// characters removed and line breaks flattened, so a hand edited value cannot
    /// forge log lines, and bounded, so it cannot flood one.
    /// </summary>
    private static string Echo(string value)
    {
        const int MaxEcho = 64;
        var clean = CertificateTextSanitizer.SanitizeDispositionMessageForLog(value) ?? string.Empty;
        return clean.Length <= MaxEcho ? clean : clean[..MaxEcho] + "...";
    }
}
