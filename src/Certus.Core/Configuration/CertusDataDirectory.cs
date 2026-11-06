using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Certus.Core.Configuration;

/// <summary>
/// The data directory a host writes to. Outside Development it is always
/// <see cref="CertusPaths.DataDirectory"/>: the folder the installer recorded, or the
/// default under %ProgramData%.
///
/// In Development, configuration may name another folder under
/// <see cref="DevelopmentKey"/>. That is what lets a test boot the real service host
/// without touching the machine's data directory, where the host would otherwise load a
/// configured install's settings overlay (its CA connection string included) and write
/// its self signed certificate and its log files (issue #413, deviation Dv12).
///
/// Two rules keep the override from being a way to move a production install:
/// <list type="bullet">
/// <item>It is read only in the Development environment, which a production service never
/// runs in.</item>
/// <item>Each host resolves it once, before it adds the settings overlay, so the overlay
/// (settings.json, which lives in the data directory) can never supply it.</item>
/// </list>
/// </summary>
public static class CertusDataDirectory
{
    /// <summary>The configuration key a Development host reads its data directory from.</summary>
    public const string DevelopmentKey = "Certus:Development:DataDirectory";

    /// <summary>
    /// The data directory for this host. Throws when a Development host is given a path
    /// that is not absolute, because a relative one would land wherever the process
    /// happened to start.
    /// </summary>
    public static string Resolve(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        if (!environment.IsDevelopment())
            return CertusPaths.DataDirectory;

        var configured = CertusPaths.NormalizeDataDirectory(configuration[DevelopmentKey]);
        if (configured is null)
            return CertusPaths.DataDirectory;

        if (!Path.IsPathFullyQualified(configured))
        {
            throw new InvalidOperationException(
                $"{DevelopmentKey} must be an absolute path; '{configured}' is not.");
        }

        return configured;
    }
}
