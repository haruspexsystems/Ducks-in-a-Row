using Certus.Core.Configuration;
using Certus.Core.Security;
using Microsoft.AspNetCore.DataProtection;

namespace Certus.Web;

/// <summary>
/// Shared Data Protection wiring for both hosts (the dev host and the Windows
/// service). The two must agree bit for bit on the application name and the
/// keyring location, or secrets protected by one cannot be decrypted by the
/// other; one extension makes that agreement structural instead of relying on
/// two copies staying identical.
///
/// The keyring lives in a "keys" folder next to the database so a data
/// directory backup carries it, and on Windows the keyring itself is DPAPI
/// protected (machine scope). Restoring the data directory onto a different
/// machine therefore cannot decrypt stored EAB secrets; the recovery is
/// regenerating each credential's secret from the dashboard (the key id and
/// its configuration survive as plaintext columns). Integration tests replace
/// the provider with the ephemeral one, so nothing touches the disk there.
/// </summary>
public static class CertusDataProtectionExtensions
{
    /// <summary>The Data Protection application discriminator both hosts share.</summary>
    public const string ApplicationName = "DucksInARow";

    /// <summary>
    /// Registers Data Protection with the shared keyring plus the
    /// <see cref="ISecretProtector"/> the EAB credential store encrypts with.
    /// Call with the manually bound, normalized options copy (the same one
    /// the connection string is built from).
    /// </summary>
    public static IServiceCollection AddCertusSecretProtection(
        this IServiceCollection services, CertusOptions certusOptions)
    {
        var keysDirectory = DataProtectionKeysDirectory(certusOptions);
        var dataProtection = services.AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToFileSystem(new DirectoryInfo(keysDirectory));

        if (OperatingSystem.IsWindows())
            dataProtection.ProtectKeysWithDpapi();

        services.AddSingleton<ISecretProtector, DataProtectionSecretProtector>();
        return services;
    }

    /// <summary>
    /// The keyring folder: "keys" next to the database, falling back to the
    /// data directory for the in memory database sentinel.
    /// </summary>
    public static string DataProtectionKeysDirectory(CertusOptions options)
    {
        return options.DatabasePath == CertusPaths.InMemoryDatabase
            ? Path.Combine(CertusPaths.DataDirectory, "keys")
            : Path.Combine(
                Path.GetDirectoryName(options.DatabasePath) ?? CertusPaths.DataDirectory,
                "keys");
    }
}
