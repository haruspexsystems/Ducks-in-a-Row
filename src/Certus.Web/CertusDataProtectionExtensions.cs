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
/// directory backup carries it. The Windows service keeps the database in the
/// data directory and refuses to start otherwise (DataFolderPlacement, issue
/// #506), so in production the keyring sits under the data directory's lock;
/// that lock is its only protection, since nothing checks a key file before it
/// is loaded. On Windows the keyring itself is DPAPI protected under the
/// account the service runs as: ProtectKeysWithDpapi() without the machine
/// scope argument, so the key files decrypt only for that account on that
/// machine (issue #635 corrected the documentation, which said machine scope).
/// Restoring the data directory onto a different machine, or running the
/// service as another account, therefore cannot decrypt the stored EAB secrets
/// or the saved SMTP password; the recovery is regenerating each credential's
/// secret from the dashboard (the key id and its configuration survive as
/// plaintext columns) and entering the SMTP password again. Integration tests
/// replace the provider with the ephemeral one, so nothing touches the disk
/// there.
/// </summary>
public static class CertusDataProtectionExtensions
{
    /// <summary>The Data Protection application discriminator both hosts share.</summary>
    public const string ApplicationName = "DucksInARow";

    /// <summary>
    /// Registers Data Protection with the shared keyring plus the
    /// <see cref="ISecretProtector"/> the EAB credential store encrypts with
    /// and the <see cref="ISmtpSecretProtector"/> the alerts card saves the
    /// SMTP password with, each under its own purpose (issue #635). Call with
    /// the manually bound, normalized options copy (the same one the
    /// connection string is built from).
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
        services.AddSingleton<ISmtpSecretProtector, SmtpPasswordProtector>();
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
