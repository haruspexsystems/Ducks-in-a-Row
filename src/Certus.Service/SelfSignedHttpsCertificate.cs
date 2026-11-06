using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Security;
using Certus.Core.Setup;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace Certus.Service;

/// <summary>
/// The self signed certificate the service serves HTTPS with until a trusted
/// one is configured: a lab and first boot convenience, never a production
/// certificate, and the first thing the setup wizard replaces.
///
/// <para>
/// Until issue #635 it was a PFX in the data folder under a password that
/// was the same in every copy of the product, so every backup of the data
/// folder carried a private key anyone could open. It is now a PKCS#12 with
/// no password at all, and the whole file is encrypted with the service's
/// Data Protection keyring under its own purpose: the same keyring that
/// protects the EAB secrets and the saved SMTP password, DPAPI protected
/// under the service account on this machine. A backup restored elsewhere,
/// or a service moved to another account, cannot read it, and that is
/// accepted: the file is regenerated whenever it cannot be read, as it always
/// was when it was absent, and the only cost is a browser asking again.
/// </para>
///
/// <para>
/// Loaded when Kestrel asks for its options, not before the host is built,
/// because the keyring is a service of the built host: the test hosts replace
/// it with an ephemeral one, and the production one must not be opened before
/// the data folder placement refusals have had their say.
/// </para>
/// </summary>
public static class SelfSignedHttpsCertificate
{
    /// <summary>The encrypted file in the data folder.</summary>
    public const string FileName = "ducks-selfsigned.bin";

    /// <summary>
    /// The file every release up to 1.0.0 wrote: a PFX under a fixed password.
    /// Deleted on sight, because it is the thing issue #635 removes.
    /// </summary>
    public const string LegacyFileName = "ducks-selfsigned.pfx";

    /// <summary>The Data Protection purpose the file is encrypted under.</summary>
    public const string Purpose = "Certus.SelfSignedHttps.v1";

    /// <summary>How long a generated certificate is valid for.</summary>
    public const int LifetimeYears = 2;

    /// <summary>
    /// A certificate this close to its expiry is replaced at the next start,
    /// so the service never serves one that has expired while it ran on.
    /// </summary>
    public const int RenewalWindowDays = 30;

    /// <summary>What a load did and why, for the start up log.</summary>
    /// <param name="Certificate">The certificate to serve, with its private key.</param>
    /// <param name="Path">The file it lives in.</param>
    /// <param name="Regenerated">True when a new certificate was generated this time.</param>
    /// <param name="Reason">Why it was regenerated, or null when the existing one was reused.</param>
    public sealed record Outcome(
        X509Certificate2 Certificate, string Path, bool Regenerated, string? Reason);

    /// <summary>
    /// Loads the fallback certificate from <paramref name="dataDirectory"/>, or
    /// generates a new one when there is none, it cannot be read with this
    /// keyring, it is corrupt, or it is within <see cref="RenewalWindowDays"/>
    /// of expiry. Logs what it did, since Kestrel asks for its options after
    /// the file logger exists.
    /// </summary>
    public static Outcome Load(
        string dataDirectory, IDataProtectionProvider provider, DateTimeOffset now, ILogger logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(logger);

        ProtectedFolder.EnsureExists(dataDirectory);
        var path = System.IO.Path.Combine(dataDirectory, FileName);
        var protector = provider.CreateProtector(Purpose);

        string? reason;
        if (!File.Exists(path))
        {
            reason = "no fallback certificate exists yet";
        }
        else if (TryRead(path, protector, out var existing, out reason))
        {
            if (existing.NotAfter.ToUniversalTime() > now.UtcDateTime.AddDays(RenewalWindowDays))
            {
                logger.LogInformation(
                    "HTTPS is using the self signed fallback certificate {Thumbprint} from {Path} " +
                    "(valid until {NotAfter:u})",
                    existing.Thumbprint, path, existing.NotAfter.ToUniversalTime());
                return new Outcome(existing, path, Regenerated: false, Reason: null);
            }

            reason = $"the existing one expires on {existing.NotAfter.ToUniversalTime():u}, " +
                     $"within {RenewalWindowDays} days";
            existing.Dispose();
        }

        var certificate = Generate(path, protector, now);
        logger.LogInformation(
            "Generated the self signed fallback HTTPS certificate {Thumbprint} at {Path} " +
            "(valid until {NotAfter:u}) because {Reason}. The file is encrypted with this " +
            "service's keyring and holds no password.",
            certificate.Thumbprint, path, certificate.NotAfter.ToUniversalTime(), reason);
        return new Outcome(certificate, path, Regenerated: true, reason);
    }

    /// <summary>
    /// Deletes the fixed password PFX an earlier release kept, when there is
    /// one, and says whether it did. The host calls this on every boot after
    /// Build, whichever certificate the boot serves: a server that moved to a
    /// CA issued certificate still had the file, and the file is the key. It
    /// is deliberately not part of <see cref="Load"/>, which runs only when
    /// the fallback is served.
    /// </summary>
    public static bool RemoveLegacyFile(string dataDirectory, ILogger logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        ArgumentNullException.ThrowIfNull(logger);

        var legacyPath = System.IO.Path.Combine(dataDirectory, LegacyFileName);
        if (!File.Exists(legacyPath))
            return false;

        try
        {
            File.Delete(legacyPath);
            logger.LogWarning(
                "Deleted {Path}, the self signed fallback certificate an earlier release kept under " +
                "a fixed password. The replacement is encrypted with this service's keyring; a browser " +
                "that accepted the old certificate will ask again. A backup taken before this release " +
                "still holds the old file; see Backup and restore.",
                legacyPath);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogError(
                ex, "{Path} could not be deleted. It is a private key under a fixed password; remove it by hand.",
                legacyPath);
            return false;
        }
    }

    private static bool TryRead(
        string path, IDataProtector protector, out X509Certificate2 certificate, out string reason)
    {
        certificate = null!;
        byte[] pkcs12;
        try
        {
            pkcs12 = protector.Unprotect(File.ReadAllBytes(path));
        }
        catch (CryptographicException)
        {
            reason = "the existing one cannot be read with this machine's keyring " +
                     "(a data folder restored from another machine or another service account)";
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            reason = $"the existing one could not be read: {ex.Message}";
            return false;
        }

        try
        {
            certificate = LoadForKestrel(pkcs12);
            reason = string.Empty;
            return true;
        }
        catch (CryptographicException)
        {
            reason = "the existing one is corrupt";
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs12);
        }
    }

    private static X509Certificate2 Generate(string path, IDataProtector protector, DateTimeOffset now)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            MachineCertificateChoices.SelfSignedFallbackSubject, rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1", "Server Authentication")], false));

        // localhost and the machine name, so browsers and tools on the box accept it.
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddDnsName(Environment.MachineName);
        request.CertificateExtensions.Add(sanBuilder.Build());

        using var generated = request.CreateSelfSigned(now, now.AddYears(LifetimeYears));

        // No password: the keyring is the protection, and a password would be
        // a second secret to keep somewhere.
        var pkcs12 = generated.Export(X509ContentType.Pkcs12);
        try
        {
            AtomicFile.WriteAllBytes(path, protector.Protect(pkcs12));

            // Re-imported rather than served as generated: CreateSelfSigned
            // returns an ephemeral key, which schannel cannot use for a TLS
            // server, so Kestrel gets the same object a load would produce.
            return LoadForKestrel(pkcs12);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs12);
        }
    }

    /// <summary>
    /// The default key set, which is what Kestrel's own certificate path loader
    /// uses: on Windows the key lands in the service account's key store for the
    /// life of the certificate object, where schannel can reach it. An ephemeral
    /// key set cannot serve TLS on Windows.
    /// </summary>
    private static X509Certificate2 LoadForKestrel(byte[] pkcs12) =>
        X509CertificateLoader.LoadPkcs12(pkcs12, password: null, X509KeyStorageFlags.DefaultKeySet);
}
