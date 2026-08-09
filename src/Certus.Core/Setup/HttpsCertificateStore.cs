using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Setup;

/// <summary>
/// The certificate store the setup wizard installs the server's own HTTPS
/// certificate into. Abstracted so the enrollment flow can be tested without
/// touching the machine store; the real implementation is
/// <see cref="MachineHttpsCertificateStore"/> (LocalMachine\My).
/// </summary>
public interface IHttpsCertificateStore
{
    /// <summary>
    /// Install a certificate that carries its private key. Returns the
    /// thumbprint the host configuration will select it by.
    /// </summary>
    string Install(X509Certificate2 certificateWithKey);

    /// <summary>
    /// Load a certificate by thumbprint, or null when it is not present.
    /// The caller owns the returned instance.
    /// </summary>
    X509Certificate2? Find(string thumbprint);

    /// <summary>
    /// Remove a certificate by thumbprint, deleting its private key on a
    /// best effort basis. Returns false when no such certificate exists.
    /// </summary>
    bool Remove(string thumbprint);

    /// <summary>
    /// Remove every certificate this product installed except
    /// <paramref name="keepThumbprint"/>, and report how many went. The
    /// background renewal service calls this once a renewal has actually been
    /// applied, because by then the thumbprint it superseded is only known to
    /// the store: the process that recorded it restarted to apply the new one.
    /// Only certificates carrying our friendly name are candidates, so a
    /// certificate an administrator put in the store by hand is never touched.
    /// </summary>
    int RemoveSuperseded(string keepThumbprint);
}

/// <summary>
/// Store for hosts that cannot install certificates: the development host
/// (Certus.Web) always runs the mock CA, whose provisioning endpoints refuse
/// before any store call, so these members exist only to satisfy the
/// dependency graph. Mirrors <c>NoOpServiceRestarter</c>.
/// </summary>
public sealed class NoOpHttpsCertificateStore : IHttpsCertificateStore
{
    public string Install(X509Certificate2 certificateWithKey) =>
        throw new PlatformNotSupportedException(
            "This host cannot install HTTPS certificates; use the Windows service host.");

    public X509Certificate2? Find(string thumbprint) => null;

    public bool Remove(string thumbprint) => false;

    public int RemoveSuperseded(string keepThumbprint) => 0;
}

/// <summary>
/// LocalMachine\My implementation. The private key is persisted into the
/// machine key store and is not marked exportable: the service reads it in
/// process, and nothing should ever need to carry it off the box. No PFX or
/// password touches the disk.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MachineHttpsCertificateStore : IHttpsCertificateStore
{
    /// <summary>Shown in certlm.msc so an admin can tell the certificate apart.</summary>
    public const string FriendlyName = "Ducks in a Row HTTPS";

    private readonly ILogger<MachineHttpsCertificateStore> _logger;

    public MachineHttpsCertificateStore(ILogger<MachineHttpsCertificateStore> logger)
    {
        _logger = logger;
    }

    public string Install(X509Certificate2 certificateWithKey)
    {
        // The enroller pairs the issued certificate with an in memory key.
        // Round trip through PFX bytes so the import persists the key into
        // the machine key store; without PersistKeySet the key would vanish
        // with this process and Kestrel could never serve the certificate.
        var pfx = certificateWithKey.Export(X509ContentType.Pfx);
        var persisted = X509CertificateLoader.LoadPkcs12(
            pfx,
            null,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
        persisted.FriendlyName = FriendlyName;

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(persisted);

        _logger.LogInformation(
            "Installed HTTPS certificate {Thumbprint} ({Subject}) into LocalMachine\\My",
            persisted.Thumbprint, persisted.Subject);

        return persisted.Thumbprint;
    }

    public X509Certificate2? Find(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        return matches.Count > 0 ? matches[0] : null;
    }

    public bool Remove(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        if (matches.Count == 0)
            return false;

        foreach (var cert in matches)
        {
            store.Remove(cert);
            TryDeletePrivateKey(cert);
            cert.Dispose();
        }

        _logger.LogInformation(
            "Removed HTTPS certificate {Thumbprint} from LocalMachine\\My", thumbprint);
        return true;
    }

    public int RemoveSuperseded(string keepThumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);

        // Our friendly name is the only marker: a certificate an administrator
        // installed by hand carries their own (or none), so it is never a
        // candidate however much it looks like ours.
        var superseded = store.Certificates
            .Where(c => string.Equals(c.FriendlyName, FriendlyName, StringComparison.Ordinal)
                        && !string.Equals(c.Thumbprint, keepThumbprint, StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var cert in superseded)
        {
            store.Remove(cert);
            TryDeletePrivateKey(cert);
            _logger.LogInformation(
                "Removed superseded HTTPS certificate {Thumbprint} ({Subject}, valid until " +
                "{NotAfter:u}) from LocalMachine\\My; {Keep} is the certificate in use",
                cert.Thumbprint, cert.Subject, cert.NotAfter.ToUniversalTime(), keepThumbprint);
            cert.Dispose();
        }

        return superseded.Count;
    }

    /// <summary>
    /// Removing a certificate from the store does not delete its key
    /// container; without this, a declined certificate would orphan a key in
    /// the machine key store. Best effort: a failure only means an unused
    /// key file lingers.
    /// </summary>
    private void TryDeletePrivateKey(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPrivateKey();
            if (rsa is RSACng rsaCng)
            {
                rsaCng.Key.Delete();
                return;
            }

            using var ecdsa = cert.GetECDsaPrivateKey();
            if (ecdsa is ECDsaCng ecdsaCng)
                ecdsaCng.Key.Delete();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex,
                "Could not delete the private key for {Thumbprint}; an orphaned key container remains",
                cert.Thumbprint);
        }
    }
}
