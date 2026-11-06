using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Setup;

/// <summary>
/// Whether this service installed a certificate in LocalMachine\My itself
/// (issue #535).
///
/// The friendly name <see cref="FriendlyName"/> is the only marker.
/// <see cref="MachineHttpsCertificateStore.Install"/> stamps it on every
/// certificate the service enrols, nothing else in the product writes it, and it
/// already decides what <see cref="IHttpsCertificateStore.RemoveSuperseded"/> may
/// delete.
///
/// The question matters because the certificate the overlay names is not always
/// one the service installed. In monitor mode the setup wizard offers the
/// certificates already in the store, and the usual choice is one Windows
/// autoenrolment renews. After a switch to full mode the service must not take
/// that certificate over: the automatic renewal leaves it to whoever issued it,
/// the service serves their renewed certificate from its next start
/// (<see cref="HttpsCertificateFollow"/>), and it stays in the expiry alerts,
/// because nothing in this product renews it.
///
/// The compare is ordinal and exact, like the store's own sweep. A friendly name
/// is a store property an administrator can edit in certlm.msc, so giving a
/// certificate this name hands it to the service, and changing it takes it
/// back. Only an administrator can write to the machine store, so that is a way
/// to move ownership on purpose, not a way round the rule.
/// </summary>
public static class HttpsCertificateOwnership
{
    /// <summary>
    /// The friendly name the service gives every certificate it installs, shown in
    /// certlm.msc so an administrator can tell the certificate apart. Its home is
    /// here rather than on <see cref="MachineHttpsCertificateStore"/>, which is
    /// Windows only, so code built for every platform can name it;
    /// <see cref="MachineHttpsCertificateStore.FriendlyName"/> is the same value.
    /// </summary>
    public const string FriendlyName = "Ducks in a Row HTTPS";

    /// <summary>Whether <paramref name="certificate"/> carries this service's friendly name.</summary>
    public static bool InstalledByService(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return string.Equals(certificate.FriendlyName, FriendlyName, StringComparison.Ordinal);
    }
}
