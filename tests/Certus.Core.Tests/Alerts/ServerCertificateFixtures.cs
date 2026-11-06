using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// <see cref="ServerCertificateIdentity"/> instances for the alerting tests: one that
/// owns nothing, and one whose store holds a certificate with a chosen serial, which is
/// what the server's own HTTPS certificate looks like to the suppression path. Shared so
/// the expiry monitor and the detail page's ladder are tested against the same shapes.
/// </summary>
internal static class ServerCertificateFixtures
{
    /// <summary>
    /// An identity that owns nothing: no thumbprint is configured, so it resolves to an
    /// empty list and every certificate alerts as it always did.
    /// </summary>
    public static ServerCertificateIdentity None() =>
        new(Substitute.For<IHttpsCertificateStore>(),
            Options.Create(new CertusOptions
            {
                // Point at a path that does not exist rather than letting the
                // default resolve to the real data directory: a unit test must
                // never read the operator's ProgramData overlay.
                SettingsOverlayPath = MissingOverlay(),
            }),
            CertusInstanceMode.Full,
            NullLogger<ServerCertificateIdentity>.Instance);

    /// <summary>
    /// An identity whose served certificate carries <paramref name="serial"/>. Automatic
    /// renewal is on, the mode is full and the service installed the certificate unless
    /// the caller says otherwise, which is the one combination where the certificate is
    /// kept out of the alerts (issues #470 and #535). <paramref name="installedByService"/>
    /// false is a certificate somebody else put in the store, which the store copy then
    /// lacks our friendly name for.
    /// </summary>
    public static (ServerCertificateIdentity Identity, X509Certificate2 Certificate) WithSerial(
        byte[] serial,
        bool autoRenewalEnabled = true,
        CertusInstanceMode? instanceMode = null,
        bool installedByService = true)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=certus.home.local", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.Create(
            request.SubjectName,
            X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(20),
            serial);

        var store = Substitute.For<IHttpsCertificateStore>();
        store.Find("AA11BB22").Returns(_ =>
        {
            var copy = X509CertificateLoader.LoadCertificate(certificate.RawData);
            if (installedByService)
                copy.FriendlyName = HttpsCertificateOwnership.FriendlyName;
            return copy;
        });

        var options = Options.Create(new CertusOptions
        {
            HttpsCertificateThumbprint = "AA11BB22",
            HttpsCertificateAutoRenewalEnabled = autoRenewalEnabled,
            // A path that does not exist reads as an empty overlay, so the
            // in process thumbprint above is the whole answer.
            SettingsOverlayPath = MissingOverlay(),
        });

        var identity = new ServerCertificateIdentity(
            store, options, instanceMode ?? CertusInstanceMode.Full,
            NullLogger<ServerCertificateIdentity>.Instance);
        return (identity, certificate);
    }

    private static string MissingOverlay() => Path.Combine(
        Path.GetTempPath(), "certus-no-such-overlay-" + Guid.NewGuid().ToString("N") + ".json");
}
