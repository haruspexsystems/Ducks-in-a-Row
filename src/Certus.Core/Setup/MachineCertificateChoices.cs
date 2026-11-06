using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;

namespace Certus.Core.Setup;

/// <summary>
/// One certificate the setup wizard offers to serve HTTPS with, in monitor mode.
/// </summary>
/// <param name="Thumbprint">What the service will be pinned to.</param>
/// <param name="Subject">The subject, as RFC 4514 renders it.</param>
/// <param name="Names">The DNS and IP names it is valid for.</param>
/// <param name="Issuer">Who issued it.</param>
/// <param name="NotAfter">End of validity.</param>
/// <param name="FriendlyName">The store's friendly name, when it has one.</param>
/// <param name="Template">The template it names, a v1 name or an OID, when it names one.</param>
/// <param name="CoversExternalHost">Whether a browser at the external URL would accept it.</param>
/// <param name="SelfSigned">Whether it issued itself, which browsers do not trust.</param>
/// <param name="Configured">Whether the service is already pinned to it.</param>
public sealed record MachineCertificateView(
    string Thumbprint,
    string Subject,
    IReadOnlyList<string> Names,
    string Issuer,
    DateTimeOffset NotAfter,
    string? FriendlyName,
    string? Template,
    bool CoversExternalHost,
    bool SelfSigned,
    bool Configured);

/// <summary>
/// Which certificates in LocalMachine\My the setup wizard may offer in monitor mode
/// (issue #471), where the service never enrols its own: an existing certificate is
/// how it gets a trusted one.
///
/// Eligibility is decided on the server, and decided again when a choice is made,
/// because a certificate the service cannot use would stop it binding HTTPS at the
/// restart that applies it. The key test is the one that matters most: the store
/// can report a private key the service account cannot actually use, so the key is
/// asked to sign, the same operation a TLS handshake needs.
/// </summary>
public static class MachineCertificateChoices
{
    /// <summary>The subject of the certificate the service generates for itself.</summary>
    public const string SelfSignedFallbackSubject = "CN=Ducks in a Row Self-Signed";

    /// <summary>
    /// Whether the service could serve HTTPS with <paramref name="certificate"/>: it
    /// is valid now, suits a TLS server, is not a CA certificate, is not the service's
    /// own fallback, and has a private key that signs.
    /// </summary>
    public static bool IsEligible(X509Certificate2 certificate, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var facts = HttpsCertificateFollow.Describe(certificate);
        return facts.NotBefore <= now
               && now < facts.NotAfter
               && facts.ServerAuthUsable
               && !facts.IsCertificateAuthority
               && !string.Equals(certificate.Subject, SelfSignedFallbackSubject, StringComparison.OrdinalIgnoreCase)
               && facts.HasPrivateKey
               && facts.KeyUsable;
    }

    /// <summary>
    /// The rows the wizard shows for the eligible certificates among
    /// <paramref name="certificates"/>: those covering the external host first, then
    /// the longest lived, then by thumbprint so the order never changes between loads.
    /// </summary>
    public static IReadOnlyList<MachineCertificateView> Describe(
        IEnumerable<X509Certificate2> certificates,
        string externalHost,
        string? configuredThumbprint,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(externalHost);

        var configured = configuredThumbprint is null
            ? null
            : HttpsCertificateFollow.NormalizeThumbprint(configuredThumbprint);

        return certificates
            .Where(certificate => IsEligible(certificate, now))
            .Select(certificate =>
            {
                var names = TlsCertificateEnroller.GetSubjectNames(certificate);
                return new MachineCertificateView(
                    Thumbprint: certificate.Thumbprint,
                    Subject: certificate.Subject,
                    Names: names,
                    Issuer: certificate.Issuer,
                    NotAfter: new DateTimeOffset(certificate.NotAfter),
                    FriendlyName: string.IsNullOrWhiteSpace(certificate.FriendlyName) ? null : certificate.FriendlyName,
                    Template: CertificateTemplateExtensionReader.ReadFrom(certificate)?.Describe(),
                    CoversExternalHost: TlsCertificateEnroller.CoversHost(names, externalHost),
                    SelfSigned: certificate.SubjectName.RawData.AsSpan()
                        .SequenceEqual(certificate.IssuerName.RawData),
                    Configured: configured is not null && string.Equals(
                        HttpsCertificateFollow.NormalizeThumbprint(certificate.Thumbprint),
                        configured,
                        StringComparison.Ordinal));
            })
            .OrderByDescending(view => view.CoversExternalHost)
            .ThenByDescending(view => view.NotAfter)
            .ThenBy(view => view.Thumbprint, StringComparer.Ordinal)
            .ToList();
    }

    private static readonly byte[] TestDigest = SHA256.HashData("Ducks in a Row key check"u8);

    /// <summary>
    /// Whether this process can sign with the certificate's private key, the
    /// operation a TLS handshake needs. Shared with the renewal follower, so the
    /// picker and the follower agree on what the service could serve.
    /// </summary>
    internal static bool KeySigns(X509Certificate2 certificate)
    {
        try
        {
            using (var rsa = certificate.GetRSAPrivateKey())
            {
                if (rsa is not null)
                {
                    rsa.SignHash(TestDigest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    return true;
                }
            }

            using (var ecdsa = certificate.GetECDsaPrivateKey())
            {
                if (ecdsa is not null)
                {
                    ecdsa.SignHash(TestDigest);
                    return true;
                }
            }

            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
