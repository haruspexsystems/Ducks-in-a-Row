using Certus.Core.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Setup;

/// <summary>
/// Tells the rest of the product which synced certificates are the server's
/// own HTTPS certificate (issue #105). That certificate is issued by the
/// monitored CA like any other, so without this it appears in the expiry
/// dashboard and fires the 30, 14, 7, and 1 day alerts for a certificate the
/// product renews for itself.
///
/// The answer is a list of serial numbers because that is the only field
/// <c>SyncedCertificate</c> and an <c>X509Certificate2</c> share:
/// the table has no thumbprint column. The two representations differ (the CA
/// database stores lowercase hex with no pad), so every comparison goes
/// through <see cref="Adcs.SerialNumbers.NormalizedEquals"/>.
///
/// Both the recorded and the served thumbprint are resolved: while a renewal
/// waits for the restart that applies it, the overlay names the new
/// certificate and the process is still serving the old one, and neither
/// should alert.
///
/// Identity and suppression are separate questions (issue #470). The
/// certificate is kept out of the alerts only while something renews it:
/// full mode with automatic renewal on. Until that issue the exclusion held
/// whatever the renewal setting said, so an install that turned renewal off,
/// and every monitor mode install, would let its own certificate expire with
/// nothing warning. <see cref="IsSuppressedFromAlerts"/> is the alerting
/// question; <see cref="IsOwnCertificate"/> stays the identity one.
///
/// Since issue #535 the alerting question also asks who installed the
/// certificate. The automatic renewal renews only one carrying this service's
/// friendly name (<see cref="HttpsCertificateOwnership"/>), so a certificate
/// somebody else installed, typically one picked in monitor mode and renewed by
/// Windows autoenrolment, alerts in full mode too: if its own renewal stops,
/// nothing in this product would replace it.
///
/// Best effort throughout, like the directory lookups: this backs alert
/// suppression, never an issuance decision, so an unreadable overlay or an
/// inaccessible store yields an empty list (nothing suppressed) rather than an
/// exception into the expiry monitor.
/// </summary>
public sealed class ServerCertificateIdentity
{
    /// <summary>
    /// How long a resolved answer is reused. The expiry monitor asks once per
    /// threshold per pass, and the certificate only changes on a renewal, so a
    /// few minutes keeps the machine store out of the inner loop without ever
    /// being noticeably stale.
    /// </summary>
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(5);

    private readonly IHttpsCertificateStore _certificateStore;
    private readonly CertusOptions _certusOptions;
    private readonly CertusInstanceMode _instanceMode;
    private readonly ILogger<ServerCertificateIdentity> _logger;
    private readonly object _gate = new();

    private Resolved _cached = Resolved.Empty;
    private DateTime _cachedAtUtc = DateTime.MinValue;

    public ServerCertificateIdentity(
        IHttpsCertificateStore certificateStore,
        IOptions<CertusOptions> certusOptions,
        CertusInstanceMode instanceMode,
        ILogger<ServerCertificateIdentity> logger)
    {
        _certificateStore = certificateStore;
        _certusOptions = certusOptions.Value;
        _instanceMode = instanceMode;
        _logger = logger;
    }

    /// <summary>
    /// Whether the expiry alerts should stay silent about this certificate: it is
    /// one of ours, this service installed it, and automatic renewal will replace
    /// it. The renewal half is checked first, because it costs nothing and, when it
    /// is false, spares the store read.
    /// </summary>
    public bool IsSuppressedFromAlerts(string? serialNumber) =>
        HttpsCertificateAutoRenewalService.IsActive(_certusOptions, _instanceMode)
        && Contains(GetResolved().InstalledByService, serialNumber);

    /// <summary>
    /// The serial numbers of the server's own HTTPS certificates, in whatever
    /// form the store reports them. Empty when no CA issued certificate is
    /// configured, on hosts that cannot read a certificate store, and on any
    /// failure.
    /// </summary>
    public IReadOnlyList<string> GetOwnSerialNumbers() => GetResolved().Own;

    /// <summary>
    /// Whether <paramref name="serialNumber"/> is one of ours. Normalizes both
    /// sides, so the CA database form and the X509 form match.
    /// </summary>
    public bool IsOwnCertificate(string? serialNumber) =>
        Contains(GetResolved().Own, serialNumber);

    /// <summary>Drop the cached answer, so the next read resolves again.</summary>
    public void Invalidate()
    {
        lock (_gate)
        {
            _cachedAtUtc = DateTime.MinValue;
        }
    }

    private Resolved GetResolved()
    {
        lock (_gate)
        {
            if (DateTime.UtcNow - _cachedAtUtc < CacheLifetime)
                return _cached;

            _cached = Resolve();
            _cachedAtUtc = DateTime.UtcNow;
            return _cached;
        }
    }

    private static bool Contains(IReadOnlyList<string> serials, string? serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
            return false;

        for (var i = 0; i < serials.Count; i++)
        {
            if (Adcs.SerialNumbers.NormalizedEquals(serials[i], serialNumber))
                return true;
        }

        return false;
    }

    private Resolved Resolve()
    {
        var thumbprints = new List<string>(2);

        try
        {
            var overlayThumbprint = SettingsOverlay
                .Load(SettingsOverlay.ResolvePath(_certusOptions))
                .HttpsCertificateThumbprint;
            if (!string.IsNullOrWhiteSpace(overlayThumbprint))
                thumbprints.Add(overlayThumbprint.Trim());
        }
        catch (Exception ex)
        {
            // A torn or hand broken overlay is surfaced loudly by the settings
            // API; here it only costs suppression, so log and carry on with
            // whatever the running process knows.
            _logger.LogDebug(ex,
                "The settings overlay could not be read while identifying the server certificate");
        }

        var served = _certusOptions.HttpsCertificateThumbprint;
        if (!string.IsNullOrWhiteSpace(served) &&
            !thumbprints.Contains(served.Trim(), StringComparer.OrdinalIgnoreCase))
        {
            thumbprints.Add(served.Trim());
        }

        var serials = new List<string>(thumbprints.Count);
        var installedByService = new List<string>(thumbprints.Count);
        foreach (var thumbprint in thumbprints)
        {
            try
            {
                using var certificate = _certificateStore.Find(thumbprint);
                if (certificate is not null && !string.IsNullOrWhiteSpace(certificate.SerialNumber))
                {
                    serials.Add(certificate.SerialNumber);
                    if (HttpsCertificateOwnership.InstalledByService(certificate))
                        installedByService.Add(certificate.SerialNumber);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex,
                    "The certificate store could not be read while identifying the server " +
                    "certificate {Thumbprint}", thumbprint);
            }
        }

        return new Resolved(serials, installedByService);
    }

    /// <summary>
    /// The serial numbers of the server's own certificates, and the ones among them
    /// this service installed. Resolved together so a single store read answers both.
    /// </summary>
    private sealed record Resolved(IReadOnlyList<string> Own, IReadOnlyList<string> InstalledByService)
    {
        public static readonly Resolved Empty = new([], []);
    }
}
