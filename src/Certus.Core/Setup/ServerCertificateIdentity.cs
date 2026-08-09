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
    private readonly ILogger<ServerCertificateIdentity> _logger;
    private readonly object _gate = new();

    private IReadOnlyList<string> _cached = [];
    private DateTime _cachedAtUtc = DateTime.MinValue;

    public ServerCertificateIdentity(
        IHttpsCertificateStore certificateStore,
        IOptions<CertusOptions> certusOptions,
        ILogger<ServerCertificateIdentity> logger)
    {
        _certificateStore = certificateStore;
        _certusOptions = certusOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// The serial numbers of the server's own HTTPS certificates, in whatever
    /// form the store reports them. Empty when no CA issued certificate is
    /// configured, on hosts that cannot read a certificate store, and on any
    /// failure.
    /// </summary>
    public IReadOnlyList<string> GetOwnSerialNumbers()
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

    /// <summary>
    /// Whether <paramref name="serialNumber"/> is one of ours. Normalizes both
    /// sides, so the CA database form and the X509 form match.
    /// </summary>
    public bool IsOwnCertificate(string? serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
            return false;

        var own = GetOwnSerialNumbers();
        for (var i = 0; i < own.Count; i++)
        {
            if (Adcs.SerialNumbers.NormalizedEquals(own[i], serialNumber))
                return true;
        }

        return false;
    }

    /// <summary>Drop the cached answer, so the next read resolves again.</summary>
    public void Invalidate()
    {
        lock (_gate)
        {
            _cachedAtUtc = DateTime.MinValue;
        }
    }

    private IReadOnlyList<string> Resolve()
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
        foreach (var thumbprint in thumbprints)
        {
            try
            {
                using var certificate = _certificateStore.Find(thumbprint);
                if (certificate is not null && !string.IsNullOrWhiteSpace(certificate.SerialNumber))
                    serials.Add(certificate.SerialNumber);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex,
                    "The certificate store could not be read while identifying the server " +
                    "certificate {Thumbprint}", thumbprint);
            }
        }

        return serials;
    }
}
