using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Attestation;

/// <summary>
/// Loads the administrator managed trust anchors for one attestation
/// format. Reads the table on every call, so an anchor added to bridge a
/// vendor root rotation applies to the next validation with no restart (the
/// same hot apply stance as the device policy service). A row whose PEM no
/// longer parses is skipped with a warning rather than failing every
/// attestation of the format: the embedded root still anchors the chain.
/// </summary>
public sealed class AttestationTrustAnchorStore
{
    private readonly CertusDbContext _db;
    private readonly ILogger<AttestationTrustAnchorStore> _logger;

    public AttestationTrustAnchorStore(
        CertusDbContext db,
        ILogger<AttestationTrustAnchorStore> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Returns the enabled anchors for <paramref name="format"/> as parsed
    /// certificates. The caller owns their disposal.
    /// </summary>
    public async Task<IReadOnlyList<X509Certificate2>> GetEnabledAnchorsAsync(
        string format, CancellationToken cancellationToken = default)
    {
        var rows = await _db.AttestationTrustAnchors
            .AsNoTracking()
            .Where(a => a.Format == format && a.Enabled)
            .ToListAsync(cancellationToken);

        var anchors = new List<X509Certificate2>(rows.Count);
        foreach (var row in rows)
        {
            try
            {
                anchors.Add(X509Certificate2.CreateFromPem(row.CertificatePem));
            }
            catch (CryptographicException ex)
            {
                _logger.LogWarning(ex,
                    "Skipping attestation trust anchor {Name} ({Fingerprint}): its stored PEM does not parse",
                    row.Name, row.Sha256Fingerprint);
            }
        }

        return anchors;
    }
}
