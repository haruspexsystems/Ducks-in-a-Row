using System.Runtime.InteropServices;
using Certus.Adcs.ComInterop;
using Certus.Core.Adcs;
using Certus.Core.Crl;
using Microsoft.Extensions.Logging;

namespace Certus.Adcs.Crl;

/// <summary>
/// Reads the configured CA's own CRLs over the same COM channel
/// <see cref="AdcsClient"/> uses, and by the same rules: a bare coclass, every
/// method dispatched by name through <c>dynamic</c>, and the object released in
/// a finally. See the ADCS COM dispatch section of CLAUDE.md.
///
/// Which properties, and why these: measured on lab 2019 on 2026-09-23, every
/// one of them dispatches by name on a real CA.
///
///   11 CR_PROP_CASIGCERTCOUNT        how many signing keys the CA has had
///   20 CR_PROP_CRLSTATE              whether that key's CRL is usable at all
///   17 CR_PROP_BASECRL               the current base CRL, per key
///   18 CR_PROP_DELTACRL              the current delta CRL, per key
///   30 CR_PROP_BASECRLPUBLISHSTATUS  whether the base reached its locations
///   31 CR_PROP_DELTACRLPUBLISHSTATUS the same for the delta
///   41 CR_PROP_CERTCDPURLS           where clients are told to read it
///
/// The CA database's CRL table (<c>ICertView2::SetTable(0x5000)</c>) holds the
/// same dates without transferring the CRL, plus a <c>CRLPublishError</c> string
/// naming the location that failed. That is the better source for a CA whose CRL
/// is megabytes, and the probe recorded its schema, but it is not used here:
/// property 17 is authoritative about what the CA holds now, where the table
/// holds one row per CRL ever published and would have to be restricted or
/// scanned. The caller keeps the transfer bounded instead, by re-reading only
/// when the CRL it already has says it should have been replaced.
/// </summary>
public sealed class AdcsCrlReader : ICaCrlReader
{
    private readonly string _caConnectionString;
    private readonly ILogger<AdcsCrlReader> _logger;

    /// <summary>
    /// A CA renewed many times still publishes only for the keys whose
    /// certificates are alive. The cap is a guard against a pathological count,
    /// not a real limit: no estate renews a CA key sixteen times.
    /// </summary>
    private const int MaxKeyIndexes = 16;

    public AdcsCrlReader(string caConnectionString, ILogger<AdcsCrlReader> logger)
    {
        _caConnectionString = caConnectionString ?? throw new ArgumentNullException(nameof(caConnectionString));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<CaCrlSnapshot> ReadAsync(CancellationToken cancellationToken = default) =>
        Task.Run(Read, cancellationToken);

    private CaCrlSnapshot Read()
    {
        _logger.LogDebug("Reading the CRLs held by {Config}", _caConnectionString);

        object? certRequest = null;
        try
        {
            certRequest = new CertRequestClass();
            dynamic d = certRequest;

            var count = (int)d.GetCAProperty(
                _caConnectionString,
                CaPropertyId.CaSigCertCount,
                0,
                PropertyType.Long,
                0);

            if (count <= 0)
            {
                _logger.LogWarning(
                    "The CA reported {Count} signing certificates, so it holds no CRL to read.", count);
                return CaCrlSnapshot.Empty;
            }

            var crls = new List<CaCrlRecord>();
            var indexes = Math.Min(count, MaxKeyIndexes);

            for (var index = 0; index < indexes; index++)
            {
                // A key whose certificate is revoked or expired still has a row,
                // and its CRL is not something to warn about.
                //
                // Every one of these results is cast back to its static type on
                // the way out. A call that takes a dynamic argument is itself
                // dynamically bound, whatever the method's declared return type,
                // and an extension method (every ILogger.Log* is one) cannot be
                // dispatched on a dynamic value: without the cast this does not
                // compile, and where it would, it would bind at run time.
                var state = (int?)ReadLong(d, CaPropertyId.CrlState, index);
                if (state is not null && state != CaDisposition.Valid)
                {
                    _logger.LogDebug(
                        "Skipping CRLs for CA key {Index}: CR_PROP_CRLSTATE is {State}.", index, state);
                    continue;
                }

                var baseCrl = (CaCrlRecord?)ReadCrl(d, CaPropertyId.BaseCrl, index, isDelta: false);
                if (baseCrl is not null)
                    crls.Add(baseCrl);

                // Deltas are off on plenty of CAs, and the property then refuses
                // rather than returning nothing, which is not a problem to report.
                var deltaCrl = (CaCrlRecord?)ReadCrl(d, CaPropertyId.DeltaCrl, index, isDelta: true);
                if (deltaCrl is not null)
                    crls.Add(deltaCrl);
            }

            var urls = (List<string>)ReadDistributionPointUrls(d, indexes - 1);

            _logger.LogDebug(
                "The CA holds {Count} CRL(s) across {Keys} key(s), published to {Urls} URL(s).",
                crls.Count, indexes, urls.Count);

            return new CaCrlSnapshot(crls, urls);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogError(ex,
                "Access denied reading the CRLs of {Config}.", _caConnectionString);
            throw new CaAccessDeniedException(CaAccessDeniedException.CrlReadPermissionMessage, ex);
        }
        catch (COMException ex) when (IsRefusal(ex))
        {
            _logger.LogError(ex,
                "Access denied reading the CRLs of {Config}. HRESULT: 0x{HResult:X8}",
                _caConnectionString, ex.HResult);
            throw new CaAccessDeniedException(CaAccessDeniedException.CrlReadPermissionMessage, ex);
        }
        catch (COMException ex)
        {
            _logger.LogError(ex,
                "Failed to read the CRLs of {Config}. HRESULT: 0x{HResult:X8}",
                _caConnectionString, ex.HResult);

            if (CaUnavailableException.IsRpcUnavailable(ex))
            {
                throw new CaUnavailableException(
                    "ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", ex);
            }

            throw new InvalidOperationException(
                $"Failed to read the CRLs of the CA: {ex.Message}", ex);
        }
        finally
        {
            ReleaseCom(certRequest);
        }
    }

    /// <summary>
    /// Whether the CA refused the service the CRL reads, as against failing
    /// them: the rule in <see cref="CaAccessDeniedException.IsRefusal"/>. On lab
    /// 2019 on 2026-09-26 (issue #440) property 11 failed first with
    /// CERTSRV_E_ENROLL_DENIED rather than E_ACCESSDENIED, so both carry the same
    /// remedy. Here because the catch sits inside a COM call, and this is the
    /// seam the unit tests reach it through.
    /// </summary>
    internal static bool IsRefusal(COMException ex) => CaAccessDeniedException.IsRefusal(ex);

    /// <summary>
    /// Reads one CRL property and parses its header. A property that refuses,
    /// or a CRL that will not parse, costs that one CRL and is not an error for
    /// the caller: a CA with deltas switched off refuses property 18 on every
    /// pass, and that is a configuration rather than a fault.
    /// </summary>
    private CaCrlRecord? ReadCrl(dynamic d, int propertyId, int index, bool isDelta)
    {
        string base64;
        try
        {
            base64 = (string)d.GetCAProperty(
                _caConnectionString,
                propertyId,
                index,
                PropertyType.Binary,
                OutputEncoding.Base64);
        }
        catch (Exception ex) when (ex is not UnauthorizedAccessException)
        {
            _logger.LogDebug(
                "The CA did not return property {Property} for key {Index}: {Message}",
                propertyId, index, ex.Message);
            return null;
        }

        byte[] der;
        try
        {
            // Convert.FromBase64String tolerates the line breaks COM inserts into
            // a long base64 string, as the certificate chain read relies on too.
            der = Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            _logger.LogWarning(
                "Property {Property} for CA key {Index} was not base64: {Message}",
                propertyId, index, ex.Message);
            return null;
        }

        if (!CrlHeaderReader.TryRead(der, out var header, out var error))
        {
            _logger.LogWarning(
                "The CRL from property {Property} for CA key {Index} could not be read: {Error}",
                propertyId, index, error);
            return null;
        }

        var publishStatus = (int?)ReadLong(
            d,
            isDelta ? CaPropertyId.DeltaCrlPublishStatus : CaPropertyId.BaseCrlPublishStatus,
            index);

        return new CaCrlRecord(
            index,
            header!.IsDelta,
            header.CrlNumberHex,
            header.ThisUpdate,
            header.NextUpdate,
            header.NextPublish,
            header.AuthorityKeyIdentifierHex,
            publishStatus);
    }

    private int? ReadLong(dynamic d, int propertyId, int index)
    {
        try
        {
            return (int)d.GetCAProperty(
                _caConnectionString, propertyId, index, PropertyType.Long, 0);
        }
        catch (Exception ex) when (ex is not UnauthorizedAccessException)
        {
            _logger.LogDebug(
                "The CA did not return property {Property} for key {Index}: {Message}",
                propertyId, index, ex.Message);
            return null;
        }
    }

    /// <summary>
    /// The URLs the CA writes into the certificates it issues, newline separated
    /// per MS-WCCE. These point at the CA's own CRL, not at its parent's.
    /// </summary>
    private List<string> ReadDistributionPointUrls(dynamic d, int index)
    {
        try
        {
            var value = (string)d.GetCAProperty(
                _caConnectionString, CaPropertyId.CertCdpUrls, index, PropertyType.String, 0);

            return value
                .Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex) when (ex is not UnauthorizedAccessException)
        {
            _logger.LogDebug(
                "The CA did not return its distribution point URLs: {Message}", ex.Message);
            return [];
        }
    }

    private static void ReleaseCom(object? comObject)
    {
        if (comObject != null && Marshal.IsComObject(comObject))
            Marshal.FinalReleaseComObject(comObject);
    }
}
