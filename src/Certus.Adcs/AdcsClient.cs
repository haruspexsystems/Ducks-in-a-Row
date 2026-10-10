using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certus.Adcs.ComInterop;
using Certus.Core.Adcs;
using Microsoft.Extensions.Logging;

namespace Certus.Adcs;

/// <summary>
/// ADCS client implementation using COM interop (DCOM/RPC).
/// Communicates with the Certificate Authority via the CCertRequest and CCertView
/// coclasses, dispatching every method through IDispatch.
///
/// Dispatch model (see issues #14 and #15, tools/AdcsQiProbe): IID_ICertRequest2
/// is not exposed by the deployed certcli.dll on the target Windows build
/// (E_NOINTERFACE). IID_ICertView2 does resolve once the correct IID is used.
/// The v1 IIDs both resolve, but the v1 interfaces are dual (inherit IDispatch),
/// so a managed [ComImport] interface declared with [InterfaceType(InterfaceIsIUnknown)]
/// places C# methods at vtable slots 3 and up, four slots short of the real
/// custom-method offset. The first such call after the cast crashes the
/// process (issue #15: SetResultColumnCount lands on OpenConnection's slot and
/// dereferences the int as a BSTR). To eliminate the vtable-layout dependency
/// we route every COM method call through IDispatch via C# `dynamic`. Names
/// are resolved by the server through GetIDsOfNames, so we do not depend on
/// managed DispId assignment or vtable offset.
///
/// Threading: individual COM instances are NOT thread safe, so we create a fresh
/// instance per operation and release it when done. All COM calls are wrapped in
/// Task.Run because the underlying DCOM/RPC calls are synchronous.
/// </summary>
public sealed class AdcsClient : IAdcsClient, IDisposable
{
    private readonly string _caConnectionString;
    private readonly ILogger<AdcsClient> _logger;

    // Template metadata resolved from AD (display name + EKU) changes rarely, but
    // GetTemplatesAsync can be called often (every ACME directory and template
    // listing). Cache the map on this singleton for a short TTL so we do not bind
    // to AD on every call.
    private static readonly TimeSpan TemplateAdCacheTtl = TimeSpan.FromMinutes(5);
    private readonly object _templateAdCacheLock = new();
    private IDictionary<string, AdcsTemplateDirectoryLookup.TemplateAdInfo>? _cachedTemplateAd;
    private DateTime _templateAdCachedAtUtc;

    // A result column key collision repeats on every row of every pass, so it is
    // reported once per colliding name rather than once per row. Keyed by name
    // rather than latched on a single flag: this client is a singleton for the
    // life of the service, so one shared flag would mute a second, unrelated
    // collision forever, which is the same silent degradation the warning exists
    // to end. Guarded by its own lock because a collision is rare enough that
    // contention is irrelevant and a torn HashSet is not.
    private readonly HashSet<string> _warnedColumnCollisions =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Creates a new ADCS client.
    /// </summary>
    /// <param name="caConnectionString">
    /// CA config string in the format "CAHostName\CAName" (e.g., "ca-server.corp.example.com\Example-CA").
    /// </param>
    /// <param name="logger">Logger instance.</param>
    public AdcsClient(string caConnectionString, ILogger<AdcsClient> logger)
    {
        _caConnectionString = caConnectionString ?? throw new ArgumentNullException(nameof(caConnectionString));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            _logger.LogDebug("Getting CA info from {Config}", _caConnectionString);

            object? certRequest = null;
            try
            {
                certRequest = new CertRequestClass();
                dynamic d = certRequest;

                var caName = (string)d.GetCAProperty(
                    _caConnectionString,
                    CaPropertyId.CaName,
                    0,
                    PropertyType.String,
                    0);

                var dnsName = (string)d.GetCAProperty(
                    _caConnectionString,
                    CaPropertyId.DnsName,
                    0,
                    PropertyType.String,
                    0);

                _logger.LogInformation("Connected to CA: {CaName} on {DnsName}", caName, dnsName);

                return new CaInfo(
                    Name: caName,
                    DnsName: dnsName,
                    DisplayName: caName,
                    IsAccessible: true);
            }
            catch (Exception ex) when (ClassifyConnectFailure(ex) is { } mapped)
            {
                // Access denied and an unreachable CA are answers the setup
                // wizard and the rights check act on, so they leave as the
                // typed exceptions every other path here throws (issue #440).
                // Folding them into "not accessible" is what left Test
                // Connection unable to tell a missing right from a CA that is
                // down.
                _logger.LogError(ex, "Failed to connect to CA at {Config}. HRESULT: 0x{HResult:X8}",
                    _caConnectionString, ex.HResult);
                throw mapped;
            }
            catch (COMException ex) when (!IsMissingComponent(ex))
            {
                _logger.LogError(ex, "Failed to connect to CA at {Config}. HRESULT: 0x{HResult:X8}",
                    _caConnectionString, ex.HResult);

                return new CaInfo(
                    Name: _caConnectionString,
                    DnsName: _caConnectionString.Split('\\')[0],
                    DisplayName: null,
                    IsAccessible: false);
            }
            finally
            {
                ReleaseCom(certRequest);
            }
        }, cancellationToken);
    }

    /// <summary>
    /// The exception a failed <see cref="GetCaInfoAsync"/> leaves with, or null
    /// when the failure stays an ordinary "not accessible" answer. Internal for
    /// unit tests.
    ///
    /// Access denied arrives three ways: as UnauthorizedAccessException, the
    /// usual shape through IDispatch; as a COMException carrying E_ACCESSDENIED;
    /// or as CERTSRV_E_ENROLL_DENIED, which a CA answers when the caller lacks
    /// its Enroll right or when it refuses remote requests altogether
    /// (IF_NOREMOTEICERTREQUEST). All three mean the CA refused the service,
    /// and none of them means the CA is down.
    /// </summary>
    internal static Exception? ClassifyConnectFailure(Exception ex) => ex switch
    {
        UnauthorizedAccessException =>
            new CaAccessDeniedException(CaAccessDeniedException.ConnectPermissionMessage, ex),
        COMException com when CaAccessDeniedException.IsRefusal(com) =>
            new CaAccessDeniedException(CaAccessDeniedException.ConnectPermissionMessage, com),
        COMException com when CaUnavailableException.IsRpcUnavailable(com) =>
            new CaUnavailableException("ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", com),
        _ => null,
    };

    /// <summary>
    /// A COM class that is not registered (REGDB_E_CLASSNOTREG), or one that
    /// activates and cannot resolve its methods (DISP_E_MEMBERNOTFOUND, which
    /// the troubleshooting guide reports for a server without RSAT-ADCS-Mgmt).
    /// Both are this server's problem rather than the CA's, so
    /// <see cref="GetCaInfoAsync"/> lets them through to callers that say so.
    /// </summary>
    internal static bool IsMissingComponent(COMException ex) =>
        ex.HResult == unchecked((int)0x80040154) || ex.HResult == unchecked((int)0x80020003);

    public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() => ReadTemplates(), cancellationToken);
    }

    /// <summary>
    /// Synchronously reads the CA template list (CR_PROP_TEMPLATES) and enriches
    /// each entry with its AD <c>displayName</c>. Shared by the async public
    /// <see cref="GetTemplatesAsync"/> and by the certificate sync path, which
    /// uses it to resolve the CA template token to a friendly name. Throws on a
    /// COM failure so the templates endpoint can surface CA-unavailable; the sync
    /// path wraps the call and treats failures as best effort.
    /// </summary>
    private IReadOnlyList<TemplateInfo> ReadTemplates()
    {
        _logger.LogDebug("Querying templates from {Config}", _caConnectionString);

        object? certRequest = null;
        try
        {
            certRequest = new CertRequestClass();
            dynamic d = certRequest;

            // CR_PROP_TEMPLATES (29) returns a string with template pairs:
            // "TemplateName\nTemplateOID\nTemplateName2\nTemplateOID2\n..."
            var templatesRaw = (string)d.GetCAProperty(
                _caConnectionString,
                CaPropertyId.Templates,
                0,
                PropertyType.String,
                0);

            var templates = ParseTemplateString(templatesRaw);

            // Issue #17: CR_PROP_TEMPLATES returns programmatic names only.
            // Enrich each entry from its AD object: the displayName ACME
            // clients address templates by, the EKU set the wizard filters
            // on, and the raw viability attributes behind the wizard's ACME
            // checklist. Templates without an AD entry keep null EKU and
            // viability, which the wizard reads as "could not verify".
            var adInfo = GetTemplateAdInfo();
            if (adInfo.Count > 0)
            {
                for (var i = 0; i < templates.Count; i++)
                {
                    if (!adInfo.TryGetValue(templates[i].Name, out var info))
                        continue;

                    templates[i] = templates[i] with
                    {
                        DisplayName = string.IsNullOrWhiteSpace(info.DisplayName)
                            ? templates[i].DisplayName
                            : info.DisplayName,
                        ExtendedKeyUsages = info.Ekus,
                        Viability = TemplateAcmeViability.FromAdAttributes(
                            info.EnrollmentFlags,
                            info.RaSignatureCount,
                            info.CertificateNameFlags,
                            info.SchemaVersion,
                            info.PrivateKeyFlags,
                            info.RaApplicationPolicies ?? Array.Empty<string>(),
                            info.DefaultCsps ?? Array.Empty<string>(),
                            info.MinimalKeySize),
                    };
                }
            }

            _logger.LogInformation("Found {Count} templates on CA", templates.Count);
            return templates;
        }
        catch (COMException ex)
        {
            _logger.LogError(ex, "Failed to query templates from {Config}. HRESULT: 0x{HResult:X8}",
                _caConnectionString, ex.HResult);
            if (CaUnavailableException.IsRpcUnavailable(ex))
                throw new CaUnavailableException(
                    "ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", ex);
            throw new InvalidOperationException(
                $"Failed to query templates from ADCS CA: {ex.Message}", ex);
        }
        finally
        {
            ReleaseCom(certRequest);
        }
    }

    public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() => ReadCaCertificateChain(), cancellationToken);
    }

    /// <summary>
    /// Synchronously reads the CA's signing certificate chain: the count of
    /// signing certificates the CA has had (renewals add one), then the full
    /// PKCS#7 chain of the newest one, ordered CA certificate first and self
    /// signed root last. Same dynamic IDispatch route and COM error mapping
    /// as <see cref="ReadTemplates"/>.
    /// </summary>
    private IReadOnlyList<byte[]> ReadCaCertificateChain()
    {
        _logger.LogDebug("Querying the CA signing certificate chain from {Config}", _caConnectionString);

        object? certRequest = null;
        try
        {
            certRequest = new CertRequestClass();
            dynamic d = certRequest;

            // CR_PROP_CASIGCERTCOUNT (11): how many signing certificates the
            // CA has had. The newest (the one in force) is at count - 1.
            var count = (int)d.GetCAProperty(
                _caConnectionString,
                CaPropertyId.CaSigCertCount,
                0,
                PropertyType.Long,
                0);
            if (count <= 0)
            {
                throw new InvalidOperationException(
                    "The CA reported no signing certificate (CR_PROP_CASIGCERTCOUNT returned " +
                    count + ").");
            }

            // CR_PROP_CASIGCERTCHAIN (13): the PKCS#7 chain of the indexed
            // signing certificate, base64 encoded when CR_OUT_BASE64 is
            // requested. Convert.FromBase64String tolerates the CRLFs COM
            // inserts into long base64 strings.
            var chainBase64 = (string)d.GetCAProperty(
                _caConnectionString,
                CaPropertyId.CaSigCertChain,
                count - 1,
                PropertyType.Binary,
                OutputEncoding.Base64);
            var pkcs7 = Convert.FromBase64String(chainBase64);

            var cms = new SignedCms();
            cms.Decode(pkcs7);

            var certificates = cms.Certificates.Cast<X509Certificate2>().ToList();
            try
            {
                var ordered = OrderChainLeafFirst(certificates);
                _logger.LogInformation(
                    "CA signing certificate chain retrieved: {Count} certificate(s)", ordered.Count);
                return ordered;
            }
            finally
            {
                foreach (var certificate in certificates)
                    certificate.Dispose();
            }
        }
        catch (COMException ex)
        {
            _logger.LogError(ex,
                "Failed to query the CA certificate chain from {Config}. HRESULT: 0x{HResult:X8}",
                _caConnectionString, ex.HResult);
            if (CaUnavailableException.IsRpcUnavailable(ex))
                throw new CaUnavailableException(
                    "ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", ex);
            throw new InvalidOperationException(
                $"Failed to query the CA certificate chain: {ex.Message}", ex);
        }
        finally
        {
            ReleaseCom(certRequest);
        }
    }

    public Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName,
        byte[] csrDer,
        CancellationToken cancellationToken = default)
    {
        // Build the attribute string up front so its guard runs before anything
        // logs or dispatches: a name carrying a newline must not reach the log
        // either, where it could forge a line. AdcsRequestAttributes owns the
        // format and refuses such a name rather than sanitizing it (issue #175).
        var attributes = AdcsRequestAttributes.ForTemplate(templateName);

        return Task.Run(() =>
        {
            _logger.LogInformation("Submitting CSR for template {Template} to {Config}",
                templateName, _caConnectionString);

            object? certRequest = null;

            // False until Submit itself has returned. Past that line the CA holds a
            // request for this CSR whatever else fails, so a CaUnavailableException
            // must never escape from beyond it: the ACME finalize reads that
            // exception as "nothing reached the CA" and releases its claim so the
            // client can retry the same order (issue #324). A failure of
            // GetRequestId or GetDispositionMessage leaves a request nobody can
            // name, which is a different thing: it stays a plain
            // InvalidOperationException and invalidates the order with the orphan
            // logged, which is the right answer for it.
            var submitReturned = false;
            try
            {
                certRequest = new CertRequestClass();
                dynamic d = certRequest;

                // Convert DER to base64 for submission. The CSR and the
                // attribute string are separate Submit parameters and are never
                // concatenated, so no CSR content can reach the attribute string
                // whatever the request encoding. Base64 is about what ADCS
                // accepts here, not a safety boundary.
                var csrBase64 = Convert.ToBase64String(csrDer);

                // Submit as PKCS#10 in base64 encoding
                var flags = RequestEncoding.Base64 | RequestEncoding.Pkcs10;
                var disposition = (int)d.Submit(
                    flags,
                    csrBase64,
                    attributes,
                    _caConnectionString);
                submitReturned = true;

                // The reason behind the disposition (issue #356). Read here, on the
                // line after the Submit, rather than below beside the message it
                // explains. The documented rule is that GetLastStatus reflects the
                // latest Submit, RetrievePending or GetCACertificate, so GetRequestId
                // and GetDispositionMessage would not disturb it, but reading first
                // means nothing here rests on that list being complete.
                //
                // Asked for only where a refusal is being reported. An issued request
                // would answer S_OK by definition, and a pending one is not a failure
                // and has no reason to give: the docs describe this value as the cause
                // behind a disposition other than issued, and it is denials they name.
                // Nothing reads the code on a pending result either, since both pending
                // arms build their own message about waiting for a CA manager. So a
                // template with CT_FLAG_PEND_ALL_REQUESTS, which answers every single
                // order this way, would have paid a COM round trip per order for a
                // value nothing consumes.
                var statusCode = IsRefusal(disposition) ? ReadLastStatus(certRequest) : null;

                var requestId = (int)d.GetRequestId();
                var rawMessage = (string?)d.GetDispositionMessage();

                // The one line form for the log, the sanitized form for the result
                // (issue #362). This was the last CA authored string in the product
                // that reached an ACME problem document, the wizard, the settings
                // page and this log line untouched; the sync path lower down this
                // same file has run its copy of the column through the sanitizer
                // since issue #224. The log gets the flattened form because Serilog
                // writes the rendered message straight through, so a multi line
                // denial otherwise reads back as several records.
                //
                // The reason rides in its own property rather than inside that one.
                // It is our own single line text so it needs no flattening, and
                // keeping the two apart leaves Message meaning exactly what the CA
                // said, which is what a structured consumer filtering on it expects.
                _logger.LogInformation(
                    "CSR submitted. RequestId={RequestId}, Disposition={Disposition}, " +
                    "Message={Message}, Reason={Reason}",
                    requestId, disposition,
                    CertificateTextSanitizer.SanitizeDispositionMessageForLog(rawMessage),
                    CaStatusCode.Explain(statusCode) ?? "none recorded");

                return BuildSubmitResult(requestId, disposition, rawMessage, statusCode);
            }
            catch (UnauthorizedAccessException ex)
            {
                // E_ACCESSDENIED needs an arm of its own because it is usually not a
                // COMException at all: the CLR maps well known HRESULTs to their
                // managed equivalents on the dynamic IDispatch path, which is why the
                // CertView and CertAdmin paths below each carry this same pair.
                //
                // This is the rarer of the two ways a permissions problem shows up
                // here, and deliberately not the one an operator meets most. A
                // template the service account cannot enroll against is refused by the
                // CA's policy module, so Submit returns normally with a Denied
                // disposition and never reaches this arm. Confirmed on the lab CA on
                // 2026-08-24: request 109 came back Disposition=2 with no exception
                // raised at all, and a disposition message of just "Denied by Policy
                // Module". What lands here is the CA refusing the call itself.
                _logger.LogError(ex,
                    "CA request access denied for template {Template}. HRESULT: 0x{HResult:X8}",
                    templateName, ex.HResult);

                // Gated on !submitReturned exactly as the outage mapping below is, and
                // for the same reason. Both exceptions promise the ACME finalize that
                // nothing reached the CA, which is what lets it release its claim and
                // leave the order retryable. Past the Submit the CA holds a request
                // for this CSR, so a denial out of GetRequestId or GetDispositionMessage
                // leaves a request nobody can name: that takes the plain path, and the
                // order is invalidated with the orphan logged, which is right for it.
                if (!submitReturned)
                    throw new CaAccessDeniedException(
                        CaAccessDeniedException.EnrollPermissionMessage, ex);
                throw new InvalidOperationException(
                    $"Failed to submit certificate request: {ex.Message}", ex);
            }
            catch (COMException ex)
            {
                _logger.LogError(ex, "Failed to submit CSR for template {Template}. HRESULT: 0x{HResult:X8}",
                    templateName, ex.HResult);
                if (!submitReturned && CaUnavailableException.IsRpcUnavailable(ex))
                    throw new CaUnavailableException(
                        "ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", ex);
                // The same denial arriving as a COMException instead. Same gate, same
                // promise; only the shape the CLR chose differs.
                if (!submitReturned && CaAccessDeniedException.IsAccessDenied(ex))
                    throw new CaAccessDeniedException(
                        CaAccessDeniedException.EnrollPermissionMessage, ex);
                throw new InvalidOperationException(
                    $"Failed to submit certificate request: {ex.Message}", ex);
            }
            finally
            {
                ReleaseCom(certRequest);
            }
        }, cancellationToken);
    }

    /// <summary>
    /// The status a disposition maps to.
    ///
    /// One switch, so <see cref="BuildSubmitResult"/> and <see cref="IsRefusal"/>
    /// cannot come to disagree about which dispositions are refusals.
    /// </summary>
    internal static SubmitStatus MapDisposition(int disposition) => disposition switch
    {
        DispositionCode.Issued => SubmitStatus.Issued,
        DispositionCode.IssuedOutOfBand => SubmitStatus.Issued,
        DispositionCode.UnderSubmission => SubmitStatus.Pending,
        DispositionCode.Denied => SubmitStatus.Denied,
        _ => SubmitStatus.Error
    };

    /// <summary>
    /// The status a CA database disposition maps to, for a request row read back
    /// out of the CA view.
    ///
    /// The read side sibling of <see cref="MapDisposition"/>, and a different
    /// vocabulary on both ends: the numbers are the database's
    /// <see cref="DbDisposition"/> values rather than the submit's
    /// <see cref="DispositionCode"/> ones, and the answer distinguishes a revoked
    /// certificate, which a submit never sees. One switch, so
    /// <see cref="MapToCertificateInfo"/> and
    /// <see cref="GetRequestStatusAsync"/> cannot come to disagree about what a
    /// row says (issue #365).
    ///
    /// Anything unrecognised reads as <see cref="CertificateStatus.Failed"/>,
    /// which is what the Error disposition itself maps to. The remaining value,
    /// Active (8), is a foreign key placeholder rather than a request outcome.
    /// </summary>
    internal static CertificateStatus MapCertificateStatus(int disposition) => disposition switch
    {
        DbDisposition.Issued => CertificateStatus.Issued,
        DbDisposition.Revoked => CertificateStatus.Revoked,
        DbDisposition.Pending => CertificateStatus.Pending,
        DbDisposition.Denied => CertificateStatus.Denied,
        _ => CertificateStatus.Failed
    };

    /// <summary>
    /// Whether the CA recorded an explanation worth reading against a row in this
    /// state. The CA writes DispositionMessage and StatusCode for a request it is
    /// still holding or has refused; an issued row carries "Issued" and a zero
    /// status code, which is noise rather than an explanation, and a revoked one
    /// carries nothing about the request at all.
    ///
    /// One predicate, so <see cref="MapToCertificateInfo"/> and
    /// <see cref="GetRequestStatusAsync"/> withhold the same pair on the same rows
    /// (issue #365).
    /// </summary>
    internal static bool CarriesExplanation(CertificateStatus status) =>
        status is CertificateStatus.Pending
            or CertificateStatus.Denied
            or CertificateStatus.Failed;

    /// <summary>
    /// The CA's own account of a request, sanitized. CA authored text bound for
    /// an ACME problem document and the dashboard, so it goes through
    /// <see cref="CertificateTextSanitizer"/> on both read paths.
    /// </summary>
    private static string? ReadDispositionMessage(Dictionary<string, object?> values) =>
        CertificateTextSanitizer.SanitizeDispositionMessage(
            values.GetValueOrDefault(ColumnName.DispositionMessage)?.ToString());

    /// <summary>
    /// The HRESULT the CA recorded, or null. Zero means success and never carries
    /// information, so it reads the same as nothing recorded; so does a column the
    /// IDispatch path handed back as something other than an int.
    /// </summary>
    private static int? ReadStatusCode(Dictionary<string, object?> values) =>
        values.GetValueOrDefault(ColumnName.StatusCode) is int code && code != 0
            ? code
            : null;

    /// <summary>
    /// Whether the CA refused this request, and so whether it holds a reason worth
    /// asking <c>GetLastStatus</c> for (issue #356).
    ///
    /// Written as the two outcomes that admit a reason rather than as "not issued",
    /// following the house rule that these are allow lists: a SubmitStatus added
    /// later then costs nothing until someone decides it should.
    /// </summary>
    internal static bool IsRefusal(int disposition) =>
        MapDisposition(disposition) is SubmitStatus.Denied or SubmitStatus.Error;

    /// <summary>
    /// The HRESULT behind a disposition, from <c>ICertRequest::GetLastStatus</c>
    /// (issue #356), or null when the CA recorded nothing or the read failed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Its own try/catch, inside the submit's, and that placement is the point
    /// rather than defensive habit. By the time this runs the CA holds a request
    /// for the CSR, so <c>submitReturned</c> is already true and the outage and
    /// access denied gates above cannot fire. But a COMException escaping from
    /// here would still reach the plain arm of the submit's own catch, become an
    /// InvalidOperationException, and invalidate an order the CA had already
    /// decided. A line added to explain a refusal would have destroyed the
    /// refusal it was explaining.
    /// </para>
    /// <para>
    /// Deliberately broad, because the failures are not one shape. The dispatch
    /// can raise COMException, a certcli build that does not expose the name
    /// raises RuntimeBinderException, and a return shape other than a LONG raises
    /// InvalidCastException. None of them is worth a request. The value is a
    /// diagnostic and its absence is an ordinary answer, which is why
    /// <see cref="SubmitResult.StatusCode"/> documents "read failed" as one of
    /// the three cases no caller may tell apart.
    /// </para>
    /// <para>
    /// Zero maps to null. GetLastStatus answers S_OK after a call that succeeded,
    /// so a zero means the request was not refused rather than refused for reason
    /// zero, and <see cref="MapToCertificateInfo"/> already reads the CA view's
    /// own StatusCode column the same way.
    /// </para>
    /// </remarks>
    /// <param name="certRequest">
    /// The CCertRequest instance that ran the submit, taken as object rather than
    /// as dynamic on purpose. A dynamic argument makes the whole call dynamically
    /// dispatched, which makes its result dynamic too, and that spreads: the log
    /// call below it cannot bind an extension method on a dynamic argument at all
    /// (CS1973). Binding this one call statically keeps the dynamic dispatch where
    /// it belongs, on the COM method inside.
    /// </param>
    private int? ReadLastStatus(object certRequest)
    {
        try
        {
            dynamic d = certRequest;
            var code = (int)d.GetLastStatus();
            return code == 0 ? null : code;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "The CA accepted the request but its status code could not be read, so the " +
                "refusal is reported with the CA's own message alone");
            return null;
        }
    }

    /// <summary>
    /// What the CA said about a submitted request, as a <see cref="SubmitResult"/>.
    ///
    /// Split out of <see cref="SubmitCertificateRequestAsync"/> so the mapping and
    /// the sanitize have a test seam, the same shape as
    /// <see cref="MapToCertificateInfo"/> one path over: the submit itself needs a
    /// live CA, this does not.
    ///
    /// The message is CA authored text bound for an ACME problem document, the
    /// wizard and the settings page, so it goes through
    /// <see cref="CertificateTextSanitizer"/> exactly as the sync path's copy of
    /// the same column does (issue #362). That call is pure string work and cannot
    /// reach the CA, so placing it here does not disturb the submitReturned
    /// reasoning above: nothing it can throw is a statement about connectivity.
    ///
    /// A blank message becomes null rather than an empty string, which is what
    /// lets the "no reason given" fallbacks in <c>OrderService</c> and
    /// <c>TlsCertificateEnroller</c> fire for a CA that answered with nothing.
    /// </summary>
    /// <param name="statusCode">
    /// The HRESULT the caller read for a refusal (issue #356), or null. It is not
    /// read here because reading it needs the live CCertRequest instance, which is
    /// exactly what keeping this method free of the CA buys.
    /// </param>
    internal static SubmitResult BuildSubmitResult(
        int requestId, int disposition, string? rawMessage, int? statusCode = null)
    {
        return new SubmitResult(requestId, MapDisposition(disposition),
            CertificateTextSanitizer.SanitizeDispositionMessage(rawMessage),
            statusCode);
    }

    public Task<CertificateResult> GetCertificateAsync(
        int requestId,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            _logger.LogDebug("Retrieving certificate for RequestId={RequestId}", requestId);

            object? certRequest = null;
            try
            {
                certRequest = new CertRequestClass();
                dynamic d = certRequest;

                var disposition = (int)d.GetIssuedCertificate(
                    _caConnectionString,
                    requestId,
                    (string?)null);

                if (disposition != DispositionCode.Issued &&
                    disposition != DispositionCode.IssuedOutOfBand)
                {
                    var status = disposition switch
                    {
                        DispositionCode.UnderSubmission => CertificateStatus.Pending,
                        DispositionCode.Denied => CertificateStatus.Denied,
                        DispositionCode.Revoked => CertificateStatus.Revoked,
                        _ => CertificateStatus.Failed
                    };

                    return new CertificateResult(requestId, status);
                }

                // Retrieve the certificate in PEM format (base64 with headers)
                var certPem = (string)d.GetCertificate(OutputEncoding.Base64Header);

                // Also get the raw DER
                var certBase64 = (string)d.GetCertificate(OutputEncoding.Base64);
                var certDer = Convert.FromBase64String(certBase64);

                // Retrieve the full PKCS#7 chain so ACME clients (RFC 8555 7.4.2)
                // see the complete leaf + issuer chain. Failure here must not
                // poison the leaf retrieval, so we log and fall back to the leaf.
                var chainPem = certPem;
                try
                {
                    var pkcs7Pem = (string)d.GetCertificate(
                        OutputEncoding.Base64Header | OutputEncoding.Chain);
                    chainPem = BuildAcmeChainPem(certDer, pkcs7Pem);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex,
                        "Failed to retrieve PKCS#7 chain for RequestId={RequestId}; " +
                        "returning leaf only", requestId);
                }

                var chainCount = CountPemCertificates(chainPem);
                _logger.LogInformation(
                    "Certificate retrieved for RequestId={RequestId}; ACME chain contains {ChainCount} cert(s)",
                    requestId, chainCount);

                return new CertificateResult(
                    requestId,
                    CertificateStatus.Issued,
                    CertificateDer: certDer,
                    CertificatePem: chainPem);
            }
            catch (UnauthorizedAccessException ex)
            {
                // ICertRequest::GetIssuedCertificate needs the caller to be the
                // request's own submitter or to hold "Read" on the CA, the same ACL
                // CCertView::OpenConnection needs below. No gate here, unlike the
                // submit: this call writes nothing and decides nothing, so there is no
                // "past this point" to protect. The certificate exists at the CA
                // either way and is collected by the pending issuance sweep once the
                // right is restored.
                _logger.LogError(ex,
                    "CA collection access denied for RequestId={RequestId}. HRESULT: 0x{HResult:X8}",
                    requestId, ex.HResult);
                throw new CaAccessDeniedException(
                    CaAccessDeniedException.CollectPermissionMessage, ex);
            }
            catch (COMException ex) when (CaAccessDeniedException.IsAccessDenied(ex))
            {
                _logger.LogError(ex,
                    "CA collection access denied for RequestId={RequestId}. HRESULT: 0x{HResult:X8}",
                    requestId, ex.HResult);
                throw new CaAccessDeniedException(
                    CaAccessDeniedException.CollectPermissionMessage, ex);
            }
            catch (COMException ex)
            {
                _logger.LogError(ex,
                    "Failed to retrieve certificate for RequestId={RequestId}. HRESULT: 0x{HResult:X8}",
                    requestId, ex.HResult);
                if (CaUnavailableException.IsRpcUnavailable(ex))
                    throw new CaUnavailableException(
                        "ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", ex);
                throw new InvalidOperationException(
                    $"Failed to retrieve certificate: {ex.Message}", ex);
            }
            finally
            {
                ReleaseCom(certRequest);
            }
        }, cancellationToken);
    }

    public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            _logger.LogDebug("Querying CA database with filter: Template={Template}, Subject={Subject}",
                query.TemplateName, query.SubjectContains);

            // Resolve the CA template token (an OID for v2/v3 templates, the
            // programmatic name for v1) to its friendly display name. Best effort:
            // a failure here must never break the certificate sync, so on error we
            // fall back to an empty map and templates display as their raw token.
            Dictionary<string, string> templateMap;
            try
            {
                templateMap = BuildTemplateDisplayMap(ReadTemplates());
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Template display-name resolution unavailable; templates will show their raw CA value.");
                templateMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }

            object? certView = null;
            object? rowEnum = null;
            try
            {
                certView = new CertViewClass();
                dynamic v = certView;
                v.OpenConnection(_caConnectionString);
                // Note: SetTable is v2-only (ICertView2). The deployed certcli.dll on
                // the target Windows build does not expose IID_ICertView2 to QI, so
                // we never call SetTable. The default request table contains issued,
                // pending, and revoked rows distinguished by the Disposition column,
                // which ApplyRestrictions filters on below.

                // Define which columns we want in the result. RawCertificate is
                // included so SAN only certificates (typical for ACME issued
                // ones, whose CSRs carry an empty subject DN) still get a
                // display name and searchable SAN list parsed from the
                // certificate itself. The same blob also yields the key
                // algorithm, key size, signature algorithm, thumbprint, EKU,
                // and key usage (issue #150), so that detail costs no extra CA
                // round trip either. DispositionMessage and StatusCode are the
                // CA's own account of why a request pended, was denied, or
                // failed; they are read only on those dispositions (see
                // MapToCertificateInfo).
                var columns = new[]
                {
                    ColumnName.RequestId,
                    ColumnName.SerialNumber,
                    ColumnName.CommonName,
                    ColumnName.DistinguishedName,
                    ColumnName.CertificateTemplate,
                    ColumnName.NotBefore,
                    ColumnName.NotAfter,
                    ColumnName.Disposition,
                    ColumnName.DispositionMessage,
                    ColumnName.StatusCode,
                    ColumnName.RequesterName,
                    ColumnName.SubmittedWhen,
                    ColumnName.RevokedWhen,
                    ColumnName.RevokedReason,
                    ColumnName.RawCertificate,
                    // The subject the CSR asked for, which is the only name a
                    // request row can have: the bare CommonName and
                    // DistinguishedName above are the issued certificate's and
                    // carry nothing until issuance (issue #186). Read back under
                    // their qualified names, see RequestColumnName.
                    RequestColumnName.DistinguishedName,
                    RequestColumnName.CommonName
                };

                // Resolve every index first and register only what resolved. A
                // schema name the deployed certcli does not recognise otherwise
                // throws straight out of the loop and takes the whole query with
                // it, for every disposition pass. Degrading to a missing column
                // is survivable; a dead sync is not.
                //
                // RequestID and Disposition are the exception. MapToCertificateInfo
                // drops any row missing either one, so losing them turns every
                // pass into a silent zero row success and the dashboard simply
                // stops updating with nothing in the log to say why. Those two
                // still fail loudly.
                var resolvedColumns = new List<int>(columns.Length);
                foreach (var col in columns)
                {
                    try
                    {
                        resolvedColumns.Add((int)v.GetColumnIndex(ColumnType.Schema, col));
                    }
                    catch (Exception ex) when (!IsRequiredColumn(col))
                    {
                        // Deliberately broad. The dynamic IDispatch path does not
                        // hand every COM failure back as a COMException: the CLR
                        // maps well known HRESULTs to their managed equivalents,
                        // which is why the OpenConnection catch below has to name
                        // UnauthorizedAccessException for E_ACCESSDENIED. An
                        // unknown schema name most likely arrives as E_INVALIDARG,
                        // so catching COMException alone would let exactly the
                        // failure this guard exists for through.
                        _logger.LogWarning(ex,
                            "CA view does not expose the {Column} column; continuing without it",
                            col);
                    }
                }

                v.SetResultColumnCount(resolvedColumns.Count);
                foreach (var idx in resolvedColumns)
                    v.SetResultColumn(idx);

                // Apply restrictions based on query
                ApplyRestrictions(v, query);

                rowEnum = v.OpenView();
                dynamic e = rowEnum!;

                var results = new List<CertificateInfo>();
                var skipped = 0;
                var warnedMissingDisposition = false;

                // Resolved once rather than per row. A subject search runs on the
                // mapped subject below, and the certificate's own parsed subject
                // is the last link in the chain that produces it, so a skipped
                // row would be searched on a different value than an unskipped
                // one. The sync never sets SubjectContains and is the only
                // production caller, so this costs nothing today; it is here so
                // the two cannot start interacting silently later.
                var alreadyDetailed = query.SubjectContains == null
                    ? query.AlreadyDetailed
                    : null;

                // Skip and Take count result-eligible rows, not raw view rows: a
                // malformed row or one filtered out by SubjectContains must not
                // consume a page slot. ICertView has no server-side offset, so for a
                // full enumeration (a large Take) the caller reads every matching
                // row once here and pages in memory.
                while ((int)e.Next() != -1)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (results.Count >= query.Take)
                        break;

                    object colEnum = e.EnumCertViewColumn();
                    var values = ReadColumnValues(colEnum, resolvedColumns.Count);
                    ReleaseCom(colEnum);

                    // A row without a readable Disposition cannot be classified
                    // and is skipped by MapToCertificateInfo. Warn once per
                    // query, with the names that did come back, so a schema
                    // naming surprise is diagnosable instead of silent.
                    if (!warnedMissingDisposition && !values.ContainsKey(ColumnName.Disposition))
                    {
                        warnedMissingDisposition = true;
                        _logger.LogWarning(
                            "CA view returned rows without a readable Disposition column (columns seen: {Columns}); these rows are skipped instead of defaulting to a Failed status",
                            string.Join(", ", values.Keys));
                    }

                    var certInfo = MapToCertificateInfo(values, templateMap, alreadyDetailed);
                    if (certInfo == null)
                        continue; // malformed row, does not count toward paging

                    // Client side filter that cannot be expressed via SetRestriction.
                    if (query.SubjectContains != null &&
                        !certInfo.Subject.Contains(query.SubjectContains, StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (skipped < query.Skip)
                    {
                        skipped++;
                        continue;
                    }

                    results.Add(certInfo);
                }

                _logger.LogInformation("Query returned {Count} certificates", results.Count);
                return (IReadOnlyList<CertificateInfo>)results;
            }
            catch (UnauthorizedAccessException ex)
            {
                // CCertView::OpenConnection on a CA where the service account lacks
                // "Read" surfaces E_ACCESSDENIED as UnauthorizedAccessException via the
                // dynamic IDispatch path. Rethrow with the remediation message so the
                // sync service logs something actionable instead of a generic failure.
                _logger.LogError(ex,
                    "CA view access denied (CCertView). HRESULT: 0x{HResult:X8}", ex.HResult);
                throw new CaAccessDeniedException(CaAccessDeniedException.SyncReadPermissionMessage, ex);
            }
            catch (COMException ex) when (CaAccessDeniedException.IsAccessDenied(ex))
            {
                _logger.LogError(ex,
                    "CA view access denied (CCertView). HRESULT: 0x{HResult:X8}", ex.HResult);
                throw new CaAccessDeniedException(CaAccessDeniedException.SyncReadPermissionMessage, ex);
            }
            catch (COMException ex)
            {
                _logger.LogError(ex, "Failed to query CA database. HRESULT: 0x{HResult:X8}", ex.HResult);
                if (CaUnavailableException.IsRpcUnavailable(ex))
                    throw new CaUnavailableException(
                        "ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", ex);
                throw new InvalidOperationException(
                    $"Failed to query CA database: {ex.Message}", ex);
            }
            finally
            {
                ReleaseCom(rowEnum);
                ReleaseCom(certView);
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Reads back what the CA recorded against one request (issue #365).
    ///
    /// <para>
    /// Deliberately not <see cref="QueryCertificatesAsync"/> with a request id
    /// added to <see cref="CertificateQuery"/>. Two reasons, and the first is a
    /// trap. <see cref="ApplyRestrictions"/> confines a query with no explicit
    /// status to issued rows, so a request id query routed through it would
    /// return nothing for exactly the denial this exists to read, and would do so
    /// only against a real CA. The second is cost: that path resolves template
    /// display names on every call, which needs a CA round trip and an AD bind
    /// this has no use for.
    /// </para>
    ///
    /// <para>
    /// One restriction, on the request table's primary key, and no disposition
    /// restriction at all, so every disposition is visible. That is the shape
    /// <c>certutil -view -restrict "RequestId=N"</c> takes.
    /// </para>
    /// </summary>
    public Task<CaRequestStatus?> GetRequestStatusAsync(
        int requestId,
        CancellationToken cancellationToken = default)
    {
        return Task.Run<CaRequestStatus?>(() =>
        {
            _logger.LogDebug("Reading the CA's record of request {RequestId}", requestId);

            object? certView = null;
            object? rowEnum = null;
            try
            {
                certView = new CertViewClass();
                dynamic v = certView;
                v.OpenConnection(_caConnectionString);

                // The same degrade unless required treatment the query path uses:
                // a schema name the deployed certcli does not recognise must cost
                // the column rather than the whole read. RequestID and Disposition
                // are required for the same reason they are there, since without
                // either there is nothing to answer with.
                var columns = new[]
                {
                    ColumnName.RequestId,
                    ColumnName.Disposition,
                    ColumnName.DispositionMessage,
                    ColumnName.StatusCode
                };

                var resolvedColumns = new List<int>(columns.Length);
                var requestIdIndex = -1;
                foreach (var col in columns)
                {
                    try
                    {
                        var index = (int)v.GetColumnIndex(ColumnType.Schema, col);
                        resolvedColumns.Add(index);
                        if (col == ColumnName.RequestId)
                            requestIdIndex = index;
                    }
                    catch (Exception ex) when (!IsRequiredColumn(col))
                    {
                        _logger.LogWarning(ex,
                            "CA view does not expose the {Column} column; continuing without it",
                            col);
                    }
                }

                v.SetResultColumnCount(resolvedColumns.Count);
                foreach (var idx in resolvedColumns)
                    v.SetResultColumn(idx);

                object idValue = requestId;
                v.SetRestriction(
                    requestIdIndex,
                    SeekOperator.Equal,
                    SortOrder.None,
                    idValue);

                rowEnum = v.OpenView();
                dynamic e = rowEnum!;

                if ((int)e.Next() == -1)
                {
                    // No such request. Not an error: the caller holds a request id
                    // this CA has no row for, which is what a restored database
                    // pointed at a different CA looks like.
                    _logger.LogDebug("The CA has no row for request {RequestId}", requestId);
                    return null;
                }

                object colEnum = e.EnumCertViewColumn();
                var values = ReadColumnValues(colEnum, resolvedColumns.Count);
                ReleaseCom(colEnum);

                if (!values.ContainsKey(ColumnName.Disposition))
                {
                    // Unclassifiable, exactly as in MapToCertificateInfo. Guessing
                    // a status here would put a wrong word in an ACME error.
                    _logger.LogWarning(
                        "The CA returned request {RequestId} without a readable Disposition " +
                        "column (columns seen: {Columns})",
                        requestId, string.Join(", ", values.Keys));
                    return null;
                }

                var disposition = values.GetValueOrDefault(ColumnName.Disposition) is int disp ? disp : 0;
                var status = MapCertificateStatus(disposition);

                return new CaRequestStatus(
                    requestId,
                    status,
                    CarriesExplanation(status) ? ReadDispositionMessage(values) : null,
                    CarriesExplanation(status) ? ReadStatusCode(values) : null);
            }
            catch (UnauthorizedAccessException ex)
            {
                // A CA view read, so it is the sync's "Read" right that is missing
                // and not the collection one. Naming the wrong permission would
                // send an operator to the wrong checkbox.
                _logger.LogError(ex,
                    "CA view access denied reading request {RequestId}. HRESULT: 0x{HResult:X8}",
                    requestId, ex.HResult);
                throw new CaAccessDeniedException(CaAccessDeniedException.SyncReadPermissionMessage, ex);
            }
            catch (COMException ex) when (CaAccessDeniedException.IsAccessDenied(ex))
            {
                _logger.LogError(ex,
                    "CA view access denied reading request {RequestId}. HRESULT: 0x{HResult:X8}",
                    requestId, ex.HResult);
                throw new CaAccessDeniedException(CaAccessDeniedException.SyncReadPermissionMessage, ex);
            }
            catch (COMException ex)
            {
                _logger.LogError(ex,
                    "Failed to read the CA's record of request {RequestId}. HRESULT: 0x{HResult:X8}",
                    requestId, ex.HResult);
                if (CaUnavailableException.IsRpcUnavailable(ex))
                    throw new CaUnavailableException(
                        "ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", ex);
                throw new InvalidOperationException(
                    $"Failed to read the CA's record of request {requestId}: {ex.Message}", ex);
            }
            finally
            {
                ReleaseCom(rowEnum);
                ReleaseCom(certView);
            }
        }, cancellationToken);
    }

    public Task RevokeCertificateAsync(
        string serialNumber,
        int reason,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            _logger.LogInformation(
                "Revoking certificate serial {Serial} (reason {Reason}) on {Config}",
                serialNumber, reason, _caConnectionString);

            object? certAdmin = null;
            try
            {
                // CCertAdmin is dual (inherits IDispatch). Per issues #14/#15 and CLAUDE.md,
                // we instantiate the coclass and dispatch every method through IDispatch via
                // `dynamic`; no typed ICertAdmin/ICertAdmin2 interface and no cast.
                certAdmin = new CertAdminClass();
                dynamic d = certAdmin;

                // ICertAdmin::RevokeCertificate(strConfig, strSerialNumber, Reason, Date).
                // The serial is lowercased to match the CA database / certutil representation;
                // the ACME side sources it from X509Certificate2.SerialNumber, which is
                // uppercase. Passing the current time for Date revokes as of now.
                d.RevokeCertificate(
                    _caConnectionString,
                    serialNumber.ToLowerInvariant(),
                    reason,
                    DateTime.UtcNow);

                _logger.LogInformation("Certificate serial {Serial} revoked", serialNumber);
            }
            catch (UnauthorizedAccessException ex)
            {
                // The dynamic IDispatch path usually surfaces E_ACCESSDENIED as
                // UnauthorizedAccessException. Revocation needs "Issue and Manage
                // Certificates" on the CA, a different ACL from request/submission.
                _logger.LogError(ex,
                    "CA revoke access denied (CCertAdmin). HRESULT: 0x{HResult:X8}", ex.HResult);
                throw new CaAccessDeniedException(CaAccessDeniedException.RevokePermissionMessage, ex);
            }
            catch (COMException ex) when (CaAccessDeniedException.IsAccessDenied(ex))
            {
                _logger.LogError(ex,
                    "CA revoke access denied (CCertAdmin). HRESULT: 0x{HResult:X8}", ex.HResult);
                throw new CaAccessDeniedException(CaAccessDeniedException.RevokePermissionMessage, ex);
            }
            catch (COMException ex)
            {
                _logger.LogError(ex, "Failed to revoke certificate {Serial}. HRESULT: 0x{HResult:X8}",
                    serialNumber, ex.HResult);
                if (CaUnavailableException.IsRpcUnavailable(ex))
                    throw new CaUnavailableException(
                        "ADCS Certificate Authority is unavailable (CertSvc RPC unreachable).", ex);
                throw new InvalidOperationException(
                    $"Failed to revoke certificate: {ex.Message}", ex);
            }
            finally
            {
                ReleaseCom(certAdmin);
            }
        }, cancellationToken);
    }

    public void Dispose()
    {
        // No persistent COM objects to release — we create and release per-call.
    }

    #region Private Helpers

    /// <summary>
    /// Parses the template string from CR_PROP_TEMPLATES.
    /// Format: "Name1\nOID1\nName2\nOID2\n..."
    /// </summary>
    internal static List<TemplateInfo> ParseTemplateString(string raw)
    {
        var templates = new List<TemplateInfo>();
        if (string.IsNullOrWhiteSpace(raw))
            return templates;

        var parts = raw.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        // Templates come in pairs: name, OID
        for (var i = 0; i + 1 < parts.Length; i += 2)
        {
            var name = parts[i].Trim();
            var oid = parts[i + 1].Trim();

            if (!string.IsNullOrEmpty(name))
            {
                templates.Add(new TemplateInfo(
                    Name: name,
                    DisplayName: name,
                    Oid: oid));
            }
        }

        return templates;
    }

    /// <summary>
    /// Builds a lookup from a CA template token to its friendly display name.
    /// Keyed by both the template OID (what the CA database stores for v2/v3
    /// templates) and the programmatic name (what it stores for v1 templates),
    /// so a row can be resolved regardless of template version. Entries with a
    /// blank display name are skipped. Comparison is case insensitive.
    /// </summary>
    internal static Dictionary<string, string> BuildTemplateDisplayMap(IReadOnlyList<TemplateInfo> templates)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in templates)
        {
            if (string.IsNullOrWhiteSpace(t.DisplayName))
                continue;
            if (!string.IsNullOrWhiteSpace(t.Oid))
                map[t.Oid] = t.DisplayName;
            if (!string.IsNullOrWhiteSpace(t.Name))
                map[t.Name] = t.DisplayName;
        }
        return map;
    }

    /// <summary>
    /// Resolves a raw CA template token to its friendly display name using the
    /// map from <see cref="BuildTemplateDisplayMap"/>. Returns the raw token when
    /// there is no entry (for example a decommissioned template no longer present
    /// on the CA), and an empty string for empty input.
    ///
    /// <para>
    /// The result is sanitized, which is why the token is returned "when" there is
    /// no entry rather than "unchanged" (issue #378). Neither value it can return
    /// is authored by Ducks: one is a CA row, the other a directory read. Doing it
    /// here rather than at the call site covers both with one strip and puts it
    /// where a test can reach it, since the row mapper itself needs a live CA view.
    /// </para>
    ///
    /// <para>
    /// After the lookup, never before. The map is keyed on exactly what the CA
    /// stored, so a stripped key would miss its entry and force the raw fallback
    /// for the very rows this guards.
    /// </para>
    /// </summary>
    internal static string ResolveTemplateName(string? rawTemplate, IReadOnlyDictionary<string, string> map)
    {
        if (string.IsNullOrEmpty(rawTemplate))
            return "";
        var resolved = map.TryGetValue(rawTemplate, out var displayName) && !string.IsNullOrWhiteSpace(displayName)
            ? displayName
            : rawTemplate;
        return CertificateTextSanitizer.SanitizeTemplateName(resolved) ?? "";
    }

    /// <summary>
    /// Returns the AD template display name map, memoized on this instance for a
    /// short TTL. The lookup is best effort and template names change rarely, so a
    /// cache miss does the AD bind once and serves later listings from memory.
    /// </summary>
    private IDictionary<string, AdcsTemplateDirectoryLookup.TemplateAdInfo> GetTemplateAdInfo()
    {
        lock (_templateAdCacheLock)
        {
            if (_cachedTemplateAd != null &&
                DateTime.UtcNow - _templateAdCachedAtUtc < TemplateAdCacheTtl)
            {
                return _cachedTemplateAd;
            }

            _cachedTemplateAd = AdcsTemplateDirectoryLookup.ResolveTemplates(_logger);
            _templateAdCachedAtUtc = DateTime.UtcNow;
            return _cachedTemplateAd;
        }
    }

    private static void ApplyRestrictions(dynamic certView, CertificateQuery query)
    {
        // Filter by disposition (status)
        if (query.Status.HasValue)
        {
            int dispositionIndex = (int)certView.GetColumnIndex(ColumnType.Schema, ColumnName.Disposition);
            var dbDisp = query.Status.Value switch
            {
                CertificateStatus.Issued => DbDisposition.Issued,
                CertificateStatus.Pending => DbDisposition.Pending,
                CertificateStatus.Revoked => DbDisposition.Revoked,
                CertificateStatus.Denied => DbDisposition.Denied,
                CertificateStatus.Failed => DbDisposition.Error,
                _ => DbDisposition.Issued
            };

            object dispValue = dbDisp;
            certView.SetRestriction(
                dispositionIndex,
                SeekOperator.Equal,
                SortOrder.None,
                dispValue);
        }
        else
        {
            // Default: only issued certificates. There is no single "all
            // dispositions" view here, so a caller that needs another disposition
            // (for example revoked) must pass query.Status explicitly.
            int dispositionIndex = (int)certView.GetColumnIndex(ColumnType.Schema, ColumnName.Disposition);
            object dispValue = (int)DbDisposition.Issued;
            certView.SetRestriction(
                dispositionIndex,
                SeekOperator.Equal,
                SortOrder.None,
                dispValue);
        }

        // Filter by template
        if (!string.IsNullOrEmpty(query.TemplateName))
        {
            int templateIndex = (int)certView.GetColumnIndex(ColumnType.Schema, ColumnName.CertificateTemplate);
            object templateValue = query.TemplateName;
            certView.SetRestriction(
                templateIndex,
                SeekOperator.Equal,
                SortOrder.None,
                templateValue);
        }

        // Filter by expiry
        if (query.ExpiringBefore.HasValue)
        {
            int notAfterIndex = (int)certView.GetColumnIndex(ColumnType.Schema, ColumnName.NotAfter);
            object dateValue = query.ExpiringBefore.Value;
            certView.SetRestriction(
                notAfterIndex,
                SeekOperator.LessOrEqual,
                SortOrder.None,
                dateValue);
        }

        // Bound how far back a disposition pass reaches by arrival time. Used
        // by the sync for the pending pass, whose table grows without limit on
        // a busy CA. An admin chases a request that is stuck now, not one that
        // stalled three years ago.
        if (query.SubmittedAfter.HasValue)
        {
            int submittedIndex = (int)certView.GetColumnIndex(ColumnType.Schema, ColumnName.SubmittedWhen);
            object submittedValue = query.SubmittedAfter.Value;
            certView.SetRestriction(
                submittedIndex,
                SeekOperator.GreaterOrEqual,
                SortOrder.None,
                submittedValue);
        }

        // Bound a disposition pass by decision time instead. Used by the sync
        // for the denied and failed passes (issue #187): a request submitted
        // before the window but decided inside it is invisible to a
        // SubmittedWhen bound, and its local row would say Pending forever.
        // Never combine with a pending pass, which has no ResolvedWhen yet.
        // The AdcsQiProbe run on the lab CA (2026-08-04) proved the
        // restriction stacks with the Disposition equality on one view and
        // that ResolvedWhen is a populated DateTime on decided rows. That run
        // had ResolvedWhen registered as a result column, which this client
        // does not do (it restricts only); the probe carries a pass in exactly
        // this restrict only shape to close that difference on a lab run.
        if (query.ResolvedAfter.HasValue)
        {
            int resolvedIndex = (int)certView.GetColumnIndex(ColumnType.Schema, ColumnName.ResolvedWhen);
            object resolvedValue = query.ResolvedAfter.Value;
            certView.SetRestriction(
                resolvedIndex,
                SeekOperator.GreaterOrEqual,
                SortOrder.None,
                resolvedValue);
        }
    }

    /// <summary>
    /// Whether a result column is load bearing enough that failing to resolve it
    /// should take the query down rather than degrade. Both of these gate
    /// <see cref="MapToCertificateInfo"/>, which drops every row that lacks
    /// either, so a missing one is indistinguishable from an empty CA.
    /// </summary>
    private static bool IsRequiredColumn(string column) =>
        column == ColumnName.RequestId || column == ColumnName.Disposition;

    /// <summary>
    /// Schema names that must keep their table qualifier, because stripping it
    /// would collide with a different column carrying a different value. See
    /// <see cref="RequestColumnName"/>. Everything else normalizes, so a request
    /// table column and its unqualified constant still meet.
    /// </summary>
    private static readonly HashSet<string> QualifiedKeyColumns =
        new(StringComparer.OrdinalIgnoreCase)
        {
            RequestColumnName.CommonName,
            RequestColumnName.DistinguishedName,
        };

    /// <summary>
    /// Turns a CA view schema column name into the key row values are stored
    /// under. GetColumnIndex accepts unqualified names when the query is built,
    /// but IEnumCERTVIEWCOLUMN::GetName returns the canonical schema name, which
    /// is table qualified for request table columns ("Request.Disposition",
    /// "Request.RequesterName", "Request.SubmittedWhen"). Both forms normalize
    /// to the bare column name so lookups by the ColumnName constants hit either
    /// way. Before this normalization those three lookups missed and every
    /// synced certificate surfaced as Failed with no requester and no request
    /// date.
    ///
    /// The two columns in <see cref="QualifiedKeyColumns"/> are the exception
    /// and keep their qualifier, because their bare form names a different
    /// column (issue #186).
    /// </summary>
    internal static string NormalizeColumnName(string name)
    {
        // Deliberately an allowlist rather than a rule about which table a name
        // belongs to. Every other request table column normalizes to its bare
        // form and is read by the ColumnName constants; only these two have a
        // twin, and only they are exempt.
        //
        // TryGetValue rather than Contains so the stored constant is returned
        // and not the caller's spelling. The match is case insensitive but the
        // dictionary these keys land in is not, and MapToCertificateInfo reads
        // them back by the exact RequestColumnName literal. Returning the input
        // verbatim would file a differently cased name under a key nothing ever
        // looks up, and unlike a collision that failure is invisible even to the
        // warning below, because it is a distinct key rather than a duplicate.
        if (QualifiedKeyColumns.TryGetValue(name, out var canonical))
            return canonical;

        var lastDot = name.LastIndexOf('.');
        return lastDot >= 0 && lastDot < name.Length - 1 ? name[(lastDot + 1)..] : name;
    }

    private Dictionary<string, object?> ReadColumnValues(object colEnumObj, int count)
    {
        dynamic colEnum = colEnumObj;
        var values = new Dictionary<string, object?>(count);

        for (var i = 0; i < count; i++)
        {
            if ((int)colEnum.Next() == -1)
                break;

            string name = NormalizeColumnName((string)colEnum.GetName());

            // RawCertificate is a binary column: request it as base64, which
            // arrives as a plain BSTR through IDispatch (same as the
            // GetCertificate and GetCAProperty paths). Everything else stays
            // on the proven Binary path.
            int encoding = string.Equals(name, ColumnName.RawCertificate, StringComparison.OrdinalIgnoreCase)
                ? OutputEncoding.Base64
                : OutputEncoding.Binary;

            object? value;
            try
            {
                value = colEnum.GetValue(encoding);
            }
            catch (COMException)
            {
                value = null; // Column may be null in the database
            }

            // Should two schema names still collide after normalization, the
            // first value wins rather than being silently overwritten, and the
            // drop is reported. Silence here is what made issue #186 possible:
            // a dropped column reads downstream exactly like a column the CA
            // never returned, so the mapping degrades with nothing to say why.
            // Once per client, because a collision repeats on every row of
            // every pass.
            if (!values.TryAdd(name, value))
            {
                bool firstForThisColumn;
                lock (_warnedColumnCollisions)
                    firstForThisColumn = _warnedColumnCollisions.Add(name);

                if (firstForThisColumn)
                    _logger.LogWarning(
                        "CA view returned two result columns that both key as {Column}; the later one is " +
                        "being dropped and whatever reads it will see nothing. Check NormalizeColumnName " +
                        "against the names this CA build returns from IEnumCERTVIEWCOLUMN::GetName",
                        name);
            }
        }

        return values;
    }

    /// <param name="alreadyDetailed">
    /// Request IDs whose DER the caller already holds everything from, so the
    /// decode and parse are skipped for them (issue #184). Null parses every row.
    /// See <see cref="CertificateQuery.AlreadyDetailed"/> for the contract.
    /// </param>
    internal CertificateInfo? MapToCertificateInfo(
        Dictionary<string, object?> values,
        IReadOnlyDictionary<string, string> templateMap,
        IReadOnlySet<int>? alreadyDetailed = null)
    {
        try
        {
            var requestId = values.GetValueOrDefault(ColumnName.RequestId) is int rid ? rid : 0;
            if (requestId <= 0)
                return null; // The sync upserts by RequestId; a row without one is unusable.

            // A row whose Disposition column is entirely absent cannot be
            // classified. Mapping it to Failed would repaint the dashboard red
            // (the pre normalization bug), so skip it instead. The caller logs
            // one warning per query when this happens.
            if (!values.ContainsKey(ColumnName.Disposition))
                return null;

            var serialNumber = values.GetValueOrDefault(ColumnName.SerialNumber)?.ToString() ?? "";
            var disposition = values.GetValueOrDefault(ColumnName.Disposition) is int disp ? disp : 0;
            var status = MapCertificateStatus(disposition);

            // Which subject column is authoritative depends on whether anything
            // was actually issued, so the status is resolved before the name.
            //
            // On an issued or revoked row the certificate's own names win, as
            // they always have: on an enrollee supplies subject template the CA
            // policy can rewrite what the CSR asked for, and the dashboard must
            // show what was signed.
            //
            // On a request row nothing was signed, so the request columns win
            // instead. The bare columns are not reliably empty there, which the
            // lab probe corrected on 2026-08-03: a policy module denial had the
            // issued CommonName filled with a copy of the request CN, because
            // the CA parses the subject before it refuses. Preferring the
            // request columns gives the full DN the requester actually sent,
            // which is what the detail page labels "Requested Subject".
            //
            // Precedence is the only thing the status decides. Every candidate is
            // sanitized on every disposition (issue #224): a signature does not
            // vouch for a name's rendering, and on an enrollee supplies subject
            // template the issued columns are as requester authored as the request
            // ones. Sanitizing per candidate rather than once at the end is load
            // bearing, because a source that sanitizes away to null has to keep
            // falling through the chain instead of collapsing it.
            //
            // Blank rather than null throughout: the CA returns an empty string
            // as readily as a null through the IDispatch GetValue path, and both
            // have to fall through.
            var issuedDn = CertificateTextSanitizer.SanitizeSubject(
                values.GetValueOrDefault(ColumnName.DistinguishedName)?.ToString());
            var issuedCn = CertificateTextSanitizer.SanitizeSubject(
                values.GetValueOrDefault(ColumnName.CommonName)?.ToString());
            var dn = status is CertificateStatus.Pending
                or CertificateStatus.Denied
                or CertificateStatus.Failed
                ? FirstNonBlank(
                    CertificateTextSanitizer.SanitizeSubject(
                        values.GetValueOrDefault(RequestColumnName.DistinguishedName)?.ToString()),
                    CertificateTextSanitizer.SanitizeSubject(
                        values.GetValueOrDefault(RequestColumnName.CommonName)?.ToString()),
                    issuedDn,
                    issuedCn)
                : FirstNonBlank(issuedDn, issuedCn);
            // ResolveTemplateName sanitizes what it returns (issue #378), so this
            // column arrives guarded like the names above it rather than raw.
            var rawTemplate = values.GetValueOrDefault(ColumnName.CertificateTemplate)?.ToString() ?? "";
            var template = ResolveTemplateName(rawTemplate, templateMap);
            var notBefore = values.GetValueOrDefault(ColumnName.NotBefore) is DateTime nb ? nb : DateTime.MinValue;
            var notAfter = values.GetValueOrDefault(ColumnName.NotAfter) is DateTime na ? na : DateTime.MinValue;
            var requester = values.GetValueOrDefault(ColumnName.RequesterName)?.ToString();
            var submitted = values.GetValueOrDefault(ColumnName.SubmittedWhen) is DateTime sw ? sw : DateTime.MinValue;

            // One parse of the certificate blob the view already returned, for
            // four things at once: the SAN list, the subject fallback, the
            // cryptographic detail, and the DER itself for the single
            // certificate download (issue #158). ACME style CSRs often carry no
            // subject DN, so the CA database subject columns are empty and the
            // issued certificate is the authoritative source. All of it is
            // optional: any decode failure keeps the row, just without them.
            //
            // Skipped entirely for a row the caller says it already holds all
            // four of (issue #184). The sync sweeps the whole inventory on every
            // interval tick, so without this every certificate the CA has ever
            // issued is decoded from base64, loaded through crypt32, hashed, has
            // its public key imported and four extensions decoded, several
            // hundred times a day, to reproduce values that were stored the first
            // time and cannot legitimately change. The three locals stay null,
            // which is the same shape a row with no blob has always produced and
            // which every writer in CertificateSyncService.UpdateEntity guards.
            string? sans = null;
            CertificateCryptoDetail? cryptoDetail = null;
            byte[]? rawCertificate = null;
            if (alreadyDetailed?.Contains(requestId) != true &&
                values.GetValueOrDefault(ColumnName.RawCertificate) is string rawBase64 &&
                !string.IsNullOrWhiteSpace(rawBase64))
            {
                try
                {
                    var der = Convert.FromBase64String(rawBase64);
                    var parsed = CertificateDerParser.Parse(der);
                    if (parsed != null)
                    {
                        sans = parsed.SubjectAlternativeNames;
                        cryptoDetail = parsed.Crypto;
                        // Only bytes that decoded as a certificate are carried
                        // forward, so nothing unparseable can reach the database
                        // and later be handed to an admin as a download.
                        rawCertificate = der;
                        // Sanitized like every other candidate. This one is not
                        // the safe fallback it looks like: it is the signed
                        // subject as X509Certificate2 renders it, which passes
                        // format characters through untouched, and it is reached
                        // on every disposition rather than only issued ones.
                        if (string.IsNullOrWhiteSpace(dn))
                            dn = CertificateTextSanitizer.SanitizeSubject(parsed.Subject);
                    }
                }
                catch (FormatException)
                {
                    // Not base64 on this build; leave the parsed fields empty.
                }
            }

            // SAN only certificate with no usable subject anywhere (modern
            // ACME CSRs carry no CN): use the first SAN as the display
            // subject. Stored as the bare name with no "CN=" prefix; both the
            // activity feed (DashboardMetricsService.ExtractCn) and the
            // frontend inventory (extractCN) render a subject without "CN="
            // verbatim.
            //
            // Sanitized for its width rather than its characters: the SAN list is
            // capped to the 2000 character SubjectAlternativeNames column, which is
            // four times what Subject holds, so the first entry alone can overflow.
            if (string.IsNullOrWhiteSpace(dn) && !string.IsNullOrWhiteSpace(sans))
                dn = CertificateTextSanitizer.SanitizeSubject(FirstSanDisplayName(sans!));

            // Revocation metadata is meaningful only for revoked rows, and the
            // CA may surface sentinel values (a zero reason, a placeholder
            // date) instead of null on other dispositions through the
            // IDispatch GetValue path. Gating on the disposition guarantees
            // non revoked rows always carry null revocation fields, which the
            // sync relies on to clear a released CertificateHold.
            // RevokedReason is the integer CRL reason code (RFC 5280 5.3.1).
            DateTime? revokedWhen = null;
            int? revokedReason = null;
            if (status == CertificateStatus.Revoked)
            {
                revokedWhen = values.GetValueOrDefault(ColumnName.RevokedWhen) is DateTime rw ? rw : null;
                revokedReason = values.GetValueOrDefault(ColumnName.RevokedReason) is int rr ? rr : null;
            }

            // The CA's own account of what happened to the request, gated on
            // disposition for the same reason as the revocation fields above: an
            // issued row carries "Issued" and a zero status code, which is noise
            // rather than an explanation, and letting it through would leave a
            // stale message behind when a pending request is finally approved.
            // A zero StatusCode means success and never carries information.
            string? dispositionMessage = null;
            int? statusCode = null;
            if (CarriesExplanation(status))
            {
                dispositionMessage = ReadDispositionMessage(values);
                statusCode = ReadStatusCode(values);
            }

            return new CertificateInfo(
                RequestId: requestId,
                SerialNumber: serialNumber,
                // Empty, never null, when no source carried a name. That is the
                // established "nothing here" value: the sync tests for it with
                // IsNullOrWhiteSpace to queue the row for the ACME backfill, and
                // the Subject column is declared required.
                Subject: dn ?? "",
                SubjectAlternativeNames: sans,
                TemplateName: template,
                NotBefore: notBefore,
                NotAfter: notAfter,
                Status: status,
                Requestor: requester,
                RequestDate: submitted,
                RevokedWhen: revokedWhen,
                RevokedReason: revokedReason,
                CryptoDetail: cryptoDetail,
                DispositionMessage: dispositionMessage,
                StatusCode: statusCode,
                RawCertificate: rawCertificate);
        }
        catch (Exception ex)
        {
            // Skip malformed rows, but log so genuine mapping bugs stay visible.
            _logger.LogDebug(ex, "Skipping a CA row that could not be mapped to CertificateInfo");
            return null;
        }
    }

    /// <summary>
    /// The first candidate that carries something, or null. The CA returns an
    /// empty string as readily as a null for a column it has nothing for, so a
    /// null coalescing chain would stop on the first empty string and never
    /// reach the source that does hold the value.
    /// </summary>
    internal static string? FirstNonBlank(params string?[] candidates)
    {
        foreach (var candidate in candidates)
        {
            if (!string.IsNullOrWhiteSpace(candidate))
                return candidate;
        }
        return null;
    }

    /// <summary>
    /// The first entry of a stored SAN list ("dns:name, ip:addr") with its
    /// label stripped, for the display subject fallback. Prefix checks rather
    /// than a colon split so IPv6 addresses keep their colons.
    /// </summary>
    internal static string FirstSanDisplayName(string sans)
    {
        var first = sans.Split(',')[0].Trim();
        if (first.StartsWith("dns:", StringComparison.OrdinalIgnoreCase)) return first[4..];
        if (first.StartsWith("ip:", StringComparison.OrdinalIgnoreCase)) return first[3..];
        return first;
    }

    /// <summary>
    /// Builds an ACME-compliant PEM chain (RFC 8555 7.4.2) from a leaf DER and a
    /// PKCS#7 PEM blob returned by ICertRequest::GetCertificate(BASE64HEADER|CHAIN).
    /// Order: leaf first, then issuers walked by Issuer to Subject linkage,
    /// including a self signed root if present. RFC 8555 7.4.2 permits including
    /// a self signed trust anchor ("MAY"); for private ADCS deployments — and
    /// for single tier CAs in particular — the root must be included so the
    /// client receives a chain of at least two certificates. Falls back to the
    /// leaf alone if the PKCS#7 carries no matching issuer. The loop terminates
    /// naturally: once a self signed cert is appended, pool.Remove drops it, so
    /// the next issuer search by IssuerName fails and the loop exits.
    /// </summary>
    internal static string BuildAcmeChainPem(byte[] leafDer, string pkcs7Pem)
    {
        var pkcs7Bytes = ExtractPkcs7Bytes(pkcs7Pem);
        var cms = new SignedCms();
        cms.Decode(pkcs7Bytes);

        using var leaf = X509CertificateLoader.LoadCertificate(leafDer);

        // Each X509Certificate2 pulled from the CMS holds a native cert context
        // handle, so dispose every one once the PEM is built (including the leaf
        // duplicate and any issuer never appended), not just the chain we walk.
        var cmsCerts = cms.Certificates.Cast<X509Certificate2>().ToList();
        try
        {
            var pool = cmsCerts
                .Where(c => !c.Thumbprint.Equals(leaf.Thumbprint, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Every block, including the last, must end in a newline. certbot parses
            // the chain with CERT_PEM_REGEX = "-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n
            // -----END CERTIFICATE-----\r?\n", which requires a trailing newline after
            // every "-----END CERTIFICATE-----". ExportCertificatePem() does not emit
            // one, so we append it after each block. Without it certbot matches only the
            // leaf and fails with "less than 2 certificates in chain" (issues #21, #26);
            // the other ACME clients tolerate the missing newline. Do not remove.
            var sb = new StringBuilder();
            sb.Append(leaf.ExportCertificatePem()).Append('\n');

            var current = leaf;
            while (true)
            {
                var issuer = pool.FirstOrDefault(c =>
                    string.Equals(c.SubjectName.Name, current.IssuerName.Name, StringComparison.Ordinal));
                if (issuer == null)
                    break;

                sb.Append(issuer.ExportCertificatePem()).Append('\n');
                pool.Remove(issuer);
                current = issuer;
            }

            return sb.ToString();
        }
        finally
        {
            foreach (var cert in cmsCerts)
                cert.Dispose();
        }
    }

    /// <summary>
    /// Orders the certificates of a chain leaf first, root last, by the same
    /// Issuer to Subject walk <see cref="BuildAcmeChainPem"/> uses. The leaf
    /// is the certificate that issued no other certificate in the set; a
    /// single self signed certificate is its own leaf and root. Returns raw
    /// DER copies so the caller can dispose the certificate instances.
    /// Unlinkable extras (a decode oddity) are dropped, like the ACME chain
    /// walk drops them.
    /// </summary>
    internal static IReadOnlyList<byte[]> OrderChainLeafFirst(IReadOnlyList<X509Certificate2> certificates)
    {
        if (certificates.Count == 0)
            return Array.Empty<byte[]>();

        var leaf = certificates.FirstOrDefault(candidate =>
                !certificates.Any(other =>
                    !ReferenceEquals(other, candidate) &&
                    string.Equals(other.IssuerName.Name, candidate.SubjectName.Name, StringComparison.Ordinal)))
            ?? certificates[0];

        var ordered = new List<byte[]> { leaf.RawData };
        var pool = certificates.Where(c => !ReferenceEquals(c, leaf)).ToList();

        var current = leaf;
        while (true)
        {
            var issuer = pool.FirstOrDefault(c =>
                string.Equals(c.SubjectName.Name, current.IssuerName.Name, StringComparison.Ordinal));
            if (issuer == null)
                break;

            ordered.Add(issuer.RawData);
            pool.Remove(issuer);
            current = issuer;
        }

        return ordered;
    }

    /// <summary>
    /// Counts -----BEGIN CERTIFICATE----- markers in a PEM blob. Used for
    /// diagnostic logging so runtime evidence shows how many certs were
    /// returned to the ACME client.
    /// </summary>
    private static int CountPemCertificates(string pem)
    {
        if (string.IsNullOrEmpty(pem)) return 0;
        const string marker = "-----BEGIN CERTIFICATE-----";
        var count = 0;
        var index = 0;
        while ((index = pem.IndexOf(marker, index, StringComparison.Ordinal)) != -1)
        {
            count++;
            index += marker.Length;
        }
        return count;
    }

    /// <summary>
    /// Strips the BEGIN/END PKCS7 (or CMS) PEM armor and returns the decoded bytes.
    /// </summary>
    private static byte[] ExtractPkcs7Bytes(string pkcs7Pem)
    {
        var sb = new StringBuilder(pkcs7Pem.Length);
        var lines = pkcs7Pem.Split('\n');
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;
            if (trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal)) continue;
            if (trimmed.StartsWith("-----END", StringComparison.Ordinal)) continue;
            sb.Append(trimmed);
        }
        return Convert.FromBase64String(sb.ToString());
    }

    /// <summary>
    /// Safely releases a COM object, handling null and already-released objects.
    /// </summary>
    private static void ReleaseCom(object? comObject)
    {
        if (comObject != null && Marshal.IsComObject(comObject))
        {
            Marshal.FinalReleaseComObject(comObject);
        }
    }

    #endregion
}
