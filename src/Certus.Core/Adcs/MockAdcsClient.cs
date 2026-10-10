using System.Diagnostics.CodeAnalysis;
using Certus.Core.Security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Certus.Core.Adcs;

/// <summary>
/// Mock ADCS client that generates real X.509 certificates using BouncyCastle.
/// Used for development and testing without a real ADCS CA.
/// </summary>
public sealed class MockAdcsClient : IAdcsClient
{
    private readonly string _caName;
    private readonly AsymmetricCipherKeyPair _caKeyPair;
    private readonly X509Certificate _caCertificate;
    private readonly List<TemplateInfo> _templates;
    private readonly Dictionary<int, MockIssuedCertificate> _issuedCerts = new();
    private readonly HashSet<string> _revokedSerials = new(StringComparer.OrdinalIgnoreCase);
    private int _nextRequestId = 1;
    private readonly object _lock = new();

    /// <summary>
    /// Controls whether certificate submissions are issued immediately or held pending.
    /// </summary>
    public bool AutoApprove { get; set; } = true;

    /// <summary>
    /// Simulated delay for certificate issuance (default: none).
    /// </summary>
    public TimeSpan IssuanceDelay { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// EKU OIDs written into the leaves the mock issues. The default is
    /// server authentication so every existing consumer passes the TLS
    /// capability ceiling unchanged; null omits the extension entirely,
    /// which the ceiling refuses (guard tests).
    /// </summary>
    public IReadOnlyList<string>? LeafEkuOids { get; set; } = new[] { TlsEkuOids.ServerAuth };

    /// <summary>
    /// BouncyCastle KeyUsage bits for issued leaves. Null omits the
    /// extension. The default matches an ordinary RSA TLS leaf.
    /// </summary>
    public int? LeafKeyUsageBits { get; set; } = KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment;

    /// <summary>
    /// When true, issued leaves carry BasicConstraints CA=true, for guard
    /// tests. The default leaf carries no BasicConstraints at all.
    /// </summary>
    public bool LeafIsCa { get; set; }

    public MockAdcsClient(string caName = "Example Issuing CA", IEnumerable<TemplateInfo>? templates = null)
    {
        // The name becomes the certificate authority's own common name, which
        // cannot be empty. Refused here so the message names this parameter
        // rather than the inner one belonging to the encoder. An empty name used
        // to produce a certificate authority whose common name was the empty
        // string, which no CA can be (issue #309).
        ArgumentException.ThrowIfNullOrEmpty(caName);

        _caName = caName;
        _caKeyPair = GenerateKeyPair();
        _caCertificate = GenerateCaCertificate(_caKeyPair, caName);
        _templates = templates?.ToList() ?? new List<TemplateInfo>
        {
            // Viability on the template the quickstart walks through, so the
            // wizard's readiness checklist is reachable in its ordinary "every
            // check passes" shape. A real CA reports these for every template it
            // publishes; with them null here the healthy checklist could not be
            // seen, or screenshotted for the guide, outside a lab. The EKU stays
            // unresolved like every sibling, for the filtering reason below.
            new("WebServer", "Web Server", "1.3.6.1.4.1.311.21.8.1",
                null,
                new TemplateAcmeViability(
                    RequiresManagerApproval: false,
                    RequiresRaSignatures: false,
                    SubjectSuppliedInRequest: true,
                    KeyAlgorithm: "RSA",
                    MinimalKeySize: 2048)),
            new("Machine", "Computer", "1.3.6.1.4.1.311.21.8.2"),
            new("User", "User", "1.3.6.1.4.1.311.21.8.3"),
            new("CodeSigning", "Code Signing", "1.3.6.1.4.1.311.21.8.4"),

            // One template shaped like an elliptic curve template on a real
            // CA, so the development host exercises the EC path the wizard's
            // readiness checklist and its certbot example take. Without it
            // every mock template carries a null viability and that path is
            // unreachable in a browser, which is how issue #213 stayed
            // invisible outside a lab.
            //
            // Two deliberate details. Subject supplied in the request, or
            // GetSetupTemplatesAsync hides it. EKU left unresolved like its
            // four siblings, because one verified EKU flips that method into
            // filtering mode and would hide the other four instead.
            new("WebServerEC", "Web Server EC", "1.3.6.1.4.1.311.21.8.5",
                null,
                new TemplateAcmeViability(
                    RequiresManagerApproval: false,
                    RequiresRaSignatures: false,
                    SubjectSuppliedInRequest: true,
                    KeyAlgorithm: "ECDSA_P256",
                    MinimalKeySize: 256)),

            // The same shape recording ECDH_P256, which is what the console
            // writes when a template's Purpose is "Signature and encryption"
            // rather than "Signature". This is not a hypothetical: the lab CA's
            // EC web server template records exactly this, and issuing against
            // it works (issue #277). Present so the substitution and its
            // advisory are reachable in a browser without a lab.
            new("WebServerECDH", "Web Server EC (encryption purpose)", "1.3.6.1.4.1.311.21.8.6",
                null,
                new TemplateAcmeViability(
                    RequiresManagerApproval: false,
                    RequiresRaSignatures: false,
                    SubjectSuppliedInRequest: true,
                    KeyAlgorithm: "ECDH_P256",
                    MinimalKeySize: 256))
        };
    }

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new CaInfo(
            Name: _caName,
            DnsName: "ca-server.corp.example.com",
            DisplayName: _caName,
            IsAccessible: true));
    }

    public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
    {
        // The mock is a one tier CA: its chain is the self signed root alone.
        return Task.FromResult<IReadOnlyList<byte[]>>(new[] { _caCertificate.GetEncoded() });
    }

    public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult<IReadOnlyList<TemplateInfo>>(_templates.AsReadOnly());
    }

    public async Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName,
        byte[] csrDer,
        CancellationToken cancellationToken = default)
    {
        // A null request is a caller's mistake rather than a request this CA
        // cannot read, and AdcsClient answers it the same way: its
        // Convert.ToBase64String raises this same exception, and it does so
        // before the Submit, so nothing reaches the CA either way. Refusing it
        // here keeps the refusal below about the content of a request that
        // exists, which is the only thing a CA gets to have an opinion about.
        ArgumentNullException.ThrowIfNull(csrDer);

        if (!_templates.Any(t => t.Name.Equals(templateName, StringComparison.OrdinalIgnoreCase)))
        {
            // Carrying the status code a real CA records for this, the same stance
            // the mock's leaves take on extensions: what the dev host renders should
            // be the shape the product meets in production, or it teaches the wrong
            // thing. CERTSRV_E_UNSUPPORTED_CERT_TYPE is exactly what ADCS answers for
            // a template it does not publish, and exactly the code that cost issue
            // #194 a lab round trip because nothing named it.
            return new SubmitResult(0, SubmitStatus.Denied,
                $"Template '{templateName}' not found on this CA.",
                CaStatusCode.UnsupportedCertType);
        }

        // A certificate authority reads the request before it decides anything
        // about it, and one it cannot read it refuses (issue #332). Ahead of the
        // pending branch as well as the issuing one, so a request this CA could
        // never issue from never becomes a row waiting on a CA manager, which is
        // why ApproveRequest below can no longer meet one.
        //
        // Error rather than Denied, matching how AdcsClient maps a disposition it
        // does not recognize. Denied now carries a remedy in both consumers:
        // TlsCertificateEnroller tells the operator to grant the service account
        // Enroll permission, and OrderService logs DescribeDenialRemedy beside the
        // refusal. Both would misdirect for a request that was simply undecodable.
        //
        // No row and request id 0, the same shape as the template refusal above.
        if (!TryReadCsr(csrDer, out var csr, out var parseError))
        {
            return new SubmitResult(0, SubmitStatus.Error,
                $"The request could not be decoded as a PKCS#10 certificate request: {parseError}");
        }

        if (IssuanceDelay > TimeSpan.Zero)
        {
            await Task.Delay(IssuanceDelay, cancellationToken);
        }

        lock (_lock)
        {
            var requestId = _nextRequestId++;

            if (AutoApprove)
            {
                // Issue from the request read above. The mock decides instantly,
                // so the decision instant is the request instant.
                var cert = IssueCertificateFrom(csr);
                var now = DateTime.UtcNow;
                _issuedCerts[requestId] = new MockIssuedCertificate(
                    RequestId: requestId,
                    TemplateName: templateName,
                    Certificate: cert,
                    Status: CertificateStatus.Issued,
                    RequestDate: now,
                    ResolvedWhen: now);

                return new SubmitResult(requestId, SubmitStatus.Issued);
            }
            else
            {
                // The CSR is kept so ApproveRequest can issue from it later, the
                // way a real CA issues from the PKCS#10 its pending row holds.
                // The row carries the same words the submit answers with, since a
                // real CA writes its account of a held request into the row too,
                // and no status code, since a request waiting on a person is not
                // failing and has no reason behind it to report.
                _issuedCerts[requestId] = new MockIssuedCertificate(
                    RequestId: requestId,
                    TemplateName: templateName,
                    Certificate: null,
                    Status: CertificateStatus.Pending,
                    RequestDate: DateTime.UtcNow,
                    CsrDer: csrDer,
                    DispositionMessage: PendingApprovalMessage);

                return new SubmitResult(requestId, SubmitStatus.Pending,
                    PendingApprovalMessage);
            }
        }
    }

    public Task<CertificateResult> GetCertificateAsync(
        int requestId,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (!_issuedCerts.TryGetValue(requestId, out var issued))
            {
                return Task.FromResult(new CertificateResult(requestId, CertificateStatus.Failed));
            }

            if (issued.Status != CertificateStatus.Issued || issued.Certificate == null)
            {
                return Task.FromResult(new CertificateResult(requestId, issued.Status));
            }

            var certDer = issued.Certificate.GetEncoded();
            var certPem = ConvertToPem(issued.Certificate);

            return Task.FromResult(new CertificateResult(
                requestId,
                CertificateStatus.Issued,
                CertificateDer: certDer,
                CertificatePem: certPem));
        }
    }

    public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query,
        CancellationToken cancellationToken = default)
    {
        // The lock guards only the shared inventory, so it is held just long
        // enough to take a snapshot of the rows the cheap restrictions keep.
        // Everything after it, including a DER parse per certificate, is pure
        // work on that snapshot: a sync sweeping the whole inventory must not
        // block a concurrent revoke for the duration.
        List<MockIssuedCertificate> matches;
        lock (_lock)
        {
            var results = _issuedCerts.Values.AsEnumerable();

            if (query.Status.HasValue)
                results = results.Where(c => c.Status == query.Status.Value);

            if (!string.IsNullOrEmpty(query.TemplateName))
                results = results.Where(c =>
                    c.TemplateName.Equals(query.TemplateName, StringComparison.OrdinalIgnoreCase));

            if (query.ExpiringBefore.HasValue)
                results = results.Where(c =>
                    c.Certificate != null &&
                    c.Certificate.NotAfter <= query.ExpiringBefore.Value);

            // Mirrors the SubmittedWhen restriction the real client applies, so
            // the dev host's sync behaves the same way against the mock CA.
            if (query.SubmittedAfter.HasValue)
                results = results.Where(c => c.RequestDate >= query.SubmittedAfter.Value);

            // Mirrors the ResolvedWhen restriction (issue #187). A row with no
            // decision yet is excluded, which is what a GreaterOrEqual
            // restriction on a null column does on the real CA.
            if (query.ResolvedAfter.HasValue)
                results = results.Where(c =>
                    c.ResolvedWhen != null && c.ResolvedWhen >= query.ResolvedAfter.Value);

            matches = results.ToList();
        }

        // Subject matching and paging both run on the projected rows, the way
        // the real client does them (issue #240). The CA view has no restriction
        // for a substring, so AdcsClient filters the mapped CertificateInfo and
        // only then spends a page slot on it; a row the search rejects must not
        // consume one. Matching the certificate's own BouncyCastle rendering
        // here instead would search a string no caller is ever handed back.
        //
        // The chain is left lazy on purpose. Skip and Take pull only as far as
        // they need, so a small page parses only the rows it reaches, which is
        // the work the real client's early break at results.Count >= Take saves.
        // Same skip the real client honours, and gated the same way (issue #184).
        // A subject search runs on the mapped subject, which the parse is the
        // last source of, so the two must not both apply to one query.
        var alreadyDetailed = query.SubjectContains == null
            ? query.AlreadyDetailed
            : null;

        var projected = matches.Select(c => ToCertificateInfo(c, alreadyDetailed));
        if (query.SubjectContains is { Length: > 0 } search)
            projected = projected.Where(c =>
                c.Subject.Contains(search, StringComparison.OrdinalIgnoreCase));

        var list = projected
            .Skip(query.Skip)
            .Take(query.Take)
            .ToList();

        return Task.FromResult<IReadOnlyList<CertificateInfo>>(list);
    }

    /// <summary>
    /// What this CA recorded against one request (issue #365). Null for a request
    /// id it has never seen, which is what the real client answers for a row the
    /// CA does not have.
    /// </summary>
    public Task<CaRequestStatus?> GetRequestStatusAsync(
        int requestId,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (!_issuedCerts.TryGetValue(requestId, out var issued))
                return Task.FromResult<CaRequestStatus?>(null);

            // The same gate the real client applies, so the mock can never report
            // a pair the CA view would withhold.
            var carries = CarriesExplanation(issued.Status);
            return Task.FromResult<CaRequestStatus?>(new CaRequestStatus(
                requestId,
                issued.Status,
                carries ? issued.DispositionMessage : null,
                carries ? issued.StatusCode : null));
        }
    }

    /// <summary>
    /// Whether the CA records an explanation against a row in this state. Mirrors
    /// <c>AdcsClient.CarriesExplanation</c>, which Certus.Core cannot reference:
    /// an issued row carries no reason worth showing and a revoked one carries
    /// nothing about the request at all.
    /// </summary>
    private static bool CarriesExplanation(CertificateStatus status) =>
        status is CertificateStatus.Pending
            or CertificateStatus.Denied
            or CertificateStatus.Failed;

    /// <summary>
    /// Projects one mock issued certificate to the shape the sync consumes,
    /// running its DER through the shared parser exactly once. One parse rather
    /// than one per field, and every call sits outside the mock's lock, so
    /// sweeping the inventory never blocks a concurrent revoke.
    ///
    /// A request id in <paramref name="alreadyDetailed"/> skips the parse
    /// altogether (issue #184), the same as in the real client. Note the mock has
    /// no CA database subject columns to fall back on, so a skipped row's Subject
    /// is empty rather than merely missing its last fallback. That is a shape the
    /// sync already handles (its blank guard keeps whatever it stored), but it
    /// means a mock backed test must not assert a subject on a skipped row.
    /// </summary>
    private static CertificateInfo ToCertificateInfo(
        MockIssuedCertificate c,
        IReadOnlySet<int>? alreadyDetailed = null)
    {
        // The mock issues real certificates, so its own DER goes through the
        // same parser the real client uses rather than inventing values. The
        // dev host then shows the detail a live CA would, and mock backed tests
        // can assert on it. A parse that fails yields neither the detail nor the
        // bytes, which is the invariant the real client holds too: nothing
        // undecodable is ever carried forward to be stored and later handed to
        // an admin as a download.
        var skip = alreadyDetailed?.Contains(c.RequestId) == true;
        var der = skip ? null : c.Certificate?.GetEncoded();
        var parsed = der == null ? null : CertificateDerParser.Parse(der);

        return new CertificateInfo(
            RequestId: c.RequestId,
            SerialNumber: c.Certificate?.SerialNumber?.ToString(16) ?? "",
            // The subject as X509Certificate2 renders it, which is the only
            // spelling anything downstream meets in production (issue #240).
            // BouncyCastle's X509Name.ToString is the RFC 4514 form: it escapes
            // a comma with a backslash where CertNameToStr quotes the whole
            // value instead, and it joins components with "," where CertNameToStr
            // joins them with ", ". Rendering it here put a second dialect into
            // SyncedCertificate.Subject that no certificate authority can
            // produce, so every mock backed test measured a shape the common
            // name readers never meet on a live host, and both reader spoofs
            // (issues #231 and #238) hid in the shape the mock could not reach.
            //
            // Empty rather than a placeholder when nothing has been signed. An
            // empty subject is already a first class case: a request row has no
            // certificate yet, an ACME leaf routinely carries no subject DN at
            // all, and the real client stores an empty string for both. The
            // sync's ACME backfill keys on exactly that emptiness to name the
            // row from its order identifier, and a placeholder word is not
            // whitespace, so it switched that backfill off. The word still
            // reaches the activity feed, from DashboardMetricsService's own
            // fallback for a blank subject, rather than from here.
            Subject: parsed?.Subject ?? "",
            // The names the leaf actually carries, through the same parser the
            // real client uses. This was hardcoded null while the mock dropped
            // the request's SAN extension, because reading the parse would have
            // implied a support that did not exist; the CSR path now copies that
            // extension, so this is a real answer (issue #295).
            //
            // Null still happens, and on a mock row it means what it means on a
            // live CA: no SAN extension at all, or one whose entries are all of a
            // kind the stored "dns:name, ip:addr" format does not spell. A device
            // order whose only name is a PermanentIdentifier otherName is exactly
            // that shape, and AdcsClient answers null for it too.
            SubjectAlternativeNames: parsed?.SubjectAlternativeNames,
            TemplateName: c.TemplateName,
            NotBefore: c.Certificate?.NotBefore ?? DateTime.MinValue,
            NotAfter: c.Certificate?.NotAfter ?? DateTime.MinValue,
            Status: c.Status,
            Requestor: "MOCK\\TestUser",
            RequestDate: c.RequestDate,
            RevokedWhen: c.RevokedWhen,
            RevokedReason: c.RevokedReason,
            CryptoDetail: parsed?.Crypto,
            // The CA's own account of the request, under the same gate the real
            // client applies. Hardcoded null before issue #365, which left the
            // dev host's dashboard showing a denied request with no reason where
            // a live CA shows one.
            DispositionMessage: CarriesExplanation(c.Status) ? c.DispositionMessage : null,
            StatusCode: CarriesExplanation(c.Status) ? c.StatusCode : null,
            RawCertificate: parsed == null ? null : der);
    }

    public Task RevokeCertificateAsync(
        string serialNumber,
        int reason,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _revokedSerials.Add(serialNumber);

            // Flip the stored certificate so demo mode and the sync surface a
            // revoked row, mirroring the real CA database. The incoming
            // serial is X509Certificate2.SerialNumber form (uppercase,
            // possibly a leading 00 pad byte); the mock stores BigInteger hex
            // (lowercase, no pad), so compare normalized.
            var match = _issuedCerts.FirstOrDefault(kv =>
                kv.Value.Certificate != null &&
                SerialNumbers.NormalizedEquals(
                    kv.Value.Certificate.SerialNumber.ToString(16), serialNumber));
            if (match.Value != null)
            {
                _issuedCerts[match.Key] = match.Value with
                {
                    Status = CertificateStatus.Revoked,
                    RevokedWhen = DateTime.UtcNow,
                    RevokedReason = reason
                };
            }
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Serial numbers the CA was asked to revoke, for test assertions. Case insensitive.
    /// </summary>
    public IReadOnlyCollection<string> RevokedSerials
    {
        get { lock (_lock) { return _revokedSerials.ToArray(); } }
    }

    /// <summary>
    /// Approves a pending request (simulates CA manager approval).
    ///
    /// Issues from the CSR the request carried, which is what a real CA does
    /// when an operator approves a held request: the pending row holds the
    /// submitted PKCS#10 and approval is a decision about that request, not a
    /// fresh enrollment. Before issue #319 this minted an unrelated self signed
    /// leaf named "CN=Approved-{requestId}", with a public key nobody held and
    /// none of the requested names, which was invisible while nothing in the
    /// product ever collected an approved request. It is not invisible now that
    /// the pending issuance sweep delivers one to a client.
    ///
    /// The submit already read this request, so a row that cannot be read here is
    /// a row that never carried one, which ArgumentNullException.ThrowIfNull now
    /// makes unreachable. The branch stays as a fail safe and denies, which is the
    /// terminal answer the submit itself would have given: a certificate authority
    /// that cannot read a request refuses it and does not substitute another
    /// (issue #332). Not covered by a test: refusing at the submit leaves no seam
    /// through the public surface that can create such a row.
    /// </summary>
    public void ApproveRequest(int requestId)
    {
        lock (_lock)
        {
            if (_issuedCerts.TryGetValue(requestId, out var issued) &&
                issued.Status == CertificateStatus.Pending)
            {
                var csr = issued.CsrDer is { } csrDer
                    && TryReadCsr(csrDer, out var parsed, out _)
                    ? parsed
                    : null;

                _issuedCerts[requestId] = csr is null
                    ? issued with
                    {
                        // The message and no code. Nothing in CaStatusCode means
                        // "the request could not be read", and naming a code that
                        // means something else would have DescribeRefusal print a
                        // reason that is not the reason.
                        Status = CertificateStatus.Denied,
                        ResolvedWhen = DateTime.UtcNow,
                        DispositionMessage = UnreadableRequestMessage,
                        StatusCode = null
                    }
                    : issued with
                    {
                        // The explanation the pending row carried goes with it. A
                        // real CA overwrites its account of a request when the
                        // request is decided, and an issued row that still said it
                        // was waiting would be read back as a stale message.
                        Certificate = IssueCertificateFrom(csr),
                        Status = CertificateStatus.Issued,
                        ResolvedWhen = DateTime.UtcNow,
                        DispositionMessage = null,
                        StatusCode = null
                    };
            }
        }
    }

    /// <summary>
    /// What a request held for a CA manager reads as, on the submit's answer and
    /// on the row alike.
    /// </summary>
    public const string PendingApprovalMessage = "Request pending CA manager approval.";

    /// <summary>
    /// What the fail safe arm of <see cref="ApproveRequest"/> records. Reachable
    /// only through a row the submit could not have created, so nothing asserts
    /// on it; it exists so that arm does not leave a refusal with no account of
    /// itself, which is the shape issue #365 set out to remove.
    /// </summary>
    public const string UnreadableRequestMessage =
        "The certificate request could not be read.";

    /// <summary>
    /// What a certificate manager's refusal reads as. The wording a live CA
    /// writes into DispositionMessage for a hand denial is not yet confirmed on
    /// the lab CA, so this stands in for it and only
    /// <see cref="StatusCode"/> below is load bearing.
    /// </summary>
    public const string ManagerDenialMessage = "Request denied by a certificate manager.";

    /// <summary>
    /// Denies a pending request (simulates a CA manager refusing it). The
    /// counterpart to <see cref="ApproveRequest"/>: a held request has two ways
    /// out and a test of the pending issuance sweep needs both.
    ///
    /// The refusal carries the pair a real CA records against the row, because
    /// the pending issuance sweep now reads it back to say why an order failed
    /// (issue #365). <c>CERTSRV_E_ADMIN_DENIED_REQUEST</c> is the code ADCS
    /// records for a denial by hand, as against the policy module's own codes
    /// the submit path meets. Both are parameters so a test can also arrange the
    /// CA that explains nothing, which is the case each caller's fallback
    /// wording exists for.
    /// </summary>
    public void DenyRequest(
        int requestId,
        string? dispositionMessage = ManagerDenialMessage,
        int? statusCode = CaStatusCode.AdminDeniedRequest)
    {
        lock (_lock)
        {
            if (_issuedCerts.TryGetValue(requestId, out var issued) &&
                issued.Status == CertificateStatus.Pending)
            {
                _issuedCerts[requestId] = issued with
                {
                    Status = CertificateStatus.Denied,
                    ResolvedWhen = DateTime.UtcNow,
                    DispositionMessage = dispositionMessage,
                    StatusCode = statusCode
                };
            }
        }
    }

    #region Certificate Generation

    private static AsymmetricCipherKeyPair GenerateKeyPair(int keySize = 2048)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        return generator.GenerateKeyPair();
    }

    private static X509Certificate GenerateCaCertificate(
        AsymmetricCipherKeyPair keyPair,
        string caName)
    {
        var generator = new X509V3CertificateGenerator();

        var serialNumber = BigInteger.ProbablePrime(120, new SecureRandom());
        generator.SetSerialNumber(serialNumber);

        // One instance for both roles: the mock is a one tier self signed root,
        // so its issuer and its subject are the same name.
        var caDn = EncodeCaName(caName);
        generator.SetIssuerDN(caDn);
        generator.SetSubjectDN(caDn);
        generator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddYears(10));
        generator.SetPublicKey(keyPair.Public);

        // Basic Constraints: CA=true
        generator.AddExtension(
            X509Extensions.BasicConstraints,
            true,
            new BasicConstraints(true));

        // Subject Key Identifier, the anchor the leaves' Authority Key
        // Identifier points back at, as on a real ADCS root.
        generator.AddExtension(
            X509Extensions.SubjectKeyIdentifier,
            false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(keyPair.Public));

        var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private);
        return generator.Generate(signatureFactory);
    }

    /// <summary>
    /// The mock certificate authority's own distinguished name, encoded rather
    /// than parsed (issue #309).
    ///
    /// <c>new X509Name(string)</c> reads its argument as a whole distinguished
    /// name, so a comma in the common name is read as a component separator, the
    /// trailing fragment carries no equals sign, and the constructor refuses the
    /// whole string with "badly formatted directory string". The client then fails
    /// to construct at all. A comma is legal inside a common name and
    /// <see cref="AdcsCaConnectionString"/> deliberately permits one, so a name
    /// this product accepts must not be a name its mock cannot hold.
    ///
    /// X500DistinguishedNameBuilder rather than BouncyCastle's own list of oids
    /// and list of values constructor, which looks like the smaller change and is
    /// not verbatim: its default entry converter reads a leading "#" as hex
    /// encoded DER and refuses it, and it strips a leading backslash, so a CA
    /// named "\Corp CA" would quietly encode as "Corp CA". Read that back through
    /// GetValueList and it still echoes the input, so the DER is the only witness.
    /// Every backslash that reaches this product is literal, which
    /// <see cref="DistinguishedNameParser"/> records as an invariant with two
    /// security findings behind it, and a silent rewrite of a name is exactly
    /// that class of defect.
    ///
    /// Fully qualified rather than imported: System.Security.Cryptography
    /// .X509Certificates also declares X509Certificate, which every signature in
    /// this file means BouncyCastle's by.
    /// </summary>
    private static X509Name EncodeCaName(string caName)
    {
        var builder = new System.Security.Cryptography.X509Certificates
            .X500DistinguishedNameBuilder();
        builder.AddCommonName(caName);
        return X509Name.GetInstance(Asn1Object.FromByteArray(builder.Build().RawData));
    }

    /// <summary>
    /// Reads a submitted PKCS#10, or reports why it could not be read.
    ///
    /// The parse is the only thing inside the try, and the issuance that follows
    /// it sits in no catch at all (issue #332). Before this the whole issuance was
    /// wrapped in a bare catch that returned a self signed certificate under a
    /// <b>fresh key pair</b>, so a request this could not read came back Issued
    /// with a public key the requester did not hold. Anything unrelated that threw
    /// further down came back the same way: a value in
    /// <see cref="LeafEkuOids"/> that is not an OID makes
    /// <see cref="AddLeafExtensions"/> throw FormatException, and the mock quietly
    /// issued a leaf with no extended key usage at all, which the TLS capability
    /// ceiling then refused for a reason nothing to do with what the test set.
    /// Narrowing the catch list alone would not have closed that; shrinking the try
    /// to the parse does.
    ///
    /// GetPublicKey is read here rather than left to the generator, because a
    /// public key algorithm this cannot recognize is a request the CA cannot issue
    /// from and belongs with the rest of the refusal.
    ///
    /// The filter is the list <see cref="FindRequestedSan"/> and
    /// CsrHelper.TryReadPermanentIdentifier already use, which covers
    /// BouncyCastle's Asn1Exception (an IOException) and Asn1ParsingException (an
    /// InvalidOperationException), plus SecurityUtilityException, which
    /// PublicKeyFactory raises for a public key algorithm it does not know and
    /// which derives from Exception directly, so the other four would miss it.
    /// Checked against BouncyCastle 2.6.2 rather than assumed: garbage bytes and a
    /// truncated sequence answer ArgumentException, a bare DER null answers
    /// InvalidOperationException, and an empty SEQUENCE answers ArgumentException.
    /// </summary>
    private static bool TryReadCsr(
        byte[] csrDer,
        [NotNullWhen(true)] out Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest? csr,
        [NotNullWhen(false)] out string? error)
    {
        // The one malformed shape the filter below cannot answer, refused ahead of
        // it rather than by catching NullReferenceException. BouncyCastle reads a
        // zero length input as a null Asn1Object, the cast to Asn1Sequence carries
        // that null through, and the CertificationRequest constructor dereferences
        // it. An empty request is trivially not a PKCS#10, so saying so plainly is
        // both truer and cheaper than parsing it.
        if (csrDer.Length == 0)
        {
            csr = null;
            error = "the request was empty";
            return false;
        }

        try
        {
            csr = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(csrDer);
            _ = csr.GetPublicKey();
            error = null;
            return true;
        }
        catch (Exception ex) when (
            ex is ArgumentException or InvalidOperationException
                or InvalidCastException or IOException or SecurityUtilityException)
        {
            csr = null;
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Issues a leaf from a request <see cref="TryReadCsr"/> has already read.
    /// Deliberately carries no catch: every failure left here is this mock's own
    /// bug rather than anything about the request, and it must surface as one.
    /// </summary>
    private X509Certificate IssueCertificateFrom(
        Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest csr)
    {
        var csrInfo = csr.GetCertificationRequestInfo();

        var generator = new X509V3CertificateGenerator();
        var serialNumber = BigInteger.ProbablePrime(120, new SecureRandom());

        generator.SetSerialNumber(serialNumber);
        generator.SetIssuerDN(_caCertificate.SubjectDN);
        generator.SetSubjectDN(csrInfo.Subject);
        generator.SetNotBefore(DateTime.UtcNow);
        generator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        generator.SetPublicKey(csr.GetPublicKey());

        // The subject alternative name is the one extension a certificate
        // authority takes from the requester rather than from the template,
        // and the Phase 0 DeviceAttestProbe run showed ADCS forwards it
        // untouched, PermanentIdentifier otherName included. Before this the
        // mock dropped it, so no certificate it had ever issued carried a
        // SAN and an ACME run against the dev host handed back a leaf every
        // modern TLS client rejects (issue #295).
        var requestedSan = FindRequestedSan(csrInfo);
        if (requestedSan != null)
            generator.AddExtension(X509Extensions.SubjectAlternativeName, requestedSan);

        AddLeafExtensions(generator);

        var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", _caKeyPair.Private);
        return generator.Generate(signatureFactory);
    }

    /// <summary>
    /// The subject alternative name extension the request asked for, or null
    /// when it asked for none or asked in a way this cannot read. The octets and
    /// the critical flag both cross verbatim, which is what lets a device order's
    /// PermanentIdentifier otherName survive a mock issuance the way it survives
    /// a real one.
    ///
    /// Only the subject alternative name. The extended key usage, the key usage
    /// and the basic constraints belong to <see cref="AddLeafExtensions"/>, which
    /// is what the guard tests drive, and the generator refuses a second
    /// extension under an OID it already holds.
    ///
    /// Reading rather than adding, with its own catch, is deliberate. Since issue
    /// #332 the caller carries no catch of its own, so an exception escaping from
    /// here would fault the submit outright, and a certificate authority does not
    /// fault over a name it could not read. The decision is unchanged and its
    /// reason is now the plainer one: a SAN that cannot be read costs the SAN and
    /// nothing else. The production path's twin walk is
    /// CsrHelper.ExtractCsrIdentity; the two stay separate because that one wants
    /// typed names and verifies the signature, while this one wants raw octets
    /// and must never fail an issuance.
    /// </summary>
    private static X509Extension? FindRequestedSan(CertificationRequestInfo csrInfo)
    {
        if (csrInfo.Attributes == null)
            return null;

        foreach (var attribute in csrInfo.Attributes)
        {
            try
            {
                if (attribute is not DerSequence sequence || sequence.Count < 2)
                    continue;
                if ((sequence[0] as DerObjectIdentifier)?.Id
                    != PkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Id)
                    continue;
                if (sequence[1] is not DerSet requested || requested.Count == 0)
                    continue;

                var san = X509Extensions.GetInstance(requested[0])
                    .GetExtension(X509Extensions.SubjectAlternativeName);
                if (san != null)
                    return san;
            }
            catch (Exception ex) when (
                ex is ArgumentException or InvalidOperationException
                    or InvalidCastException or IOException)
            {
                // A malformed extension request. The certificate is still the one
                // that was asked for, only without names that could not be read.
                // Same filter list CsrHelper.TryReadPermanentIdentifier uses.
            }
        }

        return null;
    }

    /// <summary>
    /// Applies the leaf extensions to a certificate under
    /// construction. Shared by the CSR path and the self signed path so a
    /// pending request approved later carries the same shape as an instant
    /// issuance. The real CA writes the template's extensions into every
    /// leaf; before this the mock issued bare certificates, which the TLS
    /// capability ceiling would refuse as valid for every purpose.
    /// </summary>
    private void AddLeafExtensions(X509V3CertificateGenerator generator)
    {
        // Every real ADCS leaf carries the issuer's key identifier, and the ARI
        // certificate identifier (AriCertificateId) is built from it, so this
        // one is unconditional rather than behind a Leaf* knob: those exist to
        // mint refusable leaves, and an authority key identifier refuses
        // nothing. BouncyCastle derives the same SHA-1 key id here as the
        // SubjectKeyIdentifier on the mock root, so leaf AKI == root SKI, as on
        // a real chain.
        generator.AddExtension(
            X509Extensions.AuthorityKeyIdentifier,
            false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(_caKeyPair.Public));

        if (LeafEkuOids is { Count: > 0 } ekus)
        {
            generator.AddExtension(
                X509Extensions.ExtendedKeyUsage,
                false,
                new ExtendedKeyUsage(ekus.Select(o => new DerObjectIdentifier(o)).ToArray()));
        }

        if (LeafKeyUsageBits is { } keyUsageBits)
        {
            generator.AddExtension(
                X509Extensions.KeyUsage,
                true,
                new KeyUsage(keyUsageBits));
        }

        if (LeafIsCa)
        {
            generator.AddExtension(
                X509Extensions.BasicConstraints,
                true,
                new BasicConstraints(true));
        }
    }

    private static string ConvertToPem(X509Certificate cert)
    {
        using var writer = new StringWriter();
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(cert);
        pemWriter.Writer.Flush();
        return writer.ToString();
    }

    #endregion

    /// <summary>
    /// <paramref name="ResolvedWhen"/> mirrors the CA database column of the
    /// same name: the instant the CA decided the request, null while it is
    /// still pending. Revocation does not touch it; that is what RevokedWhen
    /// is for.
    ///
    /// <paramref name="CsrDer"/> is the submitted PKCS#10, kept only for a
    /// request still waiting on a decision, so that approving it later issues
    /// from what was actually requested. An immediately issued request has no
    /// use for it: its certificate already exists.
    /// </summary>
    private sealed record MockIssuedCertificate(
        int RequestId,
        string TemplateName,
        X509Certificate? Certificate,
        CertificateStatus Status,
        DateTime RequestDate,
        DateTime? RevokedWhen = null,
        int? RevokedReason = null,
        DateTime? ResolvedWhen = null,
        byte[]? CsrDer = null,
        string? DispositionMessage = null,
        int? StatusCode = null);
}
