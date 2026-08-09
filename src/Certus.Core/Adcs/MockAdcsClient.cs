using Certus.Core.Security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

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

    public MockAdcsClient(string caName = "MockCA", IEnumerable<TemplateInfo>? templates = null)
    {
        _caName = caName;
        _caKeyPair = GenerateKeyPair();
        _caCertificate = GenerateCaCertificate(_caKeyPair, caName);
        _templates = templates?.ToList() ?? new List<TemplateInfo>
        {
            new("WebServer", "Web Server", "1.3.6.1.4.1.311.21.8.1"),
            new("Machine", "Computer", "1.3.6.1.4.1.311.21.8.2"),
            new("User", "User", "1.3.6.1.4.1.311.21.8.3"),
            new("CodeSigning", "Code Signing", "1.3.6.1.4.1.311.21.8.4")
        };
    }

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new CaInfo(
            Name: _caName,
            DnsName: "mock-ca.certus.local",
            DisplayName: $"Mock {_caName}",
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
        if (!_templates.Any(t => t.Name.Equals(templateName, StringComparison.OrdinalIgnoreCase)))
        {
            return new SubmitResult(0, SubmitStatus.Denied,
                $"Template '{templateName}' not found on this CA.");
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
                // Parse CSR and issue a certificate. The mock decides
                // instantly, so the decision instant is the request instant.
                var cert = IssueCertificateFromCsr(csrDer, templateName);
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
                _issuedCerts[requestId] = new MockIssuedCertificate(
                    RequestId: requestId,
                    TemplateName: templateName,
                    Certificate: null,
                    Status: CertificateStatus.Pending,
                    RequestDate: DateTime.UtcNow);

                return new SubmitResult(requestId, SubmitStatus.Pending,
                    "Request pending CA manager approval.");
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
        // enough to take a snapshot of the matching rows. Projecting them,
        // which includes a DER parse per certificate, is pure work on that
        // snapshot and happens after the lock is released: a sync sweeping the
        // whole inventory must not block a concurrent revoke for the duration.
        List<MockIssuedCertificate> matches;
        lock (_lock)
        {
            var results = _issuedCerts.Values.AsEnumerable();

            if (query.Status.HasValue)
                results = results.Where(c => c.Status == query.Status.Value);

            if (!string.IsNullOrEmpty(query.TemplateName))
                results = results.Where(c =>
                    c.TemplateName.Equals(query.TemplateName, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(query.SubjectContains) && query.SubjectContains != null)
            {
                var search = query.SubjectContains;
                results = results.Where(c =>
                    c.Certificate != null &&
                    c.Certificate.SubjectDN.ToString().Contains(search, StringComparison.OrdinalIgnoreCase));
            }

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

            matches = results
                .Skip(query.Skip)
                .Take(query.Take)
                .ToList();
        }

        var list = matches.Select(ToCertificateInfo).ToList();

        return Task.FromResult<IReadOnlyList<CertificateInfo>>(list);
    }

    /// <summary>
    /// Projects one mock issued certificate to the shape the sync consumes,
    /// running its DER through the shared parser exactly once. One parse rather
    /// than one per field because this runs while the mock's lock is held.
    /// </summary>
    private static CertificateInfo ToCertificateInfo(MockIssuedCertificate c)
    {
        // The mock issues real certificates, so its own DER goes through the
        // same parser the real client uses rather than inventing values. The
        // dev host then shows the detail a live CA would, and mock backed tests
        // can assert on it. A parse that fails yields neither the detail nor the
        // bytes, which is the invariant the real client holds too: nothing
        // undecodable is ever carried forward to be stored and later handed to
        // an admin as a download.
        var der = c.Certificate?.GetEncoded();
        var parsed = der == null ? null : CertificateDerParser.Parse(der);

        return new CertificateInfo(
            RequestId: c.RequestId,
            SerialNumber: c.Certificate?.SerialNumber?.ToString(16) ?? "",
            Subject: c.Certificate?.SubjectDN?.ToString() ?? "Unknown",
            SubjectAlternativeNames: null,
            TemplateName: c.TemplateName,
            NotBefore: c.Certificate?.NotBefore ?? DateTime.MinValue,
            NotAfter: c.Certificate?.NotAfter ?? DateTime.MinValue,
            Status: c.Status,
            Requestor: "MOCK\\TestUser",
            RequestDate: c.RequestDate,
            RevokedWhen: c.RevokedWhen,
            RevokedReason: c.RevokedReason,
            CryptoDetail: parsed?.Crypto,
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
    /// </summary>
    public void ApproveRequest(int requestId)
    {
        lock (_lock)
        {
            if (_issuedCerts.TryGetValue(requestId, out var issued) &&
                issued.Status == CertificateStatus.Pending)
            {
                // Generate a certificate for the approved request
                var cert = GenerateSelfSignedCert($"CN=Approved-{requestId}",
                    issued.TemplateName);

                _issuedCerts[requestId] = issued with
                {
                    Certificate = cert,
                    Status = CertificateStatus.Issued,
                    ResolvedWhen = DateTime.UtcNow
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
        generator.SetIssuerDN(new X509Name($"CN={caName}"));
        generator.SetSubjectDN(new X509Name($"CN={caName}"));
        generator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddYears(10));
        generator.SetPublicKey(keyPair.Public);

        // Basic Constraints: CA=true
        generator.AddExtension(
            X509Extensions.BasicConstraints,
            true,
            new BasicConstraints(true));

        var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private);
        return generator.Generate(signatureFactory);
    }

    private X509Certificate IssueCertificateFromCsr(byte[] csrDer, string templateName)
    {
        try
        {
            var csr = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(csrDer);
            var csrInfo = csr.GetCertificationRequestInfo();

            var generator = new X509V3CertificateGenerator();
            var serialNumber = BigInteger.ProbablePrime(120, new SecureRandom());

            generator.SetSerialNumber(serialNumber);
            generator.SetIssuerDN(_caCertificate.SubjectDN);
            generator.SetSubjectDN(csrInfo.Subject);
            generator.SetNotBefore(DateTime.UtcNow);
            generator.SetNotAfter(DateTime.UtcNow.AddYears(1));
            generator.SetPublicKey(csr.GetPublicKey());
            AddLeafExtensions(generator);

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", _caKeyPair.Private);
            return generator.Generate(signatureFactory);
        }
        catch
        {
            // If CSR parsing fails, generate a cert with a default subject
            return GenerateSelfSignedCert($"CN=issued-cert", templateName);
        }
    }

    private X509Certificate GenerateSelfSignedCert(string subject, string templateName)
    {
        var subjectKeyPair = GenerateKeyPair();
        var generator = new X509V3CertificateGenerator();
        var serialNumber = BigInteger.ProbablePrime(120, new SecureRandom());

        generator.SetSerialNumber(serialNumber);
        generator.SetIssuerDN(_caCertificate.SubjectDN);
        generator.SetSubjectDN(new X509Name(subject));
        generator.SetNotBefore(DateTime.UtcNow);
        generator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        generator.SetPublicKey(subjectKeyPair.Public);
        AddLeafExtensions(generator);

        var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", _caKeyPair.Private);
        return generator.Generate(signatureFactory);
    }

    /// <summary>
    /// Applies the configurable leaf extensions to a certificate under
    /// construction. Shared by the CSR path and the self signed path so a
    /// pending request approved later carries the same shape as an instant
    /// issuance. The real CA writes the template's extensions into every
    /// leaf; before this the mock issued bare certificates, which the TLS
    /// capability ceiling would refuse as valid for every purpose.
    /// </summary>
    private void AddLeafExtensions(X509V3CertificateGenerator generator)
    {
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
    /// </summary>
    private sealed record MockIssuedCertificate(
        int RequestId,
        string TemplateName,
        X509Certificate? Certificate,
        CertificateStatus Status,
        DateTime RequestDate,
        DateTime? RevokedWhen = null,
        int? RevokedReason = null,
        DateTime? ResolvedWhen = null);
}
