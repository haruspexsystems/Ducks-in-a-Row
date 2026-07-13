using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certus.Core.Adcs;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Setup;

/// <summary>
/// Enrolls a TLS certificate for the Ducks in a Row server itself from the
/// connected CA, using the template the wizard selected. This is also the
/// live end to end test of that template: the service submits every ACME
/// order to the CA as its own computer account, so a certificate issued here
/// proves the template, the CA policy module, and the Enroll permission for
/// the whole product.
///
/// The submission goes through <see cref="IAdcsClientFactory"/> with the
/// candidate connection string, like every other wizard probe — during setup
/// the DI bound client is the unconfigured client and cannot reach the CA.
/// </summary>
public sealed class TlsCertificateEnroller
{
    /// <summary>
    /// The RSA floor when the template's minimum could not be read, or asks
    /// for less: 2048 is the common template minimum and the smallest size
    /// current ADCS policy modules accept.
    /// </summary>
    private const int MinimumRsaKeySizeBits = 2048;

    private readonly IAdcsClientFactory _clientFactory;
    private readonly IHttpsCertificateStore _certificateStore;
    private readonly ILogger<TlsCertificateEnroller> _logger;

    public TlsCertificateEnroller(
        IAdcsClientFactory clientFactory,
        IHttpsCertificateStore certificateStore,
        ILogger<TlsCertificateEnroller> logger)
    {
        _clientFactory = clientFactory;
        _certificateStore = certificateStore;
        _logger = logger;
    }

    /// <summary>
    /// Enroll a certificate for the host in <paramref name="externalUrl"/>
    /// and install it into the HTTPS certificate store. Nothing here writes
    /// configuration or restarts the service; the caller decides that based
    /// on the coverage flags in the result.
    /// </summary>
    /// <param name="caConnectionString">The candidate CA from the wizard state.</param>
    /// <param name="templateName">The template the wizard selected.</param>
    /// <param name="externalUrl">The external URL whose host goes into CN and SAN.</param>
    /// <param name="currentHost">
    /// The host the admin's browser is on (the request Host header), so the
    /// caller can tell whether that browsing session survives the restart.
    /// </param>
    public async Task<TlsEnrollmentResult> EnrollAsync(
        string caConnectionString,
        string templateName,
        string externalUrl,
        string? currentHost,
        CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(externalUrl, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
        {
            return TlsEnrollmentResult.Failed("The external URL is not a valid absolute URL.");
        }

        var host = uri.Host;

        var client = _clientFactory.Create(caConnectionString);
        try
        {
            var (keyAlgorithm, minimalKeySize) =
                await ResolveTemplateKeyRequirementsAsync(client, templateName, cancellationToken);

            AsymmetricAlgorithm key;
            try
            {
                key = CreateKey(keyAlgorithm, minimalKeySize);
            }
            catch (CryptographicException ex)
            {
                // A template's AD attributes drive the key size and curve;
                // an unusual or corrupt value (msPKI-Minimal-Key-Size in
                // particular) can be rejected by the platform's crypto
                // provider. Fail with the same structured result the rest
                // of this method returns, instead of an unhandled 500.
                _logger.LogWarning(ex,
                    "Could not create a {Algorithm} key for template {Template} (minimum size {MinimalKeySize})",
                    keyAlgorithm ?? "RSA", templateName, minimalKeySize);
                return TlsEnrollmentResult.Failed(
                    $"Could not create a key matching template {templateName}'s requirements " +
                    $"({keyAlgorithm ?? "RSA"}, minimum {minimalKeySize?.ToString() ?? "unknown"} bits): " +
                    $"{ex.Message}");
            }

            using var _ = key;
            var csrDer = BuildCsr(key, host);

            var submit = await client.SubmitCertificateRequestAsync(templateName, csrDer, cancellationToken);

            switch (submit.Status)
            {
                case SubmitStatus.Issued:
                    break;

                case SubmitStatus.Pending:
                    _logger.LogWarning(
                        "TLS certificate request {RequestId} pended for CA manager approval on template {Template}",
                        submit.RequestId, templateName);
                    return TlsEnrollmentResult.Pending(
                        submit.RequestId,
                        $"The CA accepted the request but is holding it for CA manager approval " +
                        $"(request ID {submit.RequestId}). Manager approval defeats ACME automation: " +
                        $"every certificate request would wait for a person. Uncheck 'CA certificate " +
                        $"manager approval' on the Issuance Requirements tab of the {templateName} " +
                        $"template, deny request {submit.RequestId} in the Certification Authority " +
                        $"console, and try again.");

                case SubmitStatus.Denied:
                    _logger.LogWarning(
                        "TLS certificate request denied on template {Template}: {Message}",
                        templateName, submit.Message);
                    return TlsEnrollmentResult.Denied(
                        $"The CA denied the request: {submit.Message ?? "no reason given"}. " +
                        $"The service enrolls as the computer account {DescribeServiceAccount()}. " +
                        $"This usually means that account lacks Enroll permission: grant it Enroll " +
                        $"on the Security tab of the {templateName} template and try again.");

                default:
                    return TlsEnrollmentResult.Failed(
                        $"The CA reported an error for the request: {submit.Message ?? "no detail available"}.");
            }

            var issued = await client.GetCertificateAsync(submit.RequestId, cancellationToken);
            if (issued.Status != CertificateStatus.Issued || issued.CertificateDer is null)
            {
                return TlsEnrollmentResult.Failed(
                    $"The CA reported the certificate as issued (request ID {submit.RequestId}) " +
                    $"but it could not be retrieved (status: {issued.Status}).");
            }

            using var leaf = new X509Certificate2(issued.CertificateDer);
            using var withKey = key switch
            {
                RSA rsa => leaf.CopyWithPrivateKey(rsa),
                ECDsa ecdsa => leaf.CopyWithPrivateKey(ecdsa),
                _ => throw new InvalidOperationException($"Unsupported key type {key.GetType().Name}"),
            };
            var thumbprint = _certificateStore.Install(withKey);

            var issuedNames = GetSubjectNames(leaf);
            var externalHostCovered = CoversHost(issuedNames, host);
            var currentHostCovered = string.IsNullOrWhiteSpace(currentHost)
                ? (bool?)null
                : CoversHost(issuedNames, currentHost);

            _logger.LogInformation(
                "TLS certificate issued (request ID {RequestId}, thumbprint {Thumbprint}) for template " +
                "{Template}; names: {Names}; external host covered: {External}; browsing host covered: {Current}",
                submit.RequestId, thumbprint, templateName,
                string.Join(", ", issuedNames), externalHostCovered, currentHostCovered);

            return new TlsEnrollmentResult(
                Status: TlsEnrollmentStatus.Installed,
                Thumbprint: thumbprint,
                RequestId: submit.RequestId,
                IssuedNames: issuedNames,
                ExternalHostCovered: externalHostCovered,
                CurrentHostCovered: currentHostCovered);
        }
        finally
        {
            (client as IDisposable)?.Dispose();
        }
    }

    /// <summary>
    /// Read the template's key requirements from AD so the generated key
    /// matches what the CA policy module will enforce. Best effort: any
    /// failure falls back to the RSA default rather than blocking the
    /// enrollment on an AD read.
    /// </summary>
    private async Task<(string? KeyAlgorithm, int? MinimalKeySize)> ResolveTemplateKeyRequirementsAsync(
        IAdcsClient client,
        string templateName,
        CancellationToken cancellationToken)
    {
        try
        {
            var templates = await client.GetTemplatesAsync(cancellationToken);
            var template = templates.FirstOrDefault(
                t => string.Equals(t.Name, templateName, StringComparison.OrdinalIgnoreCase));
            return (template?.Viability?.KeyAlgorithm, template?.Viability?.MinimalKeySize);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(
                ex,
                "Could not read the key requirements of template {Template}; defaulting to RSA {Bits}",
                templateName, MinimumRsaKeySizeBits);
            return (null, null);
        }
    }

    /// <summary>
    /// Create the key pair the template asks for. ECDSA templates get a key
    /// on the matching NIST curve (from the algorithm name suffix, or the
    /// minimum key size when the name carries no curve). Everything else,
    /// including an unknown algorithm, gets RSA at the template minimum with
    /// a 2048 bit floor.
    /// </summary>
    internal static AsymmetricAlgorithm CreateKey(string? keyAlgorithm, int? minimalKeySize)
    {
        var algorithm = keyAlgorithm?.Trim().ToUpperInvariant();
        if (algorithm is not null && algorithm.StartsWith("ECDSA", StringComparison.Ordinal))
        {
            var curve = algorithm.EndsWith("P384", StringComparison.Ordinal) ? ECCurve.NamedCurves.nistP384
                : algorithm.EndsWith("P521", StringComparison.Ordinal) ? ECCurve.NamedCurves.nistP521
                : algorithm.EndsWith("P256", StringComparison.Ordinal) ? ECCurve.NamedCurves.nistP256
                : minimalKeySize switch
                {
                    >= 521 => ECCurve.NamedCurves.nistP521,
                    >= 384 => ECCurve.NamedCurves.nistP384,
                    _ => ECCurve.NamedCurves.nistP256,
                };
            return ECDsa.Create(curve);
        }

        return RSA.Create(Math.Max(MinimumRsaKeySizeBits, minimalKeySize ?? MinimumRsaKeySizeBits));
    }

    /// <summary>
    /// Build the PKCS#10 request: CN and a single SAN entry for the external
    /// host. Deliberately no extra names — machine names or localhost in a CA
    /// issued server certificate are poor hygiene, and the wizard handles a
    /// browsing session on another host with the continue link instead.
    /// EC keys do not encipher, so their key usage is signature only; some
    /// policy modules reject an EC request that claims KeyEncipherment.
    /// </summary>
    internal static byte[] BuildCsr(AsymmetricAlgorithm key, string host)
    {
        var dn = new X500DistinguishedName($"CN={host}");
        var request = key switch
        {
            RSA rsa => new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest(dn, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new ArgumentException($"Unsupported key type {key.GetType().Name}", nameof(key)),
        };

        var keyUsage = key is RSA
            ? X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment
            : X509KeyUsageFlags.DigitalSignature;
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(keyUsage, critical: false));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(SetupService.ServerAuthEku) },
                critical: false));

        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var ip))
            san.AddIpAddress(ip);
        else
            san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());

        return request.CreateSigningRequest();
    }

    /// <summary>
    /// The DNS and IP names the certificate is valid for: the SAN entries,
    /// or the CN when the certificate has no SAN extension (verifiers ignore
    /// the CN when a SAN is present, so the two are never mixed).
    /// </summary>
    public static IReadOnlyList<string> GetSubjectNames(X509Certificate2 certificate)
    {
        var names = new List<string>();
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509SubjectAlternativeNameExtension san)
            {
                names.AddRange(san.EnumerateDnsNames());
                names.AddRange(san.EnumerateIPAddresses().Select(a => a.ToString()));
            }
        }

        if (names.Count == 0)
        {
            var cn = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (!string.IsNullOrWhiteSpace(cn))
                names.Add(cn);
        }

        return names;
    }

    /// <summary>
    /// Whether any of the certificate names covers the host, the way a TLS
    /// verifier would: case insensitive exact match, a single label wildcard
    /// (*.example.com covers a.example.com but not b.a.example.com), or IP
    /// address equality.
    /// </summary>
    public static bool CoversHost(IEnumerable<string> names, string host)
    {
        var hostIsIp = IPAddress.TryParse(host, out var hostIp);

        foreach (var name in names)
        {
            if (string.Equals(name, host, StringComparison.OrdinalIgnoreCase))
                return true;

            if (hostIsIp && IPAddress.TryParse(name, out var nameIp) && nameIp.Equals(hostIp))
                return true;

            if (!hostIsIp && name.StartsWith("*.", StringComparison.Ordinal))
            {
                var dot = host.IndexOf('.');
                if (dot > 0 &&
                    string.Equals(host[(dot + 1)..], name[2..], StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Name the identity the CA sees, for the denial message: the machine
    /// account, qualified with the DNS domain when the host is domain joined.
    /// </summary>
    internal static string DescribeServiceAccount()
    {
        var machineAccount = Environment.MachineName + "$";
        var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
        return string.IsNullOrEmpty(domain)
            ? machineAccount
            : $"{machineAccount} in domain {domain}";
    }
}

/// <summary>How a TLS certificate enrollment attempt ended.</summary>
public enum TlsEnrollmentStatus
{
    /// <summary>Issued and installed into the HTTPS certificate store.</summary>
    Installed,

    /// <summary>The CA pended the request for manager approval.</summary>
    Pending,

    /// <summary>The CA denied the request.</summary>
    Denied,

    /// <summary>Any other failure, including retrieval problems.</summary>
    Failed,
}

/// <summary>
/// Outcome of <see cref="TlsCertificateEnroller.EnrollAsync"/>. On
/// <see cref="TlsEnrollmentStatus.Installed"/> the coverage flags say whether
/// the issued names include the external URL host (they will not when the
/// template builds the subject from AD) and the host the admin is browsing
/// on (null when unknown).
/// </summary>
public sealed record TlsEnrollmentResult(
    TlsEnrollmentStatus Status,
    string? Thumbprint = null,
    int? RequestId = null,
    IReadOnlyList<string>? IssuedNames = null,
    bool ExternalHostCovered = false,
    bool? CurrentHostCovered = null,
    string? Message = null)
{
    public static TlsEnrollmentResult Pending(int requestId, string message) =>
        new(TlsEnrollmentStatus.Pending, RequestId: requestId, Message: message);

    public static TlsEnrollmentResult Denied(string message) =>
        new(TlsEnrollmentStatus.Denied, Message: message);

    public static TlsEnrollmentResult Failed(string message) =>
        new(TlsEnrollmentStatus.Failed, Message: message);
}
