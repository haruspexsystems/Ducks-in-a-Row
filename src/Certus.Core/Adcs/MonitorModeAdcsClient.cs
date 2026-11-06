using Microsoft.Extensions.Logging;

namespace Certus.Core.Adcs;

/// <summary>
/// The last line of monitor mode (issue #470): an <see cref="IAdcsClient"/> that passes
/// every read through and refuses both of the product's CA writes,
/// <see cref="SubmitCertificateRequestAsync"/> and <see cref="RevokeCertificateAsync"/>.
///
/// The writes are already closed further out, where the refusal can say something
/// useful: the ACME routes answer 404, the issuance workers are not registered, and the
/// dashboard endpoints that enroll or revoke refuse by name. This is what holds when a
/// caller is missed, or added later without anyone thinking of monitor mode. So a
/// refusal here is always a defect somewhere above, and it logs at Error.
///
/// It refuses with <see cref="CaWriteRefusedException"/>, which says why. That type's
/// own comment explains why it is deliberately neither an outage nor a denial.
/// </summary>
public sealed class MonitorModeAdcsClient : IAdcsClient, IDisposable
{
    private readonly IAdcsClient _inner;
    private readonly ILogger _logger;

    public MonitorModeAdcsClient(IAdcsClient inner, ILogger<MonitorModeAdcsClient> logger)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(logger);
        _inner = inner;
        _logger = logger;
    }

    /// <summary>The client this one wraps, for the tests that check the wiring.</summary>
    public IAdcsClient Inner => _inner;

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
        => _inner.GetCaInfoAsync(cancellationToken);

    public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
        => _inner.GetTemplatesAsync(cancellationToken);

    public Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
    {
        _logger.LogError(
            "Monitor mode refused a certificate request against template {Template}. Nothing " +
            "was sent to the CA. A caller reached the CA write path that monitor mode closes " +
            "further out, which is a defect to report",
            templateName);
        throw new CaWriteRefusedException("certificate request");
    }

    public Task<CertificateResult> GetCertificateAsync(
        int requestId, CancellationToken cancellationToken = default)
        => _inner.GetCertificateAsync(requestId, cancellationToken);

    public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query, CancellationToken cancellationToken = default)
        => _inner.QueryCertificatesAsync(query, cancellationToken);

    public Task<CaRequestStatus?> GetRequestStatusAsync(
        int requestId, CancellationToken cancellationToken = default)
        => _inner.GetRequestStatusAsync(requestId, cancellationToken);

    public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
        => _inner.GetCaCertificateChainAsync(cancellationToken);

    public Task RevokeCertificateAsync(
        string serialNumber, int reason, CancellationToken cancellationToken = default)
    {
        _logger.LogError(
            "Monitor mode refused to revoke the certificate with serial number {SerialNumber} " +
            "(reason {Reason}). Nothing was sent to the CA. A caller reached the CA write path " +
            "that monitor mode closes further out, which is a defect to report",
            serialNumber, reason);
        throw new CaWriteRefusedException("revocation");
    }

    /// <summary>
    /// Disposes the wrapped client. The real client holds COM objects, and every caller
    /// of <see cref="IAdcsClientFactory"/> disposes what it was given, so the wrapper must
    /// not be where that stops.
    /// </summary>
    public void Dispose() => (_inner as IDisposable)?.Dispose();
}

/// <summary>
/// The factory half of <see cref="MonitorModeAdcsClient"/>. It matters as much as the
/// client: the HTTPS certificate enroller, the setup wizard's Test Connection and the
/// service rights check never use the injected client. They build their own through
/// <see cref="IAdcsClientFactory"/>, the wizard from a CA string in the request body, so
/// a wrapper on the injected client alone would leave the enrolment submit open.
/// </summary>
public sealed class MonitorModeAdcsClientFactory : IAdcsClientFactory
{
    private readonly IAdcsClientFactory _inner;
    private readonly ILogger<MonitorModeAdcsClient> _logger;

    public MonitorModeAdcsClientFactory(IAdcsClientFactory inner, ILogger<MonitorModeAdcsClient> logger)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(logger);
        _inner = inner;
        _logger = logger;
    }

    /// <summary>The factory this one wraps, for the tests that check the wiring.</summary>
    public IAdcsClientFactory Inner => _inner;

    public IAdcsClient Create(string caConnectionString)
        => new MonitorModeAdcsClient(_inner.Create(caConnectionString), _logger);
}
