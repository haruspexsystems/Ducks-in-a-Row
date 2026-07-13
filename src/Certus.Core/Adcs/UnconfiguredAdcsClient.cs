namespace Certus.Core.Adcs;

/// <summary>
/// The <see cref="IAdcsClient"/> bound when no CA connection string is
/// configured and the mock is not explicitly enabled. Every operation throws
/// <see cref="CaUnavailableException"/>, which the web layer already maps to
/// 503 ca-unavailable problem responses, so the service runs and serves the
/// setup wizard while refusing CA work instead of silently using the mock.
/// </summary>
public sealed class UnconfiguredAdcsClient : IAdcsClient
{
    private static CaUnavailableException NotConfigured() => new(
        "No CA connection string is configured. Complete the setup wizard to " +
        "connect a Certificate Authority.");

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
        => throw NotConfigured();

    public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
        => throw NotConfigured();

    public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
        => throw NotConfigured();

    public Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
        => throw NotConfigured();

    public Task<CertificateResult> GetCertificateAsync(
        int requestId, CancellationToken cancellationToken = default)
        => throw NotConfigured();

    public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query, CancellationToken cancellationToken = default)
        => throw NotConfigured();

    public Task RevokeCertificateAsync(
        string serialNumber, int reason, CancellationToken cancellationToken = default)
        => throw NotConfigured();
}
