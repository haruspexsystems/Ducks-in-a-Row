using Certus.Core.Adcs;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// A CA that refuses with a message the test chooses, for issue #362.
///
/// <see cref="MockAdcsClient"/> composes its own refusal wording, which is exactly
/// what makes it the wrong tool here: the guard under test is that
/// <see cref="Certus.Core.Acme.Services.OrderService"/> sanitizes CA authored text
/// on its own account rather than trusting whichever <see cref="IAdcsClient"/>
/// handed it the value. A client that only ever returns wording Ducks itself wrote
/// cannot show that. So this one returns the refusal verbatim, standing in for a
/// real CA, or for a future client, that does not.
///
/// Everything else delegates to a real mock, in the same shape as
/// <see cref="OutageAdcsClient"/>, so nothing before or after the submit is a stub.
/// </summary>
internal sealed class RefusingAdcsClient : IAdcsClient
{
    private readonly MockAdcsClient _inner = new();

    /// <summary>The status the submit answers with.</summary>
    public SubmitStatus RefuseWith { get; set; } = SubmitStatus.Denied;

    /// <summary>The message the submit answers with, handed back untouched.</summary>
    public string? RefusalMessage { get; set; }

    public Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName, byte[] csrDer, CancellationToken cancellationToken = default) =>
        Task.FromResult(new SubmitResult(0, RefuseWith, RefusalMessage));

    public Task<CertificateResult> GetCertificateAsync(
        int requestId, CancellationToken cancellationToken = default) =>
        _inner.GetCertificateAsync(requestId, cancellationToken);

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default) =>
        _inner.GetCaInfoAsync(cancellationToken);

    public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(
        CancellationToken cancellationToken = default) =>
        _inner.GetTemplatesAsync(cancellationToken);

    public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query, CancellationToken cancellationToken = default) =>
        _inner.QueryCertificatesAsync(query, cancellationToken);

    public Task<CaRequestStatus?> GetRequestStatusAsync(
        int requestId, CancellationToken cancellationToken = default) =>
        _inner.GetRequestStatusAsync(requestId, cancellationToken);

    public Task RevokeCertificateAsync(
        string serialNumber, int reason, CancellationToken cancellationToken = default) =>
        _inner.RevokeCertificateAsync(serialNumber, reason, cancellationToken);

    public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(
        CancellationToken cancellationToken = default) =>
        _inner.GetCaCertificateChainAsync(cancellationToken);
}
