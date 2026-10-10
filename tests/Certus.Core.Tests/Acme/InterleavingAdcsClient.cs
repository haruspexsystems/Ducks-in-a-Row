using Certus.Core.Adcs;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// An <see cref="IAdcsClient"/> that behaves exactly like a <see cref="MockAdcsClient"/>
/// except that it can run a caller supplied callback at either of the two instants where
/// the CA holds something the database does not know about yet.
///
/// <see cref="WhileTheCsrIsAtTheCa"/> runs once the CA has accepted the CSR and before the
/// submit result is handed back. That is the window issue #321 lives in: the request
/// exists at the CA and not one column has been written about it.
///
/// <see cref="WhileTheCertificateIsAtTheCa"/> runs once the CA has produced the
/// certificate and before <c>IssueCertificateAsync</c> sees it. That is the window issue
/// #312 lives in: the certificate exists at the CA and <c>IssueCertificateAsync</c> has
/// written nothing yet.
///
/// Running the concurrent act inside a callback makes the interleaving deterministic with
/// no threads, no delays and no TaskCompletionSource, so a test built on it cannot flake
/// and cannot quietly stop reproducing the race it was written for.
///
/// A callback standing in for a second request belongs on a second
/// <see cref="Certus.Core.Data.CertusDbContext"/> over the same connection, driving the
/// real service rather than writing a status by hand. A hand written UPDATE would test a
/// mock of the demote instead of the demote, and would keep passing after the demote
/// learned to refuse.
/// </summary>
public sealed class InterleavingAdcsClient : IAdcsClient
{
    /// <summary>The real mock every call is delegated to. Configure it as usual.</summary>
    public MockAdcsClient Inner { get; } = new();

    /// <summary>
    /// Runs once the CA has accepted the CSR for this order and before the finalize
    /// records the request id. Null means behave exactly like the mock.
    /// </summary>
    public Func<Task>? WhileTheCsrIsAtTheCa { get; set; }

    /// <summary>
    /// Runs once the CA has produced the certificate for this request and before
    /// <c>IssueCertificateAsync</c> sees it. Null means behave exactly like the mock.
    /// </summary>
    public Func<Task>? WhileTheCertificateIsAtTheCa { get; set; }

    /// <summary>
    /// The cancellation token the last submit was handed. Lets a test assert what the
    /// finalize offers the CA (issue #321) rather than only what it stores, which
    /// matters because the COM client ignores the token once its call is in flight, so
    /// no outcome alone can tell the two tokens apart.
    /// </summary>
    public CancellationToken TokenTheSubmitReceived { get; private set; }

    public async Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName,
        byte[] csrDer,
        CancellationToken cancellationToken = default)
    {
        TokenTheSubmitReceived = cancellationToken;

        var result = await Inner.SubmitCertificateRequestAsync(
            templateName, csrDer, cancellationToken);

        if (WhileTheCsrIsAtTheCa is { } concurrentRequest)
            await concurrentRequest();

        return result;
    }

    public async Task<CertificateResult> GetCertificateAsync(
        int requestId,
        CancellationToken cancellationToken = default)
    {
        var result = await Inner.GetCertificateAsync(requestId, cancellationToken);

        if (WhileTheCertificateIsAtTheCa is { } concurrentRequest)
            await concurrentRequest();

        return result;
    }

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default) =>
        Inner.GetCaInfoAsync(cancellationToken);

    public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default) =>
        Inner.GetTemplatesAsync(cancellationToken);

    public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query,
        CancellationToken cancellationToken = default) =>
        Inner.QueryCertificatesAsync(query, cancellationToken);

    public Task<CaRequestStatus?> GetRequestStatusAsync(
        int requestId,
        CancellationToken cancellationToken = default) =>
        Inner.GetRequestStatusAsync(requestId, cancellationToken);

    public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default) =>
        Inner.GetCaCertificateChainAsync(cancellationToken);

    public Task RevokeCertificateAsync(
        string serialNumber,
        int reason,
        CancellationToken cancellationToken = default) =>
        Inner.RevokeCertificateAsync(serialNumber, reason, cancellationToken);
}
