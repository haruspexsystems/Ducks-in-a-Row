using Certus.Core.Adcs;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// A CA that can be taken offline at either of the two points a finalize touches
/// it, for issue #324. Everything else delegates to a real <see cref="MockAdcsClient"/>,
/// so an order that survives the outage goes on to issue for real and the test can
/// assert on the certificate rather than on a stub.
///
/// The two hooks are not interchangeable and the whole point of the fix is that
/// they answer differently. An outage at the submit means nothing reached the CA,
/// which <see cref="IAdcsClient.SubmitCertificateRequestAsync"/> promises, so the
/// finalize releases its claim. An outage at the collection means the CA already
/// holds the request and its id is saved, so the order stays processing for the
/// pending issuance sweep.
///
/// Issue #336 drives the same two hooks with a
/// <see cref="CaAccessDeniedException"/>, because a CA that refuses this service's
/// credentials splits at exactly the same two points and for the same reason. The
/// hooks take any exception, so nothing here is specific to either issue; only the
/// log level and the outcome differ downstream.
///
/// Separate from <see cref="InterleavingAdcsClient"/>, whose doc frames it as a rig
/// for running a second request at an instant the database does not know about yet.
/// A failure hook is a different tool and does not belong there.
/// </summary>
internal sealed class OutageAdcsClient : IAdcsClient
{
    /// <summary>
    /// The real CA behind the hooks. Public so a test can approve or deny a request
    /// on the very CA this client delegates to, which matters once a hook stands
    /// between a decision and the reading of it (issue #365).
    /// </summary>
    public MockAdcsClient Inner { get; } = new();

    /// <summary>Thrown from the submit while set. Null lets the submit through.</summary>
    public Exception? FailTheSubmitWith { get; set; }

    /// <summary>Thrown from the certificate collection while set.</summary>
    public Exception? FailTheCollectionWith { get; set; }

    /// <summary>
    /// Thrown from the refusal reason read while set (issue #365). A third hook
    /// rather than a reuse of the collection one, because the two must answer
    /// differently: the collection is how the sweep learns the CA's decision, and
    /// this only decorates a decision already taken. A fault here must cost the
    /// detail and leave the refusal itself exactly as it was.
    /// </summary>
    public Exception? FailTheStatusReadWith { get; set; }

    /// <summary>Clears every fault, standing in for the CA coming back.</summary>
    public void ComeBack()
    {
        FailTheSubmitWith = null;
        FailTheCollectionWith = null;
        FailTheStatusReadWith = null;
    }

    public Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
    {
        if (FailTheSubmitWith is { } fault)
            throw fault;
        return Inner.SubmitCertificateRequestAsync(templateName, csrDer, cancellationToken);
    }

    public Task<CertificateResult> GetCertificateAsync(
        int requestId, CancellationToken cancellationToken = default)
    {
        if (FailTheCollectionWith is { } fault)
            throw fault;
        return Inner.GetCertificateAsync(requestId, cancellationToken);
    }

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default) =>
        Inner.GetCaInfoAsync(cancellationToken);

    public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(
        CancellationToken cancellationToken = default) =>
        Inner.GetTemplatesAsync(cancellationToken);

    public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query, CancellationToken cancellationToken = default) =>
        Inner.QueryCertificatesAsync(query, cancellationToken);

    public Task<CaRequestStatus?> GetRequestStatusAsync(
        int requestId, CancellationToken cancellationToken = default)
    {
        if (FailTheStatusReadWith is { } fault)
            throw fault;
        return Inner.GetRequestStatusAsync(requestId, cancellationToken);
    }

    public Task RevokeCertificateAsync(
        string serialNumber, int reason, CancellationToken cancellationToken = default) =>
        Inner.RevokeCertificateAsync(serialNumber, reason, cancellationToken);

    public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(
        CancellationToken cancellationToken = default) =>
        Inner.GetCaCertificateChainAsync(cancellationToken);
}
