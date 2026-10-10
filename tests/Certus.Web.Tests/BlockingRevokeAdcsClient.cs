using System.Collections.Concurrent;
using Certus.Core.Adcs;

namespace Certus.Web.Tests;

/// <summary>
/// An <see cref="IAdcsClient"/> that delegates to a real <see cref="MockAdcsClient"/>
/// except for revocation, which parks until the test releases it. Holding one request
/// inside the CA call while a second arrives is the only way to make a revocation race
/// deterministic, so this is the shared rig behind both surfaces' race tests: the
/// dashboard gate (issue #203) and the ACME revoke-cert gate (issue #226), which are
/// the same per serial <c>CertificateRevocationGate</c> singleton.
/// </summary>
public sealed class BlockingRevokeAdcsClient : IAdcsClient
{
    public MockAdcsClient Inner { get; } = new();

    // RunContinuationsAsynchronously, or releasing would run the server's
    // continuation inline on the test thread.
    private readonly TaskCompletionSource _firstRevokeEntered =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentQueue<string> _enteredSerials = new();
    private int _revokeCalls;

    /// <summary>Completes when the first revoke call has entered the CA.</summary>
    public Task FirstRevokeEntered => _firstRevokeEntered.Task;

    /// <summary>How many revoke calls reached the CA.</summary>
    public int RevokeCalls => Volatile.Read(ref _revokeCalls);

    /// <summary>
    /// Every serial that reached the CA, recorded on entry rather than on
    /// completion, so a parked call is already visible here. Recorded on entry is
    /// what makes a per serial assertion precise: a raw call count cannot say
    /// whether a second call was the certificate that should have been gated or a
    /// different one that rightly was not.
    /// </summary>
    public IReadOnlyCollection<string> EnteredSerials => _enteredSerials.ToArray();

    /// <summary>Lets every parked revoke call proceed to the mock.</summary>
    public void ReleaseRevokes() => _release.TrySetResult();

    public async Task RevokeCertificateAsync(
        string serialNumber, int reason, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _revokeCalls);
        _enteredSerials.Enqueue(serialNumber);
        _firstRevokeEntered.TrySetResult();
        await _release.Task.WaitAsync(cancellationToken);
        await Inner.RevokeCertificateAsync(serialNumber, reason, cancellationToken);
    }

    public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
        => Inner.GetCaInfoAsync(cancellationToken);

    public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
        => Inner.GetTemplatesAsync(cancellationToken);

    public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
        => Inner.GetCaCertificateChainAsync(cancellationToken);

    public Task<SubmitResult> SubmitCertificateRequestAsync(
        string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
        => Inner.SubmitCertificateRequestAsync(templateName, csrDer, cancellationToken);

    public Task<CertificateResult> GetCertificateAsync(
        int requestId, CancellationToken cancellationToken = default)
        => Inner.GetCertificateAsync(requestId, cancellationToken);

    public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
        CertificateQuery query, CancellationToken cancellationToken = default)
        => Inner.QueryCertificatesAsync(query, cancellationToken);

    public Task<CaRequestStatus?> GetRequestStatusAsync(
        int requestId, CancellationToken cancellationToken = default)
        => Inner.GetRequestStatusAsync(requestId, cancellationToken);
}
