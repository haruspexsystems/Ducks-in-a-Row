using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// A loopback listener standing in for the issuer download address a certificate names in its
/// authority information access extension (#642). It counts every connection that reaches it
/// and closes each at once, so a download attempt fails fast instead of waiting out the
/// retrieval timeout, and each instance serves a fresh path, so no cached download can answer
/// in its place.
///
/// Measured on Windows Server 2025 with .NET 10: a chain built with downloads on, for a leaf
/// whose issuer is missing, connected here once per build (3 of 3 runs in separate processes);
/// with <see cref="X509ChainPolicy.DisableCertificateDownloads"/>, never.
/// </summary>
internal sealed class AiaDownloadListener : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;
    private int _accepted;

    public AiaDownloadListener()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Url = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/{Guid.NewGuid():N}.cer";
        // Called directly, not through Task.Run, so the first accept is pending before the
        // constructor returns. Queued behind a busy pool under the full suite, the loop first
        // ran after DisposeAsync had stopped the listener and threw "Not listening" (#642).
        // With every pool worker blocked across construction and DisposeAsync, the Task.Run
        // shape threw that 2 of 2 runs and this shape 0 of 2, each in its own process.
        _acceptLoop = AcceptAsync();
    }

    /// <summary>The caIssuers URL to name in a certificate.</summary>
    public string Url { get; }

    /// <summary>Connections accepted so far, plus one if a connection is waiting to be accepted.</summary>
    public int Connections => Volatile.Read(ref _accepted) + (_listener.Pending() ? 1 : 0);

    /// <summary>
    /// A leaf naming <see cref="Url"/> as its issuer's download address, signed by a throwaway
    /// intermediate that is never handed out, so its chain can complete only by a download.
    /// </summary>
    public X509Certificate2 CreateOrphanLeaf(string dnsName = "acme.example")
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Orphan Test Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerRequest = new CertificateRequest("CN=Orphan Test Issuer", issuerKey, HashAlgorithmName.SHA256);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var issuerWithoutKey = issuerRequest.Create(
            root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(20), RandomNumberGenerator.GetBytes(12));
        using var issuer = issuerWithoutKey.CopyWithPrivateKey(issuerKey);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest($"CN={dnsName}", leafKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        leafRequest.CertificateExtensions.Add(san.Build());
        leafRequest.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(
            ocspUris: null, caIssuersUris: new[] { Url }));
        return leafRequest.Create(
            issuer, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(10), RandomNumberGenerator.GetBytes(12));
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (true)
            {
                using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                Interlocked.Increment(ref _accepted);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException
            // A continuation that reaches the next accept after Stop: shutdown, not a failure.
            or InvalidOperationException)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        await _acceptLoop;
        _stop.Dispose();
    }
}
