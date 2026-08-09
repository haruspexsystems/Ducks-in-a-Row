using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Setup;

public class ExternalUrlProbeTests
{
    /// <summary>
    /// The default timeout is generous on purpose. Only the test that asserts a
    /// timeout passes its own short value; everywhere else the timeout is
    /// headroom, not a fact under test, and a tight budget just turns thread
    /// pool pressure under the full Release suite into a false failure
    /// (issue #127).
    /// </summary>
    private static ExternalUrlProbe CreateProbe(TimeSpan? timeout = null)
    {
        var client = new HttpClient(ExternalUrlProbe.CreateHandler())
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
        };
        return new ExternalUrlProbe(client, NullLogger<ExternalUrlProbe>.Instance);
    }

    [Fact]
    public async Task Probe_ListenerAnswers_ReportsReachableWithTheStatus()
    {
        // Any HTTP status proves the authority answers; a 404 from a route
        // that does not exist yet still counts as reachable.
        using var listener = new MinimalHttpListener(404);
        var probe = CreateProbe();

        var result = await probe.ProbeAsync(new Uri($"http://127.0.0.1:{listener.Port}"), "WebServer");

        result.Attempted.Should().BeTrue();
        result.Reachable.Should().BeTrue();
        result.HttpStatusCode.Should().Be(404);
        result.DialedAuthority.Should().Be($"127.0.0.1:{listener.Port}");
        result.FailureKind.Should().BeNull();
    }

    [Fact]
    public async Task Probe_NothingListening_ReportsConnectionRefusedAtTheDialedPort()
    {
        // The issue #89 shape, reproduced locally: a port where nothing
        // accepts connections.
        var port = FreePort();
        var probe = CreateProbe();

        var result = await probe.ProbeAsync(new Uri($"http://127.0.0.1:{port}"), null);

        result.Attempted.Should().BeTrue();
        result.Reachable.Should().BeFalse();
        result.FailureKind.Should().Be(ExternalUrlProbeFailure.ConnectionRefused);
        result.DialedAuthority.Should().Be($"127.0.0.1:{port}");
        result.FailureDetail.Should().Contain($"127.0.0.1:{port}");
    }

    [Fact]
    public async Task Probe_ServerAcceptsButNeverAnswers_ReportsTimeout()
    {
        // A listener that accepts the connection and then stays silent, so
        // the client's own timeout is what fires.
        var silent = new TcpListener(IPAddress.Loopback, 0);
        silent.Start();
        try
        {
            var port = ((IPEndPoint)silent.LocalEndpoint).Port;
            var probe = CreateProbe(TimeSpan.FromMilliseconds(500));

            var result = await probe.ProbeAsync(new Uri($"http://127.0.0.1:{port}"), null);

            result.Reachable.Should().BeFalse();
            result.FailureKind.Should().Be(ExternalUrlProbeFailure.Timeout);
        }
        finally
        {
            silent.Stop();
        }
    }

    [Fact]
    public void BuildTargetUrl_WithTemplate_TargetsTheAcmeDirectory()
    {
        var target = ExternalUrlProbe.BuildTargetUrl(
            new Uri("https://certus.contoso.com:5001"), "Web Server ACME");

        target.AbsoluteUri.Should().Be("https://certus.contoso.com:5001/acme/Web%20Server%20ACME/directory");
    }

    [Fact]
    public void BuildTargetUrl_NoTemplate_TargetsTheAnonymousStatusEndpoint()
    {
        var target = ExternalUrlProbe.BuildTargetUrl(
            new Uri("https://certus.contoso.com:5001"), null);

        target.AbsoluteUri.Should().Be("https://certus.contoso.com:5001/api/setup/status");
    }

    [Fact]
    public void BuildTargetUrl_UsesOnlyTheAuthority_LikeTheAcmeUrlBuilder()
    {
        // A path on the external URL is dropped, matching how
        // AcmeControllerBase.AcmeUrl treats the configured value.
        var target = ExternalUrlProbe.BuildTargetUrl(
            new Uri("https://certus.contoso.com:5001/some/path"), null);

        target.AbsoluteUri.Should().Be("https://certus.contoso.com:5001/api/setup/status");
    }

    [Fact]
    public void Classify_ConnectionRefusedSocketError_IsConnectionRefused()
    {
        var exception = new HttpRequestException(
            "refused", new SocketException((int)SocketError.ConnectionRefused));

        ExternalUrlProbe.Classify(exception).Should().Be(ExternalUrlProbeFailure.ConnectionRefused);
    }

    [Fact]
    public void Classify_HostNotFoundSocketError_IsDnsFailure()
    {
        var exception = new HttpRequestException(
            "no dns", new SocketException((int)SocketError.HostNotFound));

        ExternalUrlProbe.Classify(exception).Should().Be(ExternalUrlProbeFailure.DnsFailure);
    }

    [Fact]
    public void Classify_ClientTimeout_IsTimeout()
    {
        // HttpClient wraps its own timeout in a TaskCanceledException with a
        // TimeoutException inside.
        var exception = new TaskCanceledException("timed out", new TimeoutException());

        ExternalUrlProbe.Classify(exception).Should().Be(ExternalUrlProbeFailure.Timeout);
    }

    [Fact]
    public void Classify_AuthenticationFailure_IsTlsError()
    {
        var exception = new HttpRequestException(
            "handshake failed", new AuthenticationException());

        ExternalUrlProbe.Classify(exception).Should().Be(ExternalUrlProbeFailure.TlsError);
    }

    [Fact]
    public void Classify_AnythingElse_IsOther()
    {
        ExternalUrlProbe.Classify(new HttpRequestException("plain"))
            .Should().Be(ExternalUrlProbeFailure.Other);
    }

    /// <summary>
    /// Grab a loopback port that nothing listens on by binding and releasing
    /// it. Another process could take it before the probe dials, but that
    /// window is tiny and the failure mode is a clear test failure.
    /// </summary>
    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>
    /// The smallest thing that answers HTTP on a loopback port: accepts a
    /// connection, reads the request head, writes a fixed status response.
    /// Raw TCP rather than HttpListener so no URL reservation is needed.
    ///
    /// The accept loop runs on its own background thread with blocking socket
    /// calls rather than as a thread pool task. This assembly runs its tests
    /// in parallel and the full Release suite runs it alongside a second test
    /// process, so the pool is saturated. A queued accept loop can then sit
    /// unscheduled for longer than the probe client's timeout, and the client
    /// reports a timeout against a listener that never got to accept. That is
    /// how this test failed intermittently under the full suite (issue #127).
    /// A dedicated thread is not subject to pool queueing, so the accept
    /// happens no matter how loaded the machine is.
    /// </summary>
    private sealed class MinimalHttpListener : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly Thread _acceptThread;
        private volatile bool _stopped;

        public int Port { get; }

        public MinimalHttpListener(int statusCode)
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _acceptThread = new Thread(() => AcceptLoop(statusCode))
            {
                IsBackground = true,
                Name = "external-url-probe-test-listener"
            };
            _acceptThread.Start();
        }

        private void AcceptLoop(int statusCode)
        {
            var response = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {statusCode} Probe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            while (!_stopped)
            {
                TcpClient client;
                try
                {
                    client = _listener.AcceptTcpClient();
                }
                catch
                {
                    // Disposal stops the listener, which makes the blocking
                    // accept throw. That is the only way out of this loop.
                    return;
                }

                using (client)
                {
                    try
                    {
                        // Serving one connection is bounded and its failure is
                        // its own: a caller that connects and then says nothing
                        // must not wedge the listener for everyone after it.
                        client.ReceiveTimeout = 5000;
                        client.SendTimeout = 5000;
                        var stream = client.GetStream();
                        // One inexact read is the intent: drain whatever
                        // request bytes arrived, however many, before the
                        // canned response goes out. The count is irrelevant.
                        var requestBytesRead = stream.Read(new byte[4096], 0, 4096);
                        _ = requestBytesRead;
                        stream.Write(response, 0, response.Length);
                        stream.Flush();
                    }
                    catch
                    {
                        // One bad connection does not end the listener.
                    }
                }
            }
        }

        public void Dispose()
        {
            _stopped = true;
            _listener.Stop();
            _acceptThread.Join(TimeSpan.FromSeconds(2));
        }
    }
}
