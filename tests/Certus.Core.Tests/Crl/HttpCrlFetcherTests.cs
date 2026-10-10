using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Certus.Core.Crl;

namespace Certus.Core.Tests.Crl;

/// <summary>
/// The HTTP distribution point is the copy every client outside the domain
/// reads, and the one an administrator forgets to refresh after a root CRL
/// ceremony, so the fetcher has to be able to read it and to survive it being
/// absent, huge or slow.
/// </summary>
public class HttpCrlFetcherTests
{
    private const int Cap = 1024;
    private static readonly Uri Url = new("http://pki.contoso.com/root.crl");

    [Fact]
    public async Task Reads_a_crl_and_keeps_the_validators_for_next_time()
    {
        var body = new byte[] { 1, 2, 3, 4 };
        var handler = new StubHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(body),
            };
            response.Headers.ETag = new EntityTagHeaderValue("\"abc\"");
            response.Content.Headers.LastModified = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
            return response;
        });

        var result = await Fetch(handler);

        result.Ok.Should().BeTrue();
        result.NotModified.Should().BeFalse();
        result.Crls.Should().ContainSingle().Which.Should().Equal(body);
        result.ETag.Should().Be("\"abc\"");
        result.LastModified.Should().NotBeNull();
    }

    [Fact]
    public async Task Sends_the_entity_tag_it_was_given_and_reports_not_modified()
    {
        HttpRequestMessage? seen = null;
        var handler = new StubHandler(request =>
        {
            seen = request;
            return new HttpResponseMessage(HttpStatusCode.NotModified);
        });

        var result = await Fetch(handler, knownETag: "\"abc\"");

        // The whole point of the conditional request: an hourly check of a CRL
        // that can be megabytes should normally cost a few bytes.
        seen!.Headers.IfNoneMatch.ToString().Should().Contain("abc");
        result.Ok.Should().BeTrue();
        result.NotModified.Should().BeTrue();
        result.Crls.Should().BeEmpty();
    }

    [Fact]
    public async Task Falls_back_to_if_modified_since_when_there_is_no_entity_tag()
    {
        HttpRequestMessage? seen = null;
        var handler = new StubHandler(request =>
        {
            seen = request;
            return new HttpResponseMessage(HttpStatusCode.NotModified);
        });

        var lastModified = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        await Fetch(handler, knownLastModified: lastModified);

        seen!.Headers.IfModifiedSince.Should().Be(lastModified);
    }

    [Fact]
    public async Task Reports_a_404_as_a_failure_rather_than_throwing()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        var result = await Fetch(handler);

        // A distribution point that 404s is the normal shape of "the CRL was
        // never copied to the web server", which is the failure being watched
        // for, so it has to come back as a result.
        result.Ok.Should().BeFalse();
        result.Error.Should().Contain("404");
    }

    [Fact]
    public async Task Refuses_a_body_over_the_cap_declared_in_the_headers()
    {
        var handler = new StubHandler(_ =>
        {
            var content = new ByteArrayContent(new byte[16]);
            content.Headers.ContentLength = Cap + 1;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });

        var result = await Fetch(handler);

        result.Ok.Should().BeFalse();
        result.Error.Should().Contain("limit");
    }

    [Fact]
    public async Task Refuses_a_body_that_goes_over_the_cap_while_it_is_read()
    {
        // Content-Length is a claim, not a fact, so the cap is enforced against
        // the bytes that actually arrive.
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(new byte[Cap + 64])),
        });

        var result = await Fetch(handler);

        result.Ok.Should().BeFalse();
        result.Error.Should().Contain("limit");
    }

    [Fact]
    public async Task Reports_a_connection_failure_as_a_result()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("No such host is known."));

        var result = await Fetch(handler);

        result.Ok.Should().BeFalse();
        result.Error.Should().Contain("No such host");
    }

    [Fact]
    public async Task Reports_a_connection_dropped_mid_body_as_a_result()
    {
        // The failure arrives from the body stream rather than from the send, and
        // it does not always come wrapped in an HttpRequestException.
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new FailingStream()),
        });

        var result = await Fetch(handler);

        result.Ok.Should().BeFalse();
        result.Error.Should().Contain("reset");
    }

    [Fact]
    public async Task Reports_the_client_timeout_as_a_result()
    {
        var handler = new StubHandler(_ => throw new TaskCanceledException("timed out"));

        var result = await Fetch(handler);

        result.Ok.Should().BeFalse();
        result.Error.Should().Contain("in time");
    }

    [Fact]
    public async Task Lets_the_callers_own_cancellation_out()
    {
        var handler = new StubHandler(_ => throw new TaskCanceledException("cancelled"));
        using var client = new HttpClient(handler);
        var fetcher = new HttpCrlFetcher(client);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        // A monitor pass that is being shut down must not record a cancellation
        // as a distribution point failure.
        var act = async () => await fetcher.FetchAsync(Url, Cap, null, null, cancelled.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Refuses_a_url_that_is_not_http()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new HttpClient(handler);
        var fetcher = new HttpCrlFetcher(client);

        var result = await fetcher.FetchAsync(
            new Uri("file://server/share/root.crl"), Cap, null, null);

        result.Ok.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    private static async Task<CrlFetchResult> Fetch(
        StubHandler handler,
        string? knownETag = null,
        DateTimeOffset? knownLastModified = null)
    {
        using var client = new HttpClient(handler);
        var fetcher = new HttpCrlFetcher(client);
        return await fetcher.FetchAsync(Url, Cap, knownETag, knownLastModified);
    }

    private sealed class FailingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            throw new IOException("The connection was reset by the remote host.");

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new IOException("The connection was reset by the remote host.");

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
