using System.Net;
using System.Net.Http.Headers;

namespace Certus.Core.Crl;

/// <summary>
/// Reads a CRL from an HTTP distribution point.
///
/// The URLs come from the CA's own certificate chain, not from a client, which
/// is why this deliberately does not go through AddressGuard the way the ACME
/// HTTP-01 validator does: an internal PKI publishes its CRLs on the internal
/// network, and screening out private addresses would screen out every estate
/// this product serves.
///
/// Two things bound it. A size cap, because a busy issuing CA's CRL can be
/// megabytes and this runs on a timer; and a conditional request, because the
/// answer nearly always is "the same CRL as an hour ago" and a web server can
/// say that in a few bytes.
///
/// It takes an <see cref="HttpClient"/> rather than building one, so the product
/// hands it the typed client with the configured timeout and tools/AdcsQiProbe
/// can link this file and hand it a plain one. Keep it free of any dependency
/// beyond the base class library for that reason.
/// </summary>
public sealed class HttpCrlFetcher
{
    private readonly HttpClient _client;

    public HttpCrlFetcher(HttpClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    /// <summary>
    /// Fetches <paramref name="url"/>, conditionally when a previous entity tag
    /// or last modified time is known.
    /// </summary>
    /// <param name="url">An http or https distribution point URL.</param>
    /// <param name="maxBytes">The largest response body to accept.</param>
    /// <param name="knownETag">The entity tag stored from the last successful read.</param>
    /// <param name="knownLastModified">The last modified time stored from the last successful read.</param>
    /// <param name="cancellationToken">The caller's token. A timeout is reported, not thrown.</param>
    public async Task<CrlFetchResult> FetchAsync(
        Uri url,
        int maxBytes,
        string? knownETag,
        DateTimeOffset? knownLastModified,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);

        if (url.Scheme != Uri.UriSchemeHttp && url.Scheme != Uri.UriSchemeHttps)
            return CrlFetchResult.Failure($"{url.Scheme} is not an HTTP distribution point.");

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        if (!string.IsNullOrWhiteSpace(knownETag)
            && EntityTagHeaderValue.TryParse(knownETag, out var eTag))
        {
            request.Headers.IfNoneMatch.Add(eTag);
        }
        else if (knownLastModified is not null)
        {
            request.Headers.IfModifiedSince = knownLastModified;
        }

        try
        {
            using var response = await _client
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotModified)
                return CrlFetchResult.Unchanged();

            if (!response.IsSuccessStatusCode)
                return CrlFetchResult.Failure($"The distribution point answered {(int)response.StatusCode}.");

            var declaredLength = response.Content.Headers.ContentLength;
            if (declaredLength > maxBytes)
            {
                return CrlFetchResult.Failure(
                    $"The CRL is {declaredLength} bytes, over the {maxBytes} byte limit.");
            }

            var content = await ReadCappedAsync(response, maxBytes, cancellationToken)
                .ConfigureAwait(false);
            if (content is null)
                return CrlFetchResult.Failure($"The CRL is over the {maxBytes} byte limit.");

            return CrlFetchResult.Success(
                [content],
                response.Headers.ETag?.ToString(),
                response.Content.Headers.LastModified);
        }
        catch (HttpRequestException ex)
        {
            return CrlFetchResult.Failure(ex.Message);
        }
        catch (IOException ex)
        {
            // A connection dropped while the body was being read. It usually
            // arrives wrapped in an HttpRequestException and sometimes does not,
            // and this method promises the caller a result either way.
            return CrlFetchResult.Failure(ex.Message);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // The client's own timeout. The caller's cancellation is not ours to
            // swallow, so that one falls through.
            return CrlFetchResult.Failure("The distribution point did not answer in time.");
        }
    }

    /// <summary>
    /// Copies the body while counting, and gives up as soon as it goes over the
    /// cap. Returns null when it does. A Content-Length header is not trusted to
    /// be the truth about the body's size, it is only an early way out.
    /// </summary>
    private static async Task<byte[]?> ReadCappedAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);

        using var buffer = new MemoryStream();
        var chunk = new byte[81920];

        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                break;

            if (buffer.Length + read > maxBytes)
                return null;

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}
