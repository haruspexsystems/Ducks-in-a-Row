using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Setup;

/// <summary>
/// Active reachability probe for the external URL entered in the setup
/// wizard (issue #89). Makes a real HTTP request to the URL and reports the
/// outcome: reachable, or a named failure with the exact host and port that
/// was dialed.
///
/// The probe is advisory. A failure warns the administrator and asks for an
/// explicit confirmation; it never blocks setup, because deployments behind
/// a reverse proxy or hairpin NAT can be legitimately unreachable from the
/// server itself while working fine for clients.
/// </summary>
public interface IExternalUrlProbe
{
    /// <summary>
    /// Probe the external URL. When <paramref name="templateName"/> is given
    /// the probe targets that template's ACME directory, the same URL the
    /// wizard tells clients to use; otherwise it targets the anonymous setup
    /// status endpoint.
    /// </summary>
    Task<ExternalUrlProbeResult> ProbeAsync(
        Uri externalUrl,
        string? templateName,
        CancellationToken cancellationToken = default);
}

public sealed class ExternalUrlProbe : IExternalUrlProbe
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ExternalUrlProbe> _logger;

    /// <summary>
    /// Carries the TLS certificate validation outcome from the handler
    /// callback back to the request that triggered the handshake. Absent for
    /// plain HTTP or when the connection was reused.
    /// </summary>
    private static readonly HttpRequestOptionsKey<SslPolicyErrors> SslPolicyErrorsKey =
        new("Certus.ExternalUrlProbe.SslPolicyErrors");

    public ExternalUrlProbe(HttpClient httpClient, ILogger<ExternalUrlProbe> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    /// <summary>
    /// The message handler for the probe's typed HttpClient. Accepts every
    /// server certificate, because a self signed setup certificate must read
    /// as reachable, but records whether the certificate would have validated
    /// so the wizard can mention it. Redirects are not followed: the first
    /// hop answering is what proves reachability.
    ///
    /// Deliberately not built by ChallengeHttpHandlerFactory. That handler
    /// blocks loopback and private addresses (the request forgery guard for
    /// challenge validation), but the external URL legitimately resolves to
    /// this very server.
    /// </summary>
    public static HttpClientHandler CreateHandler()
    {
        return new HttpClientHandler
        {
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (request, _, _, errors) =>
            {
                request.Options.Set(SslPolicyErrorsKey, errors);
                return true;
            },
        };
    }

    public async Task<ExternalUrlProbeResult> ProbeAsync(
        Uri externalUrl,
        string? templateName,
        CancellationToken cancellationToken = default)
    {
        var authority = $"{externalUrl.Host}:{externalUrl.Port}";
        var target = BuildTargetUrl(externalUrl, templateName);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, target);
            using var response = await _httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            string? certificateWarning = null;
            if (request.Options.TryGetValue(SslPolicyErrorsKey, out var sslErrors)
                && sslErrors != SslPolicyErrors.None)
            {
                certificateWarning =
                    $"The server answered at {authority}, but its TLS certificate does not " +
                    $"validate from here ({sslErrors}). ACME clients will need to trust the " +
                    "certificate or its issuing CA.";
            }

            _logger.LogInformation(
                "External URL probe: {Target} answered HTTP {Status} at {Authority}",
                target, (int)response.StatusCode, authority);

            return new ExternalUrlProbeResult(
                Attempted: true,
                Reachable: true,
                DialedAuthority: authority,
                HttpStatusCode: (int)response.StatusCode,
                CertificateWarning: certificateWarning);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            var kind = Classify(ex);
            var detail = DescribeFailure(kind, ex, authority, externalUrl.Host);

            _logger.LogWarning(
                "External URL probe: {Target} did not answer from this server ({Kind}): {Detail}",
                target, kind, detail);

            return new ExternalUrlProbeResult(
                Attempted: true,
                Reachable: false,
                DialedAuthority: authority,
                FailureKind: kind,
                FailureDetail: detail);
        }
    }

    /// <summary>
    /// Build the URL the probe requests. Only the authority of the external
    /// URL is used, matching how the ACME URL builder treats it. Any HTTP
    /// status in the response counts as reachable, so the target existing is
    /// not required; it only has to be behind the same authority.
    /// </summary>
    internal static Uri BuildTargetUrl(Uri externalUrl, string? templateName)
    {
        var authority = externalUrl.GetLeftPart(UriPartial.Authority);
        var path = string.IsNullOrWhiteSpace(templateName)
            ? "/api/setup/status"
            : $"/acme/{Uri.EscapeDataString(templateName)}/directory";
        return new Uri(authority + path);
    }

    /// <summary>
    /// Map a probe exception to a stable failure kind the wizard can name.
    /// Walks inner exceptions because HttpClient wraps the socket and TLS
    /// causes in HttpRequestException, and wraps its own timeout in a
    /// TaskCanceledException with a TimeoutException inside.
    /// </summary>
    internal static string Classify(Exception exception)
    {
        for (var e = exception; e is not null; e = e.InnerException)
        {
            switch (e)
            {
                case SocketException { SocketErrorCode: SocketError.ConnectionRefused }:
                    return ExternalUrlProbeFailure.ConnectionRefused;
                case SocketException
                {
                    SocketErrorCode: SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoData
                }:
                    return ExternalUrlProbeFailure.DnsFailure;
                case SocketException { SocketErrorCode: SocketError.TimedOut }:
                case TimeoutException:
                    return ExternalUrlProbeFailure.Timeout;
                case AuthenticationException:
                    return ExternalUrlProbeFailure.TlsError;
            }
        }

        return exception is OperationCanceledException
            ? ExternalUrlProbeFailure.Timeout
            : ExternalUrlProbeFailure.Other;
    }

    private static string DescribeFailure(string kind, Exception exception, string authority, string host)
    {
        return kind switch
        {
            ExternalUrlProbeFailure.ConnectionRefused =>
                $"Connection refused at {authority}. Nothing is accepting connections on that port.",
            ExternalUrlProbeFailure.Timeout =>
                $"The connection to {authority} timed out.",
            ExternalUrlProbeFailure.DnsFailure =>
                $"The host name {host} could not be resolved from this server.",
            ExternalUrlProbeFailure.TlsError =>
                $"The TLS handshake with {authority} failed. The port answered but is not speaking usable TLS.",
            _ => $"The request to {authority} failed: {exception.Message}",
        };
    }
}

/// <summary>
/// Outcome of one reachability probe. <see cref="Attempted"/> is false when
/// the probe was skipped (mock CA demo walkthrough). Any HTTP status counts
/// as reachable: a 404 still proves the connection, TLS, and HTTP all work
/// at the dialed authority.
/// </summary>
public sealed record ExternalUrlProbeResult(
    bool Attempted,
    bool Reachable,
    string DialedAuthority,
    string? FailureKind = null,
    string? FailureDetail = null,
    int? HttpStatusCode = null,
    string? CertificateWarning = null)
{
    public static ExternalUrlProbeResult Skipped(string dialedAuthority) =>
        new(Attempted: false, Reachable: false, DialedAuthority: dialedAuthority);
}

/// <summary>
/// Stable failure kind names carried in
/// <see cref="ExternalUrlProbeResult.FailureKind"/> and shown by the wizard.
/// </summary>
public static class ExternalUrlProbeFailure
{
    public const string ConnectionRefused = "connectionRefused";
    public const string Timeout = "timeout";
    public const string TlsError = "tlsError";
    public const string DnsFailure = "dnsFailure";
    public const string Other = "other";
}
