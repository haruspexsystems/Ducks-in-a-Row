using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Validates HTTP-01 challenges by making an outbound HTTP GET request to
/// http://{domain}/.well-known/acme-challenge/{token} and checking
/// that the response body contains the expected key authorization.
/// RFC 8555 §8.3
/// </summary>
public sealed class Http01ChallengeValidator : IChallengeValidator
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<Http01ChallengeValidator> _logger;

    public Http01ChallengeValidator(HttpClient httpClient, ILogger<Http01ChallengeValidator> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public string ChallengeType => "http-01";

    public async Task<ChallengeValidationResult> ValidateAsync(
        ChallengeValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var domain = context.IdentifierValue;
        var token = context.Token;
        var accountThumbprint = context.AccountThumbprint;

        // The expected key authorization: token.thumbprint
        var expectedKeyAuth = $"{token}.{accountThumbprint}";

        // Build the challenge URL through Uri rather than by interpolation, and
        // then re-read what came back (issue #345). With the new-order grammar
        // in place nothing can fail this, which is exactly the point: it is the
        // second fence, so a later loosening of the identifier grammar cannot
        // silently reopen the authority. Before that grammar existed,
        // "10.0.0.5:22" was a legal identifier and this string dropped it
        // straight into the authority, handing the client the port; "host#" cut
        // the well known path off into a fragment.
        if (!TryBuildChallengeUrl(domain, token, out var url))
        {
            _logger.LogWarning(
                "HTTP-01 validation rejected for {Domain}: the identifier does not form a challenge URL",
                domain);
            return ChallengeValidationResult.Invalid(
                "The identifier does not form a valid HTTP-01 challenge URL.");
        }

        try
        {
            _logger.LogDebug("HTTP-01 validation: fetching {Url}", url);

            using var response = await _httpClient.GetAsync(url, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "HTTP-01 validation failed for {Domain}: HTTP {StatusCode}",
                    domain, (int)response.StatusCode);
                return ChallengeValidationResult.Invalid(
                    $"HTTP-01 challenge validation failed: server returned HTTP {(int)response.StatusCode}.");
            }

            var body = (await response.Content.ReadAsStringAsync(cancellationToken)).Trim();

            if (body != expectedKeyAuth)
            {
                _logger.LogWarning(
                    "HTTP-01 validation failed for {Domain}: incorrect response. Expected key authorization, got {Length} bytes",
                    domain, body.Length);
                return ChallengeValidationResult.Invalid(
                    "Incorrect key authorization value in HTTP-01 response.");
            }

            _logger.LogInformation("HTTP-01 validation succeeded for {Domain}", domain);
            return ChallengeValidationResult.Success();
        }
        catch (HttpRequestException ex) when (ex.InnerException is AddressBlockedException blocked)
        {
            // The configured egress policy refused the connection (server side request
            // forgery guard). This is a permanent rejection, not a transient blip.
            //
            // Two different facts arrive here and they must not be reported as
            // one. An address refusal means the target resolved somewhere policy
            // will not go. A port refusal means the address was fine and the
            // connection was steered off port 80, which only a redirect can do.
            // Telling a client its address is blocked when the address resolved
            // perfectly well sends it to check DNS and firewall rules for a
            // problem that is neither.
            if (blocked.Port is { } port)
            {
                _logger.LogWarning(
                    "HTTP-01 validation rejected for {Domain}: steered to port {Port}", domain, port);
                return ChallengeValidationResult.Invalid(
                    $"HTTP-01 validation for {domain} was steered to port {port}, " +
                    "which is not permitted.");
            }

            _logger.LogWarning(
                "HTTP-01 validation rejected for {Domain}: target resolves to a blocked address", domain);
            return ChallengeValidationResult.Invalid(
                $"HTTP-01 target {domain} resolves to an address that is not permitted.");
        }
        catch (HttpRequestException ex)
        {
            // No response was received — a transport failure. Leave room to retry.
            _logger.LogWarning(ex,
                "HTTP-01 validation could not reach {Domain} (transient)", domain);
            return ChallengeValidationResult.TransientFailure(
                $"Could not connect to {domain} for HTTP-01 validation: {ex.Message}");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning("HTTP-01 validation timed out for {Domain} (transient)", domain);
            return ChallengeValidationResult.TransientFailure(
                $"HTTP-01 validation timed out connecting to {domain}.");
        }
    }

    /// <summary>
    /// The RFC 8555 section 8.3 challenge URL for an identifier: scheme http,
    /// the identifier as the whole authority, port 80, and the well known path.
    /// False when the identifier will not sit in an authority on its own, or
    /// when the URL that came back is not the one asked for: a port that is not
    /// the default, a userinfo part, a query, a fragment, a host the identifier
    /// did not name, or a path other than the challenge path. Every one of
    /// those means the client, not this server, decided where the request goes.
    /// </summary>
    private static bool TryBuildChallengeUrl(string domain, string token, out string url)
    {
        url = string.Empty;
        var expectedPath = $"/.well-known/acme-challenge/{token}";

        Uri uri;
        try
        {
            uri = new UriBuilder
            {
                Scheme = Uri.UriSchemeHttp,
                Host = domain,
                Port = 80,
                Path = expectedPath,
            }.Uri;
        }
        catch (UriFormatException)
        {
            return false;
        }

        if (!uri.IsDefaultPort
            || uri.UserInfo.Length != 0
            || uri.Query.Length != 0
            || uri.Fragment.Length != 0
            || !string.Equals(uri.Host, domain, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(uri.AbsolutePath, expectedPath, StringComparison.Ordinal))
        {
            return false;
        }

        url = uri.AbsoluteUri;
        return true;
    }
}
