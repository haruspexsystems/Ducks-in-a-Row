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
        string domain,
        string token,
        string accountThumbprint,
        CancellationToken cancellationToken = default)
    {
        // The expected key authorization: token.thumbprint
        var expectedKeyAuth = $"{token}.{accountThumbprint}";

        // Build the challenge URL
        var url = $"http://{domain}/.well-known/acme-challenge/{token}";

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
        catch (HttpRequestException ex) when (ex.InnerException is AddressBlockedException)
        {
            // The configured egress policy blocked the resolved address (server side request
            // forgery guard). This is a permanent rejection, not a transient blip.
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
}
