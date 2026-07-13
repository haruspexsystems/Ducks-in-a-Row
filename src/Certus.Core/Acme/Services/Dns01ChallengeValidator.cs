using System.Security.Cryptography;
using System.Text;
using DnsClient;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Acme.Services;

/// <summary>
/// Validates DNS-01 challenges by querying the TXT record at
/// _acme-challenge.{domain} and checking that it contains the
/// SHA-256 digest of the key authorization.
/// RFC 8555 §8.4
///
/// The expected TXT record value is:
///   base64url(SHA-256(token + "." + accountThumbprint))
/// </summary>
public sealed class Dns01ChallengeValidator : IChallengeValidator
{
    private readonly ILookupClient _dnsClient;
    private readonly ILogger<Dns01ChallengeValidator> _logger;

    public Dns01ChallengeValidator(ILookupClient dnsClient, ILogger<Dns01ChallengeValidator> logger)
    {
        _dnsClient = dnsClient;
        _logger = logger;
    }

    public string ChallengeType => "dns-01";

    public async Task<ChallengeValidationResult> ValidateAsync(
        string domain,
        string token,
        string accountThumbprint,
        CancellationToken cancellationToken = default)
    {
        // RFC 8555 §8.4: the key authorization is token.thumbprint
        var keyAuth = $"{token}.{accountThumbprint}";

        // DNS-01 stores the SHA-256 digest of the key authorization, base64url encoded
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuth));
        var expectedValue = Crypto.JwsService.Base64UrlEncode(digest);

        // For wildcards, the domain in the identifier starts with "*."
        // but the TXT record is at _acme-challenge.{base-domain} (without the "*.")
        var baseDomain = domain.StartsWith("*.", StringComparison.Ordinal)
            ? domain[2..]
            : domain;

        var queryName = $"_acme-challenge.{baseDomain}";

        try
        {
            _logger.LogDebug("DNS-01 validation: querying TXT record at {QueryName}", queryName);

            var result = await _dnsClient.QueryAsync(queryName, DnsClient.QueryType.TXT, cancellationToken: cancellationToken);

            if (result.HasError)
            {
                // A resolver error (SERVFAIL, timeout, and similar) is a transport failure,
                // not a wrong answer. Leave room to retry.
                _logger.LogWarning(
                    "DNS-01 could not resolve {Domain} (transient): {Error}",
                    domain, result.ErrorMessage);
                return ChallengeValidationResult.TransientFailure(
                    $"DNS query for {queryName} failed: {result.ErrorMessage}");
            }

            var txtRecords = result.Answers
                .TxtRecords()
                .SelectMany(txt => txt.Text)
                .ToList();

            if (txtRecords.Count == 0)
            {
                _logger.LogWarning(
                    "DNS-01 validation failed for {Domain}: no TXT records found at {QueryName}",
                    domain, queryName);
                return ChallengeValidationResult.Invalid(
                    $"No TXT records found at {queryName}.");
            }

            if (!txtRecords.Any(t => t.Trim() == expectedValue))
            {
                _logger.LogWarning(
                    "DNS-01 validation failed for {Domain}: none of the {Count} TXT records match the expected value",
                    domain, txtRecords.Count);
                return ChallengeValidationResult.Invalid(
                    $"DNS-01 TXT record at {queryName} does not contain the expected value.");
            }

            _logger.LogInformation("DNS-01 validation succeeded for {Domain}", domain);
            return ChallengeValidationResult.Success();
        }
        catch (DnsResponseException ex)
        {
            _logger.LogWarning(ex,
                "DNS-01 resolver error for {Domain} (transient)", domain);
            return ChallengeValidationResult.TransientFailure(
                $"DNS query error for {queryName}: {ex.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning("DNS-01 validation timed out for {Domain} (transient)", domain);
            return ChallengeValidationResult.TransientFailure(
                $"DNS-01 validation timed out querying {queryName}.");
        }
    }
}
