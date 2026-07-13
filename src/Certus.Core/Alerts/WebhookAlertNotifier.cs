using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Certus.Core.Alerts;

/// <summary>
/// Sends certificate expiry alert notifications via HTTP POST webhook.
/// Supports optional HMAC-SHA256 signature in X-Certus-Signature header.
/// </summary>
public sealed class WebhookAlertNotifier : IAlertNotifier
{
    private readonly AlertOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILogger<WebhookAlertNotifier> _logger;

    public string Channel => "webhook";

    public bool IsEnabled =>
        _options.Webhook is { Url.Length: > 0 };

    public WebhookAlertNotifier(
        IOptions<AlertOptions> options,
        HttpClient httpClient,
        ILogger<WebhookAlertNotifier> logger)
    {
        _options = options.Value;
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<AlertNotificationResult> SendExpiryAlertAsync(
        ExpiryAlertBatch batch,
        CancellationToken cancellationToken = default)
    {
        var webhook = _options.Webhook;
        if (webhook == null || !IsEnabled)
            return new AlertNotificationResult(false, "Webhook not configured");

        try
        {
            var payload = BuildPayload(batch);
            var json = JsonSerializer.Serialize(payload, JsonOptions);

            var request = new HttpRequestMessage(HttpMethod.Post, webhook.Url)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };

            // Add HMAC signature if secret is configured
            if (!string.IsNullOrEmpty(webhook.Secret))
            {
                var signature = ComputeHmacSha256(json, webhook.Secret);
                request.Headers.Add("X-Certus-Signature", $"sha256={signature}");
            }

            // Add custom headers
            foreach (var (key, value) in webhook.Headers)
            {
                request.Headers.TryAddWithoutValidation(key, value);
            }

            var response = await _httpClient.SendAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
                var error = $"Webhook returned {(int)response.StatusCode}: {responseBody}";
                _logger.LogWarning("Webhook alert failed: {Error}", error);
                return new AlertNotificationResult(false, error);
            }

            _logger.LogInformation(
                "Webhook alert sent for {Count} certificates ({Threshold}-day threshold) to {Url}",
                batch.Certificates.Count, batch.ThresholdDays, webhook.Url);

            return new AlertNotificationResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send webhook alert");
            return new AlertNotificationResult(false, ex.Message);
        }
    }

    private static WebhookPayload BuildPayload(ExpiryAlertBatch batch)
    {
        return new WebhookPayload
        {
            Event = "certificate.expiring",
            ThresholdDays = batch.ThresholdDays,
            CertificateCount = batch.Certificates.Count,
            Certificates = batch.Certificates.Select(c => new WebhookCertificate
            {
                CertificateId = c.CertificateId,
                Subject = c.Subject,
                SerialNumber = c.SerialNumber,
                TemplateName = c.TemplateName,
                NotAfter = c.NotAfter,
                DaysRemaining = c.DaysRemaining,
            }).ToList(),
            Timestamp = DateTime.UtcNow,
        };
    }

    private static string ComputeHmacSha256(string payload, string secret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var hash = HMACSHA256.HashData(keyBytes, payloadBytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

// Webhook JSON payload DTOs
internal sealed class WebhookPayload
{
    public string Event { get; set; } = string.Empty;
    public int ThresholdDays { get; set; }
    public int CertificateCount { get; set; }
    public List<WebhookCertificate> Certificates { get; set; } = [];
    public DateTime Timestamp { get; set; }
}

internal sealed class WebhookCertificate
{
    public int CertificateId { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string TemplateName { get; set; } = string.Empty;
    public DateTime NotAfter { get; set; }
    public int DaysRemaining { get; set; }
}
