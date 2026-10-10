using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Certus.Core.Crl;
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
        return await PostAsync(
            BuildPayload(batch),
            $"{batch.Certificates.Count} certificates ({batch.ThresholdDays}-day threshold)",
            cancellationToken);
    }

    public async Task<AlertNotificationResult> SendServerCertificateAlertAsync(
        ServerCertificateAlert alert,
        CancellationToken cancellationToken = default)
    {
        var payload = new ServerCertificateWebhookPayload
        {
            Event = "server.certificate.renewal_failed",
            Outcome = alert.Outcome,
            Detail = alert.Detail,
            TemplateName = alert.Template,
            DaysRemaining = alert.DaysRemaining,
            Timestamp = DateTime.UtcNow,
        };

        return await PostAsync(payload, $"server certificate renewal ({alert.Outcome})", cancellationToken);
    }

    /// <summary>
    /// The CRL POST (issue #447).
    ///
    /// A distinct event per stage rather than one event with a field, matching
    /// the two events already here: a receiver routes on the event name, and
    /// "this CRL expired an hour ago" and "this CRL expires in thirty days" are
    /// not the same page of a runbook.
    /// </summary>
    public async Task<AlertNotificationResult> SendCrlAlertAsync(
        CrlAlert alert,
        CancellationToken cancellationToken = default)
    {
        var payload = new CrlWebhookPayload
        {
            Event = alert.Stage switch
            {
                CrlAlertRules.ExpiredStage => "crl.expired",
                CrlAlertRules.OverdueStage => "crl.overdue",
                _ => "crl.expiring",
            },
            Stage = alert.Stage,
            IssuerName = alert.IssuerName,
            Kind = alert.Kind,
            Scope = alert.Scope,
            CrlNumber = alert.CrlNumber,
            NewerCrlNumber = alert.NewerCrlNumber,
            NextUpdate = alert.NextUpdate,
            HoursRemaining = Math.Round(alert.HoursRemaining, 1),
            Sources = [.. alert.Sources],
            LastReadAt = alert.LastReadAt,
            Timestamp = DateTime.UtcNow,
        };

        return await PostAsync(
            payload, $"the {alert.Stage} CRL warning for {alert.IssuerName}", cancellationToken);
    }

    /// <summary>
    /// The operator triggered test POST (issue #161).
    ///
    /// It deliberately goes through the same PostAsync as a real alert, so the
    /// HMAC signature, the custom headers, and the timeout are provably the ones
    /// a real alert would use. A test that took a shortcut would prove nothing
    /// about the path it is supposed to be testing.
    ///
    /// The triggering account is not in the payload. See the TestAlert doc: this
    /// body goes to a third party endpoint.
    /// </summary>
    public async Task<AlertNotificationResult> SendTestAlertAsync(
        TestAlert alert,
        CancellationToken cancellationToken = default)
    {
        var payload = new TestWebhookPayload
        {
            Event = "test.alert",
            Test = true,
            Message =
                "Test alert from Ducks in a Row. No certificate is expiring and no action is needed.",
            Timestamp = alert.TriggeredAtUtc,
        };

        return await PostAsync(payload, "a test alert", cancellationToken);
    }

    /// <summary>
    /// Serialize, sign, and POST a payload. Shared by both alert kinds so the
    /// HMAC signature, the custom headers, and the failure reporting stay
    /// identical whatever is being delivered.
    /// </summary>
    private async Task<AlertNotificationResult> PostAsync(
        object payload, string description, CancellationToken cancellationToken)
    {
        var webhook = _options.Webhook;
        if (webhook == null || !IsEnabled)
            return new AlertNotificationResult(false, "Webhook not configured");

        try
        {
            var json = JsonSerializer.Serialize(payload, payload.GetType(), JsonOptions);

            var request = new HttpRequestMessage(HttpMethod.Post, webhook.Url)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };

            if (!string.IsNullOrEmpty(webhook.Secret))
            {
                var signature = ComputeHmacSha256(json, webhook.Secret);
                request.Headers.Add("X-Certus-Signature", $"sha256={signature}");
            }

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
                "Webhook alert sent for {Description} to {Url}", description, webhook.Url);

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

/// <summary>
/// The server's own certificate carries no inventory identity (it is not a row
/// in the certificate table as far as this alert is concerned), so it gets its
/// own event name and shape rather than being squeezed into the expiry payload.
/// </summary>
internal sealed class ServerCertificateWebhookPayload
{
    public string Event { get; set; } = string.Empty;
    public string Outcome { get; set; } = string.Empty;
    public string? Detail { get; set; }
    public string? TemplateName { get; set; }
    public int? DaysRemaining { get; set; }
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// The CRL payload. Like the server certificate one, its subject is not a row in
/// the certificate inventory, so it carries no certificate id and no serial: a
/// CRL is identified by who signed it and by its own number.
///
/// <see cref="Sources"/> is the list of places this CRL is served from, and
/// <see cref="NewerCrlNumber"/> is set when a newer one is being served
/// somewhere else. Together they are what tells a receiver that a renewal
/// reached one location and not another, which is the commonest way a root CRL
/// renewal goes wrong.
/// </summary>
internal sealed class CrlWebhookPayload
{
    public string Event { get; set; } = string.Empty;
    public string Stage { get; set; } = string.Empty;
    public string IssuerName { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string? CrlNumber { get; set; }
    public string? NewerCrlNumber { get; set; }
    public DateTime NextUpdate { get; set; }
    public double HoursRemaining { get; set; }
    public List<string> Sources { get; set; } = [];
    public DateTime? LastReadAt { get; set; }
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// The test payload. It carries no certificate list at all, which is the whole
/// point: a receiver that blindly iterates certificates will fail on it rather
/// than file a fake expiry warning.
///
/// <see cref="Test"/> is redundant with the event name and is there anyway, so a
/// receiver can filter on one obvious boolean instead of string matching event
/// names it may not have been written to expect.
/// </summary>
internal sealed class TestWebhookPayload
{
    public string Event { get; set; } = string.Empty;
    public bool Test { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}
