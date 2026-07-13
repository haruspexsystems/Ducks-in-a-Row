using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Alerts;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Alerts;

public class WebhookAlertNotifierTests
{
    private static ExpiryAlertBatch CreateTestBatch(int thresholdDays = 30) => new(
        thresholdDays,
        [
            new CertificateExpiryInfo(1, "CN=test.example.com", "SERIAL001", "WebServer",
                DateTime.UtcNow.AddDays(25), 25)
        ]);

    [Fact]
    public async Task SendAlert_PostsJsonToWebhookUrl()
    {
        string? capturedBody = null;
        string? capturedUrl = null;

        var handler = new MockHttpHandler((request) =>
        {
            capturedUrl = request.RequestUri?.ToString();
            capturedBody = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });

        var client = new HttpClient(handler);
        var sut = new WebhookAlertNotifier(options, client, NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeTrue();
        capturedUrl.Should().Be("https://hooks.example.com/alerts");
        capturedBody.Should().NotBeNullOrEmpty();

        var payload = JsonSerializer.Deserialize<JsonElement>(capturedBody!);
        payload.GetProperty("event").GetString().Should().Be("certificate.expiring");
        payload.GetProperty("thresholdDays").GetInt32().Should().Be(30);
        payload.GetProperty("certificateCount").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task SendAlert_WithSecret_IncludesHmacSignature()
    {
        string? signatureHeader = null;
        string? body = null;

        var handler = new MockHttpHandler((request) =>
        {
            signatureHeader = request.Headers.TryGetValues("X-Certus-Signature", out var values)
                ? values.First() : null;
            body = request.Content?.ReadAsStringAsync().Result;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var secret = "my-webhook-secret";
        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts", Secret = secret }
        });

        var client = new HttpClient(handler);
        var sut = new WebhookAlertNotifier(options, client, NullLogger<WebhookAlertNotifier>.Instance);

        await sut.SendExpiryAlertAsync(CreateTestBatch());

        signatureHeader.Should().NotBeNull();
        signatureHeader.Should().StartWith("sha256=");

        // Verify HMAC
        var expectedHash = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(secret),
            Encoding.UTF8.GetBytes(body!));
        var expected = $"sha256={Convert.ToHexString(expectedHash).ToLowerInvariant()}";
        signatureHeader.Should().Be(expected);
    }

    [Fact]
    public async Task SendAlert_WebhookReturnsError_ReturnsFailure()
    {
        var handler = new MockHttpHandler((_) =>
            new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("Internal Server Error")
            });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });

        var client = new HttpClient(handler);
        var sut = new WebhookAlertNotifier(options, client, NullLogger<WebhookAlertNotifier>.Instance);

        var result = await sut.SendExpiryAlertAsync(CreateTestBatch());

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("500");
    }

    [Fact]
    public async Task SendAlert_WithCustomHeaders_IncludesHeaders()
    {
        string? customHeader = null;

        var handler = new MockHttpHandler((request) =>
        {
            customHeader = request.Headers.TryGetValues("X-Custom-Token", out var values)
                ? values.First() : null;
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions
            {
                Url = "https://hooks.example.com/alerts",
                Headers = new Dictionary<string, string>
                {
                    ["X-Custom-Token"] = "bearer-token-123"
                }
            }
        });

        var client = new HttpClient(handler);
        var sut = new WebhookAlertNotifier(options, client, NullLogger<WebhookAlertNotifier>.Instance);

        await sut.SendExpiryAlertAsync(CreateTestBatch());

        customHeader.Should().Be("bearer-token-123");
    }

    [Fact]
    public void IsEnabled_WithoutUrl_ReturnsFalse()
    {
        var options = Options.Create(new AlertOptions { Webhook = null });
        var sut = new WebhookAlertNotifier(options, new HttpClient(), NullLogger<WebhookAlertNotifier>.Instance);

        sut.IsEnabled.Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_WithUrl_ReturnsTrue()
    {
        var options = Options.Create(new AlertOptions
        {
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/alerts" }
        });
        var sut = new WebhookAlertNotifier(options, new HttpClient(), NullLogger<WebhookAlertNotifier>.Instance);

        sut.IsEnabled.Should().BeTrue();
    }

    /// <summary>Simple mock HTTP handler for testing.</summary>
    private class MockHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public MockHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request));
        }
    }
}
