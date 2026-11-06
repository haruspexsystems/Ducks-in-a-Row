using System.Text.Json;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Data;
using Certus.Core.Modules;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Certus.Service.Tests.Modules;

/// <summary>
/// Licence alerts on the real service host (issue #494): the module's notice crosses the module
/// host, the hosted <see cref="LicenceAlertService"/> sends it through the real webhook notifier,
/// signed, with none of the module's free text, and records it once. Monitor mode sends it too,
/// because a licence alert is not a write to the CA.
/// </summary>
public class LicenceAlertHostTests
{
    [Theory]
    [InlineData(CertusInstanceMode.FullValue)]
    [InlineData(CertusInstanceMode.MonitorValue)]
    public async Task ADueNotice_IsPostedOnce_SignedAndWithoutTheLicensee(string mode)
    {
        var receiver = new RecordingWebhookHandler();
        using var factory = new ModuleScenarioHostFactory(
            ModuleScenario.Valid,
            new NoticeModule(),
            configure: builder =>
            {
                builder.UseSetting("Certus:Alerts:Webhook:Url", "https://hooks.test.invalid/hook");
                builder.UseSetting("Certus:Alerts:Webhook:Secret", "test-signing-secret");
                // Both other monitors off, so nothing else posts at the receiver. The certificate
                // monitor's switch being off also shows it does not silence licence alerts.
                builder.UseSetting("Certus:Alerts:Enabled", "false");
                builder.UseSetting("Certus:Alerts:Crl:Enabled", "false");
                builder.ConfigureServices(services =>
                    services.AddHttpClient(nameof(WebhookAlertNotifier))
                        .ConfigurePrimaryHttpMessageHandler(() => receiver));
            },
            instanceMode: mode);
        _ = factory.Server;

        var source = factory.Services.GetRequiredService<ILicenceStatusSource>();
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
        while (source.Current.Licence is null && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        source.Current.ModuleState.Should().Be(ModuleState.Loaded);

        var service = factory.Services.GetServices<IHostedService>().OfType<LicenceAlertService>().Single();
        await service.CheckAsync();
        await service.CheckAsync();

        var licencePosts = receiver.Bodies
            .Select(b => JsonDocument.Parse(b).RootElement)
            .Where(p => p.GetProperty("event").GetString()!.StartsWith("licence.", StringComparison.Ordinal))
            .ToList();
        var payload = licencePosts.Should().ContainSingle().Which;
        payload.GetProperty("event").GetString().Should().Be("licence.expiring");
        payload.GetProperty("stage").GetString().Should().Be(LicenceAlertStages.Days7);
        payload.GetProperty("licenceId").GetString().Should().Be(NoticeModule.LicenceId);
        receiver.Bodies.Should().NotContain(b => b.Contains(NoticeModule.Licensee));
        receiver.Signatures.Should().OnlyContain(s => s != null && s.StartsWith("sha256="));

        using var scope = factory.Services.CreateScope();
        var rows = await scope.ServiceProvider.GetRequiredService<CertusDbContext>().LicenceAlertsSent.ToListAsync();
        rows.Should().ContainSingle().Which.Channels.Should().Be("webhook");
    }

    /// <summary>The stand in for the operator's webhook endpoint.</summary>
    private sealed class RecordingWebhookHandler : HttpMessageHandler
    {
        private readonly object _lock = new();
        private readonly List<string> _bodies = [];
        private readonly List<string?> _signatures = [];

        public IReadOnlyList<string> Bodies
        {
            get { lock (_lock) return [.. _bodies]; }
        }

        public IReadOnlyList<string?> Signatures
        {
            get { lock (_lock) return [.. _signatures]; }
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            var signature = request.Headers.TryGetValues("X-Certus-Signature", out var values)
                ? string.Join(",", values)
                : null;

            lock (_lock)
            {
                _bodies.Add(body);
                _signatures.Add(signature);
            }

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        }
    }
}
