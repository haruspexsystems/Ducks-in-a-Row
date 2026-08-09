using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using Certus.Core.Adcs;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The access denied half of the sync failure surface (issue #157). The CA is
/// reachable but refuses the certificate view, which has its own ACL separate
/// from enrollment: the manual sync endpoint must return the ca-access-denied
/// problem carrying the exact permission remediation, distinguishable from
/// ca-unavailable, and the sync status endpoint must report the outcome.
/// </summary>
[Trait("Category", "Integration")]
public class CaAccessDeniedSyncIntegrationTests
    : IClassFixture<CaAccessDeniedSyncIntegrationTests.AccessDeniedCaFactory>
{
    private readonly HttpClient _client;

    public CaAccessDeniedSyncIntegrationTests(AccessDeniedCaFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task TriggerSync_CaAccessDenied_Returns503WithRemediationDetail()
    {
        var response = await _client.PostAsync("/api/certificates/sync", null);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("status").GetInt32().Should().Be(503);
        root.GetProperty("type").GetString()
            .Should().Be("https://ducksinarow.app/problems/ca-access-denied");
        // The reader's fix differs from the unreachable case, so the exact
        // remediation text must flow through to the problem detail.
        root.GetProperty("detail").GetString()
            .Should().Be(CaAccessDeniedException.SyncReadPermissionMessage);
    }

    [Fact]
    public async Task SyncStatus_AfterDeniedSync_ReportsCaAccessDenied()
    {
        await _client.PostAsync("/api/certificates/sync", null);

        var response = await _client.GetAsync("/api/certificates/sync-status");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("failed").GetBoolean().Should().BeTrue();
        root.GetProperty("lastOutcome").GetString().Should().Be("caAccessDenied");
        root.GetProperty("lastMessage").GetString().Should().Contain("Grant 'Read'");
        root.GetProperty("lastSuccess").ValueKind.Should().Be(JsonValueKind.Null);
    }

    /// <summary>
    /// Test factory that replaces IAdcsClient with a stub whose CA facing
    /// calls are denied, the shape AdcsClient raises when the CA view ACL
    /// excludes the service account.
    /// </summary>
    public sealed class AccessDeniedCaFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existing = services.SingleOrDefault(d => d.ServiceType == typeof(IAdcsClient));
                if (existing != null)
                    services.Remove(existing);

                services.AddSingleton<IAdcsClient>(new AccessDeniedCaAdcsClient());
            });
        }
    }

    /// <summary>
    /// Stub IAdcsClient where every CA facing call throws CaAccessDeniedException
    /// with the sync remediation message and an E_ACCESSDENIED COMException inner.
    /// </summary>
    private sealed class AccessDeniedCaAdcsClient : IAdcsClient
    {
        private static CaAccessDeniedException Build()
            => new(CaAccessDeniedException.SyncReadPermissionMessage,
                new COMException("access denied",
                    CaAccessDeniedException.AccessDeniedHResult));

        public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new CaInfo(
                Name: "stub",
                DnsName: "stub",
                DisplayName: "stub",
                IsAccessible: false));

        public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
            => throw Build();

        public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
            => throw Build();

        public Task<SubmitResult> SubmitCertificateRequestAsync(
            string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
            => throw Build();

        public Task<CertificateResult> GetCertificateAsync(int requestId, CancellationToken cancellationToken = default)
            => throw Build();

        public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
            CertificateQuery query, CancellationToken cancellationToken = default)
            => throw Build();

        public Task RevokeCertificateAsync(
            string serialNumber, int reason, CancellationToken cancellationToken = default)
            => throw Build();
    }
}
