using System.Net;
using System.Text.Json;
using Certus.Core.Adcs;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// GET /api/certificates/sync-status, the never synced half (issue #157). The
/// page headers read the connected CA and the most recent sync outcome from
/// here, and an install that has never synced must read as unknown rather
/// than as a fabricated timestamp.
///
/// Uses a dedicated factory whose CA client parks every certificate query on
/// an infinite delay: the background sync loop's first tick (5 seconds after
/// start) can then never complete or fail, so "never synced" is deterministic
/// regardless of test timing. Host shutdown cancels the delay and the loop
/// absorbs the OperationCanceledException.
/// </summary>
[Trait("Category", "Integration")]
public class SyncStatusNeverSyncedTests : IClassFixture<SyncStatusNeverSyncedTests.SlowCaFactory>
{
    private readonly HttpClient _client;

    public SyncStatusNeverSyncedTests(SlowCaFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task SyncStatus_BeforeAnySync_ReportsNeverSynced()
    {
        var response = await _client.GetAsync("/api/certificates/sync-status");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("lastAttemptAt").ValueKind.Should().Be(JsonValueKind.Null);
        root.GetProperty("lastOutcome").ValueKind.Should().Be(JsonValueKind.Null);
        root.GetProperty("lastMessage").ValueKind.Should().Be(JsonValueKind.Null);
        root.GetProperty("failed").GetBoolean().Should().BeFalse();
        root.GetProperty("lastSuccess").ValueKind.Should().Be(JsonValueKind.Null);
        root.GetProperty("caMode").GetString().Should().Be("mock");
        root.GetProperty("caName").ValueKind.Should().Be(JsonValueKind.Null);
    }

    public sealed class SlowCaFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existing = services.SingleOrDefault(d => d.ServiceType == typeof(IAdcsClient));
                if (existing != null)
                    services.Remove(existing);

                services.AddSingleton<IAdcsClient>(new NeverCompletingCaAdcsClient());
            });
        }
    }

    /// <summary>
    /// Stub IAdcsClient whose certificate query never completes until the
    /// token cancels. Nothing else in this fixture touches the CA, so the
    /// remaining members refuse loudly rather than fake an answer.
    /// </summary>
    private sealed class NeverCompletingCaAdcsClient : IAdcsClient
    {
        public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new CaInfo(
                Name: "stub",
                DnsName: "stub",
                DisplayName: "stub",
                IsAccessible: false));

        public async Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
            CertificateQuery query, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return Array.Empty<CertificateInfo>();
        }

        public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("not used by this fixture");

        public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("not used by this fixture");

        public Task<SubmitResult> SubmitCertificateRequestAsync(
            string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("not used by this fixture");

        public Task<CertificateResult> GetCertificateAsync(int requestId, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("not used by this fixture");

        public Task RevokeCertificateAsync(
            string serialNumber, int reason, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("not used by this fixture");
    }
}

/// <summary>
/// The success half: after a completed manual sync the status endpoint must
/// report the outcome, its timestamp, and its counts. Runs on the default
/// mock CA factory, isolated from the shared seeded collection.
/// </summary>
[Trait("Category", "Integration")]
public class SyncStatusAfterSuccessTests : IClassFixture<CertusWebApplicationFactory>
{
    private readonly HttpClient _client;

    public SyncStatusAfterSuccessTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task SyncStatus_AfterManualSync_ReportsSuccessWithTimestampAndCounts()
    {
        var sync = await _client.PostAsync("/api/certificates/sync", null);
        sync.StatusCode.Should().Be(HttpStatusCode.OK);

        var response = await _client.GetAsync("/api/certificates/sync-status");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("failed").GetBoolean().Should().BeFalse();
        root.GetProperty("lastOutcome").GetString().Should().Be("success");
        root.GetProperty("lastAttemptAt").GetDateTime()
            .Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(2));

        var success = root.GetProperty("lastSuccess");
        success.ValueKind.Should().Be(JsonValueKind.Object);
        success.GetProperty("completedAtUtc").GetDateTime()
            .Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(2));
        var processed = success.GetProperty("processed").GetInt32();
        (success.GetProperty("created").GetInt32() + success.GetProperty("updated").GetInt32())
            .Should().Be(processed);
    }
}
