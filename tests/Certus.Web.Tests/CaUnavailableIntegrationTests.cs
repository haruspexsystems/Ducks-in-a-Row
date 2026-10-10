using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Adcs;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Verifies that endpoints which depend on the ADCS CA return HTTP 503
/// with an application/problem+json body when the CA RPC is unavailable.
/// Regression coverage for issue #2 failure category 3.
/// </summary>
[Trait("Category", "Integration")]
public class CaUnavailableIntegrationTests : IClassFixture<CaUnavailableIntegrationTests.UnavailableCaFactory>
{
    private readonly HttpClient _client;

    public CaUnavailableIntegrationTests(UnavailableCaFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Templates_CaUnavailable_Returns503ProblemJson()
    {
        var response = await _client.GetAsync("/api/templates");

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("status").GetInt32().Should().Be(503);
        root.GetProperty("title").GetString().Should().NotBeNullOrEmpty();
        root.GetProperty("type").GetString().Should().Be("https://ducksinarow.dev/problems/ca-unavailable");
        root.GetProperty("detail").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task AcmeDirectory_CaUnavailable_Returns503ServiceUnavailableUrn()
    {
        var response = await _client.GetAsync("/acme/WebServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var json = await response.Content.ReadAsStringAsync();
        var error = JsonSerializer.Deserialize<AcmeError>(json);

        error.Should().NotBeNull();
        error!.Type.Should().Be(AcmeErrorType.ServiceUnavailable);
        error.Type.Should().Be("urn:ietf:params:acme:error:serviceUnavailable");
        error.Status.Should().Be(503);
        error.Detail.Should().NotBeNullOrEmpty();
    }

    [Theory]
    [InlineData("/acme/WebServer/new-account")]
    [InlineData("/acme/WebServer/new-order")]
    public async Task AcmeTemplateResolvingPost_CaUnavailable_Returns503ServiceUnavailableUrn(
        string path)
    {
        // Both resolve the template before they read the JWS, so they hit the
        // CA first. Until issue #147 only the directory guarded that call and
        // these two faulted to a bare 500 with no problem document and no
        // nonce; the guard now lives on AcmeControllerBase for all three.
        var content = new StringContent("{}", Encoding.UTF8, "application/jose+json");
        var response = await _client.PostAsync(path, content);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());

        error.Should().NotBeNull();
        error!.Type.Should().Be(AcmeErrorType.ServiceUnavailable);
        error.Status.Should().Be(503);
        error.Detail.Should().NotBeNullOrEmpty();

        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "an ACME protocol response carries a nonce even when the CA is down");
    }

    [Fact]
    public async Task TriggerSync_CaUnavailable_Returns503CaUnavailableProblem()
    {
        // Regression proof for issue #157: before it, the per pass catch inside
        // the sync swallowed the CA failure and this POST returned 200 with
        // zero counts, so the dashboard could not tell a down CA from an empty
        // one.
        var response = await _client.PostAsync("/api/certificates/sync", null);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("status").GetInt32().Should().Be(503);
        root.GetProperty("type").GetString().Should().Be("https://ducksinarow.dev/problems/ca-unavailable");
        root.GetProperty("title").GetString().Should().NotBeNullOrEmpty();
        root.GetProperty("detail").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task SyncStatus_AfterFailedSync_ReportsCaUnavailable()
    {
        // Self ordering: run the failing sync first, then read the status.
        // The background loop in this factory can only ever fail the same way,
        // so no success can sneak in between the two calls.
        await _client.PostAsync("/api/certificates/sync", null);

        var response = await _client.GetAsync("/api/certificates/sync-status");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("failed").GetBoolean().Should().BeTrue();
        root.GetProperty("lastOutcome").GetString().Should().Be("caUnavailable");
        root.GetProperty("lastAttemptAt").GetDateTime()
            .Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(2));
        root.GetProperty("lastSuccess").ValueKind.Should().Be(JsonValueKind.Null);
        root.GetProperty("caMode").GetString().Should().Be("mock");
        root.GetProperty("caName").ValueKind.Should().Be(JsonValueKind.Null);
    }

    /// <summary>
    /// Test factory that replaces IAdcsClient with a stub which simulates
    /// the lab CA's RPC_S_SERVER_UNAVAILABLE failure on every call.
    /// </summary>
    public sealed class UnavailableCaFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existing = services.SingleOrDefault(d => d.ServiceType == typeof(IAdcsClient));
                if (existing != null)
                    services.Remove(existing);

                services.AddSingleton<IAdcsClient>(new UnavailableCaAdcsClient());
            });
        }
    }

    /// <summary>
    /// Stub IAdcsClient where every call throws a CaUnavailableException
    /// wrapping a COMException with HRESULT 0x800706BA (RPC_S_SERVER_UNAVAILABLE).
    /// </summary>
    private sealed class UnavailableCaAdcsClient : IAdcsClient
    {
        private static CaUnavailableException Build()
            => new("simulated CA outage",
                new COMException("RPC server unavailable",
                    CaUnavailableException.RpcServerUnavailableHResult));

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

        public Task<CaRequestStatus?> GetRequestStatusAsync(
            int requestId, CancellationToken cancellationToken = default)
            => throw Build();

        public Task RevokeCertificateAsync(
            string serialNumber, int reason, CancellationToken cancellationToken = default)
            => throw Build();
    }
}
