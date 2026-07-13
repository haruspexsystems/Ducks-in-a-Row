using System.Net;
using System.Runtime.InteropServices;
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
        root.GetProperty("type").GetString().Should().Be("https://ducksinarow.app/problems/ca-unavailable");
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

        public Task RevokeCertificateAsync(
            string serialNumber, int reason, CancellationToken cancellationToken = default)
            => throw Build();
    }
}
