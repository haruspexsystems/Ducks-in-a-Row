using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Models;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace Certus.Web.Tests;

/// <summary>
/// Every surface that reads the CA's template list or its certificate chain,
/// with the CA refusing the service those reads (issues #467 and #476). The
/// request interface answers an account without Request Certificates that way,
/// measured on lab 2019 (#440) and lab 2025 (#469). Before the fix the refusal
/// reached these callers as a plain failure or an unwrapped
/// UnauthorizedAccessException, so the ACME surface faulted to a bare 500 and
/// the administrator surfaces reported an unexplained error.
///
/// Two rules are pinned, and they pull opposite ways. The ACME wire answers 503
/// serviceUnavailable with a generic sentence, because the remedy names the
/// service's own computer account and any ACME account holder can read a problem
/// document. The administrator surfaces carry the remedy in full, because there
/// it is the whole value of the answer.
/// </summary>
[Trait("Category", "Integration")]
public class CaRefusedReadsIntegrationTests
{
    /// <summary>
    /// The shape AdcsClient now raises for CERTSRV_E_ENROLL_DENIED on these reads.
    /// </summary>
    private static CaAccessDeniedException Refusal(string message) =>
        new(message, new COMException("enroll denied", CaStatusCode.EnrollDenied));

    private static StringContent Json(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    /// <summary>
    /// What no ACME problem document may carry: the remedy text, which names the
    /// right to grant and the service's own account.
    /// </summary>
    private static void ShouldNotCarryTheRemedy(string body)
    {
        body.Should().NotContain("Request Certificates");
        body.Should().NotContain("service account");
    }

    /// <summary>
    /// A CA that answers nothing on these two reads but a refusal. Every other
    /// call that reaches the CA refuses as well, so a background service in this
    /// host meets the same CA the endpoints do. The connection answers "not
    /// accessible", as the other stubs in this project do.
    /// </summary>
    private sealed class RefusingAdcsClient : IAdcsClient
    {
        public IReadOnlyList<TemplateInfo>? PublishedTemplates { get; init; }

        public int ChainReads => _chainReads;

        private int _chainReads;

        public Task<CaInfo> GetCaInfoAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new CaInfo(
                Name: "stub", DnsName: "stub", DisplayName: "stub", IsAccessible: false));

        public Task<IReadOnlyList<TemplateInfo>> GetTemplatesAsync(CancellationToken cancellationToken = default)
            => PublishedTemplates is { } published
                ? Task.FromResult(published)
                : throw Refusal(CaAccessDeniedException.TemplateReadPermissionMessage);

        public Task<IReadOnlyList<byte[]>> GetCaCertificateChainAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _chainReads);
            throw Refusal(CaAccessDeniedException.ChainReadPermissionMessage);
        }

        public Task<SubmitResult> SubmitCertificateRequestAsync(
            string templateName, byte[] csrDer, CancellationToken cancellationToken = default)
            => throw Refusal(CaAccessDeniedException.EnrollPermissionMessage);

        public Task<CertificateResult> GetCertificateAsync(int requestId, CancellationToken cancellationToken = default)
            => throw Refusal(CaAccessDeniedException.CollectPermissionMessage);

        public Task<IReadOnlyList<CertificateInfo>> QueryCertificatesAsync(
            CertificateQuery query, CancellationToken cancellationToken = default)
            => throw Refusal(CaAccessDeniedException.SyncReadPermissionMessage);

        public Task<CaRequestStatus?> GetRequestStatusAsync(
            int requestId, CancellationToken cancellationToken = default)
            => throw Refusal(CaAccessDeniedException.SyncReadPermissionMessage);

        public Task RevokeCertificateAsync(
            string serialNumber, int reason, CancellationToken cancellationToken = default)
            => throw Refusal(CaAccessDeniedException.RevokePermissionMessage);
    }

    private class RefusingCaFactory : CertusWebApplicationFactory
    {
        public RefusingAdcsClient Client { get; }

        public RefusingCaFactory() : this(new RefusingAdcsClient()) { }

        protected RefusingCaFactory(RefusingAdcsClient client) => Client = client;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                var existing = services.SingleOrDefault(d => d.ServiceType == typeof(IAdcsClient));
                if (existing != null)
                    services.Remove(existing);

                services.AddSingleton<IAdcsClient>(Client);
            });
        }
    }

    /// <summary>
    /// The template list answers, so the ACME template gate passes and the
    /// issuer certificate endpoint goes on to read the chain, which is refused.
    /// </summary>
    private sealed class ChainRefusingCaFactory : RefusingCaFactory
    {
        public ChainRefusingCaFactory()
            : base(new RefusingAdcsClient
            {
                PublishedTemplates = [new TemplateInfo("WebServer", "Web Server", "1.3.6.1.4.1.311.21.8.1")],
            })
        {
        }
    }

    // ---- The ACME wire ----

    [Fact]
    public async Task AcmeDirectory_TemplateListRefused_Returns503ServiceUnavailable_WithoutTheRemedy()
    {
        using var factory = new RefusingCaFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/acme/WebServer/directory");

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var body = await response.Content.ReadAsStringAsync();
        var error = JsonSerializer.Deserialize<AcmeError>(body);
        error!.Type.Should().Be(AcmeErrorType.ServiceUnavailable);
        error.Status.Should().Be(503);
        error.Detail.Should().NotBeNullOrEmpty();
        ShouldNotCarryTheRemedy(body);
    }

    [Theory]
    [InlineData("/acme/WebServer/new-account")]
    [InlineData("/acme/WebServer/new-order")]
    public async Task AcmeTemplateResolvingPost_TemplateListRefused_Returns503WithANonce(string path)
    {
        // The issue #147 shape again: without the arm on AcmeControllerBase the
        // refusal escaped the action as a bare 500 with no problem document and
        // no nonce, and the client could not even retry cleanly.
        using var factory = new RefusingCaFactory();
        using var client = factory.CreateClient();
        using var content = new StringContent("{}", Encoding.UTF8, "application/jose+json");

        var response = await client.PostAsync(path, content);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        var body = await response.Content.ReadAsStringAsync();
        JsonSerializer.Deserialize<AcmeError>(body)!.Type
            .Should().Be(AcmeErrorType.ServiceUnavailable);
        ShouldNotCarryTheRemedy(body);
        response.Headers.Contains("Replay-Nonce").Should().BeTrue(
            "an ACME protocol response carries a nonce even when the CA refuses the service");
    }

    [Fact]
    public async Task IssuerCert_ChainRefused_Returns503_AndAsksTheCaAgainNextTime()
    {
        using var factory = new ChainRefusingCaFactory();
        using var client = factory.CreateClient();

        var first = await client.GetAsync("/acme/WebServer/issuer-cert");
        var second = await client.GetAsync("/acme/WebServer/issuer-cert");

        first.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        var body = await first.Content.ReadAsStringAsync();
        JsonSerializer.Deserialize<AcmeError>(body)!.Type
            .Should().Be(AcmeErrorType.ServiceUnavailable);
        ShouldNotCarryTheRemedy(body);

        // Not cached, like an outage: a right granted back takes effect on the
        // next request rather than an hour later.
        second.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        factory.Client.ChainReads.Should().Be(2);
    }

    // ---- The administrator surfaces ----

    [Fact]
    public async Task DashboardTemplates_TemplateListRefused_Returns503CaAccessDenied_WithTheRemedy()
    {
        using var factory = new RefusingCaFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/templates");

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
        var root = await ParseAsync(response);
        root.GetProperty("type").GetString()
            .Should().Be("https://ducksinarow.dev/problems/ca-access-denied");
        root.GetProperty("detail").GetString()
            .Should().Be(CaAccessDeniedException.TemplateReadPermissionMessage);
    }

    [Theory]
    [InlineData("/api/settings/ca-certificates")]
    [InlineData("/api/settings/ca-certificates/chain/pem")]
    [InlineData("/api/settings/ca-certificates/chain/p7b")]
    public async Task CaCertificates_ChainRefused_Returns503CaAccessDenied_WithTheRemedy(string path)
    {
        // A problem document of its own type, so the settings card can tell a
        // refusal from an outage rather than telling the administrator to try
        // again shortly, which no retry would ever fix.
        using var factory = new RefusingCaFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync(path);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
        var root = await ParseAsync(response);
        root.GetProperty("type").GetString()
            .Should().Be("https://ducksinarow.dev/problems/ca-access-denied");
        root.GetProperty("detail").GetString()
            .Should().Be(CaAccessDeniedException.ChainReadPermissionMessage);
    }

    [Fact]
    public async Task DeviceAttestationProfile_TemplateListRefused_Returns503WithTheRemedy()
    {
        // This endpoint had no arm at all, not even for an outage.
        using var factory = new RefusingCaFactory();
        using var client = factory.CreateClient();

        var response = await client.PostAsync(
            "/api/acme/device-attestation/profiles", Json(new { templateId = "WebServer" }));

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        (await ParseAsync(response)).GetProperty("error").GetString()
            .Should().Be(CaAccessDeniedException.TemplateReadPermissionMessage);
    }

    // ---- The setup wizard ----

    /// <summary>
    /// The wizard reads a candidate CA through the client factory rather than the
    /// registered client. Clearing UseMockCa gives the honest state of a wizard
    /// that has not completed, which takes the candidate CA from the request body
    /// and lets the TLS endpoints past their mock CA guard. The connection string
    /// stays empty, because StartupValidator refuses a configured CA with auth
    /// disabled (SEC-F1).
    /// </summary>
    private sealed class WizardFactory : CertusWebApplicationFactory
    {
        public X509Certificate2 Installed { get; } = CreateSelfSigned();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                services.PostConfigure<CertusOptions>(o => o.UseMockCa = false);

                var clientFactory = Substitute.For<IAdcsClientFactory>();
                clientFactory.Create(Arg.Any<string>()).Returns(_ => new RefusingAdcsClient());
                services.AddSingleton(clientFactory);
                services.AddSingleton<IHttpsCertificateStore>(new OneCertificateStore(Installed));
            });
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                Installed.Dispose();
            base.Dispose(disposing);
        }

        private static X509Certificate2 CreateSelfSigned()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=certus.contoso.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }
    }

    /// <summary>
    /// An in memory store holding one certificate, so the apply endpoint reaches
    /// the template resolution below its thumbprint lookup.
    /// </summary>
    private sealed class OneCertificateStore(X509Certificate2 certificate) : IHttpsCertificateStore
    {
        public string Install(X509Certificate2 certificateWithKey) => certificateWithKey.Thumbprint;

        public X509Certificate2? Find(string thumbprint) =>
            string.Equals(thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)
                ? X509CertificateLoader.LoadCertificate(certificate.RawData)
                : null;

        public bool Remove(string thumbprint) => false;

        public int RemoveSuperseded(string keepThumbprint) => 0;

        public IReadOnlyList<X509Certificate2> ListCertificates() =>
            [X509CertificateLoader.LoadCertificate(certificate.RawData)];
    }

    private const string CandidateCa = "ca.contoso.com\\Contoso-CA";

    [Fact]
    public async Task SetupTemplates_TemplateListRefused_Returns503WithTheRemedy()
    {
        // Before, the general arm answered "failed to retrieve templates" and the
        // administrator was told nothing about the missing right.
        using var factory = new WizardFactory();
        using var client = factory.CreateClient();

        var response = await client.PostAsync(
            "/api/setup/templates", Json(new { caConnectionString = CandidateCa }));

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        (await ParseAsync(response)).GetProperty("message").GetString()
            .Should().Be(CaAccessDeniedException.TemplateReadPermissionMessage);
    }

    [Fact]
    public async Task TlsCertificateApply_TemplateListRefused_Returns503WithTheRemedy()
    {
        // Before, this faulted to a bare 500: the endpoint had an outage arm and
        // no refusal arm, while the enrollment endpoint beside it had both.
        using var factory = new WizardFactory();
        using var client = factory.CreateClient();

        var response = await client.PostAsync("/api/setup/tls-certificate/apply", Json(new
        {
            caConnectionString = CandidateCa,
            templateName = "WebServer",
            externalUrl = "https://certus.contoso.com:5001",
            thumbprint = factory.Installed.Thumbprint,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        (await ParseAsync(response)).GetProperty("message").GetString()
            .Should().Be(CaAccessDeniedException.TemplateReadPermissionMessage);
    }

    [Fact]
    public async Task SetupComplete_TemplateListRefused_Returns503WithTheRemedy()
    {
        // This arm already existed, with nothing that could raise it from the
        // template read. It has a producer now, so it is pinned.
        using var factory = new WizardFactory();
        using var client = factory.CreateClient();

        var response = await client.PostAsync("/api/setup/complete", Json(new
        {
            caConnectionString = CandidateCa,
            enabledTemplates = new[] { "WebServer" },
            externalUrl = "https://certus.contoso.com:5001",
        }));

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        (await ParseAsync(response)).GetProperty("error").GetString()
            .Should().Be(CaAccessDeniedException.TemplateReadPermissionMessage);
    }
}
