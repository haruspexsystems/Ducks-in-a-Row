using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace Certus.Web.Tests;

/// <summary>
/// The setup wizard against a settings.json it cannot write to (issue #553). Since
/// issue #550 a save keeps the administrator's own keys, and refuses one that would
/// then set a key twice: a key the service manages written by hand in the colon form
/// at the top level, the way docs/hardening.md writes nested keys. Two things went
/// wrong with that refusal in the wizard, and these pin both.
///
/// <list type="bullet">
///   <item>The TLS step enrolled first and recorded afterwards, so the refusal came
///   after the CA had issued a certificate and the store had installed it, with
///   nothing naming it. It asks the overlay before enrolling now.</item>
///   <item>No wizard endpoint caught the refusal, so it surfaced as a bare 500, from
///   the last step among others. Each answers with the file named now.</item>
/// </list>
///
/// The factory runs the wizard against a stand in CA rather than the mock, for the
/// reason TlsCertificateTemplateInjectionIntegrationTests gives: the TLS endpoints
/// refuse the mock CA outright. The stand in records every submit, which is how
/// "nothing was enrolled" is asserted rather than inferred.
/// </summary>
[Trait("Category", "Integration")]
public class SetupOverlayRefusalIntegrationTests : IDisposable
{
    private const string CaConnectionString = "ca.contoso.com\\Contoso-CA";
    private const string ExternalUrl = "https://certus.contoso.com:5001";

    /// <summary>
    /// The machine store, in memory: it counts installs, and holds one certificate the
    /// apply endpoint can find by thumbprint.
    /// </summary>
    private sealed class CountingCertificateStore : IHttpsCertificateStore
    {
        private readonly X509Certificate2 _certificate = CreateSelfSignedCertificate();

        public int Installs { get; private set; }

        public string Thumbprint => _certificate.Thumbprint;

        public string Install(X509Certificate2 certificateWithKey)
        {
            Installs++;
            return certificateWithKey.Thumbprint;
        }

        public X509Certificate2? Find(string thumbprint) =>
            string.Equals(thumbprint, _certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)
                ? X509CertificateLoader.LoadCertificate(_certificate.RawData)
                : null;

        public bool Remove(string thumbprint) => false;

        public int RemoveSuperseded(string keepThumbprint) => 0;

        public IReadOnlyList<X509Certificate2> ListCertificates() =>
            [X509CertificateLoader.LoadCertificate(_certificate.RawData)];

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

    private sealed class Factory : CertusWebApplicationFactory
    {
        public IAdcsClient Ca { get; } = Substitute.For<IAdcsClient>();

        public CountingCertificateStore Store { get; } = new();

        public string DataDir => TempDataDir;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            // The CA publishes the template the wizard picks, and denies whatever is
            // submitted: a submit is the thing under test, and a denial is the
            // cheapest answer that proves one happened.
            Ca.GetTemplatesAsync(Arg.Any<CancellationToken>())
                .Returns(new List<TemplateInfo> { new("WebServer", "Web Server", "1.3.6.1.4.1.311.21.8.1") });
            Ca.SubmitCertificateRequestAsync(Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
                .Returns(new SubmitResult(0, SubmitStatus.Denied, "Denied by Policy Module"));

            var clientFactory = Substitute.For<IAdcsClientFactory>();
            clientFactory.Create(Arg.Any<string>()).Returns(Ca);

            builder.ConfigureServices(services =>
            {
                // Out of mock mode, into the unconfigured state the wizard runs in,
                // as TlsCertificateTemplateInjectionIntegrationTests explains.
                services.PostConfigure<CertusOptions>(o => o.UseMockCa = false);
                services.AddSingleton(clientFactory);
                services.AddSingleton<IHttpsCertificateStore>(Store);
            });
        }
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public SetupOverlayRefusalIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
        GC.SuppressFinalize(this);
    }

    private string OverlayPath => Path.Combine(_factory.DataDir, CertusPaths.SettingsOverlayFileName);

    /// <summary>
    /// Write settings.json by hand, once the host is up, so the host's own startup
    /// read is not what is being tested.
    /// </summary>
    private void WriteOverlay(string json) => File.WriteAllText(OverlayPath, json);

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    private Task<HttpResponseMessage> ProvisionAsync() =>
        _client.PostAsync("/api/setup/tls-certificate", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            templateName = "WebServer",
            externalUrl = ExternalUrl,
        }));

    [Fact]
    public async Task Provision_OverlayThatWouldRefuseTheRecord_RefusesBeforeEnrolling()
    {
        const string handEdited = """{ "Certus:HttpsCertificateTemplate": "WebServer" }""";
        WriteOverlay(handEdited);

        var response = await ProvisionAsync();

        // A failed outcome, the shape the wizard shows the message of.
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("outcome").GetString().Should().Be("failed");
        var message = body.GetProperty("message").GetString();
        message.Should().Contain("Certus:HttpsCertificateTemplate", "the key is what the administrator has to fix");
        message.Should().Contain("Nothing was enrolled");

        await _factory.Ca.DidNotReceiveWithAnyArgs()
            .SubmitCertificateRequestAsync(default!, default!, default);
        _factory.Store.Installs.Should().Be(0);
        File.ReadAllText(OverlayPath).Should().Be(handEdited);
    }

    [Fact]
    public async Task Provision_ColonFormKeyTheRecordDoesNotWrite_StillEnrolls()
    {
        // The control: a hand key in the colon form is legitimate (issue #550) and
        // must not block the step, only one the record would set twice.
        WriteOverlay("""{ "Certus:Acme:ChallengeValidation": { "BlockPrivateRanges": true } }""");

        var response = await ProvisionAsync();

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ParseJsonAsync(response)).GetProperty("outcome").GetString().Should().Be("denied");
        await _factory.Ca.Received(1).SubmitCertificateRequestAsync(
            "WebServer", Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Apply_OverlayThatRefusesTheRecord_NamesTheFileInsteadOfABare500()
    {
        WriteOverlay("""{ "Certus:HttpsCertificateThumbprint": "AA11BB22" }""");

        var response = await _client.PostAsync("/api/setup/tls-certificate/apply", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            templateName = "WebServer",
            externalUrl = ExternalUrl,
            thumbprint = _factory.Store.Thumbprint,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        var error = (await ParseJsonAsync(response)).GetProperty("error").GetString();
        error.Should().Contain(OverlayPath);
        SettingsOverlay.Load(OverlayPath).HttpsCertificateThumbprint.Should().BeNull();
    }

    [Fact]
    public async Task Complete_OverlayThatRefusesTheChange_NamesTheFileAndLeavesSetupOpen()
    {
        // The wizard's last step writes the external URL, so a hand written top level
        // "Certus:ExternalUrl" sets that key twice.
        const string handEdited = """{ "Certus:ExternalUrl": "https://hand.contoso.com" }""";
        WriteOverlay(handEdited);

        var response = await _client.PostAsync("/api/setup/complete", JsonContent(new
        {
            caConnectionString = CaConnectionString,
            enabledTemplates = new[] { "WebServer" },
            externalUrl = ExternalUrl,
            confirmUnreachableExternalUrl = true,
        }));

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        var error = (await ParseJsonAsync(response)).GetProperty("error").GetString();
        error.Should().Contain(OverlayPath, "the wizard shows this string, and the file is what to fix");

        File.ReadAllText(OverlayPath).Should().Be(handEdited);
        SetupStatus.Load(Path.Combine(_factory.DataDir, SetupStatus.FileName))
            .SetupCompleted.Should().BeFalse("nothing is recorded when the overlay write is refused");
    }
}
