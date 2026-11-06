using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests.MonitorMode;

/// <summary>
/// The monitor mode wizard's choice of a certificate already in the machine store
/// (issue #471). Monitor mode never enrols the server's own certificate, so this is
/// how it gets a trusted one. A factory per test, because a choice writes the draft
/// and the overlay.
/// </summary>
[Trait("Category", "Integration")]
public class ExistingCertificateIntegrationTests : IDisposable
{
    private const string Ca = "ca.contoso.com\\Contoso-CA";
    private const string ExternalUrl = "https://web01.corp.example.com:5001";

    /// <summary>A machine store double holding whatever the test minted.</summary>
    internal sealed class ListStore : IHttpsCertificateStore
    {
        public List<X509Certificate2> Certificates { get; } = [];

        public string Install(X509Certificate2 certificateWithKey) =>
            throw new NotSupportedException("The monitor mode wizard never installs a certificate.");

        public X509Certificate2? Find(string thumbprint) =>
            Certificates
                .Where(c => string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                .Select(c => X509CertificateLoader.LoadCertificate(c.RawData))
                .FirstOrDefault();

        public bool Remove(string thumbprint) => false;

        public int RemoveSuperseded(string keepThumbprint) => 0;

        // Copies that keep the key, because the caller disposes what it is given.
        public IReadOnlyList<X509Certificate2> ListCertificates() =>
            Certificates
                .Select(c => X509CertificateLoader.LoadPkcs12(c.Export(X509ContentType.Pkcs12), null))
                .ToList();
    }

    internal static X509Certificate2 Mint(
        string dnsName, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={dnsName}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(SetupService.ServerAuthEku) }, false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1), notAfter ?? DateTimeOffset.UtcNow.AddDays(90));
    }

    private sealed class Factory(bool monitor) : CertusWebApplicationFactory
    {
        public ListStore Store { get; } = new();

        public string DataDir => TempDataDir;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            if (monitor)
                builder.UseSetting(CertusInstanceMode.DevelopmentKey, CertusInstanceMode.MonitorValue);
            builder.ConfigureServices(services => services.AddSingleton<IHttpsCertificateStore>(Store));
        }
    }

    private readonly X509Certificate2 _web01 = Mint("web01.corp.example.com");
    private readonly X509Certificate2 _other = Mint("other.corp.example.com", notAfter: DateTimeOffset.UtcNow.AddDays(300));
    private readonly X509Certificate2 _localhost = Mint("localhost");
    private readonly X509Certificate2 _expired = Mint(
        "web01.corp.example.com", DateTimeOffset.UtcNow.AddDays(-60), DateTimeOffset.UtcNow.AddDays(-1));

    private Factory? _factory;
    private HttpClient? _client;

    private HttpClient Client(bool monitor = true)
    {
        _factory = new Factory(monitor);
        _factory.Store.Certificates.AddRange([_web01, _other, _localhost, _expired]);
        _client = _factory.CreateClient();
        return _client;
    }

    public void Dispose()
    {
        _client?.Dispose();
        _factory?.Dispose();
        foreach (var certificate in new[] { _web01, _other, _localhost, _expired })
            certificate.Dispose();
    }

    private string OverlayPath => Path.Combine(_factory!.DataDir, "settings.json");

    private string StatusPath => Path.Combine(_factory!.DataDir, SetupStatus.FileName);

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    private static Task<HttpResponseMessage> UseAsync(
        HttpClient client, string thumbprint, bool acceptNameMismatch = false, string ca = Ca) =>
        client.PostAsync("/api/setup/existing-certificates/use", JsonContent(new
        {
            caConnectionString = ca,
            externalUrl = ExternalUrl,
            thumbprint,
            acceptNameMismatch,
        }));

    [Fact]
    public async Task The_list_holds_only_eligible_certificates_with_covering_ones_first()
    {
        var client = Client();

        var body = await ParseJsonAsync(await client.GetAsync(
            "/api/setup/existing-certificates?externalUrl=" + Uri.EscapeDataString(ExternalUrl)));

        body.GetProperty("externalHost").GetString().Should().Be("web01.corp.example.com");
        var rows = body.GetProperty("certificates").EnumerateArray().ToList();
        rows.Select(r => r.GetProperty("thumbprint").GetString())
            .Should().Equal(_web01.Thumbprint, _other.Thumbprint, _localhost.Thumbprint);
        rows[0].GetProperty("coversExternalHost").GetBoolean().Should().BeTrue();
        rows[1].GetProperty("coversExternalHost").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task A_full_mode_server_does_not_offer_the_list()
    {
        var client = Client(monitor: false);

        var response = await client.GetAsync(
            "/api/setup/existing-certificates?externalUrl=" + Uri.EscapeDataString(ExternalUrl));

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await UseAsync(client, _web01.Thumbprint)).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task The_list_locks_once_setup_is_complete()
    {
        var client = Client();
        new SetupStatus { SetupCompleted = true, CompletedAt = DateTime.UtcNow, ExternalUrl = ExternalUrl }
            .Save(StatusPath);

        var response = await client.GetAsync(
            "/api/setup/existing-certificates?externalUrl=" + Uri.EscapeDataString(ExternalUrl));

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task A_bad_url_is_refused()
    {
        var client = Client();

        (await client.GetAsync("/api/setup/existing-certificates?externalUrl=not-a-url"))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Using_a_certificate_records_it_and_drafts_at_the_url_step_with_no_template()
    {
        var client = Client();

        var response = await UseAsync(client, _web01.Thumbprint.ToLowerInvariant());

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("outcome").GetString().Should().Be("installed");
        body.GetProperty("thumbprint").GetString().Should().Be(_web01.Thumbprint);

        SettingsOverlay.Load(OverlayPath).HttpsCertificateThumbprint.Should().Be(_web01.Thumbprint);
        var status = SetupStatus.Load(StatusPath);
        status.WizardStep.Should().Be("url");
        status.EnabledTemplates.Should().BeEmpty();
        status.CaConnectionString.Should().Be(Ca);
    }

    [Fact]
    public async Task A_certificate_for_another_name_needs_a_confirmation()
    {
        var client = Client();

        var refused = await UseAsync(client, _other.Thumbprint);
        refused.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);
        var body = await ParseJsonAsync(refused);
        body.GetProperty("reason").GetString().Should().Be("nameMismatch");
        body.GetProperty("names").EnumerateArray().Select(n => n.GetString())
            .Should().Equal("other.corp.example.com");
        File.Exists(OverlayPath).Should().BeFalse();

        (await UseAsync(client, _other.Thumbprint, acceptNameMismatch: true))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        SettingsOverlay.Load(OverlayPath).HttpsCertificateThumbprint.Should().Be(_other.Thumbprint);
    }

    [Fact]
    public async Task A_certificate_the_service_could_not_serve_is_refused_even_by_thumbprint()
    {
        // The browser's list is not trusted: eligibility is decided again here.
        var client = Client();

        (await UseAsync(client, _expired.Thumbprint)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await UseAsync(client, "00112233445566778899AABBCCDDEEFF00112233"))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task A_continue_url_is_offered_only_when_this_browser_would_lose_the_server()
    {
        // The test server answers as localhost. A certificate that does not cover
        // it would fail this browser's next request after the restart.
        var client = Client();

        var away = await ParseJsonAsync(await UseAsync(client, _web01.Thumbprint));
        away.GetProperty("continueUrl").GetString().Should().Be("https://web01.corp.example.com:5001/setup");

        var here = await ParseJsonAsync(await UseAsync(client, _localhost.Thumbprint, acceptNameMismatch: true));
        here.GetProperty("continueUrl").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task A_ca_string_that_could_forge_a_log_line_is_refused()
    {
        var client = Client();

        (await UseAsync(client, _web01.Thumbprint, ca: "ca.contoso.com\\CA\nforged"))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Keeping_the_self_signed_certificate_clears_an_earlier_pick()
    {
        var client = Client();
        (await UseAsync(client, _web01.Thumbprint)).StatusCode.Should().Be(HttpStatusCode.OK);

        var response = await client.PostAsync("/api/setup/existing-certificates/keep-self-signed",
            JsonContent(new { caConnectionString = Ca, externalUrl = ExternalUrl }));

        (await ParseJsonAsync(response)).GetProperty("outcome").GetString().Should().Be("selfSigned");
        SettingsOverlay.Load(OverlayPath).HttpsCertificateThumbprint.Should().BeNull();
        SetupStatus.Load(StatusPath).WizardStep.Should().Be("url");
    }

    [Fact]
    public async Task Keeping_the_self_signed_certificate_refuses_a_url_the_draft_could_not_use()
    {
        // The draft records this URL, so it gets the same checks the use route
        // gives it, and nothing is cleared when it fails them.
        var client = Client();
        (await UseAsync(client, _web01.Thumbprint)).StatusCode.Should().Be(HttpStatusCode.OK);

        var response = await client.PostAsync("/api/setup/existing-certificates/keep-self-signed",
            JsonContent(new { caConnectionString = Ca, externalUrl = "not-a-url" }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        SettingsOverlay.Load(OverlayPath).HttpsCertificateThumbprint.Should().Be(_web01.Thumbprint);
    }

    [Fact]
    public async Task Keeping_the_self_signed_certificate_with_nothing_picked_changes_nothing()
    {
        var client = Client();

        var response = await client.PostAsync("/api/setup/existing-certificates/keep-self-signed",
            JsonContent(new { caConnectionString = Ca, externalUrl = ExternalUrl }));

        (await ParseJsonAsync(response)).GetProperty("outcome").GetString().Should().Be("unchanged");
        File.Exists(OverlayPath).Should().BeFalse();
    }
}
