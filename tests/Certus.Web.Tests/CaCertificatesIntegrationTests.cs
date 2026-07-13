using System.Net;
using System.Text.Json;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the CA certificate download endpoints. The dev host
/// binds the mock CA, whose chain is a single self signed root, so the list
/// and every download format can be asserted end to end. Read only surface,
/// so the shared factory collection is safe.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class CaCertificatesIntegrationTests
{
    private readonly HttpClient _client;

    public CaCertificatesIntegrationTests(CertusWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    private async Task<string> GetRootThumbprintAsync()
    {
        var list = await ParseJsonAsync(await _client.GetAsync("/api/settings/ca-certificates"));
        return list[0].GetProperty("thumbprint").GetString()!;
    }

    [Fact]
    public async Task List_ReturnsTheMockRoot()
    {
        var response = await _client.GetAsync("/api/settings/ca-certificates");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.ValueKind.Should().Be(JsonValueKind.Array);
        body.GetArrayLength().Should().Be(1);
        body[0].GetProperty("role").GetString().Should().Be("root");
        body[0].GetProperty("subject").GetString().Should().Contain("Mock");
        body[0].GetProperty("thumbprint").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task DownloadDer_ReturnsBinaryCerAttachment()
    {
        var thumbprint = await GetRootThumbprintAsync();

        var response = await _client.GetAsync($"/api/settings/ca-certificates/{thumbprint}/der");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/pkix-cert");
        response.Content.Headers.ContentDisposition!.FileName.Should().EndWith(".cer");
        var bytes = await response.Content.ReadAsByteArrayAsync();
        bytes[0].Should().Be(0x30, "DER encoded certificates start with a SEQUENCE tag");
    }

    [Fact]
    public async Task DownloadPem_ReturnsPemAttachment()
    {
        var thumbprint = await GetRootThumbprintAsync();

        var response = await _client.GetAsync($"/api/settings/ca-certificates/{thumbprint}/pem");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/x-pem-file");
        response.Content.Headers.ContentDisposition!.FileName.Should().EndWith(".pem");
        var text = await response.Content.ReadAsStringAsync();
        text.Should().StartWith("-----BEGIN CERTIFICATE-----");
        text.Should().EndWith("\n", "PEM files should end with a newline for tool compatibility");
    }

    [Fact]
    public async Task DownloadChainPem_CarriesEveryCertificate()
    {
        var response = await _client.GetAsync("/api/settings/ca-certificates/chain/pem");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/x-pem-file");
        response.Content.Headers.ContentDisposition!.FileName.Should().Be("ca-chain.pem");
        var text = await response.Content.ReadAsStringAsync();
        text.Should().Contain("-----BEGIN CERTIFICATE-----");
    }

    [Fact]
    public async Task DownloadChainP7b_ReturnsAParseablePkcs7Bundle()
    {
        var response = await _client.GetAsync("/api/settings/ca-certificates/chain/p7b");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/x-pkcs7-certificates");
        response.Content.Headers.ContentDisposition!.FileName.Should().Be("ca-chain.p7b");

        var bytes = await response.Content.ReadAsByteArrayAsync();
        var cms = new System.Security.Cryptography.Pkcs.SignedCms();
        cms.Decode(bytes);
        cms.Certificates.Count.Should().Be(1, "the mock CA chain is its self signed root alone");
    }

    [Fact]
    public async Task DownloadDer_UnknownThumbprint_Returns404()
    {
        var response = await _client.GetAsync("/api/settings/ca-certificates/0000000000000000000000000000000000000000/der");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }
}
