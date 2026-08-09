using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the single certificate download on the dashboard
/// detail page (issue #158):
///   GET /api/certificates/{id}/pem
///   GET /api/certificates/{id}/der
///
/// Not to be confused with <see cref="CertificateDownloadIntegrationTests"/>,
/// which covers the ACME certificate endpoint and deliberately returns a full
/// chain per RFC 8555 7.4.2. These two endpoints are the opposite contract:
/// exactly one certificate, never a chain.
///
/// The free tier boundary is asserted here rather than left to review. Two
/// tests stand guard: one counts the certificates in the PEM body, and one
/// pins that none of the detail only fields reach the list endpoint.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class DashboardCertificateDownloadIntegrationTests
{
    /// <summary>The row seeded with a real certificate blob.</summary>
    private const int DownloadableRequestId = 5801;

    /// <summary>The row seeded without one, standing in for a pending request.</summary>
    private const int NoCertificateRequestId = 5802;

    private const string SubjectName = "download-test.example.com";

    /// <summary>
    /// How far back the seeded rows are dated. The factory and its database are
    /// shared across this collection, and the dashboard registrations endpoint
    /// counts every certificate requested inside its window, capped at 90 days,
    /// against an exact expected total. Dating these rows outside that window
    /// keeps them from being counted by a test that is not about them.
    /// </summary>
    private const int SeededAgeDays = 200;

    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public DashboardCertificateDownloadIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    /// <summary>
    /// A real self signed certificate, so the endpoints are exercised against
    /// bytes that genuinely decode rather than a placeholder. Carries a key
    /// usage and an EKU so the detail fields have something to report.
    /// </summary>
    private static X509Certificate2 CreateTestCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={SubjectName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-SeededAgeDays), DateTimeOffset.UtcNow.AddDays(165));
    }

    /// <summary>
    /// Seeds one downloadable certificate and one row with no certificate
    /// blob, returning their internal ids. Idempotent, because the factory and
    /// therefore the database are shared across the collection.
    /// </summary>
    private async Task<(int Downloadable, int NoCertificate, X509Certificate2 Certificate)> SeedAsync()
    {
        var certificate = CreateTestCertificate();

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();

        var existing = await db.SyncedCertificates
            .FirstOrDefaultAsync(c => c.RequestId == DownloadableRequestId);
        if (existing != null)
        {
            var seededNoCert = await db.SyncedCertificates
                .FirstAsync(c => c.RequestId == NoCertificateRequestId);
            certificate.Dispose();
            // Re-read the stored bytes so callers compare against what the
            // endpoints actually serve, not a freshly generated certificate.
            return (existing.Id, seededNoCert.Id, X509CertificateLoader.LoadCertificate(existing.RawCertificate!));
        }

        var now = DateTime.UtcNow;
        var downloadable = new SyncedCertificate
        {
            RequestId = DownloadableRequestId,
            SerialNumber = certificate.SerialNumber,
            Subject = certificate.Subject,
            SubjectAlternativeNames = null,
            TemplateName = "WebServer",
            NotBefore = certificate.NotBefore.ToUniversalTime(),
            NotAfter = certificate.NotAfter.ToUniversalTime(),
            Status = "Issued",
            Requestor = "HOME\\admin",
            RequestDate = now.AddDays(-SeededAgeDays),
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithmOid = "1.2.840.113549.1.1.11",
            Sha256Thumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256),
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1",
            KeyUsage = (int)(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment),
            RawCertificate = certificate.RawData,
        };

        // A request that never became a certificate: no serial, no blob, and so
        // nothing to download. This is also the shape of a row synced before
        // the DER column existed, which the next sync backfills.
        var noCertificate = new SyncedCertificate
        {
            RequestId = NoCertificateRequestId,
            SerialNumber = string.Empty,
            Subject = "CN=pending.example.com",
            TemplateName = "WebServer",
            NotBefore = DateTime.MinValue,
            NotAfter = DateTime.MinValue,
            Status = "Pending",
            Requestor = "HOME\\admin",
            RequestDate = now.AddDays(-SeededAgeDays),
        };

        db.SyncedCertificates.AddRange(downloadable, noCertificate);
        await db.SaveChangesAsync();

        return (downloadable.Id, noCertificate.Id, certificate);
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        return JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());
    }

    /// <summary>Occurrences of the PEM certificate opening line.</summary>
    private static int CountCertificates(string pem)
    {
        return pem.Split("-----BEGIN CERTIFICATE-----").Length - 1;
    }

    [Fact]
    public async Task DownloadPem_ReturnsAParsablePemAttachment()
    {
        var (id, _, certificate) = await SeedAsync();
        using var _cert = certificate;

        var response = await _client.GetAsync($"/api/certificates/{id}/pem");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/x-pem-file");
        response.Content.Headers.ContentDisposition!.FileName.Should()
            .Contain(SubjectName, "the file is named from the certificate")
            .And.EndWith(".pem");

        var pem = await response.Content.ReadAsStringAsync();
        using var roundTripped = X509Certificate2.CreateFromPem(pem);
        roundTripped.RawData.Should().Equal(certificate.RawData);
    }

    [Fact]
    public async Task DownloadPem_ContainsExactlyOneCertificate()
    {
        var (id, _, certificate) = await SeedAsync();
        certificate.Dispose();

        var response = await _client.GetAsync($"/api/certificates/{id}/pem");

        var pem = await response.Content.ReadAsStringAsync();
        CountCertificates(pem).Should().Be(1,
            "this endpoint hands back one certificate and never a chain; bulk and multi " +
            "certificate export is the paid tier and must not appear here");
    }

    [Fact]
    public async Task DownloadDer_ReturnsTheStoredBytesAsACerAttachment()
    {
        var (id, _, certificate) = await SeedAsync();
        using var _cert = certificate;

        var response = await _client.GetAsync($"/api/certificates/{id}/der");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/pkix-cert");
        response.Content.Headers.ContentDisposition!.FileName.Should().EndWith(".cer");

        var bytes = await response.Content.ReadAsByteArrayAsync();
        bytes[0].Should().Be(0x30, "DER encoded certificates start with a SEQUENCE tag");
        bytes.Should().Equal(certificate.RawData);
    }

    /// <summary>
    /// The acceptance criterion an admin actually leans on: the thumbprint the
    /// page shows is the thumbprint of the file they downloaded, so comparing
    /// it against what a host is serving means something.
    /// </summary>
    [Fact]
    public async Task DownloadedCertificate_HashesToTheDisplayedThumbprint()
    {
        var (id, _, certificate) = await SeedAsync();
        certificate.Dispose();

        var detail = await ParseJsonAsync(await _client.GetAsync($"/api/certificates/{id}"));
        var displayed = detail.GetProperty("sha256Thumbprint").GetString();

        var pem = await (await _client.GetAsync($"/api/certificates/{id}/pem")).Content.ReadAsStringAsync();
        using var downloaded = X509Certificate2.CreateFromPem(pem);
        var actual = Convert.ToHexString(SHA256.HashData(downloaded.RawData));

        actual.Should().Be(displayed);
    }

    [Fact]
    public async Task Detail_ReportsCanDownloadTrue_WhenTheCertificateIsStored()
    {
        var (id, _, certificate) = await SeedAsync();
        certificate.Dispose();

        var detail = await ParseJsonAsync(await _client.GetAsync($"/api/certificates/{id}"));

        detail.GetProperty("canDownload").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task Detail_ReportsCanDownloadFalse_WhenThereIsNoCertificate()
    {
        var (_, noCertificateId, certificate) = await SeedAsync();
        certificate.Dispose();

        var detail = await ParseJsonAsync(await _client.GetAsync($"/api/certificates/{noCertificateId}"));

        detail.GetProperty("canDownload").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Download_ReturnsNotFound_WhenThereIsNoCertificate()
    {
        var (_, noCertificateId, certificate) = await SeedAsync();
        certificate.Dispose();

        var pem = await _client.GetAsync($"/api/certificates/{noCertificateId}/pem");
        var der = await _client.GetAsync($"/api/certificates/{noCertificateId}/der");

        pem.StatusCode.Should().Be(HttpStatusCode.NotFound);
        der.StatusCode.Should().Be(HttpStatusCode.NotFound);

        var problem = await ParseJsonAsync(pem);
        problem.GetProperty("type").GetString()
            .Should().Be("https://ducksinarow.app/problems/certificate-unavailable");
    }

    [Fact]
    public async Task Download_ReturnsNotFound_ForAnUnknownCertificate()
    {
        var response = await _client.GetAsync("/api/certificates/99999999/pem");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    /// <summary>
    /// The free tier boundary, pinned. Nothing this issue added may reach the
    /// list response: not the download flag, and not the cryptographic detail
    /// it sits beside. Inventory by key algorithm is the paid Compliance tier
    /// feature, and the list endpoint is where that would start.
    /// </summary>
    [Fact]
    public async Task List_CarriesNoneOfTheDetailOnlyFields()
    {
        var (_, _, certificate) = await SeedAsync();
        certificate.Dispose();

        var body = await ParseJsonAsync(await _client.GetAsync("/api/certificates?take=200"));

        var items = body.GetProperty("items");
        items.GetArrayLength().Should().BeGreaterThan(0);

        string[] detailOnly =
        [
            "canDownload", "sha256Thumbprint", "keyAlgorithm", "keySizeBits",
            "signatureAlgorithmOid", "extendedKeyUsageOids", "keyUsage",
        ];

        foreach (var item in items.EnumerateArray())
        {
            foreach (var field in detailOnly)
            {
                item.TryGetProperty(field, out _).Should().BeFalse(
                    "{0} is detail only and must never reach the certificate list", field);
            }
        }
    }

    /// <summary>
    /// An ACME issued certificate carries no subject DN, so the file name falls
    /// through to the first SAN. Pinned because it is the normal case for
    /// certificates Ducks itself issued, not an edge case.
    /// </summary>
    [Fact]
    public async Task DownloadPem_NamesTheFileFromTheSan_WhenThereIsNoSubject()
    {
        const int requestId = 5803;
        const string sanName = "san-only.example.com";

        int id;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var existing = await db.SyncedCertificates.FirstOrDefaultAsync(c => c.RequestId == requestId);
            if (existing != null)
            {
                id = existing.Id;
            }
            else
            {
                using var rsa = RSA.Create(2048);
                // An empty subject, exactly as an ACME CSR produces.
                var request = new CertificateRequest(
                    "", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName(sanName);
                request.CertificateExtensions.Add(sanBuilder.Build());
                using var certificate = request.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddDays(-SeededAgeDays), DateTimeOffset.UtcNow.AddDays(165));

                var entity = new SyncedCertificate
                {
                    RequestId = requestId,
                    SerialNumber = certificate.SerialNumber,
                    Subject = sanName,
                    SubjectAlternativeNames = $"dns:{sanName}",
                    TemplateName = "WebServer",
                    NotBefore = certificate.NotBefore.ToUniversalTime(),
                    NotAfter = certificate.NotAfter.ToUniversalTime(),
                    Status = "Issued",
                    RequestDate = DateTime.UtcNow.AddDays(-SeededAgeDays),
                    RawCertificate = certificate.RawData,
                };
                db.SyncedCertificates.Add(entity);
                await db.SaveChangesAsync();
                id = entity.Id;
            }
        }

        var response = await _client.GetAsync($"/api/certificates/{id}/pem");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentDisposition!.FileName.Should().Contain(sanName);
    }
}
