using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The revocation scope modes enforced end to end over the revoke endpoint:
/// ducks-managed refuses a foreign template row with the out-of-scope
/// problem, a settings level mode change hot applies through the write time
/// cache without a restart, the custom list is honored, and every mode stays
/// under the TLS capability ceiling. Uses its own factory instance per test
/// so scope state never couples these facts to run order.
/// </summary>
[Trait("Category", "Integration")]
public class RevocationScopeEnforcementIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private static long _writeCounter;

    private readonly Factory _factory = new();
    private readonly HttpClient _client;

    public RevocationScopeEnforcementIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    /// <summary>
    /// Rewrites the status file with the given scope and bumps the write
    /// time, without which a fast test run can hit an unchanged mtime and
    /// the singleton policy would serve the previous snapshot.
    /// </summary>
    private void WriteScope(string mode, List<string>? revocable = null)
    {
        var path = Path.Combine(_factory.DataDir, SetupStatus.FileName);
        new SetupStatus
        {
            SetupCompleted = true,
            EnabledTemplates = ["WebServer"],
            RevocationScope = mode,
            RevocableTemplates = revocable ?? [],
        }.Save(path);
        var bump = Interlocked.Increment(ref _writeCounter);
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(bump));
    }

    /// <summary>
    /// Seeds an issued row on a template outside the enabled set, with
    /// capability columns that pass the ceiling, so scope is the only gate
    /// in play.
    /// </summary>
    private async Task<(int Id, string Serial)> SeedForeignTlsRowAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var entity = new SyncedCertificate
        {
            RequestId = Random.Shared.Next(60_000_000, 70_000_000),
            SerialNumber = $"0dc0ffee{Random.Shared.Next(0x1000, 0xFFFF):x8}",
            Subject = $"CN=scope-seeded-{Guid.NewGuid():N}",
            TemplateName = "Domain Controller",
            Status = "Issued",
            RequestDate = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow,
            NotAfter = DateTime.UtcNow.AddYears(1),
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2",
            KeyUsage = 160,
        };
        db.SyncedCertificates.Add(entity);
        await db.SaveChangesAsync();
        return (entity.Id, entity.SerialNumber);
    }

    private Task<HttpResponseMessage> PostRevokeAsync(int id, string serial) =>
        _client.PostAsync(
            $"/api/certificates/{id}/revoke",
            new StringContent(
                JsonSerializer.Serialize(new { reason = 0, serialNumber = serial }),
                Encoding.UTF8, "application/json"));

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    [Fact]
    public async Task DucksManaged_ForeignTemplateRow_Returns403OutOfScope()
    {
        WriteScope("ducks-managed");
        var (id, serial) = await SeedForeignTlsRowAsync();

        var response = await PostRevokeAsync(id, serial);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var body = await BodyAsync(response);
        body.GetProperty("type").GetString().Should().Be(
            "https://ducksinarow.app/problems/revocation-out-of-scope");
        body.GetProperty("detail").GetString().Should().Contain("ducks-managed");

        // The detail response carries the same reason and the frontend keys
        // its Settings link off exactly this kind.
        var detail = await BodyAsync(await _client.GetAsync($"/api/certificates/{id}"));
        detail.GetProperty("revocationBlocked").GetString().Should().Be("out-of-scope");
    }

    [Fact]
    public async Task ScopeChange_HotAppliesWithoutRestart()
    {
        WriteScope("ducks-managed");
        var (id, serial) = await SeedForeignTlsRowAsync();

        (await PostRevokeAsync(id, serial)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

        WriteScope("all");

        var response = await PostRevokeAsync(id, serial);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await BodyAsync(response)).GetProperty("outcome").GetString().Should().Be("revoked");
    }

    [Fact]
    public async Task Custom_HonorsTheTemplateList()
    {
        WriteScope("custom", revocable: ["Domain Controller"]);
        var listed = await SeedForeignTlsRowAsync();

        (await PostRevokeAsync(listed.Id, listed.Serial))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        WriteScope("custom", revocable: []);
        var unlisted = await SeedForeignTlsRowAsync();

        var refused = await PostRevokeAsync(unlisted.Id, unlisted.Serial);
        refused.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await BodyAsync(refused)).GetProperty("type").GetString().Should().Be(
            "https://ducksinarow.app/problems/revocation-out-of-scope");
    }

    [Fact]
    public async Task All_StaysUnderTheCeiling()
    {
        // The widest mode still cannot cross the guardrail: a smart card
        // logon certificate refuses as guardrail, not as out of scope.
        WriteScope("all");
        int id;
        string serial;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var entity = new SyncedCertificate
            {
                RequestId = Random.Shared.Next(70_000_001, 80_000_000),
                SerialNumber = "0dc0ffee00bb00bb",
                Subject = $"CN=scope-smartcard-{Guid.NewGuid():N}",
                TemplateName = "Domain Controller",
                Status = "Issued",
                RequestDate = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                NotAfter = DateTime.UtcNow.AddYears(1),
                ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.2, 1.3.6.1.4.1.311.20.2.2",
                KeyUsage = 128,
            };
            db.SyncedCertificates.Add(entity);
            await db.SaveChangesAsync();
            id = entity.Id;
            serial = entity.SerialNumber;
        }

        var response = await PostRevokeAsync(id, serial);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await BodyAsync(response)).GetProperty("type").GetString().Should().Be(
            "https://ducksinarow.app/problems/revocation-blocked-by-guardrail");
    }
}
