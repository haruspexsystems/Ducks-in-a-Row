using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Certus.Core.Audit;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Setup;
using Certus.Web.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The administrator audit trail through the real host with the real auth
/// stack (issue #634): the row carries the Windows identity, a settings change
/// records the value before and after, a credential row never carries the
/// secret, a refused request writes no row, a repeated erasure writes no second
/// row, the read API pages newest first, and refused sign ins are counted per
/// source while an administrator's own CSRF slip is not. Each test gets its own
/// host, so counts never depend on run order.
/// </summary>
[Trait("Category", "Integration")]
public class AdminAuditTrailIntegrationTests : IDisposable
{
    private sealed class Factory : AuthWebApplicationFactory
    {
        public string DataDir => TempDataDir;
    }

    private readonly Factory _factory = new();

    public void Dispose()
    {
        _factory.Dispose();
    }

    // ---- Rows ----

    [Fact]
    public async Task ASettingsChange_RecordsTheActor_TheValueBefore_AndTheValueAfter()
    {
        SeedCompletedSetup();
        using var client = Admin();

        var response = await client.PutAsync("/api/settings/allowed-domains",
            Json(new { enabled = true, domains = new[] { "example.com", "example.net" } }));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var row = (await RowsAsync()).Should().ContainSingle().Subject;
        row.Actor.Should().Be(TestAuthHandler.AdminUser);
        row.Action.Should().Be("settings.allowed-domains.changed");
        row.Target.Should().Be("allowed domains");
        row.BeforeValue.Should().Be("off");
        row.AfterValue.Should().Be("on: example.com, example.net");
        row.OccurredAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task ACredentialCreated_IsRecordedWithoutItsSecret()
    {
        SeedCompletedSetup();
        using var client = Admin();

        var response = await client.PostAsync("/api/acme/credentials",
            Json(new { name = "Build farm", domains = new[] { "build.example.com" } }));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var body = await ParseAsync(response);
        var secret = body.GetProperty("secret").GetString()!;
        var keyId = body.GetProperty("keyId").GetString()!;

        var row = (await RowsAsync()).Should().ContainSingle().Subject;
        row.Action.Should().Be("acme.eab-credential.created");
        row.Target.Should().Be($"credential {keyId}");
        row.AfterValue.Should().Contain("Build farm").And.Contain("build.example.com");
        row.AfterValue.Should().NotContain(secret, "the secret is handed out once and lives nowhere else");
        (row.BeforeValue ?? string.Empty).Should().NotContain(secret);
    }

    [Fact]
    public async Task ARefusedRequest_WritesNoRow()
    {
        SeedCompletedSetup();
        using var client = Admin();

        (await client.PutAsync("/api/acme/credentials/9999",
                Json(new { name = "ghost", domains = Array.Empty<string>() })))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.PostAsync("/api/acme/accounts/9999/erase", null))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.PutAsync("/api/settings/allowed-domains",
                Json(new { enabled = true, domains = Array.Empty<string>() })))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);

        (await RowsAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task ATransactionalAction_CommitsTheChangeAndTheRowTogether_AndASecondErasureWritesNoSecondRow()
    {
        SeedCompletedSetup();
        var accountId = await SeedAccountAsync();
        using var client = Admin();

        (await client.PostAsync($"/api/acme/accounts/{accountId}/deactivate", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await client.PostAsync($"/api/acme/accounts/{accountId}/erase", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        var again = await client.PostAsync($"/api/acme/accounts/{accountId}/erase", null);
        again.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ParseAsync(again)).GetProperty("alreadyErased").GetBoolean().Should().BeTrue();

        var rows = await RowsAsync();
        rows.Select(r => r.Action).Should().Equal("acme.account.deactivated", "acme.account.erased");
        rows.Should().OnlyContain(r => r.Actor == TestAuthHandler.AdminUser);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var account = await db.AcmeAccounts.AsNoTracking().SingleAsync(a => a.Id == accountId);
        account.Status.Should().Be("deactivated");
        account.ErasedAt.Should().NotBeNull();
        rows[1].Target.Should().Be($"account {account.AccountId}");
    }

    [Fact]
    public async Task ATransactionalActionRefused_RollsBackWithoutARow()
    {
        SeedCompletedSetup();
        var accountId = await SeedAccountAsync();
        using var client = Admin();

        // Erasing a valid account is refused 409 inside the filter's transaction.
        (await client.PostAsync($"/api/acme/accounts/{accountId}/erase", null))
            .StatusCode.Should().Be(HttpStatusCode.Conflict);

        (await RowsAsync()).Should().BeEmpty();
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        (await db.AcmeAccounts.AsNoTracking().SingleAsync(a => a.Id == accountId)).ErasedAt.Should().BeNull();
    }

    // ---- The read API ----

    [Fact]
    public async Task Entries_AreNewestFirst_PagedAndFilteredByActor()
    {
        var now = DateTime.UtcNow;
        await SeedRowsAsync(
            new AdminAuditEntry { OccurredAt = now.AddMinutes(-3), Actor = "CORP\\alice", Action = "a.first" },
            new AdminAuditEntry { OccurredAt = now.AddMinutes(-2), Actor = "CORP\\bob", Action = "b.second" },
            new AdminAuditEntry { OccurredAt = now.AddMinutes(-1), Actor = "CORP\\alice", Action = "a.third" });
        using var client = Admin();

        var page = await ParseAsync(await client.GetAsync("/api/audit/entries?take=2"));
        page.GetProperty("totalCount").GetInt32().Should().Be(3);
        page.GetProperty("hasMore").GetBoolean().Should().BeTrue();
        page.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("action").GetString())
            .Should().Equal("a.third", "b.second");

        var alice = await ParseAsync(await client.GetAsync("/api/audit/entries?actor=CORP%5Calice"));
        alice.GetProperty("totalCount").GetInt32().Should().Be(2);
        alice.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("action").GetString())
            .Should().Equal("a.third", "a.first");

        var actors = await ParseAsync(await client.GetAsync("/api/audit/actors"));
        actors.GetProperty("actors").EnumerateArray().Select(a => a.GetString())
            .Should().Equal("CORP\\alice", "CORP\\bob");
    }

    [Fact]
    public async Task TheAuditApi_IsAdminOnly()
    {
        using var anonymous = _factory.CreateClient();
        using var alice = User("alice");

        (await anonymous.GetAsync("/api/audit/entries")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await alice.GetAsync("/api/audit/entries")).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await alice.GetAsync("/api/audit/sign-in-failures")).StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ---- Refused sign ins ----

    [Fact]
    public async Task RefusedSignIns_AreCountedPerSource_ButNotAnAdministratorsOwnCsrfSlip()
    {
        using var anonymousWithCredentials = _factory.CreateClient();
        anonymousWithCredentials.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Negotiate", "refused");
        using var bareAnonymous = _factory.CreateClient();
        using var alice = User("alice");
        using var adminWithoutCsrf = _factory.CreateClient();
        adminWithoutCsrf.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, TestAuthHandler.AdminUser);

        // Counted: credentials offered and refused (twice), and an authenticated
        // non administrator turned away.
        (await anonymousWithCredentials.GetAsync("/api/certificates")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await anonymousWithCredentials.GetAsync("/api/certificates")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await alice.GetAsync("/api/certificates")).StatusCode.Should().Be(HttpStatusCode.Forbidden);

        // Not counted: a browser that has not offered credentials yet is the
        // ordinary first leg of Negotiate, and an administrator's request
        // without the CSRF header is a 403 the CSRF guard answers, not a sign in.
        (await bareAnonymous.GetAsync("/api/certificates")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await adminWithoutCsrf.PostAsync("/api/certificates/sync", null)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

        using var admin = Admin();
        var response = await admin.GetAsync("/api/audit/sign-in-failures?days=1");
        var raw = await response.Content.ReadAsStringAsync();
        response.StatusCode.Should().Be(HttpStatusCode.OK, raw);
        var body = JsonDocument.Parse(raw).RootElement.Clone();
        body.GetProperty("total").GetInt32().Should().Be(3);
        var source = body.GetProperty("sources").EnumerateArray().Should().ContainSingle().Subject;
        // TestServer has no remote address, so the source reads as unknown.
        source.GetProperty("sourceAddress").GetString().Should().Be(AdminSignInFailureRecorder.UnknownSource);
        source.GetProperty("unauthorized").GetInt32().Should().Be(2);
        source.GetProperty("forbidden").GetInt32().Should().Be(1);
    }

    // ---- Helpers ----

    private HttpClient Admin() => User(TestAuthHandler.AdminUser);

    private HttpClient User(string user)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        client.DefaultRequestHeaders.Add(CertusPolicies.CsrfHeaderName, "1");
        return client;
    }

    private void SeedCompletedSetup()
    {
        // Building the host seeds a draft shaped status file, so the host has to
        // exist before the completed one is written over it.
        _ = _factory.Services;
        new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = DateTime.UtcNow,
            EnabledTemplates = ["WebServer"],
            ExternalUrl = "https://certus.example.com:5001",
        }.Save(Path.Combine(_factory.DataDir, SetupStatus.FileName));
    }

    private async Task<int> SeedAccountAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var account = new AcmeAccount
        {
            AccountId = Guid.NewGuid().ToString("N"),
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = Guid.NewGuid().ToString("N"),
            Status = "valid",
            ContactJson = "[\"mailto:person@example.com\"]",
            CreatedAt = DateTime.UtcNow,
        };
        db.AcmeAccounts.Add(account);
        await db.SaveChangesAsync();
        return account.Id;
    }

    private async Task SeedRowsAsync(params AdminAuditEntry[] rows)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        db.AdminAuditEntries.AddRange(rows);
        await db.SaveChangesAsync();
    }

    private async Task<List<AdminAuditEntry>> RowsAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        return await db.AdminAuditEntries.AsNoTracking().OrderBy(e => e.Id).ToListAsync();
    }

    private static StringContent Json(object payload) =>
        new(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
}
