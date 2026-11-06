using System.Net;
using System.Text.Json;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Certus.Core.Data.Retention;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// The administrator's erasure endpoint (issue #637) through the real host:
/// the deactivation guard, the answer shape, the second request, and that the
/// daily retention pass is registered in the host at all.
/// </summary>
[Trait("Category", "Integration")]
public class AcmeAccountErasureIntegrationTests : IDisposable
{
    private readonly CertusWebApplicationFactory _factory = new();
    private readonly HttpClient _client;

    public AcmeAccountErasureIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Fact]
    public async Task Erase_AValidAccount_Answers409_UntilItIsDeactivated()
    {
        var id = await SeedAccountAsync("valid", "[\"mailto:person@example.com\"]");

        var refused = await _client.PostAsync($"/api/acme/accounts/{id}/erase", null);

        refused.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ParseAsync(refused)).GetProperty("error").GetString().Should().Contain("Deactivate");

        (await _client.PostAsync($"/api/acme/accounts/{id}/deactivate", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var erased = await _client.PostAsync($"/api/acme/accounts/{id}/erase", null);

        erased.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseAsync(erased);
        body.GetProperty("id").GetInt32().Should().Be(id);
        body.GetProperty("alreadyErased").GetBoolean().Should().BeFalse();
        body.GetProperty("erasedAt").GetDateTime().Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
        body.GetProperty("credentialLinkCleared").GetBoolean().Should().BeFalse();

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var row = await db.AcmeAccounts.AsNoTracking().SingleAsync(a => a.Id == id);
            row.ContactJson.Should().BeNull();
            row.ErasedAt.Should().NotBeNull();
            row.Status.Should().Be("deactivated");
        }

        // A second request reports the first and changes nothing.
        var again = await _client.PostAsync($"/api/acme/accounts/{id}/erase", null);
        again.StatusCode.Should().Be(HttpStatusCode.OK);
        var againBody = await ParseAsync(again);
        againBody.GetProperty("alreadyErased").GetBoolean().Should().BeTrue();
        againBody.GetProperty("erasedAt").GetDateTime().Should().Be(body.GetProperty("erasedAt").GetDateTime());
    }

    [Fact]
    public async Task Erase_UnknownAccount_Answers404()
    {
        (await _client.PostAsync("/api/acme/accounts/9999/erase", null))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public void TheDailyRetentionPass_IsRegisteredInTheHost()
    {
        _factory.Services.GetServices<IHostedService>()
            .Should().ContainSingle(s => s is DataRetentionService,
                "AddDataRetention registers the pass in both hosts");
    }

    private async Task<int> SeedAccountAsync(string status, string? contact)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var account = new AcmeAccount
        {
            AccountId = Guid.NewGuid().ToString("N"),
            JwkJson = """{"kty":"RSA","n":"test","e":"AQAB"}""",
            JwkThumbprint = Guid.NewGuid().ToString("N"),
            Status = status,
            ContactJson = contact,
            CreatedAt = DateTime.UtcNow,
        };
        db.AcmeAccounts.Add(account);
        await db.SaveChangesAsync();
        return account.Id;
    }

    private static async Task<JsonElement> ParseAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(json).RootElement.Clone();
    }
}
