using System.Net;
using System.Text;
using System.Text.Json;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the EAB owner principal link (issue #132): the
/// directory search endpoint serves the picker from the mock directory (the
/// dev host wiring this factory boots), the PUT re-resolves the posted SID
/// so the stored name and type are the directory's answer, unresolvable SIDs
/// are refused, and the link honors the same terminal revocation rule as
/// every other credential change. The link is display and audit only, so no
/// ACME behavior is asserted here; there is none to assert.
/// </summary>
[Trait("Category", "Integration")]
public class EabPrincipalIntegrationTests : IDisposable
{
    private readonly PrincipalFactory _factory = new();
    private readonly HttpClient _client;

    public EabPrincipalIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    // ---- Directory search ----

    [Fact]
    public async Task DirectorySearch_ReturnsThePrincipalsThePickerNeeds()
    {
        var response = await _client.GetAsync("/api/acme/directory-principals?query=web");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var principals = (await ParseJsonAsync(response))
            .GetProperty("principals").EnumerateArray().ToList();
        principals.Select(p => p.GetProperty("name").GetString()).Should().BeEquivalentTo(
            ["websvc$", "WEB01$", "Web Admins"]);
        foreach (var principal in principals)
        {
            principal.GetProperty("sid").GetString().Should().StartWith("S-1-5-21-");
            principal.GetProperty("type").GetString()
                .Should().BeOneOf("user", "computer", "group", "service account");
            principal.GetProperty("distinguishedName").GetString().Should().NotBeNull();
        }
    }

    [Fact]
    public async Task DirectorySearch_BlankQuery_ReturnsAnEmptyList()
    {
        foreach (var url in new[]
        {
            "/api/acme/directory-principals",
            "/api/acme/directory-principals?query=",
            "/api/acme/directory-principals?query=%20%20",
        })
        {
            var response = await _client.GetAsync(url);
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            (await ParseJsonAsync(response)).GetProperty("principals")
                .GetArrayLength().Should().Be(0, "{0} names no principal", url);
        }
    }

    // ---- Linking ----

    [Fact]
    public async Task Principal_Put_ReResolvesTheSid_AndTheListShowsTheOwner()
    {
        var credentialId = await CreateCredentialAsync("web servers");
        var jsmith = await FindPrincipalAsync("jsmith");

        // Only the SID travels; the stored name and type must come from the
        // directory, not from anything the client could have claimed.
        var response = await PutJsonAsync(
            $"/api/acme/credentials/{credentialId}/principal",
            new { sid = jsmith.GetProperty("sid").GetString() });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        var linked = body.GetProperty("adPrincipal");
        linked.GetProperty("name").GetString().Should().Be("jsmith");
        linked.GetProperty("type").GetString().Should().Be("user");
        body.GetProperty("updatedAt").ValueKind.Should().Be(JsonValueKind.String);

        var row = await GetSingleCredentialRowAsync();
        row.GetProperty("adPrincipal").GetProperty("name").GetString().Should().Be("jsmith");
        row.GetProperty("adPrincipal").GetProperty("sid").GetString()
            .Should().Be(jsmith.GetProperty("sid").GetString());
    }

    [Fact]
    public async Task Principal_Put_UnresolvableSid_Returns400()
    {
        var credentialId = await CreateCredentialAsync("web servers");

        // Well formed, but no directory object answers to it.
        var response = await PutJsonAsync(
            $"/api/acme/credentials/{credentialId}/principal",
            new { sid = "S-1-5-21-1-2-3-9999" });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("does not resolve");
        (await GetSingleCredentialRowAsync()).GetProperty("adPrincipal")
            .ValueKind.Should().Be(JsonValueKind.Null, "a refused link stores nothing");
    }

    [Fact]
    public async Task Principal_Put_MissingSid_Returns400()
    {
        var credentialId = await CreateCredentialAsync("web servers");

        var response = await PutJsonAsync(
            $"/api/acme/credentials/{credentialId}/principal", new { sid = "  " });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("SID is required");
    }

    [Fact]
    public async Task Principal_Put_UnknownCredential_Returns404()
    {
        var jsmith = await FindPrincipalAsync("jsmith");

        var response = await PutJsonAsync(
            "/api/acme/credentials/9999/principal",
            new { sid = jsmith.GetProperty("sid").GetString() });

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Principal_Put_RevokedCredential_Returns409()
    {
        var credentialId = await CreateCredentialAsync("terminal");
        (await _client.PostAsync($"/api/acme/credentials/{credentialId}/revoke", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        var jsmith = await FindPrincipalAsync("jsmith");

        var response = await PutJsonAsync(
            $"/api/acme/credentials/{credentialId}/principal",
            new { sid = jsmith.GetProperty("sid").GetString() });

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("revoked");
    }

    // ---- Unlinking ----

    [Fact]
    public async Task Principal_Delete_ClearsTheLink_AndIsIdempotent()
    {
        var credentialId = await CreateCredentialAsync("web servers");
        var jsmith = await FindPrincipalAsync("jsmith");
        (await PutJsonAsync(
            $"/api/acme/credentials/{credentialId}/principal",
            new { sid = jsmith.GetProperty("sid").GetString() }))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var response = await _client.DeleteAsync(
            $"/api/acme/credentials/{credentialId}/principal");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ParseJsonAsync(response)).GetProperty("adPrincipal")
            .ValueKind.Should().Be(JsonValueKind.Null);
        (await GetSingleCredentialRowAsync()).GetProperty("adPrincipal")
            .ValueKind.Should().Be(JsonValueKind.Null);

        (await _client.DeleteAsync($"/api/acme/credentials/{credentialId}/principal"))
            .StatusCode.Should().Be(HttpStatusCode.OK,
                "clearing an unlinked credential is a harmless no op");
    }

    [Fact]
    public async Task Principal_Delete_UnknownCredential_Returns404()
    {
        (await _client.DeleteAsync("/api/acme/credentials/9999/principal"))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Principal_Delete_RevokedCredential_Returns409()
    {
        var credentialId = await CreateCredentialAsync("terminal");
        (await _client.PostAsync($"/api/acme/credentials/{credentialId}/revoke", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        (await _client.DeleteAsync($"/api/acme/credentials/{credentialId}/principal"))
            .StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    // ---- Helpers ----

    private static StringContent JsonContent(object payload) => new(
        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private Task<HttpResponseMessage> PostJsonAsync(string url, object payload) =>
        _client.PostAsync(url, JsonContent(payload));

    private Task<HttpResponseMessage> PutJsonAsync(string url, object payload) =>
        _client.PutAsync(url, JsonContent(payload));

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    private async Task<int> CreateCredentialAsync(string name)
    {
        var response = await PostJsonAsync("/api/acme/credentials", new { name });
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        return (await ParseJsonAsync(response)).GetProperty("id").GetInt32();
    }

    /// <summary>
    /// Fetches one principal through the search endpoint, the same route the
    /// picker takes, so the tests never hardcode the mock directory's SIDs.
    /// </summary>
    private async Task<JsonElement> FindPrincipalAsync(string query)
    {
        var response = await _client.GetAsync(
            $"/api/acme/directory-principals?query={query}");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await ParseJsonAsync(response)).GetProperty("principals")
            .EnumerateArray().Single();
    }

    private async Task<JsonElement> GetSingleCredentialRowAsync()
    {
        var response = await _client.GetAsync("/api/acme/credentials");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await ParseJsonAsync(response)).GetProperty("credentials")
            .EnumerateArray().Single();
    }

    /// <summary>
    /// Test factory following the AdminFactory pattern: a completed setup is
    /// seeded before the host builds. The dev host Program this factory boots
    /// registers the mock principal lookup, so the directory here is the
    /// canned one.
    /// </summary>
    private sealed class PrincipalFactory : CertusWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            var status = new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = ["WebServer"],
            };
            status.Save(Path.Combine(TempDataDir, SetupStatus.FileName));
        }
    }
}
