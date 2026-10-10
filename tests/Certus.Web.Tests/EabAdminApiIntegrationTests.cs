using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the ACME tab admin API (issue #129): the enforcement
/// endpoint hot applies to the ACME surface in the same host, the credential
/// endpoints hand out a secret exactly once and never list one, regenerate
/// and revoke carry their full protocol consequences end to end, and the
/// account inventory searches, filters, pages, and deactivates. Each test
/// gets its own factory (fresh database and status file), so counts and
/// totals never couple tests to run order.
/// </summary>
[Trait("Category", "Integration")]
public class EabAdminApiIntegrationTests : IDisposable
{
    private readonly AdminFactory _factory = new();
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public EabAdminApiIntegrationTests()
    {
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
        _client.Dispose();
        _factory.Dispose();
    }

    // ---- Enforcement ----

    [Fact]
    public async Task Enforcement_Get_DefaultsToOff_WithNoUnboundAccounts()
    {
        var body = await ParseJsonAsync(await _client.GetAsync("/api/acme/eab/enforcement"));

        body.GetProperty("mode").GetString().Should().Be("off");
        body.GetProperty("unboundAccounts").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task Enforcement_Put_HotAppliesToTheDirectoryMeta()
    {
        var put = await PutJsonAsync("/api/acme/eab/enforcement", new { mode = "required" });

        put.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(put);
        body.GetProperty("mode").GetString().Should().Be("required");
        body.GetProperty("message").GetString().Should().Contain("immediately");

        // The same host serves the ACME surface, so the change is visible to
        // the very next directory fetch with no restart.
        (await FetchDirectoryExternalAccountRequiredAsync()).Should().BeTrue();

        (await PutJsonAsync("/api/acme/eab/enforcement", new { mode = "off" }))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await FetchDirectoryExternalAccountRequiredAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task Enforcement_Put_InvalidMode_Returns400()
    {
        var response = await PutJsonAsync("/api/acme/eab/enforcement", new { mode = "sometimes" });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("off, optional, required");
    }

    [Fact]
    public async Task Enforcement_Put_BeforeSetup_Returns409()
    {
        _factory.WriteIncompleteSetup();

        var response = await PutJsonAsync("/api/acme/eab/enforcement", new { mode = "required" });

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Enforcement_Get_CountsOnlyValidUnboundAccounts()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialViaApiAsync("count-check");
        await RegisterBoundAccountAsync(credential);
        var unbound = await RegisterUnboundAccountAsync("mailto:unbound@example.com");

        var before = await ParseJsonAsync(await _client.GetAsync("/api/acme/eab/enforcement"));
        before.GetProperty("unboundAccounts").GetInt32().Should().Be(1);

        // A deactivated unbound account cannot order, so it leaves the
        // grandfathered count.
        var accountRowId = await GetAccountRowIdAsync(unbound.AccountId);
        (await _client.PostAsync($"/api/acme/accounts/{accountRowId}/deactivate", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var after = await ParseJsonAsync(await _client.GetAsync("/api/acme/eab/enforcement"));
        after.GetProperty("unboundAccounts").GetInt32().Should().Be(0);
    }

    // ---- Credentials ----

    [Fact]
    public async Task Credentials_Create_ShowsTheSecretOnce_AndTheListNeverCarriesIt()
    {
        var create = await PostJsonAsync("/api/acme/credentials",
            new { name = "web team", expiresAt = (string?)null });

        create.StatusCode.Should().Be(HttpStatusCode.Created);
        var created = await ParseJsonAsync(create);
        created.GetProperty("keyId").GetString().Should().MatchRegex("^[0-9a-f]{32}$");
        var secret = created.GetProperty("secret").GetString()!;
        secret.Should().HaveLength(43, "32 random bytes base64url encoded");

        var listResponse = await _client.GetAsync("/api/acme/credentials");
        listResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var listJson = await listResponse.Content.ReadAsStringAsync();
        listJson.Should().NotContain(secret,
            "no list response may ever carry a secret, stored or fresh");

        var items = JsonSerializer.Deserialize<JsonElement>(listJson)
            .GetProperty("credentials").EnumerateArray().ToList();
        items.Should().HaveCount(1);
        var row = items[0];
        row.TryGetProperty("secret", out _).Should().BeFalse();
        row.TryGetProperty("secretProtected", out _).Should().BeFalse();
        row.GetProperty("name").GetString().Should().Be("web team");
        row.GetProperty("effectiveStatus").GetString().Should().Be("active");
        row.GetProperty("boundAccountCount").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task Credentials_Create_WithoutName_Returns400()
    {
        var response = await PostJsonAsync("/api/acme/credentials", new { name = "  " });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("name is required");
    }

    [Fact]
    public async Task Credentials_Create_PastExpiry_Returns400()
    {
        var response = await PostJsonAsync("/api/acme/credentials",
            new { name = "stale", expiresAt = DateTime.UtcNow.AddMinutes(-5).ToString("O") });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("future");
    }

    [Fact]
    public async Task Credentials_Regenerate_InvalidatesTheOldSecret_EndToEnd()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialViaApiAsync("rotate-me");

        var regenerate = await _client.PostAsync(
            $"/api/acme/credentials/{credential.Id}/regenerate", null);
        regenerate.StatusCode.Should().Be(HttpStatusCode.OK);
        var regenerated = await ParseJsonAsync(regenerate);
        regenerated.GetProperty("keyId").GetString().Should().Be(credential.KeyId,
            "regenerate rotates the secret on the same key id");
        var newSecret = regenerated.GetProperty("secret").GetString()!;
        newSecret.Should().NotBe(credential.Secret);

        // A registration signed with the old secret is refused; the new
        // secret binds. This is the end to end consequence a dashboard
        // Regenerate click promises.
        var oldKey = NewKey();
        var oldResponse = await PostNewAccountAsync(
            oldKey, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(oldKey)));
        oldResponse.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(oldResponse)).Type.Should().Be(AcmeErrorType.Unauthorized);

        var newKey = NewKey();
        var newResponse = await PostNewAccountAsync(
            newKey, BuildEabJws(credential.KeyId, newSecret, ExportRsaJwk(newKey)));
        newResponse.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task Credentials_Regenerate_UnknownIs404_RevokedIs409()
    {
        (await _client.PostAsync("/api/acme/credentials/9999/regenerate", null))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);

        var credential = await CreateCredentialViaApiAsync("revoked-rotate");
        (await _client.PostAsync($"/api/acme/credentials/{credential.Id}/revoke", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var response = await _client.PostAsync(
            $"/api/acme/credentials/{credential.Id}/regenerate", null);
        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("revoked");
    }

    [Fact]
    public async Task Credentials_Regenerate_ExpiredIs409()
    {
        var credential = await CreateCredentialViaApiAsync("expired-rotate");
        await ExpireCredentialAsync(credential.Id);

        var response = await _client.PostAsync(
            $"/api/acme/credentials/{credential.Id}/regenerate", null);

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("expired");
    }

    [Fact]
    public async Task Credentials_Revoke_SuspendsABoundAccountsOrders_EndToEnd()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialViaApiAsync("revoke-me");
        var account = await RegisterBoundAccountAsync(credential);

        // The account can order while the credential is active.
        var beforeOrder = await PostNewOrderAsync(account.Rsa, account.Kid, "ok.home.local");
        beforeOrder.StatusCode.Should().Be(HttpStatusCode.Created);

        var revoke = await _client.PostAsync(
            $"/api/acme/credentials/{credential.Id}/revoke", null);
        revoke.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ParseJsonAsync(revoke)).GetProperty("status").GetString().Should().Be("revoked");

        // The dashboard Revoke click promises suspension: the very next
        // new-order from the bound account is refused.
        var afterOrder = await PostNewOrderAsync(account.Rsa, account.Kid, "no.home.local");
        afterOrder.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var error = await ReadErrorAsync(afterOrder);
        error.Type.Should().Be(AcmeErrorType.Unauthorized);
        error.Detail.Should().Contain("revoke-me",
            "the refusal names the credential so the admin can be found");
    }

    [Fact]
    public async Task Credentials_Revoke_UnknownIs404_AndRevokeIsIdempotent()
    {
        (await _client.PostAsync("/api/acme/credentials/9999/revoke", null))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);

        var credential = await CreateCredentialViaApiAsync("twice");
        var first = await _client.PostAsync($"/api/acme/credentials/{credential.Id}/revoke", null);
        first.StatusCode.Should().Be(HttpStatusCode.OK);
        var firstRevokedAt = (await ParseJsonAsync(first)).GetProperty("revokedAt").GetDateTime();

        var second = await _client.PostAsync($"/api/acme/credentials/{credential.Id}/revoke", null);
        second.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ParseJsonAsync(second)).GetProperty("revokedAt").GetDateTime()
            .Should().Be(firstRevokedAt, "a second revoke must not restamp");
    }

    [Fact]
    public async Task Credentials_BoundAccounts_ListsTheAccounts()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialViaApiAsync("bound-list");
        var first = await RegisterBoundAccountAsync(credential, "mailto:one@example.com");
        var second = await RegisterBoundAccountAsync(credential, "mailto:two@example.com");

        var response = await _client.GetAsync($"/api/acme/credentials/{credential.Id}/accounts");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var accounts = (await ParseJsonAsync(response)).GetProperty("accounts")
            .EnumerateArray().ToList();
        accounts.Should().HaveCount(2);
        accounts.Select(a => a.GetProperty("accountId").GetString())
            .Should().BeEquivalentTo(new[] { first.AccountId, second.AccountId });

        (await _client.GetAsync("/api/acme/credentials/9999/accounts"))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ---- Accounts ----

    [Fact]
    public async Task Accounts_List_SearchesFiltersAndPages()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialViaApiAsync("web team");
        await RegisterBoundAccountAsync(credential, "mailto:alice@example.com");
        await RegisterBoundAccountAsync(credential, "mailto:bob@example.com");
        var carol = await RegisterUnboundAccountAsync("mailto:carol@example.com");

        // The list moved to the shared PagedResult envelope, so the count is
        // totalCount and the response echoes skip and take.
        var all = await FetchAccountsAsync("");
        all.GetProperty("totalCount").GetInt32().Should().Be(3);
        all.GetProperty("skip").GetInt32().Should().Be(0);
        all.GetProperty("take").GetInt32().Should().Be(50);
        all.GetProperty("hasMore").GetBoolean().Should().BeFalse();
        all.GetProperty("items").EnumerateArray().First()
            .GetProperty("accountId").GetString().Should().Be(carol.AccountId,
                "the list is newest first");

        var bound = await FetchAccountsAsync("?binding=bound");
        bound.GetProperty("totalCount").GetInt32().Should().Be(2);
        bound.GetProperty("items").EnumerateArray()
            .All(a => a.GetProperty("credential").ValueKind == JsonValueKind.Object)
            .Should().BeTrue();

        var unbound = await FetchAccountsAsync("?binding=unbound");
        unbound.GetProperty("totalCount").GetInt32().Should().Be(1);
        var unboundRow = unbound.GetProperty("items").EnumerateArray().Single();
        unboundRow.GetProperty("accountId").GetString().Should().Be(carol.AccountId);
        unboundRow.GetProperty("credential").ValueKind.Should().Be(JsonValueKind.Null);

        var byContact = await FetchAccountsAsync("?search=alice");
        byContact.GetProperty("totalCount").GetInt32().Should().Be(1);

        var byCredentialName = await FetchAccountsAsync(
            $"?search={Uri.EscapeDataString("web team")}");
        byCredentialName.GetProperty("totalCount").GetInt32().Should().Be(2,
            "search matches the bound credential's name");

        var pageOne = await FetchAccountsAsync("?take=2");
        pageOne.GetProperty("totalCount").GetInt32().Should().Be(3);
        pageOne.GetProperty("items").GetArrayLength().Should().Be(2);
        pageOne.GetProperty("hasMore").GetBoolean().Should().BeTrue();
        var pageTwo = await FetchAccountsAsync("?take=2&skip=2");
        pageTwo.GetProperty("items").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task Accounts_List_StatusAndBindingAreIndependentAxes()
    {
        // The reason status is a control of its own rather than more options
        // in the binding select: the two combine with AND, so the set the
        // enforcement policy grandfathers (valid AND unbound) is one query.
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialViaApiAsync("axis-check");
        await RegisterBoundAccountAsync(credential, "mailto:bound-valid@example.com");
        await RegisterUnboundAccountAsync("mailto:unbound-valid@example.com");
        var doomed = await RegisterUnboundAccountAsync("mailto:unbound-gone@example.com");
        (await _client.PostAsync(
            $"/api/acme/accounts/{await GetAccountRowIdAsync(doomed.AccountId)}/deactivate", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        (await FetchAccountsAsync("?status=valid")).GetProperty("totalCount")
            .GetInt32().Should().Be(2);
        (await FetchAccountsAsync("?binding=unbound")).GetProperty("totalCount")
            .GetInt32().Should().Be(2);

        // Narrower than either alone, which a single combined dropdown could
        // not express at all.
        var grandfathered = await FetchAccountsAsync("?status=valid&binding=unbound");
        grandfathered.GetProperty("totalCount").GetInt32().Should().Be(1);
        grandfathered.GetProperty("items").EnumerateArray().Single()
            .GetProperty("contacts").EnumerateArray().Single()
            .GetString().Should().Be("mailto:unbound-valid@example.com");

        (await FetchAccountsAsync("?status=deactivated")).GetProperty("totalCount")
            .GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task Accounts_List_FiltersByCredentialAndRevokedBinding()
    {
        _factory.WriteEabMode("optional");
        var keep = await CreateCredentialViaApiAsync("keep-me");
        var doomed = await CreateCredentialViaApiAsync("revoke-me");
        await RegisterBoundAccountAsync(keep, "mailto:keeper@example.com");
        await RegisterBoundAccountAsync(doomed, "mailto:orphan@example.com");
        await RegisterUnboundAccountAsync("mailto:loose@example.com");

        var byCredential = await FetchAccountsAsync($"?credentialId={keep.Id}");
        byCredential.GetProperty("totalCount").GetInt32().Should().Be(1);
        byCredential.GetProperty("items").EnumerateArray().Single()
            .GetProperty("credential").GetProperty("name").GetString().Should().Be("keep-me");

        // An id matching no credential is an empty page, not an error, so a
        // stale bookmark degrades rather than breaking.
        (await FetchAccountsAsync("?credentialId=99999")).GetProperty("totalCount")
            .GetInt32().Should().Be(0);

        (await _client.PostAsync($"/api/acme/credentials/{doomed.Id}/revoke", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var orphaned = await FetchAccountsAsync("?binding=boundToRevoked");
        orphaned.GetProperty("totalCount").GetInt32().Should().Be(1);
        orphaned.GetProperty("items").EnumerateArray().Single()
            .GetProperty("credential").GetProperty("name").GetString().Should().Be("revoke-me");
    }

    [Fact]
    public async Task Accounts_List_ActivityAndLastOrderRangeDisagreeOnNeverOrdered()
    {
        // The pair most likely to be broken by a later refactor. An idle
        // window includes an account that never ordered, because it has
        // indeed not ordered in 90 days. A range filter on the last order
        // date excludes it, because it has no such date.
        _factory.WriteEabMode("off");
        var orderer = await RegisterUnboundAccountAsync("mailto:busy@example.com");
        (await PostNewOrderAsync(orderer.Rsa, orderer.Kid, "busy.home.local"))
            .StatusCode.Should().Be(HttpStatusCode.Created);
        await RegisterUnboundAccountAsync("mailto:idle@example.com");

        (await FetchAccountsAsync("?activity=never")).GetProperty("totalCount")
            .GetInt32().Should().Be(1);
        (await FetchAccountsAsync("?activity=idle90")).GetProperty("totalCount")
            .GetInt32().Should().Be(1, "the never ordered account has not ordered in 90 days");
        (await FetchAccountsAsync("?activity=active7")).GetProperty("totalCount")
            .GetInt32().Should().Be(1, "only the account that just ordered");

        var tomorrow = Uri.EscapeDataString(
            DateTime.UtcNow.AddDays(1).ToString("O"));
        var beforeTomorrow = await FetchAccountsAsync($"?lastOrderBefore={tomorrow}");
        beforeTomorrow.GetProperty("totalCount").GetInt32().Should().Be(1,
            "a range on the last order date never matches an account without one");
        beforeTomorrow.GetProperty("items").EnumerateArray().Single()
            .GetProperty("accountId").GetString().Should().Be(orderer.AccountId);
    }

    [Fact]
    public async Task Accounts_List_FiltersByRegisteredRange()
    {
        _factory.WriteEabMode("off");
        await RegisterUnboundAccountAsync("mailto:dated@example.com");

        var yesterday = Uri.EscapeDataString(DateTime.UtcNow.AddDays(-1).ToString("O"));
        var tomorrow = Uri.EscapeDataString(DateTime.UtcNow.AddDays(1).ToString("O"));

        (await FetchAccountsAsync($"?registeredAfter={yesterday}&registeredBefore={tomorrow}"))
            .GetProperty("totalCount").GetInt32().Should().Be(1);

        // Exclusive upper bound: a window that ends before the row was made
        // excludes it, even though the row is inside the day.
        (await FetchAccountsAsync($"?registeredBefore={yesterday}"))
            .GetProperty("totalCount").GetInt32().Should().Be(0);
        (await FetchAccountsAsync($"?registeredAfter={tomorrow}"))
            .GetProperty("totalCount").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task Accounts_List_SortsByTheColumnsTheTableOffers()
    {
        // The level that proves the exact query string the frontend puts on
        // the wire binds and reaches the sort switch.
        _factory.WriteEabMode("off");
        await RegisterUnboundAccountAsync("mailto:one@example.com");
        await RegisterUnboundAccountAsync("mailto:two@example.com");
        await RegisterUnboundAccountAsync("mailto:three@example.com");

        var ascending = await ReadAccountIdsAsync("?sortBy=accountId");
        ascending.Should().BeInAscendingOrder();

        var descending = await ReadAccountIdsAsync("?sortBy=accountId&sortDesc=true");
        descending.Should().BeInDescendingOrder();
        descending.Should().BeEquivalentTo(ascending);

        // An unknown key is a silent fallthrough to the default order, not an
        // error: unlike a filter, a sort that quietly uses the default cannot
        // misrepresent which rows are in the list.
        var unknown = await ReadAccountIdsAsync("?sortBy=nonsense");
        var byDefault = await ReadAccountIdsAsync("");
        unknown.Should().Equal(byDefault);
    }

    [Fact]
    public async Task Accounts_List_InvalidFilterNames_Return400()
    {
        var binding = await _client.GetAsync("/api/acme/accounts?binding=sideways");
        binding.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(binding)).GetProperty("error").GetString()
            .Should().Contain("all, bound, unbound, boundToRevoked");

        var status = await _client.GetAsync("/api/acme/accounts?status=lapsed");
        status.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(status)).GetProperty("error").GetString()
            .Should().Contain("all, valid, deactivated");

        var activity = await _client.GetAsync("/api/acme/accounts?activity=sometimes");
        activity.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(activity)).GetProperty("error").GetString()
            .Should().Contain("idle90");

        // "revoked" is a status RFC 8555 defines but nothing here writes, so
        // the filter refuses it rather than offering a control that could
        // only ever return an empty list.
        (await _client.GetAsync("/api/acme/accounts?status=revoked"))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    private async Task<List<string>> ReadAccountIdsAsync(string query)
    {
        var body = await FetchAccountsAsync(query);
        return body.GetProperty("items").EnumerateArray()
            .Select(a => a.GetProperty("accountId").GetString()!)
            .ToList();
    }

    [Fact]
    public async Task Accounts_Deactivate_FlipsAcmeTo401_AndInvalidatesOpenOrders()
    {
        _factory.WriteEabMode("off");
        var account = await RegisterUnboundAccountAsync("mailto:doomed@example.com");
        (await PostNewOrderAsync(account.Rsa, account.Kid, "open.home.local"))
            .StatusCode.Should().Be(HttpStatusCode.Created);
        var accountRowId = await GetAccountRowIdAsync(account.AccountId);

        var deactivate = await _client.PostAsync(
            $"/api/acme/accounts/{accountRowId}/deactivate", null);

        deactivate.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(deactivate);
        body.GetProperty("status").GetString().Should().Be("deactivated");
        body.GetProperty("invalidatedOrders").GetInt32().Should().Be(1);

        // Every later request the account signs is refused by the existing
        // kid status check, with the 401 RFC 8555 §7.3.6 names for a request
        // from a deactivated account.
        var afterOrder = await PostNewOrderAsync(account.Rsa, account.Kid, "late.home.local");
        afterOrder.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await ReadErrorAsync(afterOrder)).Type.Should().Be(AcmeErrorType.Unauthorized);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var orders = await db.AcmeOrders.AsNoTracking()
                .Where(o => o.AccountId == accountRowId).ToListAsync();
            orders.Should().OnlyContain(o => o.Status == "invalid",
                "the open order was invalidated together with the account");
        }

        // Deactivation is terminal; a second attempt reports the state.
        var again = await _client.PostAsync(
            $"/api/acme/accounts/{accountRowId}/deactivate", null);
        again.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ParseJsonAsync(again)).GetProperty("error").GetString()
            .Should().Contain("deactivated");
    }

    [Fact]
    public async Task Accounts_Deactivate_Unknown_Returns404()
    {
        (await _client.PostAsync("/api/acme/accounts/9999/deactivate", null))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Accounts_Deactivated_AreNeverBoundByAReRegistration()
    {
        // Deactivation is terminal (RFC 8555 §7.3.6). A client re-running
        // registration for a deactivated account with a valid binding is
        // refused outright, and in particular the account must not be mutated
        // into a working looking bound account.
        _factory.WriteEabMode("optional");
        var account = await RegisterUnboundAccountAsync("mailto:gone@example.com");
        var accountRowId = await GetAccountRowIdAsync(account.AccountId);
        (await _client.PostAsync($"/api/acme/accounts/{accountRowId}/deactivate", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var credential = await CreateCredentialViaApiAsync("late-binding");
        var response = await PostNewAccountAsync(
            account.Rsa,
            BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(account.Rsa)),
            "mailto:gone@example.com");

        // Since #168 new-account carries the same status guard the kid path has,
        // so a deactivated key is refused here too rather than handed its own
        // account object back.
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "a deactivated key can no longer register or re-register");
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Unauthorized);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.AcmeAccounts.AsNoTracking()
            .SingleAsync(a => a.Id == accountRowId);
        row.Status.Should().Be("deactivated");
        row.ExternalAccountCredentialId.Should().BeNull(
            "a terminal account never adopts a binding");
    }

    #region Test Helpers

    private sealed record CredentialInfo(int Id, string KeyId, string Secret);

    private sealed record AccountInfo(string Kid, string AccountId, RSA Rsa);

    private string NewAccountUrl => $"{_client.BaseAddress}acme/WebServer/new-account";

    private RSA NewKey()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        return rsa;
    }

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

    private async Task<JsonElement> FetchAccountsAsync(string queryString)
    {
        var response = await _client.GetAsync($"/api/acme/accounts{queryString}");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return await ParseJsonAsync(response);
    }

    private async Task<bool> FetchDirectoryExternalAccountRequiredAsync()
    {
        var response = await _client.GetAsync("/acme/WebServer/directory");
        response.EnsureSuccessStatusCode();
        var directory = JsonSerializer.Deserialize<AcmeDirectory>(
            await response.Content.ReadAsStringAsync());
        return directory!.Meta!.ExternalAccountRequired;
    }

    private async Task<CredentialInfo> CreateCredentialViaApiAsync(string name)
    {
        var response = await PostJsonAsync("/api/acme/credentials", new { name });
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var body = await ParseJsonAsync(response);
        return new CredentialInfo(
            body.GetProperty("id").GetInt32(),
            body.GetProperty("keyId").GetString()!,
            body.GetProperty("secret").GetString()!);
    }

    private async Task<AccountInfo> RegisterBoundAccountAsync(
        CredentialInfo credential, string contact = "mailto:bound@example.com")
    {
        var rsa = NewKey();
        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa)), contact);
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var kid = response.Headers.GetValues("Location").First();
        return new AccountInfo(kid, kid.Split('/').Last(), rsa);
    }

    private async Task<AccountInfo> RegisterUnboundAccountAsync(string contact)
    {
        var rsa = NewKey();
        var response = await PostNewAccountAsync(rsa, contact: contact);
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var kid = response.Headers.GetValues("Location").First();
        return new AccountInfo(kid, kid.Split('/').Last(), rsa);
    }

    private async Task ExpireCredentialAsync(int id)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.EabCredentials.SingleAsync(c => c.Id == id);
        row.ExpiresAt = DateTime.UtcNow.AddMinutes(-5);
        await db.SaveChangesAsync();
    }

    private async Task<int> GetAccountRowIdAsync(string accountId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.AcmeAccounts.AsNoTracking()
            .SingleAsync(a => a.AccountId == accountId);
        return row.Id;
    }

    private static async Task<AcmeError> ReadErrorAsync(HttpResponseMessage response)
    {
        response.Content.Headers.ContentType?.MediaType
            .Should().Be("application/problem+json");
        return JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync())!;
    }

    private JwsFlattenedRequest BuildEabJws(string kid, string secret, string outerJwkJson)
    {
        var headerJson = $$"""{"alg":"HS256","kid":"{{kid}}","url":"{{NewAccountUrl}}"}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(outerJwkJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = HMACSHA256.HashData(JwsService.Base64UrlDecode(secret), signingInput);

        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        };
    }

    private async Task<HttpResponseMessage> PostNewAccountAsync(
        RSA rsa, JwsFlattenedRequest? eab = null, string contact = "mailto:admin@example.com")
    {
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var request = new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { contact },
            ExternalAccountBinding = eab != null
                ? JsonSerializer.SerializeToElement(eab)
                : null,
        };
        var payloadJson = JsonSerializer.Serialize(request);

        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{NewAccountUrl}}","jwk":{{jwkJson}}}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(
            signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var jws = new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        };

        return await PostJws("/acme/WebServer/new-account", jws);
    }

    private async Task<HttpResponseMessage> PostNewOrderAsync(
        RSA rsa, string kid, params string[] domains)
    {
        var nonce = await GetFreshNonce();
        var payload = new NewOrderRequest
        {
            Identifiers = domains
                .Select(d => new AcmeIdentifier { Type = "dns", Value = d })
                .ToArray(),
        };

        var url = $"{_client.BaseAddress}acme/WebServer/new-order";
        var payloadJson = JsonSerializer.Serialize(payload);
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(
            signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var jws = new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        };

        return await PostJws("/acme/WebServer/new-order", jws);
    }

    private async Task<string> GetFreshNonce()
    {
        var response = await _client.GetAsync("/acme/WebServer/new-nonce");
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    private async Task<HttpResponseMessage> PostJws(string url, JwsFlattenedRequest jws)
    {
        var json = JsonSerializer.Serialize(jws);
        var content = new StringContent(json, Encoding.UTF8, "application/jose+json");
        return await _client.PostAsync(url, content);
    }

    private static string ExportRsaJwk(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var n = JwsService.Base64UrlEncode(p.Modulus!);
        var e = JwsService.Base64UrlEncode(p.Exponent!);
        return $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
    }

    #endregion

    /// <summary>
    /// Test factory following the EabFactory pattern: a completed setup with
    /// EAB off is seeded before the host builds, tests rewrite the mode (or
    /// break the setup) as they need, and every write bumps the file's write
    /// time monotonically so the hot reading policy always notices.
    /// </summary>
    private sealed class AdminFactory : CertusWebApplicationFactory
    {
        private static long _writeCounter;

        private string StatusFilePath => Path.Combine(TempDataDir, SetupStatus.FileName);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            WriteEabMode("off");
        }

        public void WriteEabMode(string mode)
        {
            WriteStatus(new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = ["WebServer"],
                EabEnforcement = mode,
            });
        }

        /// <summary>An install whose wizard never finished, for the 409 guard.</summary>
        public void WriteIncompleteSetup()
        {
            WriteStatus(new SetupStatus { SetupCompleted = false });
        }

        private void WriteStatus(SetupStatus status)
        {
            status.Save(StatusFilePath);
            var bump = Interlocked.Increment(ref _writeCounter);
            File.SetLastWriteTimeUtc(StatusFilePath, DateTime.UtcNow.AddSeconds(bump));
        }
    }
}
