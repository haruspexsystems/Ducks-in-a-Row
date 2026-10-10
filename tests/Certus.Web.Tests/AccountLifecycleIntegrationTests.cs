using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the account resource, POST /acme/{template}/acct/{accountId}.
/// Three operations share that URL and are told apart by the payload: a lookup
/// (POST-as-GET), a contact update (RFC 8555 §7.3.2), and a deactivation (§7.3.6).
///
/// The endpoint used to implement only the lookup, so an update or a deactivation was
/// answered 200 and discarded (issue #168). A client that deactivated a compromised
/// account key was told it had succeeded and could still order certificates. These tests
/// pin all three operations, and pin the terminal half of deactivation: the account, its
/// open orders, and the key itself all stop working.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class AccountLifecycleIntegrationTests : IDisposable
{
    private const string NewAccountPath = "/acme/WebServer/new-account";
    private const string NewOrderPath = "/acme/WebServer/new-order";

    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AccountLifecycleIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
    }

    // ---- Contact update (RFC 8555 §7.3.2) ----

    [Fact]
    public async Task Update_ReplacesTheContact_AndItRoundTripsThroughPostAsGet()
    {
        // The QA suite's A2 and A3 in one: the update is accepted, and the new contact
        // is what a later read reports. A2 alone passed before the fix, because a 200
        // that discarded the payload looks exactly like a 200 that applied it.
        var (account, key) = await CreateAccountAsync("mailto:before@example.com");

        var update = await PostToAccountAsync(
            key, account, """{"contact":["mailto:after@example.com"]}""");

        update.StatusCode.Should().Be(HttpStatusCode.OK);
        ContactsOf(await ReadJsonAsync(update)).Should().Equal("mailto:after@example.com");

        var read = await PostToAccountAsync(key, account, string.Empty);
        read.StatusCode.Should().Be(HttpStatusCode.OK);
        ContactsOf(await ReadJsonAsync(read)).Should().Equal(
            new[] { "mailto:after@example.com" },
            "the update has to survive the request that made it");
    }

    [Fact]
    public async Task Update_WithAnEmptyContactArray_ClearsTheContact()
    {
        var (account, key) = await CreateAccountAsync("mailto:clear-me@example.com");

        var update = await PostToAccountAsync(key, account, """{"contact":[]}""");

        update.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadJsonAsync(update);
        body.TryGetProperty("contact", out _).Should().BeFalse(
            "a cleared contact list reads the same as one that was never set");
    }

    [Fact]
    public async Task Update_IgnoresTermsOfServiceAgreedAndUnrecognisedMembers()
    {
        // RFC 8555 §7.3.2: the server "MUST ignore any updates to the 'orders' field,
        // 'termsOfServiceAgreed' field, the 'status' field (except as allowed by Section
        // 7.3.6), or any other fields it does not recognize". Ignore, not refuse.
        var (account, key) = await CreateAccountAsync("mailto:tos@example.com");

        var update = await PostToAccountAsync(key, account,
            """{"termsOfServiceAgreed":false,"orders":"https://evil.example/orders","wat":1}""");

        update.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadJsonAsync(update);
        body.GetProperty("termsOfServiceAgreed").GetBoolean().Should().BeTrue(
            "agreement was given at registration and an update cannot withdraw it");
        body.GetProperty("orders").GetString().Should().Contain($"/acct/{account.AccountId}/orders",
            "the orders URL is the server's to publish");
        ContactsOf(body).Should().Equal(
            new[] { "mailto:tos@example.com" }, "nothing asked to change it");
    }

    [Fact]
    public async Task Update_WithAStatusOtherThanDeactivated_IsIgnored()
    {
        // Only "deactivated" is actionable. Anything else is ignored rather than
        // refused, and in particular a client cannot drive its own status anywhere.
        var (account, key) = await CreateAccountAsync("mailto:status@example.com");

        var update = await PostToAccountAsync(key, account, """{"status":"revoked"}""");

        update.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(update)).GetProperty("status").GetString().Should().Be("valid");

        // Still fully usable: the ignored status changed nothing.
        (await PostNewOrderAsync(key, account.Kid, "still-here.example.com"))
            .StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task Update_WithAnOverlongContact_IsRefused_AndKeepsTheStoredContact()
    {
        var (account, key) = await CreateAccountAsync("mailto:keep@example.com");
        var overlong = "mailto:" + new string('a', 300) + "@example.com";

        var update = await PostToAccountAsync(
            key, account, $$"""{"contact":["{{overlong}}"]}""");

        update.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(update)).Type.Should().Be(AcmeErrorType.InvalidContact);

        var read = await PostToAccountAsync(key, account, string.Empty);
        ContactsOf(await ReadJsonAsync(read)).Should().Equal(
            new[] { "mailto:keep@example.com" },
            "a refused update must not have written anything");
    }

    [Fact]
    public async Task NewAccount_WithTooManyContacts_IsRefused()
    {
        // The same guard on the registration path, so a list the update endpoint would
        // refuse cannot be smuggled in at creation instead.
        var key = NewKey();
        var contacts = string.Join(",",
            Enumerable.Range(0, 25).Select(i => $"\"mailto:c{i}@example.com\""));

        var response = await PostNewAccountAsync(
            key, $$"""{"termsOfServiceAgreed":true,"contact":[{{contacts}}]}""");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.InvalidContact);
    }

    [Fact]
    public async Task EmptyPayload_IsStillPostAsGet_AndChangesNothing()
    {
        // The read path is what every ACME client uses to fetch its account, and the
        // branch added for updates must not have moved it.
        var (account, key) = await CreateAccountAsync("mailto:read-only@example.com");

        var read = await PostToAccountAsync(key, account, string.Empty);

        read.StatusCode.Should().Be(HttpStatusCode.OK);
        read.Headers.GetValues("Location").Single()
            .Should().Contain($"/acct/{account.AccountId}");
        var body = await ReadJsonAsync(read);
        body.GetProperty("status").GetString().Should().Be("valid");
        ContactsOf(body).Should().Equal("mailto:read-only@example.com");
    }

    // ---- Deactivation (RFC 8555 §7.3.6) ----

    [Fact]
    public async Task Deactivate_IsAccepted_AndTheSameResponseReportsDeactivated()
    {
        // The QA suite's C1. A 2xx that still reports "valid" is the dangerous middle:
        // the caller believes the account is dead and it is not.
        var (account, key) = await CreateAccountAsync("mailto:doomed@example.com");

        var response = await PostToAccountAsync(key, account, """{"status":"deactivated"}""");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(response)).GetProperty("status").GetString()
            .Should().Be("deactivated", "§7.3.2 returns the RESULTING account object");

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var stored = await db.AcmeAccounts.AsNoTracking()
            .FirstAsync(a => a.AccountId == account.AccountId);
        stored.Status.Should().Be("deactivated", "and the response has to match the row");
    }

    [Fact]
    public async Task Deactivate_CancelsTheAccountsOpenOrders()
    {
        // RFC 8555 §7.3.6: "the server SHOULD cancel any pending operations authorized
        // by the account's key, such as certificate orders".
        var (account, key) = await CreateAccountAsync("mailto:orders@example.com");
        (await PostNewOrderAsync(key, account.Kid, "open.example.com"))
            .StatusCode.Should().Be(HttpStatusCode.Created);

        (await PostToAccountAsync(key, account, """{"status":"deactivated"}"""))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.AcmeAccounts.AsNoTracking()
            .FirstAsync(a => a.AccountId == account.AccountId);
        var orders = await db.AcmeOrders.AsNoTracking()
            .Where(o => o.AccountId == row.Id).ToListAsync();
        orders.Should().NotBeEmpty();
        orders.Should().OnlyContain(o => o.Status == "invalid");
    }

    [Fact]
    public async Task Deactivate_LeavesAProcessingOrderAlone()
    {
        // Issue #312. §7.3.6 says to cancel pending operations, and an order already
        // claimed by a finalize is not one this server can still cancel: its CSR is
        // at the CA, which has no idea the account just died. Writing "invalid" over
        // it collides with the completion, and one of the two writes is lost.
        //
        // The sibling above seeds only a pending order, so on its own it cannot tell
        // "cancelled everything open" from "cancelled everything". This one supplies
        // the contrast.
        var (account, key) = await CreateAccountAsync("mailto:claimed@example.com");
        (await PostNewOrderAsync(key, account.Kid, "acct-open.example.com"))
            .StatusCode.Should().Be(HttpStatusCode.Created);
        (await PostNewOrderAsync(key, account.Kid, "acct-claimed.example.com"))
            .StatusCode.Should().Be(HttpStatusCode.Created);

        // Network challenge validation does not run under TestServer, so a claimed
        // order can only be minted by writing the row, the idiom this suite already
        // uses for "valid" and "ready".
        using (var seed = _factory.Services.CreateScope())
        {
            var seedDb = seed.ServiceProvider.GetRequiredService<CertusDbContext>();
            var claimed = await seedDb.AcmeOrders
                .FirstAsync(o => o.IdentifiersJson.Contains("acct-claimed.example.com"));
            claimed.Status = "processing";
            await seedDb.SaveChangesAsync();
        }

        (await PostToAccountAsync(key, account, """{"status":"deactivated"}"""))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.AcmeAccounts.AsNoTracking()
            .FirstAsync(a => a.AccountId == account.AccountId);
        var orders = await db.AcmeOrders.AsNoTracking()
            .Where(o => o.AccountId == row.Id).ToListAsync();

        orders.Should().HaveCount(2);
        orders.Single(o => o.IdentifiersJson.Contains("acct-open.example.com"))
            .Status.Should().Be("invalid");
        orders.Single(o => o.IdentifiersJson.Contains("acct-claimed.example.com"))
            .Status.Should().Be("processing",
                "its CSR is at the CA and the finalize that claimed it owns the outcome");
    }

    [Fact]
    public async Task Deactivate_ThenNewOrder_IsRefused()
    {
        // The QA suite's C2, and the whole point of the issue: an account that reports
        // itself deactivated while still issuing offers a false revocation.
        var (account, key) = await CreateAccountAsync("mailto:no-more@example.com");
        (await PostToAccountAsync(key, account, """{"status":"deactivated"}"""))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var order = await PostNewOrderAsync(key, account.Kid, "too-late.example.com");

        order.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "RFC 8555 §7.3.6 names 401 for a request from a deactivated account");
        (await ReadErrorAsync(order)).Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task Deactivate_ThenPostAsGet_IsRefused()
    {
        var (account, key) = await CreateAccountAsync("mailto:gone@example.com");
        (await PostToAccountAsync(key, account, """{"status":"deactivated"}"""))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var read = await PostToAccountAsync(key, account, string.Empty);

        read.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "§7.3.6 names POST-as-GET explicitly, not only state changing requests");
        (await ReadErrorAsync(read)).Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task Deactivate_ThenNewAccountWithTheSameKey_IsRefused()
    {
        // new-account authenticates with an embedded jwk, so it is the one route that
        // does not pass the kid status check. Without its own guard a deactivated key
        // would still get 200 and its account object back from this one endpoint.
        var (account, key) = await CreateAccountAsync("mailto:reregister@example.com");
        (await PostToAccountAsync(key, account, """{"status":"deactivated"}"""))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var register = await PostNewAccountAsync(key, """{"termsOfServiceAgreed":true}""");
        register.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await ReadErrorAsync(register)).Type.Should().Be(AcmeErrorType.Unauthorized);

        var lookup = await PostNewAccountAsync(key, """{"onlyReturnExisting":true}""");
        lookup.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "the lookup path returns an existing account too, so it needs the same guard");
    }

    [Fact]
    public async Task Deactivate_WithAContactInTheSamePayload_DeactivatesAndDoesNotWriteTheContact()
    {
        // Deactivation wins. Writing the contact first would be writing to something
        // nobody can read back, since every later request from this key is refused.
        var (account, key) = await CreateAccountAsync("mailto:original@example.com");

        var response = await PostToAccountAsync(key, account,
            """{"status":"deactivated","contact":["mailto:ignored@example.com"]}""");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadJsonAsync(response);
        body.GetProperty("status").GetString().Should().Be("deactivated");
        ContactsOf(body).Should().Equal("mailto:original@example.com");

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var stored = await db.AcmeAccounts.AsNoTracking()
            .FirstAsync(a => a.AccountId == account.AccountId);
        stored.ContactJson.Should().Contain("original@example.com");
        stored.ContactJson.Should().NotContain("ignored@example.com");
    }

    [Fact]
    public async Task Deactivate_Twice_IsRefusedBeforeItReachesTheHandler()
    {
        // Deactivation is terminal and there is no route back: the second attempt is
        // stopped by the kid status check, not by anything in the account handler.
        var (account, key) = await CreateAccountAsync("mailto:twice@example.com");
        (await PostToAccountAsync(key, account, """{"status":"deactivated"}"""))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var again = await PostToAccountAsync(key, account, """{"status":"deactivated"}""");

        again.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await ReadErrorAsync(again)).Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task Deactivate_LeavesOtherAccountsAlone()
    {
        // A guard against the deactivation being wired to something broader than the
        // one account that signed for it.
        var (doomed, doomedKey) = await CreateAccountAsync("mailto:doomed-a@example.com");
        var (survivor, survivorKey) = await CreateAccountAsync("mailto:survivor@example.com");

        (await PostToAccountAsync(doomedKey, doomed, """{"status":"deactivated"}"""))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var read = await PostToAccountAsync(survivorKey, survivor, string.Empty);
        read.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(read)).GetProperty("status").GetString().Should().Be("valid");
    }

    #region Helpers

    private sealed record AccountInfo(string Kid, string AccountId);

    private RSA NewKey()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        return rsa;
    }

    /// <summary>Registers an account and returns its URL and the key that controls it.</summary>
    private async Task<(AccountInfo Account, RSA Key)> CreateAccountAsync(string contact)
    {
        var key = NewKey();
        var response = await PostNewAccountAsync(
            key, $$"""{"termsOfServiceAgreed":true,"contact":["{{contact}}"]}""");

        var body = await response.Content.ReadAsStringAsync();
        response.IsSuccessStatusCode.Should().BeTrue(
            "every test here builds its account through this helper; the status was " +
            "{0} and the body was {1}", response.StatusCode, body);

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), key);
    }

    /// <summary>
    /// Posts a kid authenticated request to the account URL. An empty payload is a
    /// POST-as-GET; anything else is an update (RFC 8555 §7.3.2 or §7.3.6).
    /// </summary>
    private async Task<HttpResponseMessage> PostToAccountAsync(
        RSA key, AccountInfo account, string payloadJson)
    {
        var path = $"/acme/WebServer/acct/{account.AccountId}";
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(path);
        var headerJson =
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{account.Kid}}"}""";
        return await PostJws(path, SignJws(key, headerJson, payloadJson));
    }

    private async Task<HttpResponseMessage> PostNewAccountAsync(RSA key, string payloadJson)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(NewAccountPath);
        var jwkJson = ExportRsaJwk(key);
        var headerJson =
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";
        return await PostJws(NewAccountPath, SignJws(key, headerJson, payloadJson));
    }

    private async Task<HttpResponseMessage> PostNewOrderAsync(RSA key, string kid, string domain)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(NewOrderPath);
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        var payloadJson =
            $$"""{"identifiers":[{"type":"dns","value":"{{domain}}"}]}""";
        return await PostJws(NewOrderPath, SignJws(key, headerJson, payloadJson));
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
    }

    private static async Task<AcmeError> ReadErrorAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<AcmeError>(body)
            ?? throw new InvalidOperationException($"Not a problem document: {body}");
    }

    /// <summary>
    /// The contact list of an account object, or an empty list when the member is
    /// absent. Absent and empty are different states on the wire, and the tests that
    /// care about the difference check TryGetProperty themselves.
    /// </summary>
    private static string[] ContactsOf(JsonElement account)
    {
        if (!account.TryGetProperty("contact", out var contact))
            return Array.Empty<string>();

        return contact.EnumerateArray().Select(c => c.GetString()!).ToArray();
    }

    private string ToAbsoluteUrl(string path)
    {
        var encodedPath = new Microsoft.AspNetCore.Http.PathString(path).ToUriComponent();
        return $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";
    }

    private static JwsFlattenedRequest SignJws(RSA rsa, string headerJson, string payloadJson)
    {
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = string.IsNullOrEmpty(payloadJson)
            ? string.Empty
            : JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };
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
}
