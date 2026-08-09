using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
/// Integration tests for per credential domain namespaces (issue #130): a
/// bound account may only order inside its credential's namespace, the global
/// allowed domain list stays the ceiling and the namespace narrows within it,
/// unbound accounts are unaffected, namespace edits hot apply, the finalize
/// re-check leaves the order ready, and the admin create and update endpoints
/// validate entries with the settings endpoint's { error, invalidEntries }
/// shape. Each test gets its own factory (fresh database and status file).
/// </summary>
[Trait("Category", "Integration")]
public class EabNamespaceIntegrationTests : IDisposable
{
    private readonly NamespaceFactory _factory = new();
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public EabNamespaceIntegrationTests()
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

    // ---- Order time enforcement ----

    [Fact]
    public async Task NewOrder_InsideTheNamespace_IsCreated()
    {
        var credential = await CreateCredentialViaApiAsync("scoped", "home.local");
        var account = await RegisterBoundAccountAsync(credential);

        var response = await PostNewOrderAsync(account.Rsa, account.Kid,
            "web.home.local", "home.local");

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task NewOrder_OutsideTheNamespace_IsRefused_WithSubproblemsAndAnAuditRow()
    {
        var credential = await CreateCredentialViaApiAsync("web team", "home.local");
        var account = await RegisterBoundAccountAsync(credential);

        var response = await PostNewOrderAsync(account.Rsa, account.Kid,
            "ok.home.local", "evil.example");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Detail.Should().Contain("web team",
            "the refusal names the credential so the client knows which scope applied");
        error.Detail.Should().Contain("evil.example");
        var subproblem = error.Subproblems.Should().ContainSingle(
            "only the identifier outside the namespace is a subproblem").Subject;
        subproblem.Identifier!.Value.Should().Be("evil.example");
        subproblem.Detail.Should().Contain("web team");

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var audit = await db.DomainPolicyRejections.AsNoTracking().SingleAsync();
        audit.Stage.Should().Be("newOrder-eab",
            "the activity feed tells a namespace refusal from a global policy one");
        audit.AccountId.Should().Be(account.AccountId);
        audit.RejectedIdentifiers.Should().Be("evil.example");
    }

    [Fact]
    public async Task NewOrder_TheGlobalListStaysTheCeiling()
    {
        // A namespace entry outside the global allowed domain list never
        // widens issuance: the global check runs first and refuses it, and
        // names inside the global list are still outside this namespace.
        _factory.WritePolicy(allowedDomainsEnabled: true, "home.local");
        var credential = await CreateCredentialViaApiAsync("outside", "lab.example");
        var account = await RegisterBoundAccountAsync(credential);

        var globalRefusal = await PostNewOrderAsync(account.Rsa, account.Kid, "app.lab.example");
        globalRefusal.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(globalRefusal)).Detail.Should().Contain("Settings page",
            "the global policy refuses first; the namespace entry gave the credential nothing");

        var namespaceRefusal = await PostNewOrderAsync(account.Rsa, account.Kid, "web.home.local");
        namespaceRefusal.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(namespaceRefusal)).Detail.Should().Contain("outside",
            "a name inside the global ceiling is still outside the credential's namespace");
    }

    [Fact]
    public async Task NewOrder_TheNamespaceNarrowsWithinTheGlobalList()
    {
        _factory.WritePolicy(allowedDomainsEnabled: true, "home.local");
        var credential = await CreateCredentialViaApiAsync("narrow", "web.home.local");
        var account = await RegisterBoundAccountAsync(credential);

        var outsideNamespace = await PostNewOrderAsync(account.Rsa, account.Kid, "api.home.local");
        outsideNamespace.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(outsideNamespace);
        error.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Detail.Should().Contain("narrow",
            "the name passes the global list, so the namespace is what refuses it");

        (await PostNewOrderAsync(account.Rsa, account.Kid, "x.web.home.local"))
            .StatusCode.Should().Be(HttpStatusCode.Created,
                "the intersection of the global list and the namespace allows this name");
    }

    [Fact]
    public async Task NewOrder_UnboundAccount_IsUnaffectedByNamespaces()
    {
        // Namespaces travel with a credential; an unbound (grandfathered)
        // account has none, and other credentials' namespaces are not global
        // state.
        await CreateCredentialViaApiAsync("someone else", "home.local");
        var account = await RegisterUnboundAccountAsync("mailto:free@example.com");

        (await PostNewOrderAsync(account.Rsa, account.Kid, "anything.example"))
            .StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task NewOrder_EmptyNamespace_AddsNoRestriction()
    {
        var credential = await CreateCredentialViaApiAsync("unscoped");
        var account = await RegisterBoundAccountAsync(credential);

        (await PostNewOrderAsync(account.Rsa, account.Kid, "anything.example"))
            .StatusCode.Should().Be(HttpStatusCode.Created,
                "an empty namespace means no extra restriction, never refuse everything");
    }

    [Fact]
    public async Task NewOrder_WildcardIdentifier_AllowedExactlyWhenTheBaseIs()
    {
        var credential = await CreateCredentialViaApiAsync("wild", "home.local");
        var account = await RegisterBoundAccountAsync(credential);

        (await PostNewOrderAsync(account.Rsa, account.Kid, "*.home.local"))
            .StatusCode.Should().Be(HttpStatusCode.Created);

        (await PostNewOrderAsync(account.Rsa, account.Kid, "*.other.local"))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task NamespaceEdits_HotApplyToTheNextOrder()
    {
        var credential = await CreateCredentialViaApiAsync("editable", "home.local");
        var account = await RegisterBoundAccountAsync(credential);
        (await PostNewOrderAsync(account.Rsa, account.Kid, "a.home.local"))
            .StatusCode.Should().Be(HttpStatusCode.Created);

        // The admin tightens the namespace; no restart, no re-registration.
        var update = await PutJsonAsync($"/api/acme/credentials/{credential.Id}",
            new { name = "editable", expiresAt = (string?)null, domains = new[] { "web.home.local" } });
        update.StatusCode.Should().Be(HttpStatusCode.OK);

        (await PostNewOrderAsync(account.Rsa, account.Kid, "b.home.local"))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest,
                "the order gate reads the credential per request, so the edit is already in force");
        (await PostNewOrderAsync(account.Rsa, account.Kid, "c.web.home.local"))
            .StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task Update_MovingTheExpiryForward_RevivesAnExpiredCredential_EndToEnd()
    {
        var credential = await CreateCredentialViaApiAsync("lapsed");
        var account = await RegisterBoundAccountAsync(credential);
        await ExpireCredentialAsync(credential.Id);

        var suspended = await PostNewOrderAsync(account.Rsa, account.Kid, "down.home.local");
        suspended.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(suspended)).Detail.Should().Contain("expired");

        var revive = await PutJsonAsync($"/api/acme/credentials/{credential.Id}",
            new
            {
                name = "lapsed",
                expiresAt = DateTime.UtcNow.AddDays(7).ToString("O"),
                domains = Array.Empty<string>(),
            });
        revive.StatusCode.Should().Be(HttpStatusCode.OK);

        (await PostNewOrderAsync(account.Rsa, account.Kid, "up.home.local"))
            .StatusCode.Should().Be(HttpStatusCode.Created,
                "moving the expiry forward puts the credential and its accounts back in use");
    }

    [Fact]
    public async Task Finalize_RechecksTheNamespace_AndTheOrderStaysReady()
    {
        var credential = await CreateCredentialViaApiAsync("finalize-scope", "home.local");
        var account = await RegisterBoundAccountAsync(credential);

        var orderResponse = await PostNewOrderAsync(account.Rsa, account.Kid, "fin.home.local");
        orderResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var orderId = orderResponse.Headers.GetValues("Location").First().Split('/').Last();
        var order = JsonSerializer.Deserialize<OrderResponse>(
            await orderResponse.Content.ReadAsStringAsync())!;

        // Challenge validation cannot run under TestServer, so drive the
        // order to ready directly, the state finalize requires.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var entity = await db.AcmeOrders.SingleAsync(o => o.OrderId == orderId);
            entity.Status = "ready";
            await db.SaveChangesAsync();
        }

        // The admin tightens the namespace between creation and finalize.
        (await PutJsonAsync($"/api/acme/credentials/{credential.Id}",
            new { name = "finalize-scope", expiresAt = (string?)null, domains = new[] { "other.local" } }))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var finalizePath = new Uri(order.Finalize).AbsolutePath;
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(account.Rsa, account.Kid, finalizePath, nonce,
            new FinalizeRequest { Csr = JwsService.Base64UrlEncode(BuildCsr("fin.home.local")) });
        var response = await PostJws(finalizePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Detail.Should().Contain("finalize-scope");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            (await db.AcmeOrders.AsNoTracking().SingleAsync(o => o.OrderId == orderId))
                .Status.Should().Be("ready",
                    "widening the namespace again must let the client retry this order");
            var audit = await db.DomainPolicyRejections.AsNoTracking().SingleAsync();
            audit.Stage.Should().Be("finalize-eab");
        }
    }

    // ---- The admin create and update surface ----

    [Fact]
    public async Task CredentialsApi_NormalizesTheNamespace_AndTheListCarriesIt()
    {
        var create = await PostJsonAsync("/api/acme/credentials", new
        {
            name = "punycode",
            domains = new[] { " WEB.Home.Local. ", "web.home.local", "bücher.example" },
        });
        create.StatusCode.Should().Be(HttpStatusCode.Created);
        var id = (await ParseJsonAsync(create)).GetProperty("id").GetInt32();

        // Entries normalize and de-duplicate exactly like the allowed
        // domain list: lowercase punycode A labels, first occurrence order.
        var listed = await FetchSingleCredentialRowAsync();
        listed.GetProperty("namespaces").EnumerateArray()
            .Select(e => e.GetString())
            .Should().Equal("web.home.local", "xn--bcher-kva.example");

        var update = await PutJsonAsync($"/api/acme/credentials/{id}", new
        {
            name = "renamed",
            expiresAt = (string?)null,
            domains = new[] { "home.local" },
        });
        update.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(update);
        body.GetProperty("name").GetString().Should().Be("renamed");
        body.GetProperty("namespaces").EnumerateArray().Single().GetString()
            .Should().Be("home.local");
        body.GetProperty("message").GetString().Should().Contain("immediately");

        var relisted = await FetchSingleCredentialRowAsync();
        relisted.GetProperty("name").GetString().Should().Be("renamed");
        relisted.GetProperty("namespaces").EnumerateArray().Single().GetString()
            .Should().Be("home.local");
    }

    [Fact]
    public async Task CredentialsApi_UnusableEntries_AreRefusedWithPerEntryReasons()
    {
        var create = await PostJsonAsync("/api/acme/credentials", new
        {
            name = "bad entries",
            domains = new[] { "*.home.local", "ok.local" },
        });
        create.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var createBody = await ParseJsonAsync(create);
        createBody.GetProperty("error").GetString().Should().Contain("not usable");
        var entry = createBody.GetProperty("invalidEntries").EnumerateArray().Single();
        entry.GetProperty("entry").GetString().Should().Be("*.home.local");
        entry.GetProperty("reason").GetString().Should().Contain("included automatically");

        var list = await _client.GetAsync("/api/acme/credentials");
        (await list.Content.ReadAsStringAsync()).Should().Contain("\"credentials\":[]",
            "a refused create must not leave a row behind");

        var credential = await CreateCredentialViaApiAsync("editable");
        var update = await PutJsonAsync($"/api/acme/credentials/{credential.Id}", new
        {
            name = "editable",
            expiresAt = (string?)null,
            domains = new[] { "https://home.local" },
        });
        update.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(update)).GetProperty("invalidEntries").EnumerateArray()
            .Single().GetProperty("entry").GetString().Should().Be("https://home.local");
    }

    [Fact]
    public async Task CredentialsApi_Update_OmittedDomains_IsRefused()
    {
        // The update is a full replacement, so a body without domains would
        // otherwise clear the namespace: a silent security widening for a
        // caller who only meant to rename. Removing the namespace requires
        // an explicit empty list.
        var credential = await CreateCredentialViaApiAsync("scoped", "home.local");

        var response = await PutJsonAsync($"/api/acme/credentials/{credential.Id}",
            new { name = "renamed", expiresAt = (string?)null });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("empty list");

        var row = await FetchSingleCredentialRowAsync();
        row.GetProperty("name").GetString().Should().Be("scoped",
            "the refused update must change nothing");
        row.GetProperty("namespaces").EnumerateArray().Single().GetString()
            .Should().Be("home.local");
    }

    [Fact]
    public async Task CredentialsApi_Update_UnknownRevokedAndPastExpiry_AreRefused()
    {
        (await PutJsonAsync("/api/acme/credentials/9999",
                new { name = "ghost", expiresAt = (string?)null, domains = Array.Empty<string>() }))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);

        var credential = await CreateCredentialViaApiAsync("locked");

        var pastExpiry = await PutJsonAsync($"/api/acme/credentials/{credential.Id}", new
        {
            name = "locked",
            expiresAt = DateTime.UtcNow.AddMinutes(-5).ToString("O"),
            domains = Array.Empty<string>(),
        });
        pastExpiry.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(pastExpiry)).GetProperty("error").GetString()
            .Should().Contain("future");

        (await _client.PostAsync($"/api/acme/credentials/{credential.Id}/revoke", null))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        var revoked = await PutJsonAsync($"/api/acme/credentials/{credential.Id}",
            new { name = "renamed", expiresAt = (string?)null, domains = Array.Empty<string>() });
        revoked.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ParseJsonAsync(revoked)).GetProperty("error").GetString()
            .Should().Contain("revoked");
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

    private async Task<JsonElement> FetchSingleCredentialRowAsync()
    {
        var response = await _client.GetAsync("/api/acme/credentials");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await ParseJsonAsync(response)).GetProperty("credentials")
            .EnumerateArray().Single();
    }

    private async Task<CredentialInfo> CreateCredentialViaApiAsync(
        string name, params string[] domains)
    {
        var response = await PostJsonAsync("/api/acme/credentials", new { name, domains });
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

    private JwsFlattenedRequest CreateKidJws(
        RSA rsa, string kid, string path, string nonce, object? payload)
    {
        var encodedPath = new Microsoft.AspNetCore.Http.PathString(path).ToUriComponent();
        var url = $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";
        var payloadJson = payload != null
            ? JsonSerializer.Serialize(payload)
            : "";

        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(
            signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        };
    }

    private static byte[] BuildCsr(string domain)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={domain}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(domain);
        request.CertificateExtensions.Add(sanBuilder.Build());
        return request.CreateSigningRequest();
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
    /// EAB optional (so accounts can bind) and the global allowed domain list
    /// off is seeded before the host builds; tests that exercise the
    /// intersection rewrite the file with the list on. Every write bumps the
    /// file's write time monotonically so the hot reading policies always
    /// notice.
    /// </summary>
    private sealed class NamespaceFactory : CertusWebApplicationFactory
    {
        private static long _writeCounter;

        private string StatusFilePath => Path.Combine(TempDataDir, SetupStatus.FileName);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            WritePolicy();
        }

        public void WritePolicy(bool allowedDomainsEnabled = false, params string[] allowedDomains)
        {
            var status = new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = ["WebServer"],
                EabEnforcement = "optional",
                AllowedDomainsEnabled = allowedDomainsEnabled,
                AllowedDomains = allowedDomains.ToList(),
            };
            status.Save(StatusFilePath);
            var bump = Interlocked.Increment(ref _writeCounter);
            File.SetLastWriteTimeUtc(StatusFilePath, DateTime.UtcNow.AddSeconds(bump));
        }
    }
}
