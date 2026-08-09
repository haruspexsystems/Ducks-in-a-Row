using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Attestation;
using Certus.Core.Acme.Models;
using Certus.Core.Data;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Integration tests for the device attestation admin API (Phase 5): the
/// profile, allowlist, and trust anchor endpoints behind the ACME dashboard
/// tab. The template resolution rules (a profile needs a published, ACME
/// enabled template) and the strict mode parsing are exercised end to end, and
/// one flow proves the hot apply contract: a profile created through the API
/// turns a permanent-identifier order on for the template, and deleting it
/// turns the order invisible again, with no restart. Each test gets its own
/// factory, so counts never couple to run order.
/// </summary>
[Trait("Category", "Integration")]
public class DeviceAttestAdminApiIntegrationTests : IDisposable
{
    private const string Template = "WebServer";
    private readonly DeviceAttestAdminFactory _factory = new();
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public DeviceAttestAdminApiIntegrationTests()
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

    // ---- Profiles ----

    [Fact]
    public async Task Profiles_Empty_ListReturnsNone()
    {
        var body = await GetJsonAsync("/api/acme/device-attestation/profiles");
        body.GetProperty("profiles").GetArrayLength().Should().Be(0);
    }

    [Fact]
    public async Task Profile_Create_Returns201_AndListsWithZeroAllowlist()
    {
        var create = await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = Template, gateMode = "allowlist", csrIdentifierBinding = "cn-or-san" });
        create.StatusCode.Should().Be(HttpStatusCode.Created);
        var created = await ParseJsonAsync(create);
        created.GetProperty("templateId").GetString().Should().Be(Template);
        created.GetProperty("enabled").GetBoolean().Should().BeTrue();
        created.GetProperty("gateMode").GetString().Should().Be("allowlist");
        created.GetProperty("allowlistCount").GetInt32().Should().Be(0);

        var list = await GetJsonAsync("/api/acme/device-attestation/profiles");
        list.GetProperty("profiles").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task Profile_Create_DefaultsEnabledWhenOmitted()
    {
        // A missing "enabled" JSON member must not bind to false and silently
        // create a disabled profile; the nullable bool defaults it to true.
        var create = await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = Template });
        create.StatusCode.Should().Be(HttpStatusCode.Created);
        var created = await ParseJsonAsync(create);
        created.GetProperty("enabled").GetBoolean().Should().BeTrue();
        created.GetProperty("gateMode").GetString().Should().Be("allowlist");
        created.GetProperty("csrIdentifierBinding").GetString().Should().Be("cn-or-san");
    }

    [Fact]
    public async Task Profile_Create_UnknownTemplate_Returns400()
    {
        var response = await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = "NoSuchTemplate" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("No certificate template named");
    }

    [Fact]
    public async Task Profile_Create_DisabledTemplate_Returns400()
    {
        // The mock CA publishes Machine/User/CodeSigning too, but the factory
        // enables only WebServer, so Machine resolves as not enabled for ACME.
        var response = await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = "Machine" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("not enabled for ACME");
    }

    [Fact]
    public async Task Profile_Create_InvalidGateMode_Returns400()
    {
        var response = await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = Template, gateMode = "sometimes" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("allowlist, open");
    }

    [Fact]
    public async Task Profile_Create_InvalidBinding_Returns400()
    {
        var response = await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = Template, csrIdentifierBinding = "whatever" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("cn-or-san, san-required, none");
    }

    [Fact]
    public async Task Profile_Create_DuplicateTemplate_Returns409()
    {
        (await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = Template })).StatusCode.Should().Be(HttpStatusCode.Created);

        var second = await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = Template });
        second.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Profile_Update_ChangesGateBindingAndEnabled()
    {
        var id = await CreateProfileAsync();

        var update = await PutJsonAsync($"/api/acme/device-attestation/profiles/{id}",
            new { gateMode = "open", csrIdentifierBinding = "none", enabled = false });
        update.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(update);
        body.GetProperty("gateMode").GetString().Should().Be("open");
        body.GetProperty("csrIdentifierBinding").GetString().Should().Be("none");
        body.GetProperty("enabled").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Profile_Update_UnknownId_Returns404()
    {
        var response = await PutJsonAsync("/api/acme/device-attestation/profiles/999",
            new { gateMode = "open" });
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Profile_Update_InvalidMode_Returns400()
    {
        var id = await CreateProfileAsync();
        var response = await PutJsonAsync($"/api/acme/device-attestation/profiles/{id}",
            new { gateMode = "nope" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Profile_Delete_RemovesProfile_AndCascadesAllowlist()
    {
        var id = await CreateProfileAsync();
        await AddAllowlistAsync(id, "SN-CASCADE-1");

        (await _client.DeleteAsync($"/api/acme/device-attestation/profiles/{id}"))
            .StatusCode.Should().Be(HttpStatusCode.NoContent);

        (await GetJsonAsync("/api/acme/device-attestation/profiles"))
            .GetProperty("profiles").GetArrayLength().Should().Be(0);
        // The profile is gone, so its allowlist is a 404, not an empty list.
        (await _client.GetAsync($"/api/acme/device-attestation/profiles/{id}/allowlist"))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        // And the entry rows are actually deleted, not orphaned with a dangling
        // ProfileId: check the table directly rather than trusting the 404.
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        (await db.DeviceAllowlistEntries.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task Profile_Delete_UnknownId_Returns404()
    {
        (await _client.DeleteAsync("/api/acme/device-attestation/profiles/999"))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ---- Allowlist ----

    [Fact]
    public async Task Allowlist_Add_Returns201_AndLists()
    {
        var id = await CreateProfileAsync();

        var add = await PostJsonAsync($"/api/acme/device-attestation/profiles/{id}/allowlist",
            new { identifierValue = "DEVICE-SN-1", note = "lab iphone" });
        add.StatusCode.Should().Be(HttpStatusCode.Created);
        var added = await ParseJsonAsync(add);
        added.GetProperty("identifierValue").GetString().Should().Be("DEVICE-SN-1");
        added.GetProperty("note").GetString().Should().Be("lab iphone");

        var list = await GetJsonAsync($"/api/acme/device-attestation/profiles/{id}/allowlist");
        list.GetProperty("entries").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task Allowlist_Add_EmptyValue_Returns400()
    {
        var id = await CreateProfileAsync();
        var response = await PostJsonAsync($"/api/acme/device-attestation/profiles/{id}/allowlist",
            new { identifierValue = "" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Allowlist_Add_Duplicate_Returns409()
    {
        var id = await CreateProfileAsync();
        await AddAllowlistAsync(id, "DUP-1");

        var second = await PostJsonAsync($"/api/acme/device-attestation/profiles/{id}/allowlist",
            new { identifierValue = "DUP-1" });
        second.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Allowlist_Add_UnknownProfile_Returns404()
    {
        var response = await PostJsonAsync("/api/acme/device-attestation/profiles/999/allowlist",
            new { identifierValue = "SN-1" });
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Allowlist_Update_ChangesValueAndNote()
    {
        var id = await CreateProfileAsync();
        var entryId = await AddAllowlistAsync(id, "OLD-SN");

        var update = await PutJsonAsync($"/api/acme/device-attestation/allowlist/{entryId}",
            new { identifierValue = "NEW-SN", note = "asset-42" });
        update.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(update);
        body.GetProperty("identifierValue").GetString().Should().Be("NEW-SN");
        body.GetProperty("note").GetString().Should().Be("asset-42");
    }

    [Fact]
    public async Task Allowlist_Update_UnknownEntry_Returns404()
    {
        var response = await PutJsonAsync("/api/acme/device-attestation/allowlist/999",
            new { identifierValue = "SN-1" });
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Allowlist_Update_DuplicateValue_Returns409()
    {
        var id = await CreateProfileAsync();
        await AddAllowlistAsync(id, "SN-A");
        var second = await AddAllowlistAsync(id, "SN-B");

        // Moving SN-B onto SN-A collides on the (profile, value) unique index.
        var update = await PutJsonAsync($"/api/acme/device-attestation/allowlist/{second}",
            new { identifierValue = "SN-A" });
        update.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Allowlist_Delete_Removes_ThenUnknown404()
    {
        var id = await CreateProfileAsync();
        var entryId = await AddAllowlistAsync(id, "SN-DEL");

        (await _client.DeleteAsync($"/api/acme/device-attestation/allowlist/{entryId}"))
            .StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await _client.DeleteAsync($"/api/acme/device-attestation/allowlist/{entryId}"))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ---- Trust anchors ----

    [Fact]
    public async Task Anchors_List_IncludesBuiltInAppleRoot()
    {
        var anchors = (await GetJsonAsync("/api/acme/device-attestation/trust-anchors"))
            .GetProperty("anchors");

        anchors.GetArrayLength().Should().BeGreaterThan(0);
        var apple = anchors.EnumerateArray()
            .First(a => a.GetProperty("builtIn").GetBoolean());
        apple.GetProperty("format").GetString().Should().Be("apple");
        apple.GetProperty("sha256Fingerprint").GetString()
            .Should().Be(AppleAttestationOids.RootSha256Fingerprint);
        // A built in root carries no database id and cannot be deleted.
        apple.GetProperty("id").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task Anchor_Add_Custom_Returns201_AndLists()
    {
        var pem = SelfSignedPem("CN=Test Anchor");
        var add = await PostJsonAsync("/api/acme/device-attestation/trust-anchors",
            new { format = "apple", name = "synthetic test root", certificatePem = pem });
        add.StatusCode.Should().Be(HttpStatusCode.Created);
        var added = await ParseJsonAsync(add);
        added.GetProperty("builtIn").GetBoolean().Should().BeFalse();
        added.GetProperty("name").GetString().Should().Be("synthetic test root");

        var anchors = (await GetJsonAsync("/api/acme/device-attestation/trust-anchors"))
            .GetProperty("anchors");
        anchors.EnumerateArray().Any(a => !a.GetProperty("builtIn").GetBoolean())
            .Should().BeTrue();
    }

    [Fact]
    public async Task Anchor_Add_InvalidPem_Returns400()
    {
        var response = await PostJsonAsync("/api/acme/device-attestation/trust-anchors",
            new { format = "apple", name = "bad", certificatePem = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("did not parse");
    }

    [Fact]
    public async Task Anchor_Add_UnsupportedFormat_Returns400()
    {
        var pem = SelfSignedPem("CN=Tpm Root");
        var response = await PostJsonAsync("/api/acme/device-attestation/trust-anchors",
            new { format = "tpm", name = "tpm root", certificatePem = pem });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("apple");
    }

    [Fact]
    public async Task Anchor_Add_Duplicate_Returns409()
    {
        var pem = SelfSignedPem("CN=Dup Anchor");
        (await PostJsonAsync("/api/acme/device-attestation/trust-anchors",
            new { format = "apple", name = "first", certificatePem = pem }))
            .StatusCode.Should().Be(HttpStatusCode.Created);

        var second = await PostJsonAsync("/api/acme/device-attestation/trust-anchors",
            new { format = "apple", name = "second", certificatePem = pem });
        second.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Anchor_Add_BuiltInRoot_Returns409()
    {
        // Re adding a certificate that is already a built in root is refused as
        // redundant rather than stored a second time.
        var response = await PostJsonAsync("/api/acme/device-attestation/trust-anchors",
            new { format = "apple", name = "apple again", certificatePem = EmbeddedAppleRootPem() });
        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await ParseJsonAsync(response)).GetProperty("error").GetString()
            .Should().Contain("built-in");
    }

    [Fact]
    public async Task Anchor_Delete_Removes_ThenUnknown404()
    {
        var pem = SelfSignedPem("CN=To Delete");
        var add = await PostJsonAsync("/api/acme/device-attestation/trust-anchors",
            new { format = "apple", name = "to delete", certificatePem = pem });
        var anchorId = (await ParseJsonAsync(add)).GetProperty("id").GetInt32();

        (await _client.DeleteAsync($"/api/acme/device-attestation/trust-anchors/{anchorId}"))
            .StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await _client.DeleteAsync($"/api/acme/device-attestation/trust-anchors/{anchorId}"))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Anchor_Add_MissingName_Returns400()
    {
        var pem = SelfSignedPem("CN=No Name");
        var response = await PostJsonAsync("/api/acme/device-attestation/trust-anchors",
            new { format = "apple", name = "   ", certificatePem = pem });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // ---- Hot apply: the admin API drives the Phase 4 protocol path ----

    [Fact]
    public async Task AdminProfile_HotApplies_DeviceOrderAcceptedThenInvisibleAfterDelete()
    {
        const string serial = "DEVICE-SN-ADMIN-1";

        // No profile yet: a permanent-identifier order answers the invisible
        // refusal, byte identical to a server without the feature.
        var (account, rsa) = await CreateAccountAsync();
        var before = await PostDeviceNewOrderAsync(rsa, account.Kid, serial);
        before.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(before)).Type.Should().Contain("unsupportedIdentifier");

        // Turn the feature on entirely through the admin API.
        var profileId = await CreateProfileAsync();
        await AddAllowlistAsync(profileId, serial);

        // The very next order is accepted and offers exactly one
        // device-attest-01 challenge; no restart, the protocol path reads the
        // rows the API just wrote.
        var accepted = await PostDeviceNewOrderAsync(rsa, account.Kid, serial);
        accepted.StatusCode.Should().Be(HttpStatusCode.Created);
        var order = JsonSerializer.Deserialize<OrderResponse>(
            await accepted.Content.ReadAsStringAsync())!;
        order.Authorizations.Should().HaveCount(1);
        var authz = await GetAuthzAsync(rsa, account.Kid,
            new Uri(order.Authorizations[0]).AbsolutePath);
        authz.Challenges.Should().ContainSingle()
            .Which.Type.Should().Be("device-attest-01");

        // Delete the profile: the feature goes dark again for the template.
        (await _client.DeleteAsync($"/api/acme/device-attestation/profiles/{profileId}"))
            .StatusCode.Should().Be(HttpStatusCode.NoContent);
        var after = await PostDeviceNewOrderAsync(rsa, account.Kid, serial);
        after.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(after)).Type.Should().Contain("unsupportedIdentifier");
    }

    // ---- Admin API helpers ----

    private async Task<int> CreateProfileAsync(
        string gateMode = "allowlist", string binding = "cn-or-san")
    {
        var response = await PostJsonAsync("/api/acme/device-attestation/profiles",
            new { templateId = Template, gateMode, csrIdentifierBinding = binding });
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        return (await ParseJsonAsync(response)).GetProperty("id").GetInt32();
    }

    private async Task<int> AddAllowlistAsync(int profileId, string identifierValue)
    {
        var response = await PostJsonAsync(
            $"/api/acme/device-attestation/profiles/{profileId}/allowlist",
            new { identifierValue });
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        return (await ParseJsonAsync(response)).GetProperty("id").GetInt32();
    }

    private static string SelfSignedPem(string subject)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        return cert.ExportCertificatePem();
    }

    private static string EmbeddedAppleRootPem()
    {
        using var stream = typeof(AppleAttestationVerifier).Assembly.GetManifestResourceStream(
            "Certus.Core.Acme.Attestation.AppleEnterpriseAttestationRootCa.pem")!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private Task<HttpResponseMessage> PostJsonAsync(string url, object payload) =>
        _client.PostAsync(url, JsonContent(payload));

    private Task<HttpResponseMessage> PutJsonAsync(string url, object payload) =>
        _client.PutAsync(url, JsonContent(payload));

    private async Task<JsonElement> GetJsonAsync(string url)
    {
        var response = await _client.GetAsync(url);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return await ParseJsonAsync(response);
    }

    private static StringContent JsonContent(object payload) =>
        new(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    // ---- ACME client helpers (the house JWS pattern, permanent-identifier orders) ----

    private sealed record AccountInfo(string Kid, string AccountId);

    private async Task<(AccountInfo Account, RSA Rsa)> CreateAccountAsync()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:device-admin-tests@example.com" }
        });
        var headerJson =
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{_client.BaseAddress}}acme/{{Template}}/new-account","jwk":{{jwkJson}}}""";
        var response = await PostJws($"/acme/{Template}/new-account", SignJws(rsa, headerJson, payloadJson));
        response.EnsureSuccessStatusCode();
        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    private async Task<HttpResponseMessage> PostDeviceNewOrderAsync(RSA rsa, string kid, string serial)
    {
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, kid, $"/acme/{Template}/new-order", nonce,
            new NewOrderRequest
            {
                Identifiers = new[]
                {
                    new AcmeIdentifier { Type = "permanent-identifier", Value = serial }
                }
            });
        return await PostJws($"/acme/{Template}/new-order", jws);
    }

    private async Task<AuthorizationResponse> GetAuthzAsync(RSA rsa, string kid, string authzPath)
    {
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, kid, authzPath, nonce, (object?)null);
        var response = await PostJws(authzPath, jws);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return JsonSerializer.Deserialize<AuthorizationResponse>(
            await response.Content.ReadAsStringAsync())!;
    }

    private static async Task<AcmeError> ReadErrorAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync())!;

    private JwsFlattenedRequest CreateKidJws(RSA rsa, string kid, string path, string nonce, object? payload)
    {
        var url = $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{path}";
        var payloadJson = payload != null ? JsonSerializer.Serialize(payload) : "";
        var headerJson =
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        return SignJws(rsa, headerJson, payloadJson);
    }

    private static JwsFlattenedRequest SignJws(RSA rsa, string headerJson, string payloadJson)
    {
        var protectedB64 = Certus.Core.Acme.Crypto.JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = Certus.Core.Acme.Crypto.JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = Certus.Core.Acme.Crypto.JwsService.Base64UrlEncode(signature)
        };
    }

    private async Task<string> GetFreshNonce()
    {
        var response = await _client.GetAsync($"/acme/{Template}/new-nonce");
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    private async Task<HttpResponseMessage> PostJws(string url, JwsFlattenedRequest jws)
    {
        var content = new StringContent(
            JsonSerializer.Serialize(jws), Encoding.UTF8, "application/jose+json");
        return await _client.PostAsync(url, content);
    }

    private static string ExportRsaJwk(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var n = Certus.Core.Acme.Crypto.JwsService.Base64UrlEncode(p.Modulus!);
        var e = Certus.Core.Acme.Crypto.JwsService.Base64UrlEncode(p.Exponent!);
        return $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
    }

    /// <summary>
    /// Completed setup with only WebServer enabled for ACME, so the enabled,
    /// disabled, and unknown template paths are all reachable, and EAB
    /// enforcement off so an unbound account can register and order.
    /// </summary>
    private sealed class DeviceAttestAdminFactory : CertusWebApplicationFactory
    {
        private static long _writeCounter;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            var status = new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = ["WebServer"],
                EabEnforcement = "off",
            };
            var path = Path.Combine(TempDataDir, SetupStatus.FileName);
            status.Save(path);
            var bump = Interlocked.Increment(ref _writeCounter);
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(bump));
        }
    }
}
