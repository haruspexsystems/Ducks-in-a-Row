using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Setup;

namespace Certus.Web.Tests;

/// <summary>
/// Pins the first-use chain end to end across both surfaces: setup completes
/// through the wizard's own endpoint with the restriction on and one domain
/// (the shape the wizard submits when a domain joined machine's suggestion is
/// kept), and the very next ACME orders are decided by the policy hot-reading
/// what completion just wrote. The two halves are covered separately by
/// AllowedDomainsSetupIntegrationTests (completion persists) and
/// AllowedDomainsIntegrationTests (the policy decides against a seeded file);
/// this class covers the seam between them, which is where a field report of
/// "the default domain was denied on first use" would have to live if the
/// code were at fault. The domain itself and a host under it must both
/// issue: an entry covers the domain and its subdomains.
///
/// The second test is the hand edit case from issue #630: the restriction
/// switched on with no usable entry, a state the wizard and the settings API
/// refuse to write, must refuse every order at the ACME surface with the
/// same rejectedIdentifier problem a disallowed name gets.
///
/// Own factory instance per test because completion locks setup.
/// </summary>
[Trait("Category", "Integration")]
public class AllowedDomainsFirstUseIntegrationTests : IDisposable
{
    private sealed class Factory : CertusWebApplicationFactory
    {
        /// <summary>
        /// Write the status file the way a hand edit would leave it: setup
        /// complete, the restriction on, and no entry at all.
        /// </summary>
        public void WriteHandEditedEmptyRestriction()
        {
            new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = ["WebServer"],
                AllowedDomainsEnabled = true,
                AllowedDomains = [],
            }.Save(Path.Combine(TempDataDir, SetupStatus.FileName));
        }
    }

    private readonly Factory _factory = new();
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AllowedDomainsFirstUseIntegrationTests()
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

    [Fact]
    public async Task CompleteSetupWithDefaultDomain_ThenOrder_DomainAndSubdomainIssueOthersRefused()
    {
        // The wizard's completion payload for a first run that kept the AD
        // domain suggestion: restriction on, exactly one entry.
        var completion = await _client.PostAsync("/api/setup/complete", new StringContent(
            JsonSerializer.Serialize(new
            {
                enabledTemplates = new[] { "WebServer" },
                externalUrl = "https://certus.corp.example.com:5001",
                allowedDomainsEnabled = true,
                allowedDomains = new[] { "corp.example.com" },
                // Binding switched off, so the plain new-account below reaches
                // the domain policy this class pins. A fresh install requires
                // binding otherwise (issue #631, EabSetupIntegrationTests).
                eabEnforcement = "off",
            }),
            Encoding.UTF8, "application/json"));
        completion.StatusCode.Should().Be(HttpStatusCode.OK);

        var (account, rsa) = await CreateAccountAsync();

        // The entry itself: "a cert for that domain" is the reported first
        // request, and MatchesEntry's equality arm is what admits it.
        var bareDomain = await PostNewOrderAsync(rsa, account.Kid, "corp.example.com");
        bareDomain.StatusCode.Should().Be(HttpStatusCode.Created);

        // A host under it, the everyday case.
        var subdomain = await PostNewOrderAsync(rsa, account.Kid, "web01.corp.example.com");
        subdomain.StatusCode.Should().Be(HttpStatusCode.Created);

        // A name outside the list is the shape the policy exists to refuse,
        // with the compound rejectedIdentifier problem naming it.
        var outside = await PostNewOrderAsync(rsa, account.Kid, "other.local");
        outside.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = JsonSerializer.Deserialize<AcmeError>(
            await outside.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Subproblems.Should().ContainSingle();
        error.Subproblems![0].Identifier!.Value.Should().Be("other.local");
    }

    [Fact]
    public async Task HandEditedEmptyRestriction_ThenOrder_EveryNameRefusedAsRejectedIdentifier()
    {
        // The state the wizard and the settings API refuse to write: the
        // restriction on with nothing in the list. Issue #630: the policy
        // fails closed, so the very first order after the edit is refused
        // with the problem type a disallowed name gets, naming the identifier
        // and pointing at the Settings page where the fix lives.
        _factory.WriteHandEditedEmptyRestriction();

        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid, "corp.example.com");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
        var error = JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync());
        error!.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Detail.Should().Contain("corp.example.com");
        error.Detail.Should().Contain("Settings");
        error.Subproblems.Should().ContainSingle();
        error.Subproblems![0].Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Subproblems[0].Identifier!.Value.Should().Be("corp.example.com");
    }

    #region Test Helpers

    private record AccountInfo(string Kid, string AccountId);

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
        var jws = CreateKidJws(rsa, kid, "/acme/WebServer/new-order", nonce, payload);
        return await PostJws("/acme/WebServer/new-order", jws);
    }

    private async Task<(AccountInfo Account, RSA Rsa)> CreateAccountAsync()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:test@example.com" }
        });

        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{_client.BaseAddress}}acme/WebServer/new-account","jwk":{{jwkJson}}}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var jws = new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };

        var response = await PostJws("/acme/WebServer/new-account", jws);
        response.EnsureSuccessStatusCode();

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
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
