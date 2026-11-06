using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Web.Controllers.Acme;
using Certus.Web.Tests.MonitorMode;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The ACME request body cap (issue #300) through a real Kestrel, the half of the rule TestServer
/// cannot show: TestServer does not enforce <c>[RequestSizeLimit]</c>, so only a real server
/// proves the attribute on the abstract base class reaches every endpoint, that the challenge's
/// own cap still overrides it, and what a client is actually told. AcmeRequestSizeLimitTests pins
/// the rest without a server.
///
/// <para>Every over the cap request asks for 100-continue. Kestrel refuses a declared length over
/// the limit as soon as the action starts reading, so it answers before the client has sent the
/// body, and the client then sends none. Without that, the server can close the connection while
/// the client is still writing the excess, and whether the client reads the answer first is a
/// race that has nothing to do with the code under test.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class AcmeRequestSizeLimitKestrelTests
    : IClassFixture<AcmeRequestSizeLimitKestrelTests.KestrelFactory>, IDisposable
{
    private const string AuthorizationPath = "/acme/WebServer/authz/1";
    private const string ChallengePath = "/acme/WebServer/chall/1";
    private const string NewAccountPath = "/acme/WebServer/new-account";

    private readonly KestrelFactory _factory;
    private readonly HttpClient _client;

    public AcmeRequestSizeLimitKestrelTests(KestrelFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose() => _client.Dispose();

    /// <summary>The shared web test host, served by Kestrel on a free loopback port.</summary>
    public sealed class KestrelFactory : CertusWebApplicationFactory
    {
        public KestrelFactory() => UseKestrel(0);
    }

    [Fact]
    public void EveryAcmeEndpoint_ResolvesToTheCapItsControllerDeclares()
    {
        // The endpoint metadata is what the server reads, so this is the order MVC puts the base
        // class's attribute and the challenge action's own in, rather than the order reflection
        // happens to return them.
        var endpoints = AcmeEndpoints();
        endpoints.Select(e => e.RoutePattern.RawText).Should().Contain(
            ["acme/{template}/authz/{authzId}", "acme/{template}/acct/{accountId}"],
            "these are the two the issue names");

        foreach (var endpoint in endpoints)
        {
            var raw = endpoint.RoutePattern.RawText;
            var expected = raw == "acme/{template}/chall/{challengeId}"
                ? ChallengeCap()
                : AcmeControllerBase.MaxRequestBytes;

            // Parenthesised, so an endpoint with no limit at all reads as null and fails, rather
            // than short circuiting the assertion away.
            (endpoint.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize)
                .Should().Be(expected, raw);
        }
    }

    [Fact]
    public async Task ABodyOverTheCap_IsRefused413_AsAnAcmeProblem_OnEveryPostRoute()
    {
        var routes = ProtocolRouteSamples.For(_factory.Services, "acme/")
            .Where(sample => sample.Method == HttpMethods.Post)
            // The protocol fallback is a catch all with no controller behind it and reads nothing.
            .Where(sample => !sample.Path.EndsWith("/anything", StringComparison.Ordinal))
            .Where(sample => sample.Path != ChallengePath)
            .Select(sample => sample.Path)
            .ToList();
        routes.Should().Contain([AuthorizationPath, "/acme/WebServer/acct/1", NewAccountPath,
            "/acme/WebServer/revoke-cert", "/acme/WebServer/order/1/finalize"]);

        var failures = new List<string>();
        foreach (var path in routes)
        {
            using var response = await PostAsync(path, AcmeControllerBase.MaxRequestBytes + 1, expectContinue: true);
            var body = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.RequestEntityTooLarge ||
                response.Content.Headers.ContentType?.MediaType != "application/problem+json" ||
                !response.Headers.Contains("Replay-Nonce"))
            {
                failures.Add($"{path}: {(int)response.StatusCode} {body}");
                continue;
            }

            var problem = JsonSerializer.Deserialize<AcmeError>(body)!;
            if (problem.Type != AcmeErrorType.Malformed || problem.Status != 413 ||
                problem.Detail?.Contains(AcmeControllerBase.MaxRequestBytes.ToString()) != true)
                failures.Add($"{path}: {body}");
        }

        // Joined, so a failure names every route that answered wrongly, not only the first.
        string.Join(Environment.NewLine, failures).Should().BeEmpty();
    }

    [Fact]
    public async Task ABodyAtTheCap_IsRead_AndRefusedForWhatItSays()
    {
        // The other side of the line: a body exactly at the cap is read, so a malformed one gets
        // the malformed JWS answer it always got, which is how the two stay distinct.
        using var response = await PostAsync(AuthorizationPath, AcmeControllerBase.MaxRequestBytes, expectContinue: false);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var problem = JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync())!;
        problem.Type.Should().Be(AcmeErrorType.Malformed);
        problem.Detail.Should().Be("Invalid JWS JSON.");
    }

    [Fact]
    public async Task TheChallenge_ReadsABodyPastTheGeneralCap()
    {
        // Its own cap overrides the base class's, so twice the general cap is still read.
        using var response = await PostAsync(ChallengePath, 2 * AcmeControllerBase.MaxRequestBytes, expectContinue: false);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync())!)
            .Detail.Should().Be("Invalid JWS JSON.");
    }

    [Fact]
    public async Task TheLargestAccountUpdate_IsAccepted()
    {
        // The account endpoint's largest honest body, end to end through the enforced cap: the
        // most contacts, each as long as allowed, every character escaped, on an RSA 4096 key.
        using var key = RSA.Create(4096);

        var nonce = await FreshNonceAsync();
        var jwk = ExportRsaJwk(key);
        using var created = await PostJwsAsync(NewAccountPath, Sign(key,
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{Absolute(NewAccountPath)}}","jwk":{{jwk}}}""",
            """{"termsOfServiceAgreed":true}"""));
        created.IsSuccessStatusCode.Should().BeTrue(await created.Content.ReadAsStringAsync());
        var kid = created.Headers.GetValues("Location").First();
        var accountPath = new Uri(kid).AbsolutePath;

        var contact = Enumerable.Range(0, AccountService.MaxContactEntries)
            .Select(_ => new string((char)0x4E2D, AccountService.MaxContactLength))
            .ToArray();
        nonce = await FreshNonceAsync();
        var update = Sign(key,
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{Absolute(accountPath)}}","kid":"{{kid}}"}""",
            JsonSerializer.Serialize(new { contact }));

        using var response = await PostJwsAsync(accountPath, update);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement
            .GetProperty("contact").GetArrayLength().Should().Be(AccountService.MaxContactEntries);
    }

    // ---- helpers ----

    private List<RouteEndpoint> AcmeEndpoints() =>
        _factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(e => e.RoutePattern.RawText?.TrimStart('/')
                .StartsWith("acme/", StringComparison.OrdinalIgnoreCase) == true)
            // The fallback classifies unknown ACME paths; it is not a controller endpoint.
            .Where(e => !e.RoutePattern.RawText!.Contains("**"))
            .ToList();

    /// <summary>The challenge action's own cap, read off the action rather than the endpoint under test.</summary>
    private static long ChallengeCap()
    {
        IRequestSizeLimitMetadata limit = typeof(ChallengeController)
            .GetMethod(nameof(ChallengeController.RespondToChallenge))!
            .GetCustomAttribute<RequestSizeLimitAttribute>()!;
        return limit.MaxRequestBodySize!.Value;
    }

    private async Task<HttpResponseMessage> PostAsync(string path, int bytes, bool expectContinue)
    {
        var content = new ByteArrayContent(Enumerable.Repeat((byte)'x', bytes).ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");

        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        request.Headers.ExpectContinue = expectContinue;
        return await _client.SendAsync(request);
    }

    private string Absolute(string path) =>
        $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{new PathString(path).ToUriComponent()}";

    private async Task<string> FreshNonceAsync()
    {
        using var response = await _client.GetAsync("/acme/WebServer/new-nonce");
        return response.Headers.GetValues("Replay-Nonce").First();
    }

    private async Task<HttpResponseMessage> PostJwsAsync(string path, JwsFlattenedRequest jws)
    {
        var content = new StringContent(JsonSerializer.Serialize(jws), Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");
        return await _client.PostAsync(path, content);
    }

    private static JwsFlattenedRequest Sign(RSA key, string header, string payload)
    {
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(header));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
        var signature = key.SignData(
            Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}"),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        };
    }

    private static string ExportRsaJwk(RSA key)
    {
        var p = key.ExportParameters(false);
        return $$"""{"kty":"RSA","n":"{{JwsService.Base64UrlEncode(p.Modulus!)}}","e":"{{JwsService.Base64UrlEncode(p.Exponent!)}}"}""";
    }
}
