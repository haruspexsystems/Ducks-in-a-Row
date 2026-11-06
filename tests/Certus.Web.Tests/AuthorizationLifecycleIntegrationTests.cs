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
/// Integration tests for the authorization resource,
/// POST /acme/{template}/authz/{authzId}.
///
/// Two operations share that URL and are told apart by the payload: a read
/// (POST-as-GET, RFC 8555 §7.5) and a deactivation (§7.5.2). The endpoint used to
/// implement only the read, so a deactivation was answered 200 and discarded
/// (issue #268), which is the same false success #168 had one resource up: the
/// client is told it relinquished an authorization that is still usable.
///
/// These tests pin both operations, the cascade to the order, and the two ways a
/// deactivation could be undone after the fact, namely the background validator
/// and a fresh challenge response.
/// </summary>
[Trait("Category", "Integration")]
[Collection("ACME Integration")]
public class AuthorizationLifecycleIntegrationTests : IDisposable
{
    private const string NewAccountPath = "/acme/WebServer/new-account";
    private const string NewOrderPath = "/acme/WebServer/new-order";
    private const string Deactivate = """{"status":"deactivated"}""";

    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public AuthorizationLifecycleIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
    }

    // ---- Deactivation (RFC 8555 §7.5.2) ----

    [Fact]
    public async Task Deactivate_IsAccepted_AndTheSameResponseReportsDeactivated()
    {
        // The headline. A 2xx that still reports "pending" is the dangerous middle:
        // the client believes it relinquished the authorization and it did not.
        var order = await CreateOrderAsync("authz-deactivate-headline.example.com");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(response)).GetProperty("status").GetString()
            .Should().Be("deactivated", "§7.5.2 returns the RESULTING authorization object");

        (await ReadAuthorizationStatusAsync(order.AuthorizationId))
            .Should().Be("deactivated", "and the response has to match the row");
    }

    [Fact]
    public async Task Deactivate_DemotesTheParentOrderToInvalid()
    {
        // An order carrying a deactivated authorization can never be finalized, so
        // it has to stop reporting a status that says otherwise.
        var order = await CreateOrderAsync("authz-deactivate-cascade.example.com");

        await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        (await ReadOrderStatusAsync(order.OrderId)).Should().Be("invalid");

        var read = await PostAsGetAsync(order, order.OrderPath);
        read.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(read)).GetProperty("status").GetString()
            .Should().Be("invalid", "the client polling the order must see the same thing");
    }

    [Fact]
    public async Task Deactivate_AValidAuthorization_IsAccepted()
    {
        // §7.1.6 draws the deactivation arrow from "valid". Network challenge
        // validation cannot run under TestServer, so mint the state directly.
        var order = await CreateOrderAsync("authz-deactivate-from-valid.example.com");
        await SetAuthorizationStatusAsync(order.AuthorizationId, "valid");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(response)).GetProperty("status").GetString().Should().Be("deactivated");
        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be("deactivated");
    }

    [Fact]
    public async Task Deactivate_AnInvalidAuthorization_IsRefused()
    {
        // Terminal. The client asked for "deactivated" and would be handed
        // "invalid", which is the false success this issue exists to remove.
        var order = await CreateOrderAsync("authz-deactivate-from-invalid.example.com");
        await SetAuthorizationStatusAsync(order.AuthorizationId, "invalid");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be("invalid");
    }

    [Fact]
    public async Task Deactivate_Twice_IsIdempotent()
    {
        // Unlike the account equivalent, this arm is genuinely reachable: the
        // ACCOUNT stays valid, so the second request still authenticates and gets
        // as far as the handler.
        var order = await CreateOrderAsync("authz-deactivate-twice.example.com");
        await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        // Put the order back so a second demote would be visible if it happened.
        await SetOrderStatusAsync(order.OrderId, "pending");

        var second = await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        second.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(second)).GetProperty("status").GetString().Should().Be("deactivated");
        (await ReadOrderStatusAsync(order.OrderId)).Should().Be(
            "pending", "the second request must write nothing at all");
    }

    [Fact]
    public async Task Deactivate_WithTheOrderAlreadyValid_LeavesTheOrderAlone()
    {
        // A valid order already holds its certificate. Demoting it would lose the
        // only record tying that certificate to this account.
        var order = await CreateOrderAsync("authz-deactivate-issued.example.com");
        await SetOrderStatusAsync(order.OrderId, "valid");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be("deactivated");
        (await ReadOrderStatusAsync(order.OrderId)).Should().Be("valid");
    }

    [Fact]
    public async Task Deactivate_WithTheOrderProcessing_LeavesTheOrderAlone()
    {
        // Issue #312. A processing order has been claimed by a finalize and its CSR
        // is at the CA, so its outcome belongs to that finalize. Demoting it here
        // collides with the completion, and one of the two writes is lost: either
        // the client is told "invalid" for an order that then reads "valid", or the
        // order reads "invalid" while still holding the certificate it was issued.
        //
        // The third member of this family, and the one that runs over real HTTP
        // rather than against the service, because the demote and the response are
        // built through the same scoped DbContext. That is where a status written
        // round the change tracker without a reload shows up.
        var order = await CreateOrderAsync("authz-deactivate-processing.example.com");
        await SetOrderStatusAsync(order.OrderId, "processing");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be(
            "deactivated", "the client's own request still stands");
        (await ReadOrderStatusAsync(order.OrderId)).Should().Be("processing");
    }

    [Fact]
    public async Task Deactivate_OneOfTwoAuthorizations_LeavesTheSiblingAlone()
    {
        var order = await CreateOrderAsync(
            "authz-deactivate-pair-a.example.com", "authz-deactivate-pair-b.example.com");

        await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be("deactivated");
        (await ReadAuthorizationStatusAsync(order.AuthorizationIds[1])).Should().Be(
            "pending", "deactivation is per identifier, not per order");
        (await ReadOrderStatusAsync(order.OrderId)).Should().Be(
            "invalid", "but the order still cannot complete");
    }

    [Fact]
    public async Task Deactivate_LeavesTheAccountsOtherOrdersAlone()
    {
        var first = await CreateOrderAsync("authz-deactivate-scope-one.example.com");
        var second = await CreateOrderAsync(
            first, "authz-deactivate-scope-two.example.com");

        await PostToAuthzAsync(first, first.AuthorizationPath, Deactivate);

        (await ReadOrderStatusAsync(second.OrderId)).Should().Be("pending");
        (await ReadAuthorizationStatusAsync(second.AuthorizationId)).Should().Be("pending");
    }

    // ---- Payload handling ----

    [Fact]
    public async Task EmptyPayload_IsStillPostAsGet_AndChangesNothing()
    {
        var order = await CreateOrderAsync("authz-read-empty.example.com");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, string.Empty);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(response)).GetProperty("status").GetString().Should().Be("pending");
        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be("pending");
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"status":null}""")]
    public async Task PayloadWithNoStatusMember_IsTreatedAsPostAsGet(string payload)
    {
        // §7.5.2 defines only the deactivation payload, so a payload asking for no
        // status change asks for nothing. Other ACME servers accept a bare {} as
        // POST-as-GET and clients do send it, so read rather than refuse.
        var order = await CreateOrderAsync($"authz-read-{payload.Length}.example.com");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, payload);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(response)).GetProperty("status").GetString().Should().Be("pending");
        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be("pending");
    }

    [Theory]
    [InlineData("""{"status":"valid"}""")]
    [InlineData("""{"status":"pending"}""")]
    [InlineData("""{"status":"revoked"}""")]
    public async Task PayloadWithAnUnrecognisedStatus_IsRefused(string payload)
    {
        // The deliberate divergence from the account handler, which ignores this
        // shape because §7.3.2 tells it to. §7.5.2 carries no such instruction, and
        // answering 200 with the unchanged object is precisely the defect #268
        // reports. The "pending" case is the sharpest: it asks for the status the
        // row already has, and a 200 there would be indistinguishable from success.
        var order = await CreateOrderAsync($"authz-bad-status-{payload.Length}.example.com");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, payload);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be("pending");
    }

    [Fact]
    public async Task PayloadThatIsNotJson_IsRefused()
    {
        var order = await CreateOrderAsync("authz-bad-json.example.com");

        var response = await PostToAuthzAsync(order, order.AuthorizationPath, "not json at all");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
        (await ReadAuthorizationStatusAsync(order.AuthorizationId)).Should().Be("pending");
    }

    // ---- The authorization stays deactivated (§7.5.2 second sentence) ----

    [Fact]
    public async Task Deactivate_ThenFinalize_IsRefused()
    {
        var order = await CreateOrderAsync("authz-deactivate-finalize.example.com");
        await SetAuthorizationStatusAsync(order.AuthorizationId, "valid");
        await SetOrderStatusAsync(order.OrderId, "ready");

        await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        var finalize = await PostToPathAsync(
            order, $"{order.OrderPath}/finalize", """{"csr":"aGVsbG8"}""");

        finalize.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(finalize)).Type.Should().Be(AcmeErrorType.OrderNotReady);
    }

    [Fact]
    public async Task Finalize_OnAReadyOrderCarryingADeactivatedAuthorization_IsRefused()
    {
        // The backstop rather than the demote: force the order back to ready after
        // the deactivation, so the order status check cannot be what refuses.
        // §7.5.2 says a deactivated authorization is never sufficient for issuance.
        var order = await CreateOrderAsync("authz-deactivate-backstop.example.com");
        await SetAuthorizationStatusAsync(order.AuthorizationId, "valid");
        await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);
        await SetOrderStatusAsync(order.OrderId, "ready");

        var finalize = await PostToPathAsync(
            order, $"{order.OrderPath}/finalize", """{"csr":"aGVsbG8"}""");

        finalize.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var error = await ReadErrorAsync(finalize);
        error.Type.Should().Be(AcmeErrorType.OrderNotReady);
        error.Detail.Should().Contain(
            "authz-deactivate-backstop.example.com",
            "the client needs to know which identifier it disowned");
    }

    [Fact]
    public async Task RespondToChallenge_OnADeactivatedAuthorization_IsRefused()
    {
        // Without this a client could deactivate an authorization and then still
        // drive its pending challenge to "processing", where the background
        // validator would set the authorization back to "valid".
        var order = await CreateOrderAsync("authz-deactivate-challenge.example.com");
        var challengePath = await FirstChallengePathAsync(order);
        await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        var response = await PostToPathAsync(order, challengePath, "{}");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Unauthorized);
        (await ReadFirstChallengeStatusAsync(order.AuthorizationId)).Should().Be(
            "pending", "it must never reach processing, which is what the validator sweeps");
    }

    // ---- The challenge resource: an empty payload reads (issue #482) ----
    //
    // RFC 8555 §6.3 makes an empty payload a fetch, and §7.5.1 makes {} the answer.
    // Until #482 only device-attest-01 told the two apart, so reading a pending
    // network challenge started its validation, possibly before the client had
    // provisioned the response, and a premature validation fails the challenge.
    // The background worker does run under TestServer and sweeps every few seconds,
    // so a challenge that has moved reads processing or, once swept, invalid (no
    // network validation can pass here). Only "pending" is deterministic, so these
    // tests assert it where nothing should have moved and "not pending" after an
    // answer, never "processing" read back from the row.

    [Theory]
    [InlineData("http-01")]
    [InlineData("dns-01")]
    [InlineData("tls-alpn-01")]
    public async Task PostAsGet_OnAPendingChallenge_ReadsItAndStartsNothing(string type)
    {
        var order = await CreateOrderAsync($"chall-read-{type}.example.com");
        var challengePath = await ChallengePathAsync(order, type);

        var response = await PostAsGetAsync(order, challengePath);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadJsonAsync(response);
        body.GetProperty("type").GetString().Should().Be(type);
        body.GetProperty("status").GetString().Should().Be(
            "pending", "a read reports the challenge as it is");
        UpLink(response).Should().Be(
            ToAbsoluteUrl(order.AuthorizationPath),
            "every challenge response names its authorization (RFC 8555 §7.1)");

        (await ReadChallengeStatusAsync(order.AuthorizationId, type)).Should().Be(
            "pending", "a read must not start validation, which the background worker would run");
    }

    [Fact]
    public async Task PostAsGet_ThenAnAnswer_StillStartsValidation()
    {
        // The read must spend nothing: the {} that follows it is still the answer.
        // The second read lands on a challenge that is no longer pending, which is
        // the arm the polling clients (dehydrated, uacme, win-acme, HAProxy, step)
        // hit after answering, so it must carry the same header as the others.
        var order = await CreateOrderAsync("chall-read-then-answer.example.com");
        var challengePath = await ChallengePathAsync(order, "http-01");
        (await PostAsGetAsync(order, challengePath)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadChallengeStatusAsync(order.AuthorizationId, "http-01")).Should().Be(
            "pending", "so the answer below is what moves it, not the read");

        var answer = await PostToPathAsync(order, challengePath, "{}");

        answer.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(answer)).GetProperty("status").GetString().Should().Be("processing");
        UpLink(answer).Should().Be(ToAbsoluteUrl(order.AuthorizationPath));
        (await ReadChallengeStatusAsync(order.AuthorizationId, "http-01")).Should().NotBe(
            "pending", "the answer starts validation");

        var poll = await PostAsGetAsync(order, challengePath);

        poll.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(poll)).GetProperty("status").GetString().Should().NotBe("pending");
        UpLink(poll).Should().Be(ToAbsoluteUrl(order.AuthorizationPath));
    }

    [Fact]
    public async Task PostAsGet_OnAChallengeUnderADeactivatedAuthorization_StillReads()
    {
        // The deactivated authorization refusal is for the state change only, as its
        // comment in ChallengeController says. RespondToChallenge_OnADeactivated...
        // above pins that {} there is still a 403.
        var order = await CreateOrderAsync("chall-read-deactivated.example.com");
        var challengePath = await ChallengePathAsync(order, "http-01");
        await PostToAuthzAsync(order, order.AuthorizationPath, Deactivate);

        var response = await PostAsGetAsync(order, challengePath);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(response)).GetProperty("status").GetString().Should().Be("pending");
        (await ReadChallengeStatusAsync(order.AuthorizationId, "http-01")).Should().Be("pending");
    }

    [Theory]
    [InlineData("")]
    [InlineData("{}")]
    public async Task AnotherAccountsChallenge_IsRefused_WhetherReadOrAnswered(string payload)
    {
        // Ownership comes strictly before the payload test, so a caller who does not
        // own the challenge learns nothing about it and cannot start it either.
        var victim = await CreateOrderAsync($"chall-tenant-victim-{payload.Length}.example.com");
        var attacker = await CreateOrderAsync($"chall-tenant-attacker-{payload.Length}.example.com");
        var challengePath = await ChallengePathAsync(victim, "http-01");

        var response = await PostToPathAsync(attacker, challengePath, payload);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Unauthorized);
        (await ReadChallengeStatusAsync(victim.AuthorizationId, "http-01")).Should().Be("pending");
    }

    [Fact]
    public async Task RespondToChallenge_OnAnInvalidAuthorization_IsRefused()
    {
        // Issue #481. Once one challenge has failed, RFC 8555 section 7.1.6 makes the
        // authorization invalid, and a sibling answered afterwards can no longer make
        // it valid. Refusing the answer tells the client so at once. The state is
        // minted because network validation does not run under TestServer; it is the
        // state the worker now leaves after a failed http-01.
        var order = await CreateOrderAsync("authz-invalid-sibling.example.com");
        var (siblingPath, siblingId) = await ChallengeAsync(order, "dns-01");
        await SetAuthorizationStatusAsync(order.AuthorizationId, "invalid");

        var response = await PostToPathAsync(order, siblingPath, "{}");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
        (await ReadChallengeStatusAsync(siblingId)).Should().Be(
            "pending", "a refused answer must not reach processing, which the validator sweeps");
    }

    [Fact]
    public async Task RespondToChallenge_OnAValidAuthorization_IsStillAccepted()
    {
        // The control for the refusal above. The check is an allow list, and "valid"
        // is on it: a client may answer a second challenge on an authorization a
        // sibling already proved, which changes nothing either way.
        var order = await CreateOrderAsync("authz-valid-sibling.example.com");
        var (siblingPath, siblingId) = await ChallengeAsync(order, "dns-01");
        await SetAuthorizationStatusAsync(order.AuthorizationId, "valid");

        var response = await PostToPathAsync(order, siblingPath, "{}");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadChallengeStatusAsync(siblingId)).Should().Be("processing");
    }

    [Fact]
    public async Task PostAsGet_OnAPendingChallengeUnderAnInvalidAuthorization_StillReads()
    {
        // Issues #481 and #482 together. The refusal of an answer under an invalid
        // authorization is for the state change only, like the deactivated one: an
        // empty payload is a read, and the read sits above both refusals in
        // ChallengeController. Before #482 this read was a 400 (see #601).
        var order = await CreateOrderAsync("chall-read-invalid-authz.example.com");
        var (siblingPath, siblingId) = await ChallengeAsync(order, "dns-01");
        await SetAuthorizationStatusAsync(order.AuthorizationId, "invalid");

        var response = await PostAsGetAsync(order, siblingPath);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadJsonAsync(response)).GetProperty("status").GetString().Should().Be("pending");
        (await ReadChallengeStatusAsync(siblingId)).Should().Be(
            "pending", "a read must not start validation");
    }

    // ---- Read path branches that had no coverage ----

    [Fact]
    public async Task GetAuthorization_UnknownId_Returns404()
    {
        var order = await CreateOrderAsync("authz-unknown.example.com");

        var response = await PostToAuthzAsync(
            order, "/acme/WebServer/authz/no-such-authorization", string.Empty);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task GetAuthorization_ForAnotherAccountsAuthorization_Returns403()
    {
        var victim = await CreateOrderAsync("authz-tenant-victim-read.example.com");
        var attacker = await CreateOrderAsync("authz-tenant-attacker-read.example.com");

        var response = await PostToAuthzAsync(
            attacker, victim.AuthorizationPath, string.Empty);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Unauthorized);
    }

    [Fact]
    public async Task Deactivate_AnotherAccountsAuthorization_Returns403_AndWritesNothing()
    {
        // The read test above would pass even if ownership were checked AFTER the
        // payload branch. This one is what pins the order of the two.
        var victim = await CreateOrderAsync("authz-tenant-victim-write.example.com");
        var attacker = await CreateOrderAsync("authz-tenant-attacker-write.example.com");

        var response = await PostToAuthzAsync(attacker, victim.AuthorizationPath, Deactivate);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadAuthorizationStatusAsync(victim.AuthorizationId)).Should().Be("pending");
        (await ReadOrderStatusAsync(victim.OrderId)).Should().Be("pending");
    }

    #region Helpers

    /// <summary>An account, and one order created under it.</summary>
    private sealed record OrderInfo(
        string Kid,
        RSA Key,
        string OrderId,
        string OrderPath,
        string[] AuthorizationIds,
        string[] AuthorizationPaths)
    {
        public string AuthorizationId => AuthorizationIds[0];
        public string AuthorizationPath => AuthorizationPaths[0];
    }

    private RSA NewKey()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        return rsa;
    }

    /// <summary>Registers an account and creates one order under it.</summary>
    private async Task<OrderInfo> CreateOrderAsync(params string[] domains)
    {
        var key = NewKey();
        var accountResponse = await PostNewAccountAsync(
            key, """{"termsOfServiceAgreed":true,"contact":["mailto:authz@example.com"]}""");
        accountResponse.IsSuccessStatusCode.Should().BeTrue(
            "every test here builds its account through this helper; the status was {0} " +
            "and the body was {1}",
            accountResponse.StatusCode, await accountResponse.Content.ReadAsStringAsync());

        var kid = accountResponse.Headers.GetValues("Location").First();
        return await CreateOrderAsync(kid, key, domains);
    }

    /// <summary>Creates a second order under an existing account.</summary>
    private Task<OrderInfo> CreateOrderAsync(OrderInfo existing, params string[] domains)
        => CreateOrderAsync(existing.Kid, existing.Key, domains);

    private async Task<OrderInfo> CreateOrderAsync(string kid, RSA key, string[] domains)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(NewOrderPath);
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        var identifiers = string.Join(
            ",", domains.Select(d => $$"""{"type":"dns","value":"{{d}}"}"""));
        var response = await PostJws(
            NewOrderPath, SignJws(key, headerJson, $$"""{"identifiers":[{{identifiers}}]}"""));

        response.IsSuccessStatusCode.Should().BeTrue(
            "the order helper must succeed; the status was {0} and the body was {1}",
            response.StatusCode, await response.Content.ReadAsStringAsync());

        var orderPath = new Uri(response.Headers.GetValues("Location").First()).AbsolutePath;
        var body = await ReadJsonAsync(response);
        var authzPaths = body.GetProperty("authorizations")
            .EnumerateArray()
            .Select(a => new Uri(a.GetString()!).AbsolutePath)
            .ToArray();

        return new OrderInfo(
            kid,
            key,
            orderPath.Split('/').Last(),
            orderPath,
            authzPaths.Select(p => p.Split('/').Last()).ToArray(),
            authzPaths);
    }

    /// <summary>
    /// Posts a kid authenticated request to an authorization URL. An empty payload
    /// is a POST-as-GET; anything else is an update (RFC 8555 §7.5.2).
    /// </summary>
    private Task<HttpResponseMessage> PostToAuthzAsync(
        OrderInfo order, string authzPath, string payloadJson)
        => PostToPathAsync(order, authzPath, payloadJson);

    private Task<HttpResponseMessage> PostAsGetAsync(OrderInfo order, string path)
        => PostToPathAsync(order, path, string.Empty);

    private async Task<HttpResponseMessage> PostToPathAsync(
        OrderInfo order, string path, string payloadJson)
    {
        var nonce = await GetFreshNonce();
        var url = ToAbsoluteUrl(path);
        var headerJson =
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{order.Kid}}"}""";
        return await PostJws(path, SignJws(order.Key, headerJson, payloadJson));
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

    private async Task<string> FirstChallengePathAsync(OrderInfo order)
    {
        var response = await PostAsGetAsync(order, order.AuthorizationPath);
        var challenge = (await ReadJsonAsync(response))
            .GetProperty("challenges").EnumerateArray().First();
        return new Uri(challenge.GetProperty("url").GetString()!).AbsolutePath;
    }

    /// <summary>The path of the order's first authorization's challenge of one type.</summary>
    private async Task<string> ChallengePathAsync(OrderInfo order, string type)
    {
        var response = await PostAsGetAsync(order, order.AuthorizationPath);
        var challenge = (await ReadJsonAsync(response))
            .GetProperty("challenges").EnumerateArray()
            .Single(c => c.GetProperty("type").GetString() == type);
        return new Uri(challenge.GetProperty("url").GetString()!).AbsolutePath;
    }

    /// <summary>The target of the response's Link rel="up" header, or null when it has none.</summary>
    private static string? UpLink(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Link", out var links))
            return null;

        return links
            .Where(l => l.EndsWith(";rel=\"up\"", StringComparison.Ordinal))
            .Select(l => l[(l.IndexOf('<') + 1)..l.IndexOf('>')])
            .SingleOrDefault();
    }

    /// <summary>The path and public id of the order's challenge of one type.</summary>
    private async Task<(string Path, string ChallengeId)> ChallengeAsync(OrderInfo order, string type)
    {
        var response = await PostAsGetAsync(order, order.AuthorizationPath);
        var challenge = (await ReadJsonAsync(response))
            .GetProperty("challenges").EnumerateArray()
            .Single(c => c.GetProperty("type").GetString() == type);
        var path = new Uri(challenge.GetProperty("url").GetString()!).AbsolutePath;
        return (path, path.Split('/').Last());
    }

    // ---- Direct database access ----
    //
    // Network challenge validation does not run under TestServer, so a "valid"
    // authorization or a "ready" order can only be minted by writing the row. This
    // is the idiom AllowedDomainsIntegrationTests and EabIntegrationTests already
    // use. Reads go through a fresh scope with AsNoTracking, because a row read
    // back through the request's own tracked graph would prove nothing about what
    // was persisted.

    private async Task SetAuthorizationStatusAsync(string authorizationId, string status)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var authz = await db.AcmeAuthorizations
            .FirstAsync(a => a.AuthorizationId == authorizationId);
        authz.Status = status;
        await db.SaveChangesAsync();
    }

    private async Task SetOrderStatusAsync(string orderId, string status)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var order = await db.AcmeOrders.FirstAsync(o => o.OrderId == orderId);
        order.Status = status;
        await db.SaveChangesAsync();
    }

    private async Task<string> ReadAuthorizationStatusAsync(string authorizationId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        return (await db.AcmeAuthorizations.AsNoTracking()
            .FirstAsync(a => a.AuthorizationId == authorizationId)).Status;
    }

    private async Task<string> ReadOrderStatusAsync(string orderId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        return (await db.AcmeOrders.AsNoTracking()
            .FirstAsync(o => o.OrderId == orderId)).Status;
    }

    private async Task<string> ReadFirstChallengeStatusAsync(string authorizationId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        return (await db.AcmeChallenges.AsNoTracking()
            .Where(c => c.Authorization.AuthorizationId == authorizationId)
            .OrderBy(c => c.Id)
            .FirstAsync()).Status;
    }

    private async Task<string> ReadChallengeStatusAsync(string authorizationId, string type)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        return (await db.AcmeChallenges.AsNoTracking()
            .SingleAsync(c => c.Authorization.AuthorizationId == authorizationId
                && c.Type == type)).Status;
    }

    private async Task<string> ReadChallengeStatusAsync(string challengeId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        return (await db.AcmeChallenges.AsNoTracking()
            .FirstAsync(c => c.ChallengeId == challengeId)).Status;
    }

    // ---- JWS plumbing ----

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
