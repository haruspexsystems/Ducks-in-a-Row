using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Tests.Acme.Attestation;

namespace Certus.Web.Tests;

/// <summary>
/// End to end tests for the device-attest-01 protocol surface
/// (draft-ietf-acme-device-attest-08): the newOrder identifier gate, the
/// attObj intake on the challenge endpoint, the background validation of a
/// synthetic apple attestation against a seeded trust anchor, and the
/// finalize CSR binding, all through the mock CA. The gate semantics under
/// test: a template with no active profile answers exactly like a server
/// without the feature, the allowlist refuses loudly with an audit row, and
/// the gate re-checks fail closed mid flight.
/// </summary>
[Trait("Category", "Integration")]
public class DeviceAttestIntegrationTests
    : IClassFixture<DeviceAttestWebApplicationFactory>, IDisposable
{
    private const string Template = DeviceAttestWebApplicationFactory.Template;
    private const string Serial = "SN-IT-0001";
    private const string Udid = "00008030-000A1B2C3D4E5F60";

    private static readonly TimeSpan ValidationTimeout = TimeSpan.FromSeconds(20);

    private readonly DeviceAttestWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly List<IDisposable> _disposables = new();

    public DeviceAttestIntegrationTests(DeviceAttestWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var disposable in _disposables)
            disposable.Dispose();
        _client.Dispose();
    }

    // ---- newOrder gate ----

    [Fact]
    public async Task NewOrder_NoProfile_AnswersLikeAnUnsupportedType()
    {
        await _factory.ResetDeviceStateAsync();
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid, DeviceIdentifier(Serial));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.UnsupportedIdentifier);
        // The refusal must be byte identical to the unsupported type answer:
        // no mention of profiles, allowlists, or the feature existing at all.
        error.Detail.Should().Be("Unsupported identifier type: 'permanent-identifier'.");
    }

    [Fact]
    public async Task NewOrder_DisabledProfile_SameInvisibleRefusal()
    {
        await _factory.ResetDeviceStateAsync();
        await _factory.SeedProfileAsync(enabled: false, allowlistedDevices: Serial);
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid, DeviceIdentifier(Serial));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.UnsupportedIdentifier);
        error.Detail.Should().Be("Unsupported identifier type: 'permanent-identifier'.");

        (await _factory.GetAuditRowsAsync("newOrder-device")).Should().BeEmpty(
            "an invisible refusal must not leave an audit trail either");
    }

    [Fact]
    public async Task NewOrder_MixedIdentifiers_ReturnsMalformed()
    {
        await _factory.ResetDeviceStateAsync();
        await _factory.SeedProfileAsync();
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid,
            DeviceIdentifier(Serial),
            new AcmeIdentifier { Type = "dns", Value = "mixed.example.com" });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
    }

    [Fact]
    public async Task NewOrder_NotOnAllowlist_RejectsAndAudits()
    {
        await _factory.ResetDeviceStateAsync();
        await _factory.SeedProfileAsync(allowlistedDevices: "SOME-OTHER-SN");
        var (account, rsa) = await CreateAccountAsync();

        var response = await PostNewOrderAsync(rsa, account.Kid, DeviceIdentifier(Serial));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.RejectedIdentifier);
        error.Subproblems.Should().ContainSingle()
            .Which.Identifier!.Value.Should().Be(Serial);

        var audit = await _factory.GetAuditRowsAsync("newOrder-device");
        audit.Should().ContainSingle();
        audit[0].AccountId.Should().Be(account.AccountId);
        audit[0].TemplateId.Should().Be(Template);
        audit[0].RejectedIdentifiers.Should().Contain(Serial);
    }

    [Fact]
    public async Task NewOrder_ListedDevice_CreatesOrderWithSingleDeviceChallenge()
    {
        await _factory.ResetDeviceStateAsync();
        await _factory.SeedProfileAsync(allowlistedDevices: Serial);
        var (account, rsa) = await CreateAccountAsync();

        var order = await CreateDeviceOrderAsync(rsa, account.Kid, Serial);
        var authz = await GetAuthzAsync(rsa, account.Kid, order.AuthzPath);

        authz.Identifier.Type.Should().Be("permanent-identifier");
        authz.Identifier.Value.Should().Be(Serial);
        authz.Wildcard.Should().BeFalse();
        authz.Challenges.Should().ContainSingle()
            .Which.Type.Should().Be("device-attest-01");
        authz.Challenges[0].Token.Should().NotBeNullOrEmpty();
    }

    // ---- attObj intake ----

    [Fact]
    public async Task Challenge_EmptyAttObj_Returns400AndStaysPending()
    {
        var flow = await StartOpenModeFlowAsync();

        var response = await PostChallengeAsync(
            flow.Rsa, flow.Kid, flow.ChallengePath, new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Detail.Should().Contain("attObj");

        var authz = await GetAuthzAsync(flow.Rsa, flow.Kid, flow.AuthzPath);
        authz.Challenges[0].Status.Should().Be(
            "pending", "a refused intake must not spend the single shot");
    }

    [Fact]
    public async Task Challenge_OversizeAttObj_Returns400()
    {
        var flow = await StartOpenModeFlowAsync();

        var response = await PostChallengeAsync(
            flow.Rsa, flow.Kid, flow.ChallengePath,
            new { attObj = new string('A', 96_001) });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Detail.Should().Contain("too large");
    }

    [Fact]
    public async Task Challenge_AttObjNotBase64Url_Returns400()
    {
        var flow = await StartOpenModeFlowAsync();

        var response = await PostChallengeAsync(
            flow.Rsa, flow.Kid, flow.ChallengePath,
            new { attObj = "!!!not-base64url!!!" });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Detail.Should().Contain("base64url");
    }

    // ---- full flows through the background worker ----

    [Fact]
    public async Task FullFlow_OpenMode_IssuesThroughTheMockCa()
    {
        var flow = await StartOpenModeFlowAsync();
        var attObj = BuildAttestation(flow, attestedSerial: Serial);

        var challengeResponse = await PostChallengeAsync(
            flow.Rsa, flow.Kid, flow.ChallengePath, new { attObj });
        challengeResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var authz = await WaitForAuthzDecisionAsync(flow);
        authz.Status.Should().Be("valid", authz.Challenges[0].Error?.Detail);

        var ready = await WaitForOrderStatusAsync(flow, "ready");
        ready.Status.Should().Be("ready");

        var csr = DeviceCsrBuilder.Build(flow.DeviceKey, $"CN={Serial}");
        var finalizeResponse = await FinalizeAsync(flow.Rsa, flow.Kid, flow.FinalizePath, csr);
        finalizeResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var issued = await GetOrderAsync(flow.Rsa, flow.Kid, flow.OrderPath);
        issued.Status.Should().Be("valid");
        issued.Certificate.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task FullFlow_WrongAttestedSerial_FailsWithBadAttestationStatement()
    {
        var flow = await StartOpenModeFlowAsync();
        var attObj = BuildAttestation(flow, attestedSerial: "A-DIFFERENT-DEVICE");

        (await PostChallengeAsync(flow.Rsa, flow.Kid, flow.ChallengePath, new { attObj }))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var authz = await WaitForAuthzDecisionAsync(flow);
        authz.Status.Should().Be("invalid");
        authz.Challenges[0].Status.Should().Be("invalid");
        authz.Challenges[0].Error!.Type.Should().Be(AcmeErrorType.BadAttestationStatement);

        (await WaitForOrderStatusAsync(flow, "invalid")).Status.Should().Be("invalid");
    }

    [Fact]
    public async Task DelistedBeforeValidation_FailsClosedAndAudits()
    {
        // The order was created while the device was listed; the delisting
        // lands before the attestation is validated. The gate re-check in
        // the validator must refuse a perfect attestation.
        var flow = await StartFlowAsync(
            gateMode: "allowlist", allowlistedDevices: new[] { Serial });
        var attObj = BuildAttestation(flow, attestedSerial: Serial);

        await _factory.RemoveAllowlistEntryAsync(Serial);

        (await PostChallengeAsync(flow.Rsa, flow.Kid, flow.ChallengePath, new { attObj }))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var authz = await WaitForAuthzDecisionAsync(flow);
        authz.Status.Should().Be("invalid");
        authz.Challenges[0].Error!.Type.Should().Be(AcmeErrorType.BadAttestationStatement);
        authz.Challenges[0].Error!.Detail.Should().Contain("policy");

        // The worker writes the audit row last in its validation unit, after
        // the authorization outcome this test just observed, so poll for it.
        var audit = await WaitForAuditRowsAsync("challenge-device");
        audit.Should().ContainSingle();
        audit[0].RejectedIdentifiers.Should().Contain(Serial);
    }

    [Fact]
    public async Task Finalize_WrongKeyCsr_ReturnsBadCsrAndKeepsOrderReady()
    {
        var flow = await DriveToReadyAsync();
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = DeviceCsrBuilder.Build(otherKey, $"CN={Serial}");

        var response = await FinalizeAsync(flow.Rsa, flow.Kid, flow.FinalizePath, csr);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.BadCsr);
        error.Detail.Should().Contain("attested device key");

        (await GetOrderAsync(flow.Rsa, flow.Kid, flow.OrderPath)).Status.Should().Be(
            "ready", "the client may retry with a CSR for the attested key");
    }

    [Fact]
    public async Task Finalize_DelistedDevice_RejectsAndAuditsFinalizeDevice()
    {
        var flow = await DriveToReadyAsync(
            gateMode: "allowlist", allowlistedDevices: new[] { Serial });
        await _factory.RemoveAllowlistEntryAsync(Serial);
        var csr = DeviceCsrBuilder.Build(flow.DeviceKey, $"CN={Serial}");

        var response = await FinalizeAsync(flow.Rsa, flow.Kid, flow.FinalizePath, csr);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.RejectedIdentifier);

        var audit = await _factory.GetAuditRowsAsync("finalize-device");
        audit.Should().ContainSingle();
        audit[0].RejectedIdentifiers.Should().Contain(Serial);

        (await GetOrderAsync(flow.Rsa, flow.Kid, flow.OrderPath)).Status.Should().Be(
            "ready", "restoring the allowlist entry lets the client retry");
    }

    // ---- flow plumbing ----

    /// <summary>Everything a test needs to drive one device order.</summary>
    private sealed record DeviceFlow(
        RSA Rsa,
        string Kid,
        string OrderPath,
        string FinalizePath,
        string AuthzPath,
        string ChallengePath,
        string ChallengeToken,
        X509Certificate2 Root,
        ECDsa DeviceKey);

    private sealed record DeviceOrder(
        string OrderPath, string FinalizePath, string AuthzPath);

    private Task<DeviceFlow> StartOpenModeFlowAsync() =>
        StartFlowAsync(gateMode: "open", allowlistedDevices: Array.Empty<string>());

    /// <summary>
    /// Seeds a fresh profile and anchor, creates an account and a device
    /// order for <see cref="Serial"/>, and fetches the challenge, leaving
    /// the attestation POST to the test.
    /// </summary>
    private async Task<DeviceFlow> StartFlowAsync(
        string gateMode, string[] allowlistedDevices)
    {
        await _factory.ResetDeviceStateAsync();

        var root = SyntheticAttestationBuilder.CreateRoot();
        _disposables.Add(root);
        await _factory.SeedProfileAsync(
            gateMode: gateMode, allowlistedDevices: allowlistedDevices);
        await _factory.SeedAnchorAsync(root);

        var (account, rsa) = await CreateAccountAsync();
        var order = await CreateDeviceOrderAsync(rsa, account.Kid, Serial);
        var authz = await GetAuthzAsync(rsa, account.Kid, order.AuthzPath);
        var challenge = authz.Challenges.Single();

        var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _disposables.Add(deviceKey);

        return new DeviceFlow(
            rsa, account.Kid, order.OrderPath, order.FinalizePath, order.AuthzPath,
            new Uri(challenge.Url).AbsolutePath, challenge.Token, root, deviceKey);
    }

    /// <summary>A full happy validation, returning once the order is ready.</summary>
    private async Task<DeviceFlow> DriveToReadyAsync(
        string gateMode = "open", string[]? allowlistedDevices = null)
    {
        var flow = await StartFlowAsync(gateMode, allowlistedDevices ?? Array.Empty<string>());
        var attObj = BuildAttestation(flow, attestedSerial: Serial);

        (await PostChallengeAsync(flow.Rsa, flow.Kid, flow.ChallengePath, new { attObj }))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var authz = await WaitForAuthzDecisionAsync(flow);
        authz.Status.Should().Be("valid", authz.Challenges[0].Error?.Detail);
        (await WaitForOrderStatusAsync(flow, "ready")).Status.Should().Be("ready");

        return flow;
    }

    /// <summary>
    /// The base64url attestation object for this flow's challenge token,
    /// attesting <paramref name="attestedSerial"/> with the flow's device key.
    /// </summary>
    private string BuildAttestation(DeviceFlow flow, string attestedSerial)
    {
        using var leaf = SyntheticAttestationBuilder.CreateLeaf(
            flow.Root, attestedSerial, Udid,
            SyntheticAttestationBuilder.NonceFor(flow.ChallengeToken),
            key: flow.DeviceKey);
        return SyntheticAttestationBuilder.ToChallengePayload(
            SyntheticAttestationBuilder.BuildAttestationObject("apple", new[] { leaf }));
    }

    /// <summary>
    /// Polls the authorization until the background worker has decided it
    /// (status leaves "pending"), or fails the test after the timeout.
    /// </summary>
    private async Task<AuthorizationResponse> WaitForAuthzDecisionAsync(DeviceFlow flow)
    {
        var deadline = DateTime.UtcNow + ValidationTimeout;
        while (true)
        {
            var authz = await GetAuthzAsync(flow.Rsa, flow.Kid, flow.AuthzPath);
            if (authz.Status != "pending")
                return authz;
            if (DateTime.UtcNow > deadline)
                return authz;
            await Task.Delay(150);
        }
    }

    /// <summary>
    /// Polls the order until it reaches <paramref name="expected"/> or the
    /// timeout passes. The worker persists the authorization outcome and
    /// recalculates the order status in two saves, so an order observed
    /// right after the authorization flipped can lag it by a beat.
    /// </summary>
    private async Task<OrderResponse> WaitForOrderStatusAsync(DeviceFlow flow, string expected)
    {
        var deadline = DateTime.UtcNow + ValidationTimeout;
        while (true)
        {
            var order = await GetOrderAsync(flow.Rsa, flow.Kid, flow.OrderPath);
            if (order.Status == expected || DateTime.UtcNow > deadline)
                return order;
            await Task.Delay(150);
        }
    }

    /// <summary>
    /// Polls for audit rows under one stage until at least one exists or
    /// the timeout passes, for rows the background worker writes after the
    /// state the test has already observed.
    /// </summary>
    private async Task<List<Certus.Core.Data.Entities.DomainPolicyRejection>>
        WaitForAuditRowsAsync(string stage)
    {
        var deadline = DateTime.UtcNow + ValidationTimeout;
        while (true)
        {
            var rows = await _factory.GetAuditRowsAsync(stage);
            if (rows.Count > 0 || DateTime.UtcNow > deadline)
                return rows;
            await Task.Delay(100);
        }
    }

    // ---- ACME client helpers (the house JWS pattern) ----

    private sealed record AccountInfo(string Kid, string AccountId);

    private static AcmeIdentifier DeviceIdentifier(string value) =>
        new() { Type = "permanent-identifier", Value = value };

    private async Task<(AccountInfo Account, RSA Rsa)> CreateAccountAsync()
    {
        var rsa = RSA.Create(2048);
        _disposables.Add(rsa);
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:device-tests@example.com" }
        });

        var headerJson =
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{_client.BaseAddress}}acme/{{Template}}/new-account","jwk":{{jwkJson}}}""";
        var jws = SignJws(rsa, headerJson, payloadJson);

        var response = await PostJws($"/acme/{Template}/new-account", jws);
        response.EnsureSuccessStatusCode();

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    private async Task<HttpResponseMessage> PostNewOrderAsync(
        RSA rsa, string kid, params AcmeIdentifier[] identifiers)
    {
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, kid, $"/acme/{Template}/new-order", nonce,
            new NewOrderRequest { Identifiers = identifiers });
        return await PostJws($"/acme/{Template}/new-order", jws);
    }

    private async Task<DeviceOrder> CreateDeviceOrderAsync(
        RSA rsa, string kid, string identifierValue)
    {
        var response = await PostNewOrderAsync(rsa, kid, DeviceIdentifier(identifierValue));
        response.StatusCode.Should().Be(HttpStatusCode.Created);

        var orderPath = new Uri(response.Headers.GetValues("Location").First()).AbsolutePath;
        var order = JsonSerializer.Deserialize<OrderResponse>(
            await response.Content.ReadAsStringAsync())!;
        order.Authorizations.Should().HaveCount(1);

        return new DeviceOrder(
            orderPath,
            new Uri(order.Finalize).AbsolutePath,
            new Uri(order.Authorizations[0]).AbsolutePath);
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

    private async Task<OrderResponse> GetOrderAsync(RSA rsa, string kid, string orderPath)
    {
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, kid, orderPath, nonce, (object?)null);
        var response = await PostJws(orderPath, jws);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return JsonSerializer.Deserialize<OrderResponse>(
            await response.Content.ReadAsStringAsync())!;
    }

    private async Task<HttpResponseMessage> PostChallengeAsync(
        RSA rsa, string kid, string challengePath, object payload)
    {
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, kid, challengePath, nonce, payload);
        return await PostJws(challengePath, jws);
    }

    private async Task<HttpResponseMessage> FinalizeAsync(
        RSA rsa, string kid, string finalizePath, byte[] csrDer)
    {
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, kid, finalizePath, nonce,
            new FinalizeRequest { Csr = JwsService.Base64UrlEncode(csrDer) });
        return await PostJws(finalizePath, jws);
    }

    private static async Task<AcmeError> ReadErrorAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<AcmeError>(await response.Content.ReadAsStringAsync())!;

    private JwsFlattenedRequest CreateKidJws(
        RSA rsa, string kid, string path, string nonce, object? payload)
    {
        var url = $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{path}";
        var payloadJson = payload != null
            ? JsonSerializer.Serialize(payload)
            : ""; // POST-as-GET has empty payload

        var headerJson =
            $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        return SignJws(rsa, headerJson, payloadJson);
    }

    private static JwsFlattenedRequest SignJws(RSA rsa, string headerJson, string payloadJson)
    {
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = rsa.SignData(
            signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature)
        };
    }

    private async Task<string> GetFreshNonce()
    {
        var response = await _client.GetAsync($"/acme/{Template}/new-nonce");
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
}
