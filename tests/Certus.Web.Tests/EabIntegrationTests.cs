using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Security;
using Certus.Core.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// Verifies external account binding (RFC 8555 §7.3.4) at the ACME surface:
/// the directory meta follows the enforcement mode with no restart, the
/// new-account matrix across Off / Optional / Required (including the
/// grandfathering read path and the bind and rebind rules for existing
/// accounts), the structural refusals with their problem types, the order
/// time suspension for accounts bound to a revoked or expired credential,
/// and that the MAC secret never lands in the database in plaintext.
/// </summary>
[Trait("Category", "Integration")]
public class EabIntegrationTests : IClassFixture<EabIntegrationTests.EabFactory>, IDisposable
{
    private readonly EabFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public EabIntegrationTests(EabFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
        _client.Dispose();
    }

    private string NewAccountUrl => $"{_client.BaseAddress}acme/WebServer/new-account";

    // ---- Directory meta ----

    [Fact]
    public async Task Directory_ExternalAccountRequired_FollowsTheMode_WithoutRestart()
    {
        _factory.WriteEabMode("off");
        (await FetchDirectoryMetaAsync()).Should().BeFalse();

        _factory.WriteEabMode("required");
        (await FetchDirectoryMetaAsync()).Should().BeTrue();

        // Optional still allows unbound registration, so the RFC flag that
        // says "all newAccount requests must include EAB" stays off.
        _factory.WriteEabMode("optional");
        (await FetchDirectoryMetaAsync()).Should().BeFalse();
    }

    // ---- new-account: Off ----

    [Fact]
    public async Task NewAccount_Off_IgnoresAPresentedBinding()
    {
        _factory.WriteEabMode("off");
        var credential = await CreateCredentialAsync("off-ignore");
        var rsa = NewKey();

        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa)));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var account = await ReadAccountAsync(response);
        account.ExternalAccountBinding.HasValue.Should().BeFalse(
            "a binding presented while enforcement is off is ignored, not recorded");

        (await GetAccountRowCredentialIdAsync(response)).Should().BeNull();
    }

    // ---- new-account: Optional ----

    [Fact]
    public async Task NewAccount_Optional_WithoutBinding_Creates201Unbound()
    {
        _factory.WriteEabMode("optional");
        var rsa = NewKey();

        var response = await PostNewAccountAsync(rsa);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        (await ReadAccountAsync(response)).ExternalAccountBinding.HasValue.Should().BeFalse();
    }

    [Fact]
    public async Task NewAccount_Optional_ValidBinding_BindsAndEchoesIt()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("optional-bind");
        var rsa = NewKey();

        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa)));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var account = await ReadAccountAsync(response);
        account.ExternalAccountBinding.HasValue.Should().BeTrue(
            "RFC 8555 §7.3.4: the account object MUST include the binding");
        EchoedKid(account).Should().Be(credential.KeyId);

        (await GetAccountRowCredentialIdAsync(response)).Should().Be(credential.Id);
    }

    [Fact]
    public async Task NewAccount_Optional_InvalidBinding_HardFails_AndCreatesNoAccount()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("optional-invalid");
        var rsa = NewKey();
        var jwk = ExportRsaJwk(rsa);
        var wrongSecret = JwsService.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, wrongSecret, jwk));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Unauthorized);

        // An invalid presented binding must never fall through to an unbound
        // registration.
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var thumbprint = JwsService.ComputeThumbprint(jwk);
        (await db.AcmeAccounts.AnyAsync(a => a.JwkThumbprint == thumbprint))
            .Should().BeFalse();
    }

    // ---- new-account: Required ----

    [Fact]
    public async Task NewAccount_Required_WithoutBinding_Returns400ExternalAccountRequired()
    {
        _factory.WriteEabMode("required");
        var rsa = NewKey();

        var response = await PostNewAccountAsync(rsa);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.ExternalAccountRequired);
    }

    [Fact]
    public async Task NewAccount_Required_ValidBinding_Creates201Bound()
    {
        _factory.WriteEabMode("required");
        var credential = await CreateCredentialAsync("required-bind");
        var rsa = NewKey();

        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa)));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        (await GetAccountRowCredentialIdAsync(response)).Should().Be(credential.Id);
    }

    [Fact]
    public async Task NewAccount_Required_OnlyReturnExisting_KeepsWorkingForExistingAccounts()
    {
        // The grandfathering contract: an account registered before
        // enforcement keeps resolving through the newAccount read path.
        _factory.WriteEabMode("off");
        var rsa = NewKey();
        (await PostNewAccountAsync(rsa)).StatusCode.Should().Be(HttpStatusCode.Created);

        _factory.WriteEabMode("required");
        var response = await PostNewAccountAsync(rsa, onlyReturnExisting: true);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task NewAccount_Required_ExistingUnboundAccount_PlainRePost_ReturnsTheAccount()
    {
        // certbot and cert-manager re-run plain registration (no
        // onlyReturnExisting) with their saved key. RFC 8555 §7.3 returns the
        // existing account for a known key; a grandfathered account must get
        // its account back, not externalAccountRequired.
        _factory.WriteEabMode("off");
        var rsa = NewKey();
        (await PostNewAccountAsync(rsa)).StatusCode.Should().Be(HttpStatusCode.Created);

        _factory.WriteEabMode("required");
        var response = await PostNewAccountAsync(rsa);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await GetAccountRowCredentialIdAsync(response)).Should().BeNull(
            "the re-POST does not invent a binding");
    }

    [Fact]
    public async Task NewAccount_Required_OnlyReturnExisting_UnknownKey_IsAccountDoesNotExist()
    {
        _factory.WriteEabMode("required");
        var rsa = NewKey();

        var response = await PostNewAccountAsync(rsa, onlyReturnExisting: true);

        // The read path answers with the read path error, not with
        // externalAccountRequired.
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.AccountDoesNotExist);
    }

    // ---- new-account: bind and rebind rules for existing accounts ----

    [Fact]
    public async Task NewAccount_ExistingUnboundAccount_ValidBinding_AdoptsIt()
    {
        _factory.WriteEabMode("optional");
        var rsa = NewKey();
        (await PostNewAccountAsync(rsa)).StatusCode.Should().Be(HttpStatusCode.Created);

        var credential = await CreateCredentialAsync("adopt");
        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa)));

        response.StatusCode.Should().Be(HttpStatusCode.OK, "the account already existed");
        var account = await ReadAccountAsync(response);
        EchoedKid(account).Should().Be(credential.KeyId);
        (await GetAccountRowCredentialIdAsync(response)).Should().Be(credential.Id);
    }

    [Fact]
    public async Task NewAccount_ExistingAccountBoundElsewhere_KeepsTheOriginalBinding()
    {
        _factory.WriteEabMode("optional");
        var credentialA = await CreateCredentialAsync("original");
        var credentialB = await CreateCredentialAsync("interloper");
        var rsa = NewKey();

        var first = await PostNewAccountAsync(
            rsa, BuildEabJws(credentialA.KeyId, credentialA.Secret, ExportRsaJwk(rsa)));
        first.StatusCode.Should().Be(HttpStatusCode.Created);

        var second = await PostNewAccountAsync(
            rsa, BuildEabJws(credentialB.KeyId, credentialB.Secret, ExportRsaJwk(rsa)));

        second.StatusCode.Should().Be(HttpStatusCode.OK);
        var account = await ReadAccountAsync(second);
        EchoedKid(account).Should().Be(credentialA.KeyId,
            "a different credential must never silently swap the stored binding");
        (await GetAccountRowCredentialIdAsync(second)).Should().Be(credentialA.Id);
    }

    // ---- new-account: refusals ----

    [Fact]
    public async Task NewAccount_RevokedCredential_Returns403()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("revoked-reg");
        await RevokeCredentialAsync(credential.Id);
        var rsa = NewKey();

        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa)));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(response)).Detail.Should().Contain("revoked");
    }

    [Fact]
    public async Task NewAccount_ExpiredCredential_Returns403()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync(
            "expired-reg", expiresAt: DateTime.UtcNow.AddMinutes(-5));
        var rsa = NewKey();

        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa)));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(response)).Detail.Should().Contain("expired");
    }

    [Fact]
    public async Task NewAccount_UnsupportedEabAlgorithm_Returns400WithTheAcceptedList()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("bad-alg");
        var rsa = NewKey();

        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa), alg: "RS256"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.BadSignatureAlgorithm);
        error.Algorithms.Should().Contain("HS256");
    }

    [Fact]
    public async Task NewAccount_EabPayloadKeyMismatch_Returns400Malformed()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("key-mismatch");
        var rsa = NewKey();
        var otherRsa = NewKey();

        // Valid MAC, but the inner payload carries a different account key
        // than the one signing the outer JWS.
        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(otherRsa)));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Malformed);
    }

    // ---- The order time gate ----

    [Fact]
    public async Task NewOrder_AccountBoundToRevokedCredential_Returns403()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("order-gate");
        var (account, rsa) = await CreateBoundAccountAsync(credential);

        await RevokeCredentialAsync(credential.Id);
        var response = await PostNewOrderAsync(rsa, account.Kid, "gate.home.local");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var error = await ReadErrorAsync(response);
        error.Type.Should().Be(AcmeErrorType.Unauthorized);
        error.Detail.Should().Contain("order-gate");
        error.Detail.Should().Contain("revoked");
    }

    [Fact]
    public async Task NewOrder_AccountBoundToExpiredCredential_Returns403()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("expiry-gate");
        var (account, rsa) = await CreateBoundAccountAsync(credential);

        await ExpireCredentialAsync(credential.Id);
        var response = await PostNewOrderAsync(rsa, account.Kid, "expired.home.local");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(response)).Detail.Should().Contain("expired");
    }

    [Fact]
    public async Task NewOrder_UnboundAccount_IsUnaffectedByTheGate()
    {
        _factory.WriteEabMode("optional");
        var rsa = NewKey();
        var created = await PostNewAccountAsync(rsa);
        created.StatusCode.Should().Be(HttpStatusCode.Created);
        var kid = created.Headers.GetValues("Location").First();

        var response = await PostNewOrderAsync(rsa, kid, "unbound.home.local");

        response.StatusCode.Should().Be(HttpStatusCode.Created,
            "grandfathered accounts pay no EAB cost at order time");
    }

    [Fact]
    public async Task Finalize_AccountBoundToRevokedCredential_Returns403_AndTheOrderStaysReady()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("finalize-gate");
        var (account, rsa) = await CreateBoundAccountAsync(credential);

        // Order created while the credential is active.
        var orderResponse = await PostNewOrderAsync(rsa, account.Kid, "fin.home.local");
        orderResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        var location = orderResponse.Headers.GetValues("Location").First();
        var orderId = location.Split('/').Last();
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

        await RevokeCredentialAsync(credential.Id);

        var finalizePath = new Uri(order.Finalize).AbsolutePath;
        var nonce = await GetFreshNonce();
        var jws = CreateKidJws(rsa, account.Kid, finalizePath, nonce,
            new FinalizeRequest { Csr = JwsService.Base64UrlEncode(BuildCsr("fin.home.local")) });
        var response = await PostJws(finalizePath, jws);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await ReadErrorAsync(response)).Type.Should().Be(AcmeErrorType.Unauthorized);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            (await db.AcmeOrders.SingleAsync(o => o.OrderId == orderId))
                .Status.Should().Be("ready",
                    "restoring the credential must let the client retry this order");
        }
    }

    // ---- Key rollover and storage invariants ----

    [Fact]
    public async Task KeyRollover_KeepsTheBinding()
    {
        _factory.WriteEabMode("optional");
        var credential = await CreateCredentialAsync("rollover");
        var (account, _) = await CreateBoundAccountAsync(credential);
        var newRsa = NewKey();

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var accountService = scope.ServiceProvider.GetRequiredService<AccountService>();
            var row = await db.AcmeAccounts.SingleAsync(a => a.AccountId == account.AccountId);

            var outcome = await accountService.ChangeKeyAsync(row, ExportRsaJwk(newRsa));

            outcome.Should().Be(KeyChangeOutcome.Changed);
        }

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
            var row = await db.AcmeAccounts.AsNoTracking()
                .SingleAsync(a => a.AccountId == account.AccountId);

            row.ExternalAccountCredentialId.Should().Be(credential.Id,
                "rolling the account key must not touch the binding");
            row.EabJwsJson.Should().NotBeNullOrEmpty(
                "the echoed binding is the registration time proof and survives rollover");
        }
    }

    [Fact]
    public async Task Credential_SecretIsNeverStoredInPlaintext()
    {
        var credential = await CreateCredentialAsync("storage-check");

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.EabCredentials.AsNoTracking()
            .SingleAsync(c => c.Id == credential.Id);

        row.SecretProtected.Should().NotBe(credential.Secret);
        row.SecretProtected.Should().NotContain(credential.Secret[..20]);

        var protector = scope.ServiceProvider.GetRequiredService<ISecretProtector>();
        protector.TryUnprotect(row.SecretProtected).Should().Be(credential.Secret);
    }

    #region Test Helpers

    private sealed record CredentialInfo(int Id, string KeyId, string Secret);

    private sealed record AccountInfo(string Kid, string AccountId);

    private RSA NewKey()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        return rsa;
    }

    private async Task<bool> FetchDirectoryMetaAsync()
    {
        var response = await _client.GetAsync("/acme/WebServer/directory");
        response.EnsureSuccessStatusCode();
        var directory = JsonSerializer.Deserialize<AcmeDirectory>(
            await response.Content.ReadAsStringAsync());
        return directory!.Meta!.ExternalAccountRequired;
    }

    private async Task<CredentialInfo> CreateCredentialAsync(
        string name, DateTime? expiresAt = null)
    {
        using var scope = _factory.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<EabCredentialService>();
        var (credential, secret) = await service.CreateAsync(name, expiresAt);
        return new CredentialInfo(credential.Id, credential.KeyId, secret);
    }

    private async Task RevokeCredentialAsync(int id)
    {
        using var scope = _factory.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<EabCredentialService>();
        (await service.RevokeAsync(id)).Should().NotBeNull();
    }

    private async Task ExpireCredentialAsync(int id)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.EabCredentials.SingleAsync(c => c.Id == id);
        row.ExpiresAt = DateTime.UtcNow.AddMinutes(-5);
        await db.SaveChangesAsync();
    }

    private async Task<(AccountInfo Account, RSA Rsa)> CreateBoundAccountAsync(
        CredentialInfo credential)
    {
        var rsa = NewKey();
        var response = await PostNewAccountAsync(
            rsa, BuildEabJws(credential.KeyId, credential.Secret, ExportRsaJwk(rsa)));
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    private async Task<int?> GetAccountRowCredentialIdAsync(HttpResponseMessage response)
    {
        var accountId = response.Headers.GetValues("Location").First().Split('/').Last();
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertusDbContext>();
        var row = await db.AcmeAccounts.AsNoTracking()
            .SingleAsync(a => a.AccountId == accountId);
        return row.ExternalAccountCredentialId;
    }

    private static async Task<AcmeAccountResponse> ReadAccountAsync(HttpResponseMessage response)
    {
        return JsonSerializer.Deserialize<AcmeAccountResponse>(
            await response.Content.ReadAsStringAsync())!;
    }

    private static async Task<AcmeError> ReadErrorAsync(HttpResponseMessage response)
    {
        response.Content.Headers.ContentType?.MediaType
            .Should().Be("application/problem+json");
        return JsonSerializer.Deserialize<AcmeError>(
            await response.Content.ReadAsStringAsync())!;
    }

    private static string EchoedKid(AcmeAccountResponse account)
    {
        var jws = account.ExternalAccountBinding!.Value.Deserialize<JwsFlattenedRequest>()!;
        var header = JsonSerializer.Deserialize<JwsProtectedHeader>(
            JwsService.Base64UrlDecode(jws.Protected))!;
        return header.Kid!;
    }

    private JwsFlattenedRequest BuildEabJws(
        string kid, string secret, string outerJwkJson,
        string alg = "HS256", string? url = null)
    {
        url ??= NewAccountUrl;
        var headerJson = $$"""{"alg":"{{alg}}","kid":"{{kid}}","url":"{{url}}"}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(outerJwkJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var key = JwsService.Base64UrlDecode(secret);
        var signature = alg switch
        {
            "HS384" => HMACSHA384.HashData(key, signingInput),
            "HS512" => HMACSHA512.HashData(key, signingInput),
            // Anything else is refused before the MAC matters.
            _ => HMACSHA256.HashData(key, signingInput),
        };

        return new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        };
    }

    private async Task<HttpResponseMessage> PostNewAccountAsync(
        RSA rsa, JwsFlattenedRequest? eab = null, bool onlyReturnExisting = false)
    {
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var request = new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:eab-test@example.com" },
            OnlyReturnExisting = onlyReturnExisting,
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
        var jws = CreateKidJws(rsa, kid, "/acme/WebServer/new-order", nonce, payload);
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
    /// Test factory that seeds the wizard status file with an EAB enforcement
    /// mode, following the AllowedDomainsFactory pattern. Tests rewrite the
    /// mode as they need it; the policy hot reads the file.
    /// </summary>
    public sealed class EabFactory : CertusWebApplicationFactory
    {
        private static long _writeCounter;

        public string StatusFilePath => Path.Combine(TempDataDir, SetupStatus.FileName);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            WriteEabMode("off");
        }

        /// <summary>
        /// Rewrite the mode and bump the file's write time monotonically, so
        /// the policy's write time cache always sees a change even when two
        /// writes land within the file system timestamp resolution.
        /// </summary>
        public void WriteEabMode(string mode)
        {
            new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = ["WebServer"],
                EabEnforcement = mode,
            }.Save(StatusFilePath);

            var bump = Interlocked.Increment(ref _writeCounter);
            File.SetLastWriteTimeUtc(StatusFilePath, DateTime.UtcNow.AddSeconds(bump));
        }
    }
}
