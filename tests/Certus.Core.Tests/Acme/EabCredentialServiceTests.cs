using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.ActiveDirectory;
using Certus.Core.Data;
using Certus.Core.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for the EAB credential service: creation hands the plaintext secret
/// out exactly once and stores only the protected form, regeneration keeps
/// the key id and configuration while killing the old secret, revocation is
/// terminal, and binding verification walks the RFC 8555 §7.3.4 checks
/// against stored credentials, failing closed when the stored secret cannot
/// be decrypted.
/// </summary>
public class EabCredentialServiceTests : IDisposable
{
    private const string Url = "https://ducks.home.local/acme/WebServer/new-account";

    private readonly SqliteConnection _connection;
    private readonly CertusDbContext _db;
    private readonly EabCredentialService _sut;

    public EabCredentialServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite(_connection)
            .Options;
        _db = new CertusDbContext(options);
        _db.Database.EnsureCreated();

        _sut = new EabCredentialService(
            _db, new FakeSecretProtector(), NullLogger<EabCredentialService>.Instance);
    }

    public void Dispose()
    {
        _db.Dispose();
        _connection.Dispose();
    }

    /// <summary>
    /// Reversible stand in for the Data Protection backed protector: the
    /// prefix marks a protected value, and anything without it decrypts to
    /// null, which is exactly how a foreign keyring failure surfaces.
    /// </summary>
    private sealed class FakeSecretProtector : ISecretProtector
    {
        private const string Prefix = "protected:";

        public string Protect(string plaintext) => Prefix + plaintext;

        public string? TryUnprotect(string protectedValue) =>
            protectedValue.StartsWith(Prefix, StringComparison.Ordinal)
                ? protectedValue[Prefix.Length..]
                : null;
    }

    private static string ExportRsaJwk(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var n = JwsService.Base64UrlEncode(p.Modulus!);
        var e = JwsService.Base64UrlEncode(p.Exponent!);
        return $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
    }

    private static JsonElement BuildEab(
        string kid, string secretBase64Url, string payloadJwkJson, string url = Url)
    {
        var headerJson = $$"""{"alg":"HS256","kid":"{{kid}}","url":"{{url}}"}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJwkJson));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = HMACSHA256.HashData(
            JwsService.Base64UrlDecode(secretBase64Url), signingInput);

        return JsonSerializer.SerializeToElement(new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(signature),
        });
    }

    // ---- Creation ----

    [Fact]
    public async Task CreateAsync_HandsOutTheSecretOnce_AndStoresOnlyTheProtectedForm()
    {
        var (credential, secret) = await _sut.CreateAsync("web servers");

        // 32 random bytes base64url encoded: 43 characters, no padding.
        secret.Should().HaveLength(43);
        credential.KeyId.Should().MatchRegex("^[0-9a-f]{32}$");
        credential.Status.Should().Be("active");
        credential.NamespacesJson.Should().Be("[]");

        // The stored value is whatever the protector produced, never the raw
        // secret itself. (That the real protector's output does not contain
        // the plaintext is covered by the integration test against the actual
        // Data Protection provider.)
        var row = await _db.EabCredentials.AsNoTracking().SingleAsync();
        row.SecretProtected.Should().NotBe(secret);
        row.SecretProtected.Should().Be("protected:" + secret);
    }

    [Fact]
    public async Task CreateAsync_StoresNormalizedNamespaces()
    {
        var (credential, _) = await _sut.CreateAsync(
            "scoped", normalizedNamespaces: ["apps.home.local", "web.home.local"]);

        credential.NamespacesJson.Should().Be("""["apps.home.local","web.home.local"]""");
    }

    [Fact]
    public async Task CreateAsync_EmptyName_Throws()
    {
        var act = () => _sut.CreateAsync("   ");

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task CreateAsync_PinsTheExpiryToUtc()
    {
        // A Local kind (a JSON body carrying an offset) converts to the same
        // instant in UTC; an Unspecified kind (no offset given) is taken to
        // already mean UTC. Expiry checks compare against DateTime.UtcNow,
        // so both must land as Utc kind wall time.
        var instant = DateTime.UtcNow.AddDays(1);
        var (fromLocal, _) = await _sut.CreateAsync(
            "local kind", expiresAt: instant.ToLocalTime());
        fromLocal.ExpiresAt!.Value.Kind.Should().Be(DateTimeKind.Utc);
        fromLocal.ExpiresAt.Value.Should().BeCloseTo(instant, TimeSpan.FromSeconds(1));

        var unspecified = DateTime.SpecifyKind(
            DateTime.UtcNow.AddDays(2), DateTimeKind.Unspecified);
        var (fromUnspecified, _) = await _sut.CreateAsync(
            "unspecified kind", expiresAt: unspecified);
        fromUnspecified.ExpiresAt!.Value.Kind.Should().Be(DateTimeKind.Utc);
        fromUnspecified.ExpiresAt.Value
            .Should().Be(DateTime.SpecifyKind(unspecified, DateTimeKind.Utc));
    }

    // ---- Regeneration ----

    [Fact]
    public async Task RegenerateSecretAsync_RotatesTheSecret_KeepsKidAndNamespaces()
    {
        var (credential, oldSecret) = await _sut.CreateAsync(
            "web servers", normalizedNamespaces: ["home.local"]);
        var oldKeyId = credential.KeyId;

        var result = await _sut.RegenerateSecretAsync(credential.Id);

        result.Outcome.Should().Be(EabRegenerateOutcome.Regenerated);
        result.Credential!.KeyId.Should().Be(oldKeyId);
        result.Credential.NamespacesJson.Should().Be("""["home.local"]""");
        result.Credential.SecretRegeneratedAt.Should().NotBeNull();
        var newSecret = result.Secret;
        newSecret.Should().NotBeNull();
        newSecret.Should().NotBe(oldSecret);

        // The old secret no longer verifies a binding; the new one does.
        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);
        var oldResult = await _sut.VerifyBindingAsync(
            jwk, Url, BuildEab(oldKeyId, oldSecret, jwk));
        oldResult.Outcome.Should().Be(EabVerificationOutcome.Unauthorized);

        var newResult = await _sut.VerifyBindingAsync(
            jwk, Url, BuildEab(oldKeyId, newSecret!, jwk));
        newResult.Outcome.Should().Be(EabVerificationOutcome.Verified);
    }

    [Fact]
    public async Task RegenerateSecretAsync_RevokedCredential_IsRefused()
    {
        var (credential, _) = await _sut.CreateAsync("web servers");
        await _sut.RevokeAsync(credential.Id);

        var result = await _sut.RegenerateSecretAsync(credential.Id);

        result.Outcome.Should().Be(EabRegenerateOutcome.Revoked);
        result.Credential.Should().NotBeNull();
        result.Secret.Should().BeNull();
    }

    [Fact]
    public async Task RegenerateSecretAsync_ExpiredCredential_IsRefused()
    {
        // A fresh secret on an expired credential could never verify, so
        // handing one out would only mislead the administrator.
        var (credential, _) = await _sut.CreateAsync(
            "expired", expiresAt: DateTime.UtcNow.AddMinutes(-5));

        var result = await _sut.RegenerateSecretAsync(credential.Id);

        result.Outcome.Should().Be(EabRegenerateOutcome.Expired);
        result.Secret.Should().BeNull();
    }

    [Fact]
    public async Task RegenerateSecretAsync_UnknownId_ReportsNotFound()
    {
        var result = await _sut.RegenerateSecretAsync(9999);

        result.Outcome.Should().Be(EabRegenerateOutcome.NotFound);
        result.Credential.Should().BeNull();
        result.Secret.Should().BeNull();
    }

    // ---- Revocation ----

    [Fact]
    public async Task RevokeAsync_SetsTheTerminalState_AndIsIdempotent()
    {
        var (credential, _) = await _sut.CreateAsync("web servers");

        var revoked = await _sut.RevokeAsync(credential.Id);
        revoked!.Status.Should().Be("revoked");
        var firstRevokedAt = (await _db.EabCredentials.AsNoTracking().SingleAsync()).RevokedAt;
        firstRevokedAt.Should().NotBeNull();

        (await _sut.RevokeAsync(credential.Id)).Should().NotBeNull();
        (await _db.EabCredentials.AsNoTracking().SingleAsync())
            .RevokedAt.Should().Be(firstRevokedAt, "a second revoke must not restamp");
    }

    [Fact]
    public async Task RevokeAsync_UnknownId_ReturnsNull()
    {
        (await _sut.RevokeAsync(9999)).Should().BeNull();
    }

    // ---- Binding verification ----

    [Fact]
    public async Task VerifyBindingAsync_ValidBinding_ReturnsVerifiedWithTheCredential()
    {
        var (credential, secret) = await _sut.CreateAsync("web servers");
        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);

        var result = await _sut.VerifyBindingAsync(
            jwk, Url, BuildEab(credential.KeyId, secret, jwk));

        result.Outcome.Should().Be(EabVerificationOutcome.Verified);
        result.Credential!.Id.Should().Be(credential.Id);
    }

    [Fact]
    public async Task VerifyBindingAsync_UnknownKid_IsUnauthorized()
    {
        var (_, secret) = await _sut.CreateAsync("web servers");
        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);

        var result = await _sut.VerifyBindingAsync(
            jwk, Url, BuildEab("ffffffffffffffffffffffffffffffff", secret, jwk));

        result.Outcome.Should().Be(EabVerificationOutcome.Unauthorized);
    }

    [Fact]
    public async Task VerifyBindingAsync_RevokedCredential_IsUnauthorized()
    {
        var (credential, secret) = await _sut.CreateAsync("web servers");
        await _sut.RevokeAsync(credential.Id);
        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);

        var result = await _sut.VerifyBindingAsync(
            jwk, Url, BuildEab(credential.KeyId, secret, jwk));

        result.Outcome.Should().Be(EabVerificationOutcome.Unauthorized);
        result.Detail.Should().Contain("revoked");
    }

    [Fact]
    public async Task VerifyBindingAsync_ExpiredCredential_IsUnauthorized()
    {
        var (credential, secret) = await _sut.CreateAsync(
            "web servers", expiresAt: DateTime.UtcNow.AddMinutes(-5));
        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);

        var result = await _sut.VerifyBindingAsync(
            jwk, Url, BuildEab(credential.KeyId, secret, jwk));

        result.Outcome.Should().Be(EabVerificationOutcome.Unauthorized);
        result.Detail.Should().Contain("expired");
    }

    [Fact]
    public async Task VerifyBindingAsync_WrongMacKey_IsUnauthorized()
    {
        var (credential, _) = await _sut.CreateAsync("web servers");
        var wrongSecret = JwsService.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);

        var result = await _sut.VerifyBindingAsync(
            jwk, Url, BuildEab(credential.KeyId, wrongSecret, jwk));

        result.Outcome.Should().Be(EabVerificationOutcome.Unauthorized);
        result.Detail.Should().Contain("signature");
    }

    [Fact]
    public async Task VerifyBindingAsync_PayloadKeyMismatch_IsMalformed()
    {
        var (credential, secret) = await _sut.CreateAsync("web servers");
        using var outerKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);

        // The MAC is valid, but the inner payload carries a different key
        // than the one that signed the outer JWS.
        var result = await _sut.VerifyBindingAsync(
            ExportRsaJwk(outerKey), Url,
            BuildEab(credential.KeyId, secret, ExportRsaJwk(otherKey)));

        result.Outcome.Should().Be(EabVerificationOutcome.Malformed);
        result.Detail.Should().Contain("does not match");
    }

    [Fact]
    public async Task VerifyBindingAsync_UnsupportedAlgorithm_MapsToItsOwnOutcome()
    {
        var (credential, secret) = await _sut.CreateAsync("web servers");
        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);

        // Rebuild the EAB with an asymmetric alg in the inner header.
        var headerJson = $$"""{"alg":"RS256","kid":"{{credential.KeyId}}","url":"{{Url}}"}""";
        var protectedB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwsService.Base64UrlEncode(Encoding.UTF8.GetBytes(jwk));
        var eab = JsonSerializer.SerializeToElement(new JwsFlattenedRequest
        {
            Protected = protectedB64,
            Payload = payloadB64,
            Signature = JwsService.Base64UrlEncode(
                HMACSHA256.HashData(JwsService.Base64UrlDecode(secret),
                    Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}"))),
        });

        var result = await _sut.VerifyBindingAsync(jwk, Url, eab);

        result.Outcome.Should().Be(EabVerificationOutcome.UnsupportedAlgorithm);
    }

    [Fact]
    public async Task VerifyBindingAsync_UndecryptableStoredSecret_FailsClosed()
    {
        var (credential, secret) = await _sut.CreateAsync("web servers");

        // A data directory restored onto another machine: the stored value no
        // longer decrypts. The fake protector returns null for anything
        // without its prefix, the same contract as the real one.
        var row = await _db.EabCredentials.SingleAsync();
        row.SecretProtected = "not-a-protected-value";
        await _db.SaveChangesAsync();

        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);
        var result = await _sut.VerifyBindingAsync(
            jwk, Url, BuildEab(credential.KeyId, secret, jwk));

        result.Outcome.Should().Be(EabVerificationOutcome.Unauthorized);
        result.Detail.Should().Contain("unusable");
    }

    // ---- Update ----

    [Fact]
    public async Task UpdateAsync_ReplacesNameExpiryAndNamespace()
    {
        var (credential, secret) = await _sut.CreateAsync(
            "old name", normalizedNamespaces: ["old.local"]);
        var expiry = DateTime.UtcNow.AddDays(30);

        var result = await _sut.UpdateAsync(
            credential.Id, " new name ", expiry, ["web.home.local"]);

        result.Outcome.Should().Be(EabUpdateOutcome.Updated);
        result.Credential!.Name.Should().Be("new name");
        result.Credential.ExpiresAt.Should().BeCloseTo(expiry, TimeSpan.FromSeconds(1));
        result.Credential.NamespacesJson.Should().Be("""["web.home.local"]""");
        result.Credential.UpdatedAt.Should().NotBeNull();

        // The key id and secret are untouched: the copy already handed to a
        // client keeps verifying after the edit.
        result.Credential.KeyId.Should().Be(credential.KeyId);
        using var rsa = RSA.Create(2048);
        var jwk = ExportRsaJwk(rsa);
        (await _sut.VerifyBindingAsync(jwk, Url, BuildEab(credential.KeyId, secret, jwk)))
            .Outcome.Should().Be(EabVerificationOutcome.Verified);
    }

    [Fact]
    public async Task UpdateAsync_ClearingTheExpiry_StoresNull()
    {
        var (credential, _) = await _sut.CreateAsync(
            "expiring", expiresAt: DateTime.UtcNow.AddDays(1));

        var result = await _sut.UpdateAsync(credential.Id, "expiring", null, []);

        result.Outcome.Should().Be(EabUpdateOutcome.Updated);
        result.Credential!.ExpiresAt.Should().BeNull();
    }

    [Fact]
    public async Task UpdateAsync_MovingTheExpiryForward_RevivesAnExpiredCredential()
    {
        var (credential, _) = await _sut.CreateAsync(
            "lapsed", expiresAt: DateTime.UtcNow.AddMinutes(-5));
        (await _sut.GetBindingGateAsync(credential.Id))
            .Status.Should().Be(EabBindingGateStatus.Expired);

        var result = await _sut.UpdateAsync(
            credential.Id, "lapsed", DateTime.UtcNow.AddDays(7), []);

        result.Outcome.Should().Be(EabUpdateOutcome.Updated);
        (await _sut.GetBindingGateAsync(credential.Id))
            .Status.Should().Be(EabBindingGateStatus.Allowed,
                "an expired credential recovers when its date moves forward");
    }

    [Fact]
    public async Task UpdateAsync_RevokedCredential_IsRefused()
    {
        var (credential, _) = await _sut.CreateAsync(
            "terminal", normalizedNamespaces: ["keep.local"]);
        await _sut.RevokeAsync(credential.Id);

        var result = await _sut.UpdateAsync(credential.Id, "renamed", null, ["new.local"]);

        result.Outcome.Should().Be(EabUpdateOutcome.Revoked);
        var row = await _db.EabCredentials.AsNoTracking().SingleAsync();
        row.Name.Should().Be("terminal", "a refused update must change nothing");
        row.NamespacesJson.Should().Be("""["keep.local"]""");
    }

    [Fact]
    public async Task UpdateAsync_UnknownId_ReportsNotFound()
    {
        (await _sut.UpdateAsync(9999, "ghost", null, []))
            .Outcome.Should().Be(EabUpdateOutcome.NotFound);
    }

    // ---- Owner principal ----

    private static readonly AdPrincipal WebServerPrincipal = new(
        "S-1-5-21-1-2-3-1201", "WEB01$", "computer",
        "CN=WEB01,CN=Computers,DC=home,DC=local");

    [Fact]
    public async Task SetPrincipalAsync_StoresTheLink_AndTheListCarriesIt()
    {
        var (credential, _) = await _sut.CreateAsync("web servers");
        (await _sut.ListAsync())[0].AdPrincipal.Should().BeNull(
            "a fresh credential has no owner link");

        var result = await _sut.SetPrincipalAsync(credential.Id, WebServerPrincipal);

        result.Outcome.Should().Be(EabUpdateOutcome.Updated);
        result.Credential!.AdPrincipalSid.Should().Be("S-1-5-21-1-2-3-1201");
        result.Credential.AdPrincipalName.Should().Be("WEB01$");
        result.Credential.AdPrincipalType.Should().Be("computer");
        result.Credential.UpdatedAt.Should().NotBeNull();

        var row = (await _sut.ListAsync())[0];
        row.AdPrincipal.Should().Be(new EabCredentialPrincipal(
            "S-1-5-21-1-2-3-1201", "WEB01$", "computer"));
    }

    [Fact]
    public async Task SetPrincipalAsync_RevokedCredential_IsRefused()
    {
        var (credential, _) = await _sut.CreateAsync("terminal");
        await _sut.RevokeAsync(credential.Id);

        var result = await _sut.SetPrincipalAsync(credential.Id, WebServerPrincipal);

        result.Outcome.Should().Be(EabUpdateOutcome.Revoked);
        var row = await _db.EabCredentials.AsNoTracking().SingleAsync();
        row.AdPrincipalSid.Should().BeNull("a refused link must change nothing");
    }

    [Fact]
    public async Task ClearPrincipalAsync_RemovesTheLink_AndIsIdempotent()
    {
        var (credential, _) = await _sut.CreateAsync("web servers");
        await _sut.SetPrincipalAsync(credential.Id, WebServerPrincipal);

        var cleared = await _sut.ClearPrincipalAsync(credential.Id);

        cleared.Outcome.Should().Be(EabUpdateOutcome.Updated);
        var row = await _db.EabCredentials.AsNoTracking().SingleAsync();
        row.AdPrincipalSid.Should().BeNull();
        row.AdPrincipalName.Should().BeNull();
        row.AdPrincipalType.Should().BeNull();

        (await _sut.ClearPrincipalAsync(credential.Id))
            .Outcome.Should().Be(EabUpdateOutcome.Updated,
                "clearing an unlinked credential is a harmless no op");
    }

    [Fact]
    public async Task PrincipalOperations_UnknownId_ReportNotFound()
    {
        (await _sut.SetPrincipalAsync(9999, WebServerPrincipal))
            .Outcome.Should().Be(EabUpdateOutcome.NotFound);
        (await _sut.ClearPrincipalAsync(9999))
            .Outcome.Should().Be(EabUpdateOutcome.NotFound);
    }

    // ---- The order time gate ----

    [Fact]
    public async Task GetBindingGateAsync_ActiveCredential_Allows()
    {
        var (credential, _) = await _sut.CreateAsync("web servers");

        var gate = await _sut.GetBindingGateAsync(credential.Id);

        gate.Status.Should().Be(EabBindingGateStatus.Allowed);
        gate.Name.Should().Be("web servers");
    }

    [Fact]
    public async Task GetBindingGateAsync_RevokedCredential_Suspends()
    {
        var (credential, _) = await _sut.CreateAsync("web servers");
        await _sut.RevokeAsync(credential.Id);

        var gate = await _sut.GetBindingGateAsync(credential.Id);

        gate.Status.Should().Be(EabBindingGateStatus.Revoked);
    }

    [Fact]
    public async Task GetBindingGateAsync_ExpiredCredential_Suspends()
    {
        var expiresAt = DateTime.UtcNow.AddMinutes(-5);
        var (credential, _) = await _sut.CreateAsync("web servers", expiresAt: expiresAt);

        var gate = await _sut.GetBindingGateAsync(credential.Id);

        gate.Status.Should().Be(EabBindingGateStatus.Expired);
        gate.ExpiresAt.Should().BeCloseTo(expiresAt, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task GetBindingGateAsync_MissingCredential_FailsClosed()
    {
        var gate = await _sut.GetBindingGateAsync(9999);

        gate.Status.Should().Be(EabBindingGateStatus.Missing);
    }

    [Fact]
    public async Task GetBindingGateAsync_FutureExpiry_StillAllows()
    {
        var (credential, _) = await _sut.CreateAsync(
            "web servers", expiresAt: DateTime.UtcNow.AddDays(30));

        (await _sut.GetBindingGateAsync(credential.Id))
            .Status.Should().Be(EabBindingGateStatus.Allowed);
    }

    [Fact]
    public async Task GetBindingGateAsync_CarriesTheNamespace()
    {
        var (credential, _) = await _sut.CreateAsync(
            "scoped", normalizedNamespaces: ["web.home.local", "apps.home.local"]);

        var gate = await _sut.GetBindingGateAsync(credential.Id);

        gate.Status.Should().Be(EabBindingGateStatus.Allowed);
        gate.Namespaces.Should().Equal("web.home.local", "apps.home.local");
    }

    [Fact]
    public async Task GetBindingGateAsync_SuspendedCredential_CarriesNoNamespace()
    {
        var (credential, _) = await _sut.CreateAsync(
            "revoked scope", normalizedNamespaces: ["home.local"]);
        await _sut.RevokeAsync(credential.Id);

        var gate = await _sut.GetBindingGateAsync(credential.Id);

        gate.Status.Should().Be(EabBindingGateStatus.Revoked);
        gate.Namespaces.Should().BeEmpty("only the Allowed state creates orders");
    }
}
