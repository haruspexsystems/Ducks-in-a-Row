using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Certus.Core.Acme.Crypto;
using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// The key change refusals that can only happen at the save, after the controller's
/// pre-check found the new key free (RFC 8555 §7.3.5, issue #127). The pre-check and the
/// save are separate statements, so a concurrent request can register the key between them,
/// and the unique index on the thumbprint is what catches it. Until issue #127 that arm
/// answered 409 with no Location header, and it also answered 409 for any other failure to
/// save, so a locked database told the client its new key was taken when it was not.
///
/// <para>
/// Neither arm is reachable by timing from a test, so the factory's DbContext carries a hook
/// that runs a callback once, at the moment the key swap is about to be saved. That is the
/// window the race lives in. The class has its own factory and therefore its own collection,
/// rather than joining the shared "ACME Integration" one, so its host never overlaps the
/// shared host or touches the shared database.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public class KeyChangeRaceIntegrationTests
    : IClassFixture<KeyChangeRaceIntegrationTests.KeySwapHookFactory>, IDisposable
{
    private const string KeyChangePath = "/acme/WebServer/key-change";

    private readonly KeySwapHookFactory _factory;
    private readonly HttpClient _client;
    private readonly List<RSA> _keys = new();

    public KeyChangeRaceIntegrationTests(KeySwapHookFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public void Dispose()
    {
        // A failing test must not leave the hook armed for the next one.
        _factory.Hook.Disarm();
        foreach (var key in _keys)
            key.Dispose();
    }

    [Fact]
    public async Task KeyChange_KeyClaimedBetweenThePreCheckAndTheSave_Returns409WithLocation()
    {
        var (accountA, oldKeyA) = await CreateAccountAsync();
        var newKey = NewKey();
        var jws = await BuildKeyChangeJws(oldKeyA, newKey, accountA.Kid, accountA.Kid);

        // Stands in for a concurrent new-account registering the same key after the
        // controller looked and found it free. It drives the real service on its own scope,
        // and so its own DbContext, as a second request would, rather than writing a row by
        // hand, so the refusal that follows is the unique index's and nothing else's.
        string? holderAccountId = null;
        _factory.Hook.BeforeNextKeySwap(async () =>
        {
            using var scope = _factory.Services.CreateScope();
            var accounts = scope.ServiceProvider.GetRequiredService<AccountService>();
            var (holder, alreadyExists) = await accounts.CreateAccountAsync(
                ExportRsaJwk(newKey), new NewAccountRequest { TermsOfServiceAgreed = true });
            alreadyExists.Should().BeFalse("the key must have been free when the hook ran");
            holderAccountId = holder!.AccountId;
        });

        var response = await PostJws(KeyChangePath, jws);
        var body = await response.Content.ReadAsStringAsync();

        holderAccountId.Should().NotBeNull(
            "the hook must fire, or this test never reached the race it exists for; " +
            "the status was {0} and the body was {1}", response.StatusCode, body);
        response.StatusCode.Should().Be(HttpStatusCode.Conflict, "the response body was {0}", body);
        var error = JsonSerializer.Deserialize<AcmeError>(body);
        error!.Type.Should().Be(AcmeErrorType.Malformed,
            "the race answers exactly what the pre-check answers for the same key");
        response.Headers.Location.Should().NotBeNull(
            "RFC 8555 §7.3.5 makes a 409 name the account holding the key, on this arm too");
        response.Headers.Location!.ToString().Should().Be(
            ToAbsoluteUrl(AccountPath(holderAccountId!)),
            "the 409 points at the account that won the race, not at the one that lost it");

        using var verify = _factory.Services.CreateScope();
        var db = verify.ServiceProvider.GetRequiredService<CertusDbContext>();
        (await db.AcmeAccounts.AsNoTracking().SingleAsync(a => a.AccountId == accountA.AccountId))
            .JwkThumbprint.Should().Be(JwsService.ComputeThumbprint(ExportRsaJwk(oldKeyA)),
                "the losing account keeps its old key");
    }

    [Fact]
    public async Task KeyChange_SaveFailsForAnotherReason_IsNotReportedAsAConflict()
    {
        // The other half of issue #127. A locked database at the save is not a statement
        // about who holds the key. Before the fix this answered 409 with no Location, which
        // is the exact signature of the failure the issue was filed on.
        var (accountA, oldKeyA) = await CreateAccountAsync();
        var newKey = NewKey();
        var jws = await BuildKeyChangeJws(oldKeyA, newKey, accountA.Kid, accountA.Kid);

        var fired = false;
        _factory.Hook.BeforeNextKeySwap(() =>
        {
            fired = true;
            // The shape EF Core produces when SQLite reports SQLITE_BUSY at the save.
            throw new DbUpdateException(
                "An error occurred while saving the entity changes. See the inner exception for details.",
                new SqliteException("SQLite Error 5: 'database is locked'.", 5, 5));
        });

        var response = await PostJws(KeyChangePath, jws);
        var body = await response.Content.ReadAsStringAsync();

        fired.Should().BeTrue("the hook must fire, or this test never reached the save");
        response.StatusCode.Should().NotBe(HttpStatusCode.Conflict,
            "nothing holds the new key, so telling the client it is in use would be false");
        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError,
            "an unexpected save failure answers 500, as a new-account that hits one does; " +
            "the response body was {0}", body);
    }

    #region Helpers

    private record AccountInfo(string Kid, string AccountId);

    private RSA NewKey()
    {
        var rsa = RSA.Create(2048);
        _keys.Add(rsa);
        return rsa;
    }

    private async Task<(AccountInfo Account, RSA Rsa)> CreateAccountAsync()
    {
        var rsa = NewKey();
        var jwkJson = ExportRsaJwk(rsa);
        var nonce = await GetFreshNonce();
        var payloadJson = JsonSerializer.Serialize(new NewAccountRequest
        {
            TermsOfServiceAgreed = true,
            Contact = new[] { "mailto:keychange-race@example.com" }
        });

        var url = ToAbsoluteUrl("/acme/WebServer/new-account");
        var headerJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","jwk":{{jwkJson}}}""";
        var jws = SignJws(rsa, headerJson, payloadJson);

        var response = await PostJws("/acme/WebServer/new-account", jws);
        var body = await response.Content.ReadAsStringAsync();
        response.IsSuccessStatusCode.Should().BeTrue(
            "new-account must succeed before the key-change assertions mean anything; " +
            "the status was {0} and the body was {1}", response.StatusCode, body);

        var kid = response.Headers.GetValues("Location").First();
        return (new AccountInfo(kid, kid.Split('/').Last()), rsa);
    }

    /// <summary>
    /// Builds a key-change request: the outer JWS is signed by the old account key (kid) and
    /// its payload is an inner JWS signed by the new key (jwk) carrying { account, oldKey }.
    /// </summary>
    private async Task<JwsFlattenedRequest> BuildKeyChangeJws(
        RSA oldKey, RSA newKey, string kid, string accountUrl)
    {
        var url = ToAbsoluteUrl(KeyChangePath);

        var newJwk = ExportRsaJwk(newKey);
        var oldJwk = ExportRsaJwk(oldKey);
        var innerHeaderJson = $$"""{"alg":"RS256","url":"{{url}}","jwk":{{newJwk}}}""";
        var innerPayloadJson = $$"""{"account":"{{accountUrl}}","oldKey":{{oldJwk}}}""";
        var innerJws = SignJws(newKey, innerHeaderJson, innerPayloadJson);

        var nonce = await GetFreshNonce();
        var outerHeaderJson = $$"""{"alg":"RS256","nonce":"{{nonce}}","url":"{{url}}","kid":"{{kid}}"}""";
        var outerPayloadJson = JsonSerializer.Serialize(innerJws);
        return SignJws(oldKey, outerHeaderJson, outerPayloadJson);
    }

    private static string AccountPath(string accountId) => $"/acme/WebServer/acct/{accountId}";

    private string ToAbsoluteUrl(string path)
    {
        var encodedPath = new Microsoft.AspNetCore.Http.PathString(path).ToUriComponent();
        return $"{_client.BaseAddress!.Scheme}://{_client.BaseAddress.Authority}{encodedPath}";
    }

    private static JwsFlattenedRequest SignJws(RSA rsa, string headerJson, string payloadJson)
    {
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

    /// <summary>
    /// A factory whose DbContext runs <see cref="Hook"/> on every save. Everything else is
    /// the shared factory's: the file database, the seeded WebServer template, the mock CA.
    /// </summary>
    public sealed class KeySwapHookFactory : CertusWebApplicationFactory
    {
        public KeySwapSaveHook Hook { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            builder.ConfigureServices(services =>
                services.ConfigureDbContext<CertusDbContext>(options => options.AddInterceptors(Hook)));
        }
    }

    /// <summary>
    /// Runs a callback once, as a key swap is about to be saved, which is the instant between
    /// the key change pre-check and the unique index. A save that changes no account
    /// thumbprint passes straight through, so the background workers and every other request
    /// on the host are untouched, armed or not.
    /// </summary>
    public sealed class KeySwapSaveHook : SaveChangesInterceptor
    {
        private Func<Task>? _beforeNextKeySwap;

        public void BeforeNextKeySwap(Func<Task> callback) =>
            Interlocked.Exchange(ref _beforeNextKeySwap, callback);

        public void Disarm() => Interlocked.Exchange(ref _beforeNextKeySwap, null);

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (eventData.Context is { } context && IsKeySwap(context))
            {
                var callback = Interlocked.Exchange(ref _beforeNextKeySwap, null);
                if (callback != null)
                    await callback();
            }
            return result;
        }

        private static bool IsKeySwap(DbContext context) =>
            context.ChangeTracker.Entries<AcmeAccount>().Any(e =>
                e.State == EntityState.Modified &&
                e.Property(a => a.JwkThumbprint).IsModified);
    }
}
