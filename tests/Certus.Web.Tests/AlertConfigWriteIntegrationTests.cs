using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Certus.Web.Tests;

/// <summary>
/// PUT /api/alerts/config and POST /api/alerts/config/apply (issue #162).
///
/// <para>
/// Its own host rather than the shared "ACME Integration" collection, for the
/// same reason <see cref="AlertTestSendIntegrationTests"/> takes one: these
/// tests write settings.json in the host's data directory, and that file would
/// otherwise leak into every other class sharing the fixture and make the
/// ownership assertions depend on run order.
/// </para>
///
/// <para>
/// One thing this file cannot cover: <c>CsrfHeaderMiddleware</c> is not
/// registered when authentication is disabled, which is how every integration
/// test runs, so the CSRF requirement on this endpoint is structural (the global
/// middleware covers every mutating /api request) rather than asserted here.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public class AlertConfigWriteIntegrationTests : IClassFixture<CertusWebApplicationFactory>
{
    private readonly CertusWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public AlertConfigWriteIntegrationTests(CertusWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    /// <summary>
    /// Reads the overlay through the same store the endpoint writes with, so a
    /// path resolution mistake shows up as a failing test rather than a test
    /// that quietly inspects a file nobody wrote.
    /// </summary>
    private SettingsOverlay.AlertOverlaySettings? SavedAlerts()
    {
        using var scope = _factory.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AlertConfigStore>().Read().Saved;
    }

    private Task<HttpResponseMessage> PutRawAsync(string json) =>
        _client.PutAsync(
            "/api/alerts/config",
            new StringContent(json, Encoding.UTF8, "application/json"));

    private static object ValidBody(
        bool enabled = true,
        int interval = 60,
        int[]? thresholds = null,
        string host = "relay.example.com",
        string from = "ducks@example.com",
        string[]? recipients = null,
        int port = 587,
        string tlsMode = "starttls",
        string username = "",
        string fromName = "Ducks in a Row",
        string? password = null,
        bool clearPassword = false,
        bool clearUsername = false) => new
        {
            enabled,
            checkIntervalMinutes = interval,
            thresholdDays = thresholds ?? [30, 14, 7, 1],
            smtp = new
            {
                host,
                port,
                tlsMode,
                username,
                clearUsername,
                password,
                clearPassword,
                fromAddress = from,
                fromName,
                recipients = recipients ?? ["ops@example.com"],
            },
        };

    // ── The write itself ──

    [Fact]
    public async Task Put_ValidConfig_PersistsToTheOverlayAndReportsRestartPending()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config",
            ValidBody(interval: 90, thresholds: [60, 30]));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("config").GetProperty("restartPending").GetBoolean().Should().BeTrue();
        body.GetProperty("warnings").EnumerateArray().Should().BeEmpty();

        var saved = SavedAlerts();
        saved.Should().NotBeNull();
        saved!.CheckIntervalMinutes.Should().Be(90);
        saved.ThresholdDays.Should().Equal(60, 30);
        saved.Smtp!.Host.Should().Be("relay.example.com");
        saved.Smtp.Recipients.Should().Equal("ops@example.com");
    }

    [Fact]
    public async Task Put_LeavesTheRestOfTheOverlayAlone()
    {
        // The overlay also carries the CA connection string and the HTTPS
        // certificate thumbprint. An alert save that dropped either would
        // unconfigure the CA or send the host back to its self signed
        // certificate at the next restart.
        string overlayPath;
        using (var scope = _factory.Services.CreateScope())
        {
            overlayPath = scope.ServiceProvider.GetRequiredService<AlertConfigStore>().OverlayPath;
        }

        SettingsOverlay.Mutate(overlayPath, current => current with
        {
            CaConnectionString = "ca.example.com\\Example-CA",
            HttpsCertificateThumbprint = "ABCDEF0123456789",
        });

        var response = await _client.PutAsJsonAsync("/api/alerts/config", ValidBody());
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var overlay = SettingsOverlay.Load(overlayPath);
        overlay.CaConnectionString.Should().Be("ca.example.com\\Example-CA");
        overlay.HttpsCertificateThumbprint.Should().Be("ABCDEF0123456789");
        overlay.Alerts.Should().NotBeNull();
    }

    // ── The password: writable, write only, protected at rest ──

    [Fact]
    public async Task Put_WithAnSmtpPassword_StoresItProtectedAndNeverEchoesIt()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-ducks", password: "hunter2"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().NotContain("hunter2");

        // Protected at rest: the overlay holds a blob the plaintext is not a
        // substring of, and the round trip through the real Data Protection
        // stack (the ephemeral provider in tests) proves Protect ran.
        var saved = SavedAlerts();
        saved!.Smtp!.PasswordProtected.Should().NotBeNullOrEmpty();
        saved.Smtp.PasswordProtected.Should().NotContain("hunter2");

        var configJson = await (await _client.GetAsync("/api/alerts/config"))
            .Content.ReadAsStringAsync();
        configJson.Should().NotContain("hunter2");
        configJson.Should().NotContain(saved.Smtp.PasswordProtected!,
            "the ciphertext is withheld too; a blob in a browser response is attack surface");
    }

    [Fact]
    public async Task Put_WithoutMentioningThePassword_CarriesTheStoredBlobForward()
    {
        // Every save rewrites the whole alert block, so an ordinary edit of an
        // unrelated field must not wipe the saved password.
        await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-ducks", password: "hunter2"));
        var blob = SavedAlerts()!.Smtp!.PasswordProtected;
        blob.Should().NotBeNullOrEmpty();

        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-ducks", interval: 45));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        SavedAlerts()!.Smtp!.PasswordProtected.Should().Be(blob);
    }

    [Fact]
    public async Task Put_ClearPassword_StoresAnEmptyBlobSoTheRemovalIsRecorded()
    {
        await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-ducks", password: "hunter2"));
        SavedAlerts()!.Smtp!.PasswordProtected.Should().NotBeNullOrEmpty();

        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(clearPassword: true));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // Empty, not null, the same distinction the username draws. Null would
        // mean the dashboard does not manage this field and appsettings.json
        // decides, which is indistinguishable from never having saved a
        // password, so every reader that falls back on the overlay's silence
        // would go on using the one this save just removed (issue #286).
        SavedAlerts()!.Smtp!.PasswordProtected.Should().BeEmpty();
    }

    [Fact]
    public async Task Put_SettingAndClearingThePasswordTogether_IsRejected()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(password: "hunter2", clearPassword: true));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync()).Should().NotContain("hunter2");
    }

    // ── The excluded set is refused, not ignored ──

    [Theory]
    [InlineData("\"useSsl\": false")]
    [InlineData("\"passwordProtected\": \"CfDJ8-injected-blob\"")]
    public async Task Put_WithAnUnwritableSmtpSetting_IsRejected(string extraMember)
    {
        // useSsl was replaced by the explicit tlsMode and never became a
        // request member; passwordProtected is the stored form and accepting
        // it from a request would let a caller plant a blob the keyring never
        // produced. Both are unknown members and Disallow turns them into 400s.
        var response = await PutRawAsync($$"""
            {
              "enabled": true,
              "checkIntervalMinutes": 60,
              "thresholdDays": [30],
              "smtp": { "host": "relay.example.com", {{extraMember}} }
            }
            """);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(70000)]
    public async Task Put_PortOutOfRange_IsRejected(int port)
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(port: port));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Put_UnknownTlsMode_IsRejectedWithTheCanonicalNames()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(tlsMode: "opportunistic"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var body = await ParseJsonAsync(response);
        body.GetProperty("problems").EnumerateArray().Should().Contain(
            p => p.GetString()!.Contains("starttls"));
    }

    [Fact]
    public async Task Put_TransportFields_PersistToTheOverlay()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config",
            ValidBody(port: 465, tlsMode: "implicit", username: "svc-ducks", fromName: "Certificate Alerts"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var saved = SavedAlerts();
        saved!.Smtp!.Port.Should().Be(465);
        saved.Smtp.TlsMode.Should().Be("implicit");
        saved.Smtp.Username.Should().Be("svc-ducks");
        saved.Smtp.FromName.Should().Be("Certificate Alerts");
    }

    /// <summary>
    /// The regression issue #261 had to avoid to be shippable at all. The config
    /// endpoint no longer returns the username, so the card renders an empty
    /// username box, and a save of any unrelated field submits that empty box.
    /// If an empty username still meant "contact the relay anonymously", the
    /// first ordinary edit after a page load would drop relay authentication
    /// with no error and nothing in the response to notice it by.
    /// </summary>
    [Fact]
    public async Task Put_WithNoUsername_KeepsTheStoredOneRatherThanBlankingIt()
    {
        await _client.PutAsJsonAsync("/api/alerts/config", ValidBody(username: "svc-ducks"));
        SavedAlerts()!.Smtp!.Username.Should().Be("svc-ducks");

        // An ordinary edit of an unrelated field, with the username box empty
        // exactly as the card submits it.
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(interval: 120, username: ""));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var saved = SavedAlerts();
        saved!.CheckIntervalMinutes.Should().Be(120);
        saved.Smtp!.Username.Should().Be("svc-ducks");
    }

    [Fact]
    public async Task Put_WithClearUsername_StoresAnEmptyOneSoTheRelayIsAnonymous()
    {
        await _client.PutAsJsonAsync("/api/alerts/config", ValidBody(username: "svc-ducks"));

        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(clearUsername: true));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // Empty, not null. Null would mean the dashboard does not manage this
        // field and appsettings.json decides, which is a different state from
        // an administrator having deliberately removed the account name.
        SavedAlerts()!.Smtp!.Username.Should().BeEmpty();
    }

    [Fact]
    public async Task Put_SettingAndClearingTheUsernameAtOnce_IsRejected()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-ducks", clearUsername: true));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var body = await ParseJsonAsync(response);
        body.GetProperty("problems").EnumerateArray().Should().Contain(
            p => p.GetString()!.Contains("remove the saved one"));
    }

    /// <summary>
    /// The warning has to read the overlay rather than the process once a
    /// removal is saved. The bound options still carry the old account name
    /// until the restart lands, so treating those as evidence that a username
    /// is stored would silence the warning about the state the removal just
    /// created: a password standing on its own.
    /// </summary>
    [Fact]
    public async Task Put_AfterClearingTheUsername_StillWarnsThatThePasswordStandsAlone()
    {
        await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-ducks", password: "hunter2"));
        await _client.PutAsJsonAsync("/api/alerts/config", ValidBody(clearUsername: true));

        // An ordinary later edit, carrying no username at all.
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(interval: 90));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("warnings").EnumerateArray().Select(w => w.GetString())
            .Should().Contain(w => w!.Contains("username is blank"));
    }

    [Fact]
    public async Task Put_ANewUsername_ReplacesTheStoredOne()
    {
        await _client.PutAsJsonAsync("/api/alerts/config", ValidBody(username: "svc-ducks"));

        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-herons"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        SavedAlerts()!.Smtp!.Username.Should().Be("svc-herons");
    }

    [Fact]
    public async Task Put_WithAWebhookBlock_IsRejected()
    {
        // The webhook URL is excluded because operator controlled outbound HTTP
        // is an SSRF shape. It has no member on the request type at all.
        var response = await PutRawAsync("""
            {
              "enabled": true,
              "checkIntervalMinutes": 60,
              "thresholdDays": [30],
              "webhook": { "url": "https://attacker.example.com/collect" }
            }
            """);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        SavedAlerts()?.ToString().Should().NotContain("attacker.example.com");
    }

    // ── Invalid input ──

    [Fact]
    public async Task Put_EmptyThresholdList_IsRejectedWithAReadableProblem()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(thresholds: []));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var body = await ParseJsonAsync(response);
        body.GetProperty("problems").EnumerateArray().Should().ContainSingle()
            .Which.GetString().Should().Contain("at least one warning threshold");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public async Task Put_NonPositiveThreshold_IsRejected(int threshold)
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(thresholds: [30, threshold]));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Put_MalformedRecipient_IsRejected()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(recipients: ["not an address"]));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var body = await ParseJsonAsync(response);
        body.GetProperty("problems").EnumerateArray().Should().NotBeEmpty();
    }

    [Fact]
    public async Task Put_HostThatIsReallyAUrl_IsRejected()
    {
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(host: "smtp://relay.example.com:587"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // ── Warnings save rather than refuse ──

    [Fact]
    public async Task Put_EmptyRecipients_SavesAndWarns()
    {
        // The state an operator passes through when moving to a webhook.
        var response = await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(recipients: []));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("warnings").EnumerateArray().Should().NotBeEmpty();
        SavedAlerts()!.Smtp!.Recipients.Should().BeEmpty();
    }

    // ── Ownership, and the saved versus in force distinction ──

    [Fact]
    public async Task GetConfig_AfterASave_ReportsManagedFieldsWithoutClaimingTheValuesAreInForce()
    {
        // The honesty requirement in one test. IOptions<AlertOptions> is a
        // snapshot taken when the host started, and the overlay is registered
        // with reload switched off, so a saved value cannot be in force until a
        // restart. The endpoint has to report the running values and say
        // separately which fields the dashboard now owns.
        await _client.PutAsJsonAsync("/api/alerts/config", ValidBody(interval: 17, thresholds: [99]));

        var response = await _client.GetAsync("/api/alerts/config");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);

        body.GetProperty("checkIntervalMinutes").GetInt32().Should().NotBe(17,
            "the saved value is not in force until the service restarts");

        var managed = body.GetProperty("managedFields").EnumerateArray()
            .Select(e => e.GetString()).ToList();
        managed.Should().Contain("enabled");
        managed.Should().Contain("checkIntervalMinutes");
        managed.Should().Contain("thresholdDays");
        managed.Should().Contain("smtp.host");
        managed.Should().Contain("smtp.recipients");

        body.GetProperty("overlayUnreadable").GetBoolean().Should().BeFalse();
    }

    /// <summary>
    /// Removing a credential is still an act of ownership. Both halves have to
    /// stay on the managed list afterwards, or the card would tell an
    /// administrator that appsettings.json decides a field they just emptied
    /// from this page. Before issue #286 the username stayed and the password
    /// silently dropped off, because a removal stored nothing for it.
    /// </summary>
    [Fact]
    public async Task GetConfig_AfterClearingBothHalvesOfTheCredential_StillReportsThemManaged()
    {
        await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-ducks", password: "hunter2"));
        await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(clearUsername: true, clearPassword: true));

        var body = await ParseJsonAsync(await _client.GetAsync("/api/alerts/config"));

        var managed = body.GetProperty("managedFields").EnumerateArray()
            .Select(e => e.GetString()).ToList();
        managed.Should().Contain("smtp.username");
        managed.Should().Contain("smtp.password");
    }

    /// <summary>
    /// A restart stays owed until it happens, so the server has to answer that
    /// question on every read rather than the browser remembering it.
    ///
    /// Without this, an administrator who saves, closes the tab, and comes back
    /// before restarting sees no banner and a form re-seeded with the running
    /// values. It reads as though the save was lost, and nothing anywhere says a
    /// restart is still owed.
    /// </summary>
    [Fact]
    public async Task GetConfig_ReportsRestartPendingOnAFreshRequest_NotOnlyInTheSaveResponse()
    {
        await _client.PutAsJsonAsync("/api/alerts/config", ValidBody(interval: 33));

        // A completely separate request, standing in for a page reload in a new
        // browser session.
        var body = await ParseJsonAsync(await _client.GetAsync("/api/alerts/config"));

        body.GetProperty("restartPending").GetBoolean().Should().BeTrue();
        body.GetProperty("checkIntervalMinutes").GetInt32().Should().NotBe(33);
    }

    [Fact]
    public async Task Put_BlankSenderWithARelayHost_IsRejected()
    {
        // Every save writes this key, so a blank one would overwrite the
        // ducks@localhost default with an empty string. Nothing downstream
        // objects and the failure only appears at the relay.
        var response = await _client.PutAsJsonAsync("/api/alerts/config", ValidBody(from: ""));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var body = await ParseJsonAsync(response);
        body.GetProperty("problems").EnumerateArray().Should().ContainSingle()
            .Which.GetString().Should().Contain("sender address is required");
    }

    /// <summary>
    /// No secret value ever appears in the response, and a just saved relay
    /// host does not appear either, because it is not in force yet.
    ///
    /// <para>
    /// The second half is the interesting one. The host is deliberately readable
    /// once it is running (a field an administrator can set but cannot see is one
    /// they cannot safely edit), so the naive expectation here is to find
    /// "relay.example.com" in the body right after saving it. Finding it would
    /// mean the endpoint was reporting the overlay rather than the process, and
    /// the card would show a value as in force that the alerting engine is not
    /// using. <c>managedFields</c> is how a saved host is reported instead.
    /// </para>
    ///
    /// <para>
    /// Mostly assertions on values rather than key names, because hasPassword
    /// and hasCredentials are legitimate presence flags whose names must
    /// appear. The username is the exception and gets both: since issue #261 it
    /// is write only, so neither the value nor a property called "username" may
    /// come back, which is also the rule the QA secret guard applies. The
    /// populated in-force case is covered by AlertConfigViewTests in
    /// Certus.Core.Tests; it cannot be covered here without restarting the
    /// host.
    /// </para>
    /// </summary>
    [Fact]
    public async Task GetConfig_NeverReturnsASecretValueAndNotAnUnappliedHostEither()
    {
        await _client.PutAsJsonAsync(
            "/api/alerts/config", ValidBody(username: "svc-ducks", password: "hunter2"));
        var blob = SavedAlerts()!.Smtp!.PasswordProtected!;

        var json = await (await _client.GetAsync("/api/alerts/config")).Content.ReadAsStringAsync();

        json.Should().NotContain("hunter2");
        json.Should().NotContain(blob);
        json.Should().NotContain("\"url\"");
        json.Should().NotContain("relay.example.com");
        // The saved username is reported through managedFields and
        // hasCredentials only. Neither the value nor the property name comes
        // back since issue #261, and the name matters on its own: the QA secret
        // guard flags a field called "username" without reading it.
        json.Should().NotContain("svc-ducks");
        json.Should().NotContain("\"username\"");

        var managed = JsonSerializer.Deserialize<JsonElement>(json)
            .GetProperty("managedFields").EnumerateArray().Select(e => e.GetString());
        managed.Should().Contain("smtp.host");
        managed.Should().Contain("smtp.username");
        managed.Should().Contain("smtp.password");
    }

    // ── Apply ──

    [Fact]
    public async Task ApplyConfig_OnAHostThatCannotRestartItself_SaysSoRatherThanClaimingSuccess()
    {
        // The dev host registers NoOpServiceRestarter, so the operator is told
        // to restart by hand instead of being told a restart is under way.
        var response = await _client.PostAsync("/api/alerts/config/apply", null);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await ParseJsonAsync(response);
        body.GetProperty("restartScheduled").GetBoolean().Should().BeFalse();
        body.GetProperty("message").GetString().Should().Contain("Restart the service");
    }
}
