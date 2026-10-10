using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Certus.Core.Alerts;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// A password removed from the dashboard but not yet restarted onto (issue
/// #286). The state only exists when the running process still carries the old
/// blob, so these tests need a host that started with one, which the shared
/// factory has no way to give them: it has no <c>Certus:Alerts</c> section at
/// all, so every fallback to the bound options lands on null and the bug cannot
/// be reproduced.
///
/// <para>
/// The blob seeded below is deliberate nonsense. Nothing here has to decrypt
/// it: the code paths under test only ask whether a blob is present, and the
/// one path that does try to decrypt it is precisely the witness the test send
/// case uses. Its "could not be read on this machine" message is reachable only
/// when a blob was picked up, so the message's absence is proof the removal was
/// honoured, and no live relay is needed to tell the two outcomes apart.
/// </para>
///
/// <para>
/// One class rather than two, so the single test send here owns the singleton
/// cooldown for this host and cannot be made order dependent by a sibling.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public class AlertClearedPasswordIntegrationTests
    : IClassFixture<AlertStalePasswordWebApplicationFactory>
{
    private readonly HttpClient _client;

    public AlertClearedPasswordIntegrationTests(AlertStalePasswordWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    private static object ConfigBody(
        int interval = 60,
        string username = "",
        string? password = null,
        bool clearPassword = false,
        bool clearUsername = false) => new
        {
            enabled = true,
            checkIntervalMinutes = interval,
            thresholdDays = new[] { 30, 14, 7, 1 },
            smtp = new
            {
                host = "relay.example.com",
                port = 587,
                tlsMode = "starttls",
                username,
                clearUsername,
                password,
                clearPassword,
                fromAddress = "ducks@example.com",
                fromName = "Ducks in a Row",
                recipients = new[] { "ops@example.com" },
            },
        };

    /// <summary>
    /// Save a password, remove it, and leave the running process still holding
    /// the old blob. That is the starting state both tests below need.
    ///
    /// <para>
    /// Deliberately asserts nothing about what the removal stored. How it is
    /// recorded is <c>Put_ClearPassword_StoresAnEmptyBlobSoTheRemovalIsRecorded</c>'s
    /// question, and a guard here would fail first and hide whether the two
    /// behaviours below are actually being held to anything.
    /// </para>
    /// </summary>
    private async Task ClearASavedPasswordAsync()
    {
        await _client.PutAsJsonAsync(
            "/api/alerts/config", ConfigBody(username: "svc-ducks", password: "hunter2"));
        await _client.PutAsJsonAsync("/api/alerts/config", ConfigBody(clearPassword: true));
    }

    /// <summary>
    /// The mirror of <c>Put_AfterClearingTheUsername_StillWarnsThatThePasswordStandsAlone</c>,
    /// which the username has had since issue #261. The warning describes the
    /// state after the save, so the removal has to win over the blob the process
    /// is still running on; treating that blob as evidence a password is stored
    /// silences the one warning this state deserves.
    /// </summary>
    [Fact]
    public async Task Put_AfterClearingThePassword_WarnsThatTheUsernameStandsAlone()
    {
        await ClearASavedPasswordAsync();

        // An ordinary later edit, carrying neither half of the credential.
        var response = await _client.PutAsJsonAsync("/api/alerts/config", ConfigBody(interval: 90));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ParseJsonAsync(response);
        body.GetProperty("warnings").EnumerateArray().Select(w => w.GetString())
            .Should().Contain(w => w!.Contains("no password is stored"));
    }

    /// <summary>
    /// The issue itself. A test send falls back to the stored credential for
    /// whichever half the form did not retype, and both halves have to read a
    /// removal the same way: the card shows the pending state, so a test must
    /// prove the pending state. Before this fix the username honoured the
    /// removal and the password ignored it, so the test authenticated with a
    /// password already on its way out while connecting as nobody.
    /// </summary>
    [Fact]
    public async Task SendTest_AfterClearingThePassword_DoesNotAuthenticateWithTheOldBlob()
    {
        await ClearASavedPasswordAsync();

        // A candidate that names neither half of the credential, which is what
        // the card sends when the operator retypes neither.
        var response = await _client.PostAsJsonAsync("/api/alerts/test", new
        {
            smtp = new
            {
                host = "smtp.test.invalid",
                port = 2525,
                tlsMode = "none",
                fromAddress = "ducks@example.com",
                fromName = "Ducks in a Row",
                recipients = new[] { "ops@example.com" },
            },
        });

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "the request was carried out; the per channel result is the answer");

        var email = (await ParseJsonAsync(response)).GetProperty("results").EnumerateArray()
            .Single(r => r.GetProperty("channel").GetString() == "email");

        // It fails either way: there is no relay at smtp.test.invalid. What
        // differs is where. The seeded blob is not a Data Protection payload, so
        // picking it up fails the send before a socket is ever opened, with a
        // message no other path produces. Reaching the relay instead is the
        // proof that the removal was honoured.
        email.GetProperty("success").GetBoolean().Should().BeFalse();
        email.GetProperty("errorMessage").GetString()
            .Should().NotContain("could not be read on this machine");
    }
}

/// <summary>
/// A host that starts with a saved SMTP password already in force, so a removal
/// saved through the dashboard leaves the overlay and the bound options
/// disagreeing, which is the only state issue #286 lives in.
///
/// The blob is not decryptable on purpose; see the test class for why that is
/// the point rather than a shortcut. Only <c>PasswordProtected</c> is seeded:
/// it is not one of <c>AlertOptions.OutrankableKeys</c>, so supplying it as host
/// configuration cannot make the dashboard's password field read as outranked
/// and change what the endpoints are willing to do with it.
/// </summary>
public sealed class AlertStalePasswordWebApplicationFactory : CertusWebApplicationFactory
{
    /// <summary>
    /// Shaped like a Data Protection payload and decodable as none. What matters
    /// is only that it is not empty.
    /// </summary>
    public const string StaleBlob = "CfDJ8-not-a-real-protected-payload";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        // Certus.Web's appsettings.json has no Certus:Alerts section, so this
        // collides with nothing and is read before Program.cs binds AlertOptions.
        builder.UseSetting(
            $"{AlertOptions.SectionName}:Smtp:PasswordProtected", StaleBlob);

        // Off, so the ExpiryMonitorService this host also registers does not
        // wake up and start working through the test database on a timer.
        builder.UseSetting(AlertOptions.EnabledKey, "false");
    }
}
