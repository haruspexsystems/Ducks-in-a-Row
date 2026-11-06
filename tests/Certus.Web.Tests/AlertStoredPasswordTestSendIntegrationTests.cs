using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Certus.Core.Alerts;
using Microsoft.AspNetCore.Hosting;

namespace Certus.Web.Tests;

/// <summary>
/// POST /api/alerts/test must not carry the stored SMTP password to a relay
/// other than the one it was saved for (issue #635, CRA R09). The host here
/// runs with a relay and a stored password blob in its bound options, which
/// is the state after a restart on a saved configuration.
///
/// <para>
/// The blob is the same deliberate nonsense the cleared password tests use:
/// nothing here needs to decrypt it. A candidate that reaches the notifier
/// with it fails with "could not be read on this machine", which is exactly
/// the witness that the send was attempted rather than refused.
/// </para>
///
/// <para>
/// Its own factory and therefore its own throttle. The refusal is proven not
/// to arm the cooldown by the same relay test that follows it in the same
/// method; a second host is used for the typed password case, because the
/// first host's cooldown is armed by then.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public class AlertStoredPasswordTestSendIntegrationTests
    : IClassFixture<AlertSavedRelayWebApplicationFactory>
{
    private readonly AlertSavedRelayWebApplicationFactory _factory;

    public AlertStoredPasswordTestSendIntegrationTests(AlertSavedRelayWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

    private static object Candidate(string host, int port, string tlsMode, string? password = null) => new
    {
        smtp = new
        {
            host,
            port,
            tlsMode,
            password,
            fromAddress = "ducks@example.com",
            fromName = "Ducks in a Row",
            recipients = new[] { "ops@example.com" },
        },
    };

    [Fact]
    public async Task SendTest_StoredPassword_GoesOnlyToTheSavedRelay()
    {
        var client = _factory.CreateClient();

        // Another host, the saved port and TLS mode, no password typed: refused
        // before anything connects, with the text the card shows.
        var otherHost = await client.PostAsJsonAsync(
            "/api/alerts/test", Candidate("smtp.attacker.invalid", 587, "starttls"));
        otherHost.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ParseJsonAsync(otherHost)).GetProperty("error").GetString()
            .Should().Be(SmtpTestSendPolicy.Refusal);

        // The saved host with TLS switched off: the same refusal. This is the
        // shape of the attack the issue names.
        var tlsOff = await client.PostAsJsonAsync(
            "/api/alerts/test", Candidate(AlertSavedRelayWebApplicationFactory.Host, 587, "none"));
        tlsOff.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // The saved relay exactly: the stored password may be used, so the send
        // is attempted. It reaches the notifier, which cannot read the seeded
        // blob; that message is the proof the refusal above did not fire here,
        // and that the two refusals armed no cooldown.
        var sameRelay = await client.PostAsJsonAsync(
            "/api/alerts/test", Candidate(AlertSavedRelayWebApplicationFactory.Host, 587, "starttls"));
        sameRelay.StatusCode.Should().Be(HttpStatusCode.OK);
        var email = (await ParseJsonAsync(sameRelay)).GetProperty("results").EnumerateArray()
            .Single(r => r.GetProperty("channel").GetString() == "email");
        email.GetProperty("success").GetBoolean().Should().BeFalse();
        email.GetProperty("errorMessage").GetString().Should().Contain("could not be read on this machine");
    }

    [Fact]
    public async Task SendTest_AnotherRelayWithItsOwnPassword_IsAttempted()
    {
        // A fresh host, so the cooldown the test above arms does not reach here.
        using var fresh = _factory.WithWebHostBuilder(_ => { });
        var client = fresh.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/alerts/test", Candidate("smtp.test.invalid", 2525, "none", password: "typed-for-this-relay"));

        response.StatusCode.Should().Be(HttpStatusCode.OK, "a test that carries its own password may go anywhere");
        var email = (await ParseJsonAsync(response)).GetProperty("results").EnumerateArray()
            .Single(r => r.GetProperty("channel").GetString() == "email");
        email.GetProperty("success").GetBoolean().Should().BeFalse("there is no relay at smtp.test.invalid");
        email.GetProperty("errorMessage").GetString().Should().NotContain("could not be read on this machine");
        email.GetProperty("errorMessage").GetString().Should().NotContain("typed-for-this-relay");
    }
}

/// <summary>
/// A host running on a saved relay with a stored password blob, the state after
/// a restart on a configuration saved from the dashboard. Only the values the
/// test send compares are set, plus the blob; see
/// <see cref="AlertStalePasswordWebApplicationFactory"/> for why seeding the blob
/// through host configuration is safe.
/// </summary>
public sealed class AlertSavedRelayWebApplicationFactory : CertusWebApplicationFactory
{
    public const string Host = "relay.example.com";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.UseSetting($"{AlertOptions.SectionName}:Smtp:Host", Host);
        builder.UseSetting($"{AlertOptions.SectionName}:Smtp:Port", "587");
        builder.UseSetting($"{AlertOptions.SectionName}:Smtp:TlsMode", "StartTls");
        builder.UseSetting($"{AlertOptions.SectionName}:Smtp:FromAddress", "ducks@example.com");
        builder.UseSetting($"{AlertOptions.SectionName}:Smtp:Recipients:0", "ops@example.com");
        builder.UseSetting(
            $"{AlertOptions.SectionName}:Smtp:PasswordProtected",
            AlertStalePasswordWebApplicationFactory.StaleBlob);

        // Off, so the expiry monitor does not wake up on a timer against the
        // test database.
        builder.UseSetting(AlertOptions.EnabledKey, "false");
    }
}
