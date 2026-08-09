using Certus.Core.Alerts;
using Certus.Core.Configuration;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// The sanitized alert configuration the dashboard is served (issue #161).
///
/// No database and no host: AlertConfigView is a pure projection, in the same
/// spirit as CertificateAlertLadder, precisely so these cases are cheap.
/// </summary>
public class AlertConfigViewTests
{
    [Fact]
    public void From_DerivesChannelEnabledFromTheNotifiersNotTheConfigBlock()
    {
        // An SMTP block is present, but the notifier says it cannot send. Only
        // the notifier knows its own rule, which is the whole reason this flag
        // is not computed from "the block is non null".
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "relay.example.com", Recipients = [] },
        };

        var view = AlertConfigView.From(options, [new FakeNotifier("email", enabled: false)]);

        view.Smtp.Should().NotBeNull();
        view.Smtp!.Enabled.Should().BeFalse();
    }

    [Fact]
    public void From_SmtpHostSetButNoRecipients_ReportsHasHostAndNotEnabled()
    {
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "relay.example.com", Recipients = [] },
        };

        var view = AlertConfigView.From(options, [new FakeNotifier("email", enabled: false)]);

        view.Smtp!.HasHost.Should().BeTrue();
        view.Smtp.Recipients.Should().BeEmpty();
        view.Smtp.Enabled.Should().BeFalse();
    }

    [Fact]
    public void From_RecipientsListedButNoHost_ReportsHasHostFalse()
    {
        // The mirror image of the case above. Both report Enabled false and the
        // dashboard has to give opposite advice, which is what HasHost is for.
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "", Recipients = ["ops@example.com"] },
        };

        var view = AlertConfigView.From(options, [new FakeNotifier("email", enabled: false)]);

        view.Smtp!.HasHost.Should().BeFalse();
        view.Smtp.Recipients.Should().ContainSingle();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void From_SenderBlankButHostAndRecipientsSet_ReportsHasFromAddressFalse(string sender)
    {
        // The third incomplete state (issue #209): everything but the sender
        // is configured, which an explicit null for Smtp:FromAddress in
        // appsettings.json produces. HasFromAddress is what lets the card
        // give this case its own advice instead of a generic "not configured".
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions
            {
                Host = "relay.example.com",
                FromAddress = sender,
                Recipients = ["ops@example.com"],
            },
        };

        var view = AlertConfigView.From(options, [new FakeNotifier("email", enabled: false)]);

        view.Smtp!.HasFromAddress.Should().BeFalse();
        view.Smtp.HasHost.Should().BeTrue();
        view.Smtp.Recipients.Should().ContainSingle();
        view.Smtp.Enabled.Should().BeFalse();
    }

    [Fact]
    public void From_NoSmtpBlock_ReturnsNullSmtp()
    {
        // Null is a third state, distinct from a block that is present but
        // incomplete, and the dashboard says something different about it.
        var view = AlertConfigView.From(new AlertOptions { Smtp = null }, []);

        view.Smtp.Should().BeNull();
    }

    [Fact]
    public void From_NoWebhookBlock_ReturnsNullWebhook()
    {
        var view = AlertConfigView.From(new AlertOptions { Webhook = null }, []);

        view.Webhook.Should().BeNull();
    }

    [Fact]
    public void From_NeverCarriesTheWebhookUrlOrItsHeaderNames()
    {
        var options = new AlertOptions
        {
            Webhook = new WebhookOptions
            {
                Url = "https://hooks.example.com/services/T000/B000/xoxb-secret-token",
                Secret = "shared-secret",
                Headers = new Dictionary<string, string> { ["X-Custom-Token"] = "bearer-abc" },
            },
        };

        var view = AlertConfigView.From(options, [new FakeNotifier("webhook", enabled: true)]);

        // Serialized, so this also catches a property added later that leaks.
        var json = System.Text.Json.JsonSerializer.Serialize(view);
        json.Should().NotContain("hooks.example.com");
        json.Should().NotContain("xoxb-secret-token");
        json.Should().NotContain("shared-secret");
        json.Should().NotContain("X-Custom-Token");
        json.Should().NotContain("bearer-abc");

        view.Webhook!.HasSecret.Should().BeTrue();
        view.Webhook.HeaderCount.Should().Be(1);
    }

    /// <summary>
    /// The SMTP password never appears, from either source: the plaintext
    /// configuration file value or the dashboard's protected blob (whose
    /// ciphertext is itself withheld, because a blob in a browser response is
    /// an offline attack surface for no benefit).
    ///
    /// This assertion has narrowed twice as fields became writable. Issue #162
    /// moved the host and from address into the clear, and the full transport
    /// (port, TLS mode, username, from name) followed when it became dashboard
    /// writable: a field an administrator can set but cannot see is one they
    /// cannot safely edit. The password is the boundary that remains, and this
    /// test is what holds it.
    /// </summary>
    [Fact]
    public void From_NeverCarriesTheSmtpPasswordInAnyForm()
    {
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions
            {
                Host = "relay.internal.example.com",
                Port = 2525,
                Username = "svc-ducks",
                Password = "hunter2",
                PasswordProtected = "CfDJ8-opaque-protected-blob",
                FromAddress = "ducks@example.com",
                FromName = "Ducks Notifier",
                Recipients = ["ops@example.com"],
            },
        };

        var view = AlertConfigView.From(options, [new FakeNotifier("email", enabled: true)]);

        var json = System.Text.Json.JsonSerializer.Serialize(view);
        json.Should().NotContain("hunter2");
        json.Should().NotContain("CfDJ8-opaque-protected-blob");

        // The recipient list is deliberately kept: an operator has to be able to
        // see who is being told. Presence is all that is said about the password.
        json.Should().Contain("ops@example.com");
        view.Smtp!.HasCredentials.Should().BeTrue();
        view.Smtp.HasPassword.Should().BeTrue();
    }

    /// <summary>
    /// The transport settings are returned in the clear now that they are
    /// writable, and the TLS mode reported is always the effective one: the
    /// explicit choice when stored, otherwise what the legacy UseSsl and port
    /// derivation will do, so the form's dropdown shows what a send would use.
    /// </summary>
    [Fact]
    public void From_CarriesTheWritableTransportSettingsWithTheEffectiveTlsMode()
    {
        var derived = AlertConfigView.From(new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "relay.example.com", Port = 465, UseSsl = true },
        }, []);
        derived.Smtp!.Port.Should().Be(465);
        derived.Smtp.TlsMode.Should().Be("implicit");

        var explicitMode = AlertConfigView.From(new AlertOptions
        {
            Smtp = new SmtpOptions
            {
                Host = "relay.example.com",
                Port = 465,
                UseSsl = true,
                TlsMode = SmtpTlsMode.StartTls,
                Username = "svc-ducks",
                FromName = "Ducks Notifier",
            },
        }, []);
        explicitMode.Smtp!.TlsMode.Should().Be("starttls");
        explicitMode.Smtp.Username.Should().Be("svc-ducks");
        explicitMode.Smtp.FromName.Should().Be("Ducks Notifier");
    }

    [Fact]
    public void From_ReportsHasPasswordFromEitherSource()
    {
        AlertConfigView.From(new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "h", Password = "plaintext-from-file" },
        }, []).Smtp!.HasPassword.Should().BeTrue();

        AlertConfigView.From(new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "h", PasswordProtected = "blob" },
        }, []).Smtp!.HasPassword.Should().BeTrue();

        AlertConfigView.From(new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "h" },
        }, []).Smtp!.HasPassword.Should().BeFalse();
    }

    /// <summary>
    /// The counterpart to the assertion above: the two writable transport
    /// settings are returned in the clear, because the form has to show what it
    /// is editing (issue #162). HasHost is kept alongside the host itself, since
    /// the card branches on the presence check in several places.
    /// </summary>
    [Fact]
    public void From_CarriesTheWritableSmtpHostAndFromAddress()
    {
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions
            {
                Host = "relay.internal.example.com",
                FromAddress = "ducks@example.com",
                Recipients = ["ops@example.com"],
            },
        };

        var view = AlertConfigView.From(options, [new FakeNotifier("email", enabled: true)]);

        view.Smtp!.Host.Should().Be("relay.internal.example.com");
        view.Smtp.FromAddress.Should().Be("ducks@example.com");
        view.Smtp.HasHost.Should().BeTrue();
        view.Smtp.HasFromAddress.Should().BeTrue();
    }

    /// <summary>
    /// From is a pure projection of the bound options, so it cannot know what
    /// the settings file layering looks like. The controller fills the ownership
    /// fields in; empty here means "not asked", never "nothing is managed".
    /// </summary>
    [Fact]
    public void From_LeavesTheOwnershipFieldsForTheController()
    {
        var view = AlertConfigView.From(new AlertOptions(), []);

        view.ManagedFields.Should().BeEmpty();
        view.OutrankedFields.Should().BeEmpty();
        view.OverlayUnreadable.Should().BeFalse();
        view.RestartPending.Should().BeFalse();
    }

    // ── HasUnappliedChanges: is a restart still owed? ──

    private static readonly HashSet<string> NothingOutranked = new(StringComparer.OrdinalIgnoreCase);

    private static AlertOptions InForce(
        bool enabled = true,
        int interval = 60,
        int[]? thresholds = null,
        string? host = null,
        string? from = null,
        string[]? recipients = null,
        int port = 587,
        SmtpTlsMode? tlsMode = null,
        string? username = null,
        string? fromName = null,
        string? passwordBlob = null)
    {
        var options = new AlertOptions
        {
            Enabled = enabled,
            CheckIntervalMinutes = interval,
            ThresholdDays = thresholds ?? [30, 14, 7, 1],
        };

        if (host != null || from != null || recipients != null)
        {
            options.Smtp = new SmtpOptions
            {
                Host = host ?? string.Empty,
                FromAddress = from ?? string.Empty,
                Recipients = recipients ?? [],
                Port = port,
                TlsMode = tlsMode,
                Username = username,
                PasswordProtected = passwordBlob,
            };
            if (fromName != null)
                options.Smtp.FromName = fromName;
        }

        return options;
    }

    [Fact]
    public void HasUnappliedChanges_NothingSaved_IsFalse()
    {
        AlertConfigView.HasUnappliedChanges(InForce(), null, NothingOutranked)
            .Should().BeFalse();
    }

    [Fact]
    public void HasUnappliedChanges_SavedMatchesRunning_IsFalse()
    {
        // Saving a value that already matches must not leave the card demanding
        // a restart that would change nothing. The whole writable set,
        // transport fields and password blob included.
        var saved = new SettingsOverlay.AlertOverlaySettings(
            Enabled: true,
            CheckIntervalMinutes: 60,
            ThresholdDays: [30, 14, 7, 1],
            Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                Host: "relay.example.com",
                FromAddress: "ducks@example.com",
                Recipients: ["ops@example.com"],
                Port: 587,
                TlsMode: "starttls",
                Username: "svc-ducks",
                FromName: "Ducks in a Row",
                PasswordProtected: "blob-in-force"));

        var inForce = InForce(
            host: "relay.example.com", from: "ducks@example.com", recipients: ["ops@example.com"],
            port: 587, tlsMode: SmtpTlsMode.StartTls, username: "svc-ducks",
            fromName: "Ducks in a Row", passwordBlob: "blob-in-force");

        AlertConfigView.HasUnappliedChanges(inForce, saved, NothingOutranked).Should().BeFalse();
    }

    [Theory]
    [InlineData("enabled")]
    [InlineData("interval")]
    [InlineData("thresholds")]
    [InlineData("host")]
    [InlineData("from")]
    [InlineData("recipients")]
    [InlineData("port")]
    [InlineData("tlsMode")]
    [InlineData("username")]
    [InlineData("fromName")]
    [InlineData("password")]
    public void HasUnappliedChanges_AnyWritableFieldDiffers_IsTrue(string field)
    {
        var saved = new SettingsOverlay.AlertOverlaySettings(
            Enabled: field == "enabled" ? false : true,
            CheckIntervalMinutes: field == "interval" ? 90 : 60,
            ThresholdDays: field == "thresholds" ? [60, 30] : [30, 14, 7, 1],
            Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                Host: field == "host" ? "new.example.com" : "relay.example.com",
                FromAddress: field == "from" ? "new@example.com" : "ducks@example.com",
                Recipients: field == "recipients"
                    ? ["someone.else@example.com"]
                    : ["ops@example.com"],
                Port: field == "port" ? 465 : 587,
                TlsMode: field == "tlsMode" ? "implicit" : "starttls",
                Username: field == "username" ? "new-user" : "svc-ducks",
                FromName: field == "fromName" ? "New Name" : "Ducks in a Row",
                PasswordProtected: field == "password" ? "new-blob" : "blob-in-force"));

        var inForce = InForce(
            host: "relay.example.com", from: "ducks@example.com", recipients: ["ops@example.com"],
            port: 587, tlsMode: SmtpTlsMode.StartTls, username: "svc-ducks",
            fromName: "Ducks in a Row", passwordBlob: "blob-in-force");

        AlertConfigView.HasUnappliedChanges(inForce, saved, NothingOutranked).Should().BeTrue();
    }

    [Fact]
    public void HasUnappliedChanges_ClearedPassword_OwesARestart()
    {
        // Removing the password is a change like any other: the running
        // process still holds the blob until it restarts.
        var saved = new SettingsOverlay.AlertOverlaySettings(
            Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                Host: "relay.example.com",
                PasswordProtected: null));

        var inForce = InForce(host: "relay.example.com", passwordBlob: "blob-in-force");

        AlertConfigView.HasUnappliedChanges(inForce, saved, NothingOutranked).Should().BeTrue();
    }

    [Fact]
    public void HasUnappliedChanges_OutrankedPasswordKey_IsSkipped()
    {
        // With Certus:Alerts:Smtp:Password supplied by the environment the
        // blob never applies, so a difference there is permanent and must not
        // demand a restart forever.
        var saved = new SettingsOverlay.AlertOverlaySettings(
            Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                Host: "relay.example.com",
                PasswordProtected: "never-applies"));

        var outranked = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            AlertOptions.SmtpPasswordKey,
        };

        AlertConfigView.HasUnappliedChanges(
                InForce(host: "relay.example.com"), saved, outranked)
            .Should().BeFalse();
    }

    [Fact]
    public void HasUnappliedChanges_OutrankedKeyDiffers_IsFalse()
    {
        // An environment variable outranks the overlay permanently, so the
        // difference survives any restart. Reporting it would leave the card
        // demanding a restart forever.
        var saved = new SettingsOverlay.AlertOverlaySettings(CheckIntervalMinutes: 90);

        var outranked = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            AlertOptions.CheckIntervalMinutesKey,
        };

        AlertConfigView.HasUnappliedChanges(InForce(interval: 15), saved, outranked)
            .Should().BeFalse();
    }

    [Fact]
    public void HasUnappliedChanges_SavedSmtpAgainstNoRunningBlock_IsTrue()
    {
        // The default install ships "Smtp": null, so the first save from the
        // dashboard always owes a restart.
        var saved = new SettingsOverlay.AlertOverlaySettings(
            Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(Host: "relay.example.com"));

        AlertConfigView.HasUnappliedChanges(InForce(), saved, NothingOutranked).Should().BeTrue();
    }

    [Fact]
    public void From_NoCredentials_ReportsHasCredentialsFalse()
    {
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions { Host = "relay.example.com", Username = null },
            Webhook = new WebhookOptions { Url = "https://hooks.example.com/x", Secret = null },
        };

        var view = AlertConfigView.From(options, []);

        view.Smtp!.HasCredentials.Should().BeFalse();
        view.Webhook!.HasSecret.Should().BeFalse();
    }

    [Fact]
    public void From_CarriesTheDerivedExpiryWindowAndThresholds()
    {
        // The regression guard for useExpiryWarningDays, which every expiry
        // affordance in the dashboard reads (issue #152).
        var options = new AlertOptions { ThresholdDays = [7, 60, 1] };
        options.NormalizeThresholdDays();

        var view = AlertConfigView.From(options, []);

        view.ThresholdDays.Should().Equal(60, 7, 1);
        view.ExpiryWarningDays.Should().Be(60);
    }

    [Fact]
    public void From_CarriesEnabledAndTheCheckInterval()
    {
        var options = new AlertOptions { Enabled = false, CheckIntervalMinutes = 15 };

        var view = AlertConfigView.From(options, []);

        view.Enabled.Should().BeFalse();
        view.CheckIntervalMinutes.Should().Be(15);
    }

    /// <summary>A notifier that only has to answer Channel and IsEnabled.</summary>
    private sealed class FakeNotifier(string channel, bool enabled) : IAlertNotifier
    {
        public string Channel { get; } = channel;
        public bool IsEnabled { get; } = enabled;

        public Task<AlertNotificationResult> SendExpiryAlertAsync(
            ExpiryAlertBatch batch, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AlertNotificationResult> SendServerCertificateAlertAsync(
            ServerCertificateAlert alert, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<AlertNotificationResult> SendTestAlertAsync(
            TestAlert alert, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
