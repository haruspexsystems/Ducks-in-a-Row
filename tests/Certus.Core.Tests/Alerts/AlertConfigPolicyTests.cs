using Certus.Core.Alerts;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// What the dashboard may save into the alert configuration (issue #162).
///
/// The line these tests hold is the one between an error and a warning: an error
/// refuses the write because the input cannot be stored as a working
/// configuration, and a warning saves it while saying it will not deliver. A
/// state an operator passes through on the way somewhere else must never be an
/// error, or the card fights them mid change.
/// </summary>
public class AlertConfigPolicyTests
{
    private static AlertConfigInput Valid(
        bool enabled = true,
        int interval = 60,
        int[]? thresholds = null,
        string? host = "relay.example.com",
        string? from = "ducks@example.com",
        string[]? recipients = null) =>
        new(
            Enabled: enabled,
            CheckIntervalMinutes: interval,
            ThresholdDays: thresholds ?? [30, 14, 7, 1],
            SmtpHost: host,
            SmtpFromAddress: from,
            SmtpRecipients: recipients ?? ["ops@example.com"]);

    // ── The happy path and normalization ──

    [Fact]
    public void Validate_GoodInput_NormalizesAndCarriesTheWholeWritableSet()
    {
        var result = AlertConfigPolicy.Validate(Valid(), webhookDeliverable: false);

        result.IsValid.Should().BeTrue();
        result.Warnings.Should().BeEmpty();

        var saved = result.Normalized!;
        saved.Enabled.Should().BeTrue();
        saved.CheckIntervalMinutes.Should().Be(60);
        saved.ThresholdDays.Should().Equal(30, 14, 7, 1);
        saved.Smtp!.Host.Should().Be("relay.example.com");
        saved.Smtp.FromAddress.Should().Be("ducks@example.com");
        saved.Smtp.Recipients.Should().Equal("ops@example.com");
    }

    [Fact]
    public void Validate_ThresholdsAreSortedWidestFirstAndDeduplicated()
    {
        var result = AlertConfigPolicy.Validate(
            Valid(thresholds: [7, 30, 7, 1]), webhookDeliverable: false);

        result.Normalized!.ThresholdDays.Should().Equal(30, 7, 1);
    }

    [Fact]
    public void Validate_TrimsAndDeduplicatesRecipients()
    {
        var result = AlertConfigPolicy.Validate(
            Valid(recipients: ["  ops@example.com  ", "OPS@example.com", "sec@example.com"]),
            webhookDeliverable: false);

        result.IsValid.Should().BeTrue();
        result.Normalized!.Smtp!.Recipients.Should().Equal("ops@example.com", "sec@example.com");
    }

    // ── Errors: input that cannot be stored as a working configuration ──

    [Fact]
    public void Validate_EmptyThresholdList_IsRefused()
    {
        // Not a warning. An empty array is not a state the alerting engine
        // tolerates, so it is not storable.
        var result = AlertConfigPolicy.Validate(
            Valid(thresholds: []), webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Normalized.Should().BeNull();
        result.Errors.Should().ContainSingle().Which.Should().Contain("at least one warning threshold");
    }

    [Fact]
    public void Validate_EmptyThresholdList_IsStillRefusedWithMonitoringOff()
    {
        // The message must not offer switching monitoring off as a way out,
        // because it is not one: the check runs either way.
        var result = AlertConfigPolicy.Validate(
            Valid(enabled: false, thresholds: []), webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().NotContain("switch expiry monitoring off");
    }

    /// <summary>
    /// A blank sender with a relay host set is the quietest way to break
    /// alerting there is, so it is refused rather than warned about.
    ///
    /// Every save writes this key, so a blank one overwrites the
    /// ducks@localhost initializer default with an empty string. Nothing
    /// downstream objects: EmailAlertNotifier.IsEnabled checks the host and the
    /// recipients but not the sender, so the card reports the channel enabled,
    /// and MimeKit builds "From: &lt;&gt;" without complaint. The failure only
    /// appears at the relay, which rejects a null reverse path, by which time it
    /// reads as a delivery fault rather than a configuration one.
    /// </summary>
    [Fact]
    public void Validate_BlankSenderWithARelayHost_IsRefused()
    {
        var result = AlertConfigPolicy.Validate(Valid(from: ""), webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Normalized.Should().BeNull();
        result.Errors.Should().ContainSingle().Which.Should().Contain("sender address is required");
    }

    [Fact]
    public void Validate_BlankSenderWithNoRelayHost_IsFine()
    {
        // Email is switched off entirely, so there is no sender to require.
        var result = AlertConfigPolicy.Validate(
            Valid(host: "", from: "", recipients: []), webhookDeliverable: true);

        result.IsValid.Should().BeTrue();
        result.Normalized!.Smtp!.FromAddress.Should().BeEmpty();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-3)]
    [InlineData(4000)]
    public void Validate_ThresholdOutOfRange_IsRefused(int threshold)
    {
        // Refused rather than quietly dropped the way NormalizeThresholdDays
        // does: a value discarded on the way into the file is a threshold the
        // operator believes is armed.
        var result = AlertConfigPolicy.Validate(
            Valid(thresholds: [30, threshold]), webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain(threshold.ToString());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1441)]
    public void Validate_CheckIntervalOutOfRange_IsRefused(int interval)
    {
        var result = AlertConfigPolicy.Validate(
            Valid(interval: interval), webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain("check interval");
    }

    [Theory]
    [InlineData("not an address")]
    [InlineData("ops@")]
    [InlineData("@example.com")]
    [InlineData("Ops Team <ops@example.com>")]
    public void Validate_MalformedRecipient_IsRefused(string recipient)
    {
        // The display name form parses fine in MimeKit and would be encoded
        // safely, but a stored value that is only ever an address is one less
        // thing for a reader of this file to reason about.
        var result = AlertConfigPolicy.Validate(
            Valid(recipients: [recipient]), webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
    }

    [Fact]
    public void Validate_BlankRecipient_IsRefused()
    {
        var result = AlertConfigPolicy.Validate(
            Valid(recipients: ["ops@example.com", "   "]), webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Contains("cannot be blank"));
    }

    [Theory]
    [InlineData("smtp://relay.example.com")]
    [InlineData("relay.example.com:587")]
    [InlineData("relay example com")]
    [InlineData("relay.example.com/submit")]
    public void Validate_HostThatIsReallyAUrl_IsRefused(string host)
    {
        // Everything an operator might paste into a box labelled "host".
        var result = AlertConfigPolicy.Validate(Valid(host: host), webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain("SMTP host name");
    }

    [Theory]
    [InlineData("relay.example.com")]
    [InlineData("relay")]
    [InlineData("192.168.1.25")]
    public void Validate_UsableHostForms_AreAccepted(string host)
    {
        var result = AlertConfigPolicy.Validate(Valid(host: host), webhookDeliverable: false);

        result.IsValid.Should().BeTrue();
        result.Normalized!.Smtp!.Host.Should().Be(host);
    }

    // ── Warnings: saved, but nothing will be delivered ──

    [Fact]
    public void Validate_EmptyRecipientsWithNoWebhook_WarnsRatherThanRefusing()
    {
        // The state an operator passes through when moving from email to a
        // webhook. Refusing it would make the card fight them.
        var result = AlertConfigPolicy.Validate(
            Valid(recipients: []), webhookDeliverable: false);

        result.IsValid.Should().BeTrue();
        result.Normalized!.Smtp!.Recipients.Should().BeEmpty();
        result.Warnings.Should().ContainSingle().Which.Should().Contain("nobody is listed to receive");
    }

    [Fact]
    public void Validate_RecipientsWithNoHost_WarnsWithTheOppositeAdvice()
    {
        var result = AlertConfigPolicy.Validate(Valid(host: ""), webhookDeliverable: false);

        result.IsValid.Should().BeTrue();
        result.Warnings.Should().ContainSingle().Which.Should().Contain("no relay host is set");
    }

    [Fact]
    public void Validate_NothingConfiguredAtAll_SaysSo()
    {
        var result = AlertConfigPolicy.Validate(
            Valid(host: "", recipients: []), webhookDeliverable: false);

        result.IsValid.Should().BeTrue();
        result.Warnings.Should().ContainSingle().Which.Should().Contain("Nothing is configured to send over");
    }

    [Fact]
    public void Validate_EmptyRecipientsWithAWorkingWebhook_SaysEmailOnlyIsSilent()
    {
        // A different warning: warnings must not claim everything goes nowhere
        // when the webhook is still delivering.
        var result = AlertConfigPolicy.Validate(
            Valid(recipients: []), webhookDeliverable: true);

        result.IsValid.Should().BeTrue();
        result.Warnings.Should().ContainSingle()
            .Which.Should().Contain("The webhook is still delivering");
    }

    [Fact]
    public void Validate_MonitoringOff_SaysThatFirstAndStops()
    {
        // With monitoring off, advice about relays and recipients is noise: the
        // one thing worth saying is that nothing is being checked at all.
        var result = AlertConfigPolicy.Validate(
            Valid(enabled: false, host: "", recipients: []), webhookDeliverable: false);

        result.IsValid.Should().BeTrue();
        result.Warnings.Should().ContainSingle()
            .Which.Should().Contain("Expiry monitoring is switched off");
    }

    [Fact]
    public void Validate_WorkingEmail_WarnsAboutNothing()
    {
        var result = AlertConfigPolicy.Validate(Valid(), webhookDeliverable: false);

        result.Warnings.Should().BeEmpty();
    }

    // ── The transport fields (port, TLS mode, credentials, from name) ──

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void Validate_PortOutOfRange_IsRefused(int port)
    {
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpPort = port }, webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain("between 1 and 65535");
    }

    [Theory]
    [InlineData("starttls", "starttls")]
    [InlineData("STARTTLS", "starttls")]
    [InlineData(" Implicit ", "implicit")]
    [InlineData("none", "none")]
    public void Validate_TlsMode_IsParsedTolerantlyAndStoredCanonically(string sent, string stored)
    {
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpPort = 587, SmtpTlsMode = sent }, webhookDeliverable: false);

        result.IsValid.Should().BeTrue();
        result.Normalized!.Smtp!.TlsMode.Should().Be(stored);
    }

    [Fact]
    public void Validate_UnknownTlsMode_IsRefusedNamingTheCanonicalSet()
    {
        // Strict like the EAB enforcement endpoint's mode parse: a typo that
        // silently became starttls would change how a credential travels.
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpTlsMode = "opportunistic" }, webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle()
            .Which.Should().ContainAll("none", "starttls", "implicit");
    }

    [Fact]
    public void Validate_OmittedTransportFields_AreNotStored()
    {
        // A stale dashboard from before these fields were writable omits them,
        // and the save must not turn that omission into "reset the transport".
        var result = AlertConfigPolicy.Validate(Valid(), webhookDeliverable: false);

        result.Normalized!.Smtp!.Port.Should().BeNull();
        result.Normalized.Smtp.TlsMode.Should().BeNull();
        result.Normalized.Smtp.FromName.Should().BeNull();
    }

    [Fact]
    public void Validate_NeverDecidesTheUsername()
    {
        // Null whether or not the request carried one, because since issue #261
        // the username is resolved from the file under the store's lock, the
        // same way the password blob is. Deciding it here would write a
        // snapshot and lose a racing save; deciding it here as null would drop
        // the stored value out of the overlay entirely.
        AlertConfigPolicy.Validate(Valid(), webhookDeliverable: false)
            .Normalized!.Smtp!.Username.Should().BeNull();

        AlertConfigPolicy.Validate(
                Valid() with { SmtpUsername = "svc-ducks" }, webhookDeliverable: false)
            .Normalized!.Smtp!.Username.Should().BeNull();
    }

    [Fact]
    public void Validate_TransportFields_AreTrimmedAndCarried()
    {
        var result = AlertConfigPolicy.Validate(
            Valid() with
            {
                SmtpPort = 465,
                SmtpTlsMode = "implicit",
                SmtpUsername = " svc-ducks ",
                SmtpFromName = " Certificate Alerts ",
            },
            webhookDeliverable: false,
            hasStoredPassword: true);

        result.IsValid.Should().BeTrue();
        result.Warnings.Should().BeEmpty();
        result.Normalized!.Smtp!.Port.Should().Be(465);
        result.Normalized.Smtp.FromName.Should().Be("Certificate Alerts");

        // The username is trimmed by ResolveUsername rather than here; see
        // ResolveUsername_TrimsANewName.
    }

    [Fact]
    public void Validate_SettingAndClearingThePassword_IsRefused()
    {
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpPassword = "hunter2", SmtpClearPassword = true },
            webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain("not both");
    }

    [Fact]
    public void Validate_UsernameWithoutAnyPassword_Warns()
    {
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpUsername = "svc-ducks" },
            webhookDeliverable: false,
            hasStoredPassword: false);

        result.IsValid.Should().BeTrue();
        result.Warnings.Should().ContainSingle()
            .Which.Should().Contain("without authentication");
    }

    [Fact]
    public void Validate_UsernameWithAStoredPassword_DoesNotWarn()
    {
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpUsername = "svc-ducks" },
            webhookDeliverable: false,
            hasStoredPassword: true);

        result.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Validate_ClearingThePasswordWhileAUsernameStands_Warns()
    {
        // The stored password no longer counts once this save removes it.
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpUsername = "svc-ducks", SmtpClearPassword = true },
            webhookDeliverable: false,
            hasStoredPassword: true);

        result.Warnings.Should().ContainSingle()
            .Which.Should().Contain("without authentication");
    }

    // ── The password blob resolution ──

    [Fact]
    public void ResolvePasswordBlob_NewPassword_IsProtected()
    {
        var blob = AlertConfigPolicy.ResolvePasswordBlob(
            "hunter2", clearPassword: false, currentBlob: "old-blob", p => "protected:" + p);

        blob.Should().Be("protected:hunter2");
    }

    [Fact]
    public void ResolvePasswordBlob_Clear_StoresAnEmptyBlobRatherThanNull()
    {
        // Empty and null are different overlay states, exactly as they are for
        // the username: empty means the dashboard owns the field and holds no
        // password, null means the dashboard does not own it and
        // appsettings.json wins. Returning null for a removal made a reader that
        // falls back on the overlay's silence honour the removal for the
        // username and ignore it for the password (issue #286).
        AlertConfigPolicy.ResolvePasswordBlob(
                null, clearPassword: true, currentBlob: "old-blob", p => "protected:" + p)
            .Should().BeEmpty();
    }

    [Fact]
    public void ResolvePasswordBlob_NoChange_CarriesTheCurrentBlobForward()
    {
        // The load bearing arm: every save rewrites the whole alert block, so
        // this is what keeps an ordinary edit from wiping the saved password.
        AlertConfigPolicy.ResolvePasswordBlob(
                null, clearPassword: false, currentBlob: "old-blob", p => "protected:" + p)
            .Should().Be("old-blob");
    }

    [Fact]
    public void ResolvePasswordBlob_WithNothingStored_StaysNull()
    {
        // Silence, not a removal. Nothing is written for the field and
        // appsettings.json keeps deciding.
        AlertConfigPolicy.ResolvePasswordBlob(
                null, clearPassword: false, currentBlob: null, p => "protected:" + p)
            .Should().BeNull();
    }

    // ── The username resolution (issue #261) ──

    [Fact]
    public void ResolveUsername_TrimsANewName()
    {
        AlertConfigPolicy.ResolveUsername(
                " svc-ducks ", clearUsername: false, currentUsername: "svc-old")
            .Should().Be("svc-ducks");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ResolveUsername_NoChange_CarriesTheStoredNameForward(string? requested)
    {
        // The arm the whole issue turns on. The config endpoint stopped
        // returning the username, so the card renders an empty box and submits
        // it on every save. Reading that as "blank the account" would drop
        // relay authentication on an ordinary edit of an unrelated field, and
        // the overlay writer omits nulls, so returning null would drop the
        // saved name out of the file just as completely.
        AlertConfigPolicy.ResolveUsername(
                requested, clearUsername: false, currentUsername: "svc-ducks")
            .Should().Be("svc-ducks");
    }

    [Fact]
    public void ResolveUsername_Clear_StoresAnEmptyNameRatherThanNull()
    {
        // Empty and null are different overlay states: empty means the
        // dashboard owns the field and the relay is contacted anonymously,
        // null means the dashboard does not own it and appsettings.json wins.
        AlertConfigPolicy.ResolveUsername(
                null, clearUsername: true, currentUsername: "svc-ducks")
            .Should().BeEmpty();
    }

    [Fact]
    public void ResolveUsername_WithNothingStored_StaysNull()
    {
        AlertConfigPolicy.ResolveUsername(null, clearUsername: false, currentUsername: null)
            .Should().BeNull();
    }

    [Fact]
    public void Validate_SettingAndClearingTheUsername_IsRefused()
    {
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpUsername = "svc-ducks", SmtpClearUsername = true },
            webhookDeliverable: false);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain("not both");
    }

    [Fact]
    public void Validate_ClearingTheUsernameWhileAPasswordStands_Warns()
    {
        var result = AlertConfigPolicy.Validate(
            Valid() with { SmtpClearUsername = true },
            webhookDeliverable: false,
            hasStoredPassword: true,
            hasStoredUsername: true);

        result.IsValid.Should().BeTrue();
        result.Warnings.Should().ContainSingle()
            .Which.Should().Contain("username is blank");
    }

    [Fact]
    public void Validate_OmittedUsernameWithBothStored_DoesNotWarn()
    {
        // The ordinary save after issue #261: the card sends no username
        // because it has none to send, and both halves are already stored, so
        // authentication will happen and there is nothing to say.
        var result = AlertConfigPolicy.Validate(
            Valid(),
            webhookDeliverable: false,
            hasStoredPassword: true,
            hasStoredUsername: true);

        result.Warnings.Should().BeEmpty();
    }
}
