using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;

namespace Certus.Core.Tests.Alerts;

/// <summary>
/// Tests for the threshold normalization. Regression cover for the duplicated
/// thresholds log line ("30d, 14d, 7d, 1d, 30d, 14d, 7d, 1d"): the
/// configuration binder appends bound array elements onto the property's
/// existing value, so a C# initializer default plus the same array in
/// appsettings yielded every threshold twice. The initializer is now empty and
/// the defaults are applied by NormalizeThresholdDays via PostConfigure.
/// </summary>
public class AlertOptionsTests
{
    [Fact]
    public void Normalize_NoConfiguredThresholds_AppliesDefaults()
    {
        var options = new AlertOptions();

        options.NormalizeThresholdDays();

        options.ThresholdDays.Should().Equal(30, 14, 7, 1);
    }

    [Fact]
    public void Normalize_DuplicatedThresholds_DedupsToOnePass()
    {
        var options = new AlertOptions { ThresholdDays = [30, 14, 7, 1, 30, 14, 7, 1] };

        options.NormalizeThresholdDays();

        options.ThresholdDays.Should().Equal(30, 14, 7, 1);
    }

    [Fact]
    public void Normalize_SortsDescendingAndDropsNonPositiveValues()
    {
        var options = new AlertOptions { ThresholdDays = [1, 7, 99, 7, 0, -3] };

        options.NormalizeThresholdDays();

        options.ThresholdDays.Should().Equal(99, 7, 1);
    }

    // ── ExpiryWarningDays: the one window the whole UI reads (issue #152) ──

    [Fact]
    public void ExpiryWarningDays_DefaultInstall_IsThirty()
    {
        var options = new AlertOptions();
        options.NormalizeThresholdDays();

        options.ExpiryWarningDays.Should().Be(30);
    }

    [Fact]
    public void ExpiryWarningDays_IsTheWidestConfiguredThreshold()
    {
        var options = new AlertOptions { ThresholdDays = [7, 60, 30] };
        options.NormalizeThresholdDays();

        options.ExpiryWarningDays.Should().Be(60);
    }

    [Fact]
    public void ExpiryWarningDays_NarrowThresholds_NarrowTheWindow()
    {
        // Coupling runs both ways on purpose: an operator who alerts only at
        // 7 days gets a 7 day dashboard rather than one warning about
        // certificates the product never intends to mention.
        var options = new AlertOptions { ThresholdDays = [7] };
        options.NormalizeThresholdDays();

        options.ExpiryWarningDays.Should().Be(7);
    }

    [Fact]
    public void ExpiryWarningDays_NeverNormalized_FallsBackRatherThanThrowing()
    {
        // Max() on an empty array throws. An instance that skipped
        // PostConfigure (a bare construction, or a manual .Get<AlertOptions>()
        // bind) must still answer, because this feeds every expiry surface.
        var options = new AlertOptions();

        options.ExpiryWarningDays.Should().Be(AlertOptions.DefaultExpiryWarningDays);
    }

    [Fact]
    public void ExpiryWarningDays_IgnoresEnabled()
    {
        // Enabled gates delivery, not the meaning of "expiring soon". Honouring
        // the configured window with email off keeps one rule instead of two.
        var options = new AlertOptions { Enabled = false, ThresholdDays = [60] };
        options.NormalizeThresholdDays();

        options.ExpiryWarningDays.Should().Be(60);
    }

    [Fact]
    public void Binding_ConfiguredArray_FullyReplacesTheDefaults()
    {
        // With the empty initializer, binding yields exactly the configured
        // values: nothing left over for the binder to append onto.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Certus:Alerts:ThresholdDays:0"] = "21",
                ["Certus:Alerts:ThresholdDays:1"] = "3",
            })
            .Build();

        var options = new AlertOptions();
        config.GetSection(AlertOptions.SectionName).Bind(options);
        options.NormalizeThresholdDays();

        options.ThresholdDays.Should().Equal(21, 3);
    }

    // ── ApplyOverlay: what an administrator saved from the dashboard (#162) ──

    private static readonly HashSet<string> NothingOutranked = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The regression this whole design exists for.
    ///
    /// <para>
    /// The shipped Certus.Service/appsettings.json carries
    /// <c>ThresholdDays: [30, 14, 7, 1]</c>, and the settings overlay is a JSON
    /// configuration source layered over it. .NET flattens a JSON array into
    /// indexed keys and merges providers one index at a time, so an overlay
    /// saving <c>[60, 30]</c> supplies index 0 and 1 only and the binder yields
    /// <c>[60, 30, 7, 1]</c>. NormalizeThresholdDays cannot catch it: all four
    /// are positive, distinct and correctly ordered. Left to the binder, the
    /// threshold list can only ever grow.
    /// </para>
    ///
    /// <para>
    /// This test builds the service host's exact layering rather than using a
    /// WebApplicationFactory on purpose. Certus.Web/appsettings.json has no
    /// Certus:Alerts section at all and Certus.Web/Program.cs never calls
    /// AddSettingsOverlay, so the dev host has nothing to merge against and an
    /// integration test cannot reproduce the fault.
    /// </para>
    /// </summary>
    [Fact]
    public void ApplyOverlay_ShorterThresholdList_DoesNotKeepTheAppSettingsTail()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Exactly what the service host ships.
                ["Certus:Alerts:ThresholdDays:0"] = "30",
                ["Certus:Alerts:ThresholdDays:1"] = "14",
                ["Certus:Alerts:ThresholdDays:2"] = "7",
                ["Certus:Alerts:ThresholdDays:3"] = "1",
            })
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // The overlay, layered over it, saving a narrower ladder.
                ["Certus:Alerts:ThresholdDays:0"] = "60",
                ["Certus:Alerts:ThresholdDays:1"] = "30",
            })
            .Build();

        var options = new AlertOptions();
        configuration.GetSection(AlertOptions.SectionName).Bind(options);

        // The bug, demonstrated: the binder alone keeps the 7 and the 1.
        options.ThresholdDays.Should().Equal(60, 30, 7, 1);

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(ThresholdDays: [60, 30]),
            NothingOutranked);
        options.NormalizeThresholdDays();

        // The fix: the overlay replaces an array wholesale rather than merging
        // it index by index, so the narrower ladder is the one that survives.
        options.ThresholdDays.Should().Equal(60, 30);
    }

    [Fact]
    public void ApplyOverlay_ShorterRecipientList_DoesNotKeepTheAppSettingsTail()
    {
        // The same trap on the other array. It bites wherever an operator listed
        // recipients in appsettings.json, which is what the card told them to do
        // before this endpoint existed, so "remove someone" has to actually
        // remove them.
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions
            {
                Host = "relay.example.com",
                Recipients = ["a@example.com", "b@example.com", "c@example.com"],
            },
        };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                    Recipients: ["a@example.com"])),
            NothingOutranked);

        options.Smtp!.Recipients.Should().Equal("a@example.com");
    }

    [Fact]
    public void ApplyOverlay_Null_LeavesEverythingAlone()
    {
        // An install that never saved must behave exactly as it did before.
        var options = new AlertOptions
        {
            Enabled = false,
            CheckIntervalMinutes = 15,
            ThresholdDays = [21],
            Smtp = new SmtpOptions { Host = "relay.example.com" },
        };

        options.ApplyOverlay(null, NothingOutranked);

        options.Enabled.Should().BeFalse();
        options.CheckIntervalMinutes.Should().Be(15);
        options.ThresholdDays.Should().Equal(21);
        options.Smtp!.Host.Should().Be("relay.example.com");
    }

    [Fact]
    public void ApplyOverlay_UnsetMembers_LeaveTheBoundValueStanding()
    {
        var options = new AlertOptions { Enabled = false, CheckIntervalMinutes = 15 };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(Enabled: true),
            NothingOutranked);

        options.Enabled.Should().BeTrue();
        options.CheckIntervalMinutes.Should().Be(15, "a null member is not managed from the dashboard");
    }

    [Fact]
    public void ApplyOverlay_MaterializesAnAbsentSmtpBlock()
    {
        // The shipped appsettings.json has "Smtp": null, so without this an
        // administrator could never turn email on from the dashboard, which is
        // the whole point of making the host writable.
        var options = new AlertOptions { Smtp = null };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                    Host: "relay.example.com",
                    Recipients: ["ops@example.com"])),
            NothingOutranked);

        options.Smtp.Should().NotBeNull();
        options.Smtp!.Host.Should().Be("relay.example.com");
        options.Smtp.Recipients.Should().Equal("ops@example.com");
    }

    [Fact]
    public void ApplyOverlay_EmptySmtpBlock_DoesNotMaterializeOne()
    {
        // "No SMTP block" and "a block that is present but incomplete" are
        // different states and AlertConfigView gives them opposite advice, so an
        // all null overlay block must not turn one into the other.
        var options = new AlertOptions { Smtp = null };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings()),
            NothingOutranked);

        options.Smtp.Should().BeNull();
    }

    [Fact]
    public void ApplyOverlay_OutrankedScalar_KeepsTheHigherPrecedenceValue()
    {
        // An environment variable or command line switch still outranks the
        // overlay, which is the ordering AddSettingsOverlay documents.
        var options = new AlertOptions { Enabled = false, CheckIntervalMinutes = 15 };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(Enabled: true, CheckIntervalMinutes: 90),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { AlertOptions.EnabledKey });

        options.Enabled.Should().BeFalse("an environment variable supplies this key");
        options.CheckIntervalMinutes.Should().Be(90, "nothing outranks this one");
    }

    [Fact]
    public void ApplyOverlay_ArraysAreOwnedByTheOverlayEvenWhenOtherKeysAreOutranked()
    {
        // Arrays are deliberately exempt from the outranked guard: honouring the
        // layering for an array means honouring it per index, which is exactly
        // the merge ApplyOverlay exists to defeat.
        var options = new AlertOptions { ThresholdDays = [30, 14, 7, 1] };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(ThresholdDays: [60]),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                AlertOptions.EnabledKey,
                AlertOptions.CheckIntervalMinutesKey,
                AlertOptions.SmtpHostKey,
                AlertOptions.SmtpFromAddressKey,
            });

        options.ThresholdDays.Should().Equal(60);
    }

    // ── ApplyOverlay: the transport fields and the password blob ──

    [Fact]
    public void ApplyOverlay_TransportFields_ApplyOverTheBoundValues()
    {
        var options = new AlertOptions { Smtp = new SmtpOptions { Port = 25, UseSsl = false } };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                    Port: 465,
                    TlsMode: "implicit",
                    Username: "svc-ducks",
                    FromName: "Certificate Alerts",
                    PasswordProtected: "blob")),
            NothingOutranked);

        options.Smtp!.Port.Should().Be(465);
        options.Smtp.TlsMode.Should().Be(SmtpTlsMode.Implicit);
        options.Smtp.Username.Should().Be("svc-ducks");
        options.Smtp.FromName.Should().Be("Certificate Alerts");
        options.Smtp.PasswordProtected.Should().Be("blob");
    }

    [Fact]
    public void ApplyOverlay_AnyTransportMemberAlone_MaterializesTheBlock()
    {
        // The "is the block empty" guard must name every member of the SMTP
        // slice: a member missing from it makes an overlay managing only that
        // member silently no-op.
        var options = new AlertOptions { Smtp = null };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(Port: 2525)),
            NothingOutranked);

        options.Smtp.Should().NotBeNull();
        options.Smtp!.Port.Should().Be(2525);
    }

    [Fact]
    public void ApplyOverlay_UnrecognizedTlsModeString_IsSkippedNotGuessed()
    {
        // Only reachable by hand editing the file; the policy stores canonical
        // names. Skipping leaves the legacy UseSsl and port derivation deciding.
        var options = new AlertOptions { Smtp = new SmtpOptions() };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(TlsMode: "opportunistic")),
            NothingOutranked);

        options.Smtp!.TlsMode.Should().BeNull();
    }

    [Fact]
    public void ApplyOverlay_OutrankedPasswordKey_KeepsTheBlobOut()
    {
        // An environment variable supplying Certus:Alerts:Smtp:Password must
        // beat the dashboard's saved password. The blob is not even copied in,
        // so the notifier's "blob wins over plaintext" rule cannot shadow the
        // higher layer.
        var options = new AlertOptions
        {
            Smtp = new SmtpOptions { Password = "from-environment" },
        };

        options.ApplyOverlay(
            new SettingsOverlay.AlertOverlaySettings(
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(PasswordProtected: "blob")),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                AlertOptions.SmtpPasswordKey,
            });

        options.Smtp!.PasswordProtected.Should().BeNull();
        options.Smtp.Password.Should().Be("from-environment");
    }
}
