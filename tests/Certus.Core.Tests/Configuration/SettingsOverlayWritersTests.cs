using Certus.Core.Adcs;
using Certus.Core.Alerts;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// Every writer of settings.json keeps the keys an administrator added by hand
/// (issue #550). Each one goes through <c>SettingsOverlay.Mutate</c>, but each is
/// driven here through its own entry point, so a writer that ever stops going
/// through it, or builds a fresh record where it should change one, fails here by
/// name. The background HTTPS renewal, the one writer no administrator triggers,
/// is covered with the rest of its pass in <c>HttpsCertificateAutoRenewalServiceTests</c>.
/// </summary>
public class SettingsOverlayWritersTests : IDisposable
{
    private const string Ca = "ca01.corp.example.com\\Corp Issuing CA";
    private const string Url = "https://web01.corp.example.com:5001";

    private readonly string _tempDir =
        Path.Combine(Path.GetTempPath(), $"certus-overlay-writers-{Guid.NewGuid():N}");
    private readonly string _overlayPath;
    private readonly CertusOptions _options;

    public SettingsOverlayWritersTests()
    {
        Directory.CreateDirectory(_tempDir);
        _overlayPath = Path.Combine(_tempDir, CertusPaths.SettingsOverlayFileName);
        _options = new CertusOptions
        {
            DatabasePath = Path.Combine(_tempDir, "ducks.db"),
            SettingsOverlayPath = _overlayPath,
        };

        // The file as setup leaves it, then the hand edit on top.
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(Ca, Url,
                HttpsCertificateThumbprint: "AAAA", HttpsCertificateTemplate: "WebServer"),
            _overlayPath);
        HandEditedOverlay.AddTo(_overlayPath);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private SetupService CreateSetupService() =>
        new(Substitute.For<IAdcsClientFactory>(),
            Substitute.For<ICaDiscoveryService>(),
            Substitute.For<IExternalUrlProbe>(),
            Options.Create(_options),
            CertusInstanceMode.Full,
            NullLogger<SetupService>.Instance);

    [Fact]
    public void AlertSettingsSave_KeepsTheHandKeys()
    {
        // The alert card replaces the alert block it manages, and the webhook sits
        // inside that block, so this is the writer that reaches deepest.
        var store = new AlertConfigStore(Options.Create(_options), new ConfigurationBuilder().Build());

        store.Save(
            new SettingsOverlay.AlertOverlaySettings(
                Enabled: true,
                CheckIntervalMinutes: 90,
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(Host: "relay.corp.example.com")),
            resolvePasswordBlob: current => current,
            resolveUsername: current => current);

        HandEditedOverlay.ShouldStillBeInForce(_overlayPath);
        var overlay = SettingsOverlay.Load(_overlayPath);
        overlay.Alerts!.CheckIntervalMinutes.Should().Be(90);
        overlay.Alerts.Smtp!.Host.Should().Be("relay.corp.example.com");
        overlay.CaConnectionString.Should().Be(Ca);
    }

    [Fact]
    public void SetupCompletion_KeepsTheHandKeys()
    {
        CreateSetupService().CompleteSetup(new SetupConfiguration(
            "ca02.corp.example.com\\Corp Issuing CA 2", ["WebServer"], "https://ducks.corp.example.com"));

        HandEditedOverlay.ShouldStillBeInForce(_overlayPath);
        var overlay = SettingsOverlay.Load(_overlayPath);
        overlay.CaConnectionString.Should().Be("ca02.corp.example.com\\Corp Issuing CA 2");
        overlay.ExternalUrl.Should().Be("https://ducks.corp.example.com");
    }

    [Fact]
    public void ExternalUrlChange_KeepsTheHandKeys()
    {
        CreateSetupService().UpdateExternalUrl("https://ducks.corp.example.com");

        HandEditedOverlay.ShouldStillBeInForce(_overlayPath);
        SettingsOverlay.Load(_overlayPath).ExternalUrl.Should().Be("https://ducks.corp.example.com");
    }

    [Fact]
    public void ThumbprintRecord_KeepsTheHandKeys()
    {
        // The write the background renewal makes, through the same method.
        CreateSetupService().SetHttpsCertificateThumbprint("BBBB", "WebServer");

        HandEditedOverlay.ShouldStillBeInForce(_overlayPath);
        SettingsOverlay.Load(_overlayPath).HttpsCertificateThumbprint.Should().Be("BBBB");
    }

    /// <summary>
    /// Issue #553. Every path that enrolls the server's certificate asks
    /// <c>EnsureHttpsCertificateCanBeRecorded</c> before it enrolls, and relies on the
    /// answer being the record's own: refused exactly when the record would be. Each
    /// case puts one key at the top level in the colon form, the way docs/hardening.md
    /// writes nested keys, beside a section that does not hold it.
    /// </summary>
    [Theory]
    // The record sets the template, so a hand written one collides.
    [InlineData("Certus:HttpsCertificateTemplate", "WebServer", true)]
    // A record with no template keeps none, so the same file passes.
    [InlineData("Certus:HttpsCertificateTemplate", null, false)]
    // The thumbprint is always set.
    [InlineData("Certus:HttpsCertificateThumbprint", null, true)]
    // Keys the record leaves alone never collide, managed or not.
    [InlineData("Certus:CaConnectionString", "WebServer", false)]
    [InlineData("Certus:Acme:ChallengeValidation:BlockPrivateRanges", "WebServer", false)]
    public void ThumbprintRecordDryRun_RefusesExactlyWhatTheRecordRefuses(
        string colonKey, string? templateName, bool refused)
    {
        var handEdited =
            "{ \"Certus\": { \"ExternalUrl\": \"" + Url + "\" }, \"" + colonKey + "\": \"by hand\" }";
        File.WriteAllText(_overlayPath, handEdited);
        var service = CreateSetupService();

        var dryRun = () => service.EnsureHttpsCertificateCanBeRecorded(templateName);
        var record = () => service.SetHttpsCertificateThumbprint("BBBB", templateName);

        if (refused)
        {
            dryRun.Should().Throw<SettingsOverlayConflictException>().WithMessage($"*{colonKey}*");
            File.ReadAllText(_overlayPath).Should().Be(handEdited, "a dry run writes nothing");
            record.Should().Throw<SettingsOverlayConflictException>();
        }
        else
        {
            dryRun.Should().NotThrow();
            File.ReadAllText(_overlayPath).Should().Be(handEdited, "a dry run writes nothing");
            record.Should().NotThrow();
            SettingsOverlay.Load(_overlayPath).HttpsCertificateThumbprint.Should().Be("BBBB");
        }
    }

    [Fact]
    public void ThumbprintClear_RemovesOnlyTheThumbprint()
    {
        // A member set to null leaves the file, the omit null rule, and nothing
        // beside it goes with it.
        CreateSetupService().ClearHttpsCertificateThumbprint().Should().BeTrue();

        HandEditedOverlay.ShouldStillBeInForce(_overlayPath);
        var overlay = SettingsOverlay.Load(_overlayPath);
        overlay.HttpsCertificateThumbprint.Should().BeNull();
        overlay.HttpsCertificateTemplate.Should().BeNull();
        File.ReadAllText(_overlayPath).Should().NotContain("HttpsCertificateThumbprint");
    }

    [Fact]
    public void StartupRepin_KeepsTheHandKeys()
    {
        HttpsCertificateFollow.TryRepin(_overlayPath, "AAAA", "BBBB", out var failure).Should().BeTrue();

        failure.Should().BeNull();
        HandEditedOverlay.ShouldStillBeInForce(_overlayPath);
        SettingsOverlay.Load(_overlayPath).HttpsCertificateThumbprint.Should().Be("BBBB");
    }
}
