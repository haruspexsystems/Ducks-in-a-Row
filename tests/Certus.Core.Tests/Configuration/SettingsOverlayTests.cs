using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// The settings overlay must land between the shipped appsettings defaults and
/// the higher priority sources (environment variables, command line). A plain
/// Add would append it last and silently invert that precedence.
/// </summary>
public class SettingsOverlayTests : IDisposable
{
    private readonly string _appDir;
    private readonly string _dataDir;

    public SettingsOverlayTests()
    {
        var root = Path.Combine(Path.GetTempPath(), $"certus-overlay-{Guid.NewGuid():N}");
        _appDir = Path.Combine(root, "app");
        _dataDir = Path.Combine(root, "data");
        Directory.CreateDirectory(_appDir);
        Directory.CreateDirectory(_dataDir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path.GetDirectoryName(_appDir)!, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void Overlay_OverridesAppSettings_ButNotLaterSources()
    {
        File.WriteAllText(Path.Combine(_appDir, "appsettings.json"),
            """{ "Certus": { "CaConnectionString": "from-appsettings", "ExternalUrl": "from-appsettings" } }""");
        File.WriteAllText(Path.Combine(_dataDir, "settings.json"),
            """{ "Certus": { "CaConnectionString": "from-overlay", "ExternalUrl": "from-overlay" } }""");

        var manager = new ConfigurationManager();
        manager.SetBasePath(_appDir);
        manager.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
        // Stands in for environment variables / command line: any source added
        // after appsettings that must keep winning over the overlay.
        manager.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Certus:ExternalUrl"] = "from-environment",
        });

        ((IConfigurationBuilder)manager).AddSettingsOverlay(_dataDir);

        manager["Certus:CaConnectionString"].Should().Be("from-overlay",
            "the overlay overrides shipped appsettings defaults");
        manager["Certus:ExternalUrl"].Should().Be("from-environment",
            "sources registered after appsettings keep their precedence over the overlay");
    }

    [Fact]
    public void Overlay_IsOptional_WhenFileAbsent()
    {
        File.WriteAllText(Path.Combine(_appDir, "appsettings.json"),
            """{ "Certus": { "CaConnectionString": "from-appsettings" } }""");

        var manager = new ConfigurationManager();
        manager.SetBasePath(_appDir);
        manager.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

        ((IConfigurationBuilder)manager).AddSettingsOverlay(_dataDir);

        manager["Certus:CaConnectionString"].Should().Be("from-appsettings");
    }

    [Fact]
    public void Overlay_WithoutAppSettingsSource_IsStillRegistered()
    {
        File.WriteAllText(Path.Combine(_dataDir, "settings.json"),
            """{ "Certus": { "CaConnectionString": "from-overlay" } }""");

        var manager = new ConfigurationManager();

        ((IConfigurationBuilder)manager).AddSettingsOverlay(_dataDir);

        manager["Certus:CaConnectionString"].Should().Be("from-overlay");
    }

    [Fact]
    public void Overlay_CreatesTheDataDirectory()
    {
        var freshDir = Path.Combine(_dataDir, "not-yet-created");

        var manager = new ConfigurationManager();
        ((IConfigurationBuilder)manager).AddSettingsOverlay(freshDir);

        Directory.Exists(freshDir).Should().BeTrue();
    }

    [Fact]
    public void Load_MissingFile_ReturnsEmptySettings()
    {
        var settings = SettingsOverlay.Load(Path.Combine(_dataDir, "settings.json"));

        settings.CaConnectionString.Should().BeNull();
        settings.ExternalUrl.Should().BeNull();
    }

    [Fact]
    public void Load_RoundTripsSave()
    {
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        var saved = new SettingsOverlay.OverlaySettings(
            CaConnectionString: "ca.contoso.com\\Contoso-CA",
            ExternalUrl: "https://certus.contoso.com:5001",
            HttpsCertificateThumbprint: "ABCDEF0123456789");

        SettingsOverlay.Save(saved, overlayPath);
        var loaded = SettingsOverlay.Load(overlayPath);

        loaded.Should().Be(saved);
    }

    [Fact]
    public void Save_OmitsAnUnsetThumbprint()
    {
        // Null values are omitted so they never mask a lower precedence
        // configuration source; the new key must follow the same rule.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings("ca\\CA", "https://certus.example.com"),
            overlayPath);

        File.ReadAllText(overlayPath).Should().NotContain("HttpsCertificateThumbprint");
    }

    [Fact]
    public void Load_IsCaseInsensitive()
    {
        // Tolerate a hand edited file whose key casing drifted; the
        // configuration binder reading the same file is case insensitive too.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath,
            """{ "certus": { "caConnectionString": "from-file", "externalUrl": "https://certus.example.com" } }""");

        var loaded = SettingsOverlay.Load(overlayPath);

        loaded.CaConnectionString.Should().Be("from-file");
        loaded.ExternalUrl.Should().Be("https://certus.example.com");
    }

    [Fact]
    public void Load_CorruptFile_Throws()
    {
        // A corrupt overlay must fail loudly: rewriting it from an empty
        // record would drop the CA connection string and unconfigure the CA
        // at the next restart.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, "{ this is not json");

        var act = () => SettingsOverlay.Load(overlayPath);

        act.Should().Throw<System.Text.Json.JsonException>();
    }

    [Fact]
    public void Load_ToleratesUnknownSiblingKeys()
    {
        // The configuration provider accepts keys outside the Certus section,
        // so Load must not treat them as corruption.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath,
            """{ "comment": "hand edited", "SchemaVersion": 1, "Certus": { "ExternalUrl": "https://certus.example.com" } }""");

        var loaded = SettingsOverlay.Load(overlayPath);

        loaded.ExternalUrl.Should().Be("https://certus.example.com");
        loaded.CaConnectionString.Should().BeNull();
    }

    [Fact]
    public void Load_NonObjectRoot_Throws()
    {
        // A non object root would also fail the configuration build at the
        // next start; failing loudly here beats silently rewriting the file.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, """["not", "an", "object"]""");

        var act = () => SettingsOverlay.Load(overlayPath);

        act.Should().Throw<System.Text.Json.JsonException>();
    }

    // ── The dashboard owned alert block (issue #162) ──

    [Fact]
    public void Alerts_RoundTripSave()
    {
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        var saved = new SettingsOverlay.OverlaySettings(
            CaConnectionString: "ca.contoso.com\\Contoso-CA",
            ExternalUrl: "https://certus.contoso.com:5001",
            Alerts: new SettingsOverlay.AlertOverlaySettings(
                Enabled: true,
                CheckIntervalMinutes: 90,
                ThresholdDays: [60, 30],
                Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(
                    Host: "relay.contoso.com",
                    FromAddress: "ducks@contoso.com",
                    Recipients: ["ops@contoso.com"],
                    Port: 465,
                    TlsMode: "implicit",
                    Username: "svc-ducks",
                    FromName: "Certificate Alerts",
                    PasswordProtected: "CfDJ8-opaque-blob")));

        SettingsOverlay.Save(saved, overlayPath);
        var loaded = SettingsOverlay.Load(overlayPath);

        loaded.Alerts!.Enabled.Should().BeTrue();
        loaded.Alerts.CheckIntervalMinutes.Should().Be(90);
        loaded.Alerts.ThresholdDays.Should().Equal(60, 30);
        loaded.Alerts.Smtp!.Host.Should().Be("relay.contoso.com");
        loaded.Alerts.Smtp.FromAddress.Should().Be("ducks@contoso.com");
        loaded.Alerts.Smtp.Recipients.Should().Equal("ops@contoso.com");
        loaded.Alerts.Smtp.Port.Should().Be(465);
        loaded.Alerts.Smtp.TlsMode.Should().Be("implicit");
        loaded.Alerts.Smtp.Username.Should().Be("svc-ducks");
        loaded.Alerts.Smtp.FromName.Should().Be("Certificate Alerts");
        loaded.Alerts.Smtp.PasswordProtected.Should().Be("CfDJ8-opaque-blob");
    }

    [Fact]
    public void Alerts_LandOnTheConfigurationKeysTheSectionBindsFrom()
    {
        // The block is written under "Certus", so it has to flatten onto
        // Certus:Alerts:*, the same keys AlertOptions.SectionName binds. If it
        // ever landed somewhere else the file would look right and do nothing.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(null, null,
                Alerts: new SettingsOverlay.AlertOverlaySettings(
                    CheckIntervalMinutes: 90,
                    Smtp: new SettingsOverlay.AlertSmtpOverlaySettings(Host: "relay.contoso.com"))),
            overlayPath);

        var manager = new ConfigurationManager();
        ((IConfigurationBuilder)manager).AddSettingsOverlay(_dataDir);

        manager["Certus:Alerts:CheckIntervalMinutes"].Should().Be("90");
        manager["Certus:Alerts:Smtp:Host"].Should().Be("relay.contoso.com");
    }

    [Fact]
    public void Alerts_UnsetMembersAreOmittedFromTheFile()
    {
        // A null member means "not managed from the dashboard", so it must not
        // be written: an explicit null would mask the appsettings value instead
        // of leaving it to stand.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(null, null,
                Alerts: new SettingsOverlay.AlertOverlaySettings(Enabled: true)),
            overlayPath);

        var json = File.ReadAllText(overlayPath);
        json.Should().Contain("Enabled");
        json.Should().NotContain("CheckIntervalMinutes");
        json.Should().NotContain("Smtp");
    }

    [Fact]
    public void Alerts_AreAbsentUntilSomethingIsSaved()
    {
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings("ca\\CA", "https://certus.example.com"),
            overlayPath);

        File.ReadAllText(overlayPath).Should().NotContain("Alerts");
        SettingsOverlay.Load(overlayPath).Alerts.Should().BeNull();
    }

    [Fact]
    public void TryLoadAlerts_CorruptFile_ReportsFailureRatherThanThrowing()
    {
        // This runs while options are being built. Throwing would take the host
        // down over a corrupt overlay, which is worse than the corruption.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, "{ this is not json");

        var alerts = SettingsOverlay.TryLoadAlerts(overlayPath, out var failure);

        alerts.Should().BeNull();
        failure.Should().NotBeNull();
    }

    [Fact]
    public void TryLoadAlerts_MissingFile_IsNotAFailure()
    {
        var alerts = SettingsOverlay.TryLoadAlerts(
            Path.Combine(_dataDir, "settings.json"), out var failure);

        alerts.Should().BeNull();
        failure.Should().BeNull("a fresh install has simply never saved anything");
    }

    // ── FindOutrankedKeys: what the dashboard cannot usefully change ──

    private const string IntervalKey = "Certus:Alerts:CheckIntervalMinutes";
    private const string HostKey = "Certus:Alerts:Smtp:Host";

    private ConfigurationManager BuildLayeredConfiguration(
        Dictionary<string, string?>? aboveTheOverlay = null,
        Dictionary<string, string?>? hostConfiguration = null)
    {
        File.WriteAllText(Path.Combine(_appDir, "appsettings.json"),
            $$"""{ "Certus:Alerts": { "CheckIntervalMinutes": 60, "Smtp": { "Host": "from-appsettings" } } }""");

        var manager = new ConfigurationManager();

        // WebApplication.CreateBuilder puts host configuration at the front, so
        // a provider that classifies as "other" is not automatically a higher
        // precedence one. The boundary logic has to place it correctly.
        if (hostConfiguration != null)
            manager.AddInMemoryCollection(hostConfiguration);

        manager.SetBasePath(_appDir);
        manager.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
        ((IConfigurationBuilder)manager).AddSettingsOverlay(_dataDir);

        if (aboveTheOverlay != null)
            manager.AddInMemoryCollection(aboveTheOverlay);

        return manager;
    }

    [Fact]
    public void FindOutrankedKeys_NoOverride_FindsNothing()
    {
        var configuration = BuildLayeredConfiguration();

        SettingsOverlay.FindOutrankedKeys(configuration, [IntervalKey, HostKey]).Should().BeEmpty();
    }

    [Fact]
    public void FindOutrankedKeys_EnvironmentVariable_OutranksTheOverlay()
    {
        var configuration = BuildLayeredConfiguration(
            aboveTheOverlay: new Dictionary<string, string?> { [IntervalKey] = "15" });

        var outranked = SettingsOverlay.FindOutrankedKeys(configuration, [IntervalKey, HostKey]);

        outranked.Should().BeEquivalentTo([IntervalKey]);
    }

    [Fact]
    public void FindOutrankedKeys_AppSettingsValue_DoesNotOutrankTheOverlay()
    {
        // appsettings.json supplies both keys, and the overlay is meant to beat
        // it. Reporting these as outranked would disable every field on the card
        // for the ordinary case.
        var configuration = BuildLayeredConfiguration();

        SettingsOverlay.FindOutrankedKeys(configuration, [IntervalKey, HostKey]).Should().BeEmpty();
    }

    [Fact]
    public void FindOutrankedKeys_HostConfigurationAheadOfAppSettings_DoesNotOutrank()
    {
        // The trap this boundary exists for: a provider before appsettings is the
        // lowest precedence layer there is, even though it classifies as "other".
        var configuration = BuildLayeredConfiguration(
            hostConfiguration: new Dictionary<string, string?> { [IntervalKey] = "5" });

        SettingsOverlay.FindOutrankedKeys(configuration, [IntervalKey, HostKey]).Should().BeEmpty();
    }

    [Fact]
    public void FindOutrankedKeys_EmptyOverrideValue_CountsAsUnset()
    {
        // appsettings ships several keys as an explicit JSON null, which lands in
        // configuration data as an empty string and must never read as a real
        // override.
        var configuration = BuildLayeredConfiguration(
            aboveTheOverlay: new Dictionary<string, string?> { [HostKey] = "" });

        SettingsOverlay.FindOutrankedKeys(configuration, [IntervalKey, HostKey]).Should().BeEmpty();
    }

    // ── Mutate: read, change and write as one step ──

    [Fact]
    public void Mutate_PreservesEveryKeyItDidNotChange()
    {
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(
            new SettingsOverlay.OverlaySettings(
                CaConnectionString: "ca.contoso.com\\Contoso-CA",
                ExternalUrl: "https://certus.contoso.com:5001",
                HttpsCertificateThumbprint: "ABCDEF0123456789",
                HttpsCertificateTemplate: "WebServer"),
            overlayPath);

        SettingsOverlay.Mutate(overlayPath, current => current with
        {
            Alerts = new SettingsOverlay.AlertOverlaySettings(Enabled: false),
        });

        var loaded = SettingsOverlay.Load(overlayPath);
        loaded.CaConnectionString.Should().Be("ca.contoso.com\\Contoso-CA");
        loaded.ExternalUrl.Should().Be("https://certus.contoso.com:5001");
        loaded.HttpsCertificateThumbprint.Should().Be("ABCDEF0123456789");
        loaded.HttpsCertificateTemplate.Should().Be("WebServer");
        loaded.Alerts!.Enabled.Should().BeFalse();
    }

    [Fact]
    public void Mutate_CorruptFile_ThrowsWithoutWriting()
    {
        // The overlay also holds the CA connection string. Saving over a file
        // that could not be read would drop it and unconfigure the CA at the
        // next start, so the caller has to answer for the corruption.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, "{ this is not json");

        var act = () => SettingsOverlay.Mutate(overlayPath, c => c with { ExternalUrl = "https://x" });

        act.Should().Throw<System.Text.Json.JsonException>();
        File.ReadAllText(overlayPath).Should().Be("{ this is not json");
    }

    [Fact]
    public void Mutate_ConcurrentWriters_DoNotLoseEachOthersChanges()
    {
        // The real pairing is the HTTPS renewal service writing a thumbprint
        // from its background timer while an administrator saves alert settings.
        // With a bare Load then Save the later writer wins and the earlier
        // change is gone.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(new SettingsOverlay.OverlaySettings("ca\\CA", "https://certus.example.com"), overlayPath);

        Parallel.For(0, 40, i =>
        {
            if (i % 2 == 0)
            {
                SettingsOverlay.Mutate(overlayPath, c => c with
                {
                    HttpsCertificateThumbprint = "ABCDEF0123456789",
                });
            }
            else
            {
                SettingsOverlay.Mutate(overlayPath, c => c with
                {
                    Alerts = new SettingsOverlay.AlertOverlaySettings(CheckIntervalMinutes: 90),
                });
            }
        });

        var loaded = SettingsOverlay.Load(overlayPath);
        loaded.HttpsCertificateThumbprint.Should().Be("ABCDEF0123456789");
        loaded.Alerts!.CheckIntervalMinutes.Should().Be(90);
        loaded.CaConnectionString.Should().Be("ca\\CA");
    }
}
