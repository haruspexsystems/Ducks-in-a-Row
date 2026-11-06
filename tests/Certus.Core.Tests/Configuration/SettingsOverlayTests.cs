using Certus.Core.Configuration;
using Certus.Core.Tests.Security;
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

    // ── Keys the service does not manage (issue #550) ──

    [Fact]
    public void Save_RewritesAHandEditedFileItDidNotChange_ByteForByte()
    {
        // Every key a save does not manage goes back as its raw text: the escaped
        // backslash, the non ASCII letter, the ampersand the default encoder would
        // turn into &, the number written as 60.0 and the one line array. And
        // the managed keys come out exactly as the service always wrote them, so a
        // save that changes nothing changes no byte.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        var handEdited = """
            {
              "Certus": {
                "CaConnectionString": "ca01.corp.example.com\\Corp Issuing CA",
                "ExternalUrl": "https://web01.corp.example.com:5001",
                "RateLimiting": {
                  "NewOrderLimit": 5,
                  "WindowSeconds": 60.0
                },
                "Alerts": {
                  "Enabled": true,
                  "ThresholdDays": [
                    60,
                    30
                  ],
                  "Webhook": {
                    "Url": "https://hooks.corp.example.com/ducks?token=abc&channel=pki"
                  }
                }
              },
              "Certus:Acme:ChallengeValidation": {
                "BlockPrivateRanges": true,
                "AdditionalBlockedCidrs": [ "100.64.0.0/10" ]
              },
              "Auth": {
                "AdminGroup": "CORP\\Domänen-Admins"
              }
            }
            """.ReplaceLineEndings();
        File.WriteAllText(overlayPath, handEdited);

        SettingsOverlay.Mutate(overlayPath, current => current);

        File.ReadAllText(overlayPath).Should().Be(handEdited);
    }

    [Fact]
    public void Save_KeepsEveryKeyItDoesNotManage_InsideAndOutsideTheSection()
    {
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(new SettingsOverlay.OverlaySettings("ca\\CA", "https://old.example.com"), overlayPath);
        HandEditedOverlay.AddTo(overlayPath);

        SettingsOverlay.Mutate(overlayPath, current => current with
        {
            ExternalUrl = "https://certus.example.com",
            Alerts = new SettingsOverlay.AlertOverlaySettings(CheckIntervalMinutes: 90),
        });

        HandEditedOverlay.ShouldStillBeInForce(overlayPath);
        var loaded = SettingsOverlay.Load(overlayPath);
        loaded.ExternalUrl.Should().Be("https://certus.example.com");
        loaded.Alerts!.CheckIntervalMinutes.Should().Be(90);
        loaded.CaConnectionString.Should().Be("ca\\CA");
    }

    [Fact]
    public void Save_FileWithNoSection_KeepsItsKeysAndAddsTheSection()
    {
        // The file docs/quickstart.md has an administrator create before setup ever
        // runs: nothing in it but the admin group.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, """{ "Auth": { "AdminGroup": "CORP\\Ducks Admins" } }""");

        SettingsOverlay.Mutate(overlayPath, current => current with { ExternalUrl = "https://certus.example.com" });

        using var configuration = new ConfigurationManager();
        ((IConfigurationBuilder)configuration).AddSettingsOverlay(_dataDir);
        configuration["Auth:AdminGroup"].Should().Be("CORP\\Ducks Admins");
        configuration["Certus:ExternalUrl"].Should().Be("https://certus.example.com");
    }

    [Fact]
    public void Save_ManagedKeyInAnotherCase_IsReplacedRatherThanWrittenTwice()
    {
        // Load reads a member ignoring case, so the save must match it the same way.
        // Writing ExternalUrl beside the hand typed externalUrl would set one
        // configuration key twice, and the JSON provider refuses that file outright.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath,
            """{ "certus": { "externalUrl": "https://old.example.com", "SyncIntervalMinutes": 15 } }""");

        SettingsOverlay.Mutate(overlayPath, current => current with { ExternalUrl = "https://certus.example.com" });

        using var configuration = new ConfigurationManager();
        ((IConfigurationBuilder)configuration).AddSettingsOverlay(_dataDir);
        configuration["Certus:ExternalUrl"].Should().Be("https://certus.example.com");
        configuration["Certus:SyncIntervalMinutes"].Should().Be("15");
        File.ReadAllText(overlayPath).Should().NotContain("old.example.com");
    }

    [Fact]
    public void Save_BlockTheRecordLeavesUnset_KeepsTheAdministratorsKeysInsideIt()
    {
        // A null alert block means the dashboard manages none of it. The members it
        // would manage go, by the omit null rule, but the webhook beside them is the
        // administrator's and stays.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, """
            { "Certus": { "Alerts": { "Enabled": false, "Webhook": { "Url": "https://hooks.example.com/x" } } } }
            """);

        SettingsOverlay.Save(new SettingsOverlay.OverlaySettings("ca\\CA", null), overlayPath);

        using var configuration = new ConfigurationManager();
        ((IConfigurationBuilder)configuration).AddSettingsOverlay(_dataDir);
        configuration["Certus:Alerts:Webhook:Url"].Should().Be("https://hooks.example.com/x");
        configuration["Certus:Alerts:Enabled"].Should().BeNull();
        configuration["Certus:CaConnectionString"].Should().Be("ca\\CA");
    }

    [Fact]
    public void Save_ThatWouldSetAKeyTwice_ThrowsWithoutWriting()
    {
        // The colon form at the top level, the way docs/hardening.md writes nested
        // keys, names the same configuration key as ExternalUrl inside the section.
        // Writing both would stop the next start, so the writer is told instead.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        const string handEdited = """{ "Certus:ExternalUrl": "https://hand.example.com" }""";
        File.WriteAllText(overlayPath, handEdited);

        var act = () => SettingsOverlay.Mutate(overlayPath, c => c with { ExternalUrl = "https://certus.example.com" });

        // Its own type (issue #553), so a caller can tell the refusal from a file that
        // is not JSON, and still a JsonException, so every existing arm catches it.
        act.Should().Throw<SettingsOverlayConflictException>().WithMessage("*Certus:ExternalUrl*");
        File.ReadAllText(overlayPath).Should().Be(handEdited);
    }

    // ── EnsureCanMutate: the save without the write (issue #553) ──

    [Fact]
    public void EnsureCanMutate_ChangeThatWouldSetAKeyTwice_ThrowsAndWritesNothing()
    {
        // The case the HTTPS certificate record meets: the thumbprint in the section,
        // and the template written by hand in the colon form at the top level. The
        // record sets the template too, so the save would set that key twice.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        const string handEdited = """
            {
              "Certus": { "HttpsCertificateThumbprint": "AA11BB22" },
              "Certus:HttpsCertificateTemplate": "WebServer"
            }
            """;
        File.WriteAllText(overlayPath, handEdited);
        var writtenAt = File.GetLastWriteTimeUtc(overlayPath);

        var act = () => SettingsOverlay.EnsureCanMutate(overlayPath, c => c with
        {
            HttpsCertificateThumbprint = "CC33DD44",
            HttpsCertificateTemplate = "WebServer",
        });

        act.Should().Throw<SettingsOverlayConflictException>()
            .WithMessage("*Certus:HttpsCertificateTemplate*")
            .WithMessage($"*{overlayPath}*");
        File.ReadAllText(overlayPath).Should().Be(handEdited);
        File.GetLastWriteTimeUtc(overlayPath).Should().Be(writtenAt);
    }

    [Fact]
    public void EnsureCanMutate_ChangeThatLoads_WritesNothing()
    {
        // The dry run must not be a save: a change it allows still leaves every byte
        // where it was, hand keys included.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(new SettingsOverlay.OverlaySettings("ca\\CA", "https://certus.example.com"), overlayPath);
        HandEditedOverlay.AddTo(overlayPath);
        var before = File.ReadAllBytes(overlayPath);

        SettingsOverlay.EnsureCanMutate(overlayPath, c => c with
        {
            HttpsCertificateThumbprint = "CC33DD44",
            HttpsCertificateTemplate = "WebServer",
        });

        File.ReadAllBytes(overlayPath).Should().Equal(before);
        SettingsOverlay.Load(overlayPath).HttpsCertificateThumbprint.Should().BeNull();
    }

    [Fact]
    public void EnsureCanMutate_ColonKeyTheChangeLeavesUnset_IsAllowed()
    {
        // As precise as the save: a colon form key only collides with a change that
        // sets the same member, so a hand written URL never blocks a certificate.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, """{ "Certus:ExternalUrl": "https://hand.example.com" }""");

        var act = () => SettingsOverlay.EnsureCanMutate(overlayPath, c => c with
        {
            HttpsCertificateThumbprint = "CC33DD44",
            HttpsCertificateTemplate = "WebServer",
        });

        act.Should().NotThrow();
        // And the save agrees, which is the property the dry run exists to predict.
        SettingsOverlay.Mutate(overlayPath, c => c with
        {
            HttpsCertificateThumbprint = "CC33DD44",
            HttpsCertificateTemplate = "WebServer",
        });
        SettingsOverlay.Load(overlayPath).HttpsCertificateThumbprint.Should().Be("CC33DD44");
    }

    [Fact]
    public void EnsureCanMutate_CorruptFile_ThrowsWhatTheSaveThrows()
    {
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, "{ this is not json");

        var act = () => SettingsOverlay.EnsureCanMutate(overlayPath, c => c with { ExternalUrl = "https://x" });

        act.Should().Throw<System.Text.Json.JsonException>()
            .Which.Should().NotBeOfType<SettingsOverlayConflictException>(
                "a file that is not JSON is not a refused change, and callers answer the two differently");
        File.ReadAllText(overlayPath).Should().Be("{ this is not json");
    }

    [Fact]
    public void EnsureCanMutate_NoFile_CreatesNeitherTheFileNorItsFolder()
    {
        var folder = Path.Combine(_dataDir, "not-yet");
        var overlayPath = Path.Combine(folder, "settings.json");

        SettingsOverlay.EnsureCanMutate(overlayPath, c => c with { ExternalUrl = "https://certus.example.com" });

        Directory.Exists(folder).Should().BeFalse("a dry run writes nothing, not even the folder a save would make");
    }

    [Fact]
    public void Save_CorruptFile_ThrowsWithoutWriting()
    {
        // Save now reads the file it replaces, so it answers a corrupt one the way
        // Mutate always has: writing over it would discard whatever it holds.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath, "{ this is not json");

        var act = () => SettingsOverlay.Save(new SettingsOverlay.OverlaySettings("ca\\CA", null), overlayPath);

        act.Should().Throw<System.Text.Json.JsonException>();
        File.ReadAllText(overlayPath).Should().Be("{ this is not json");
    }

    // ── An overlay the service cannot trust (issue #489) ──

    [Fact]
    public void Overlay_Untrusted_IsNotAdded_AndTheVerdictSaysWhy()
    {
        // The escalation #489 reproduced: a standard user who can write settings.json
        // names their own group as the dashboard's administrators.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath,
            """{ "Certus": { "CaConnectionString": "from-overlay" }, "Auth": { "AdminGroup": "planted" } }""");
        FileAcl.GrantEveryoneWrite(overlayPath);

        var manager = new ConfigurationManager();
        var verdict = ((IConfigurationBuilder)manager).AddSettingsOverlay(_dataDir);

        verdict.IsTrusted.Should().BeFalse();
        verdict.Reason.Should().Contain(FileAcl.EveryoneSid);
        manager["Auth:AdminGroup"].Should().BeNull();
        manager["Certus:CaConnectionString"].Should().BeNull();
    }

    [Fact]
    public void Overlay_Trusted_HonoursEveryKey_AuthIncluded()
    {
        // No key filter, by decision on #489: the overlay is the administrator's
        // configuration file, and what protects it is who may write it.
        File.WriteAllText(Path.Combine(_dataDir, "settings.json"),
            """{ "Auth": { "AdminGroup": "CORP\\Ducks Admins" } }""");

        var manager = new ConfigurationManager();
        var verdict = ((IConfigurationBuilder)manager).AddSettingsOverlay(_dataDir);

        verdict.IsTrusted.Should().BeTrue();
        manager["Auth:AdminGroup"].Should().Be("CORP\\Ducks Admins");
    }

    [Fact]
    public void Load_Untrusted_ReadsAsAbsent()
    {
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(new SettingsOverlay.OverlaySettings("planted\\CA", "https://planted.example"), overlayPath);
        FileAcl.GrantEveryoneWrite(overlayPath);

        var loaded = SettingsOverlay.Load(overlayPath);

        loaded.CaConnectionString.Should().BeNull();
        loaded.ExternalUrl.Should().BeNull();
    }

    [Fact]
    public void Mutate_Untrusted_WritesAFreshTrustedFile_WithOnlyTheChange()
    {
        // How an administrator recovers: saving from the wizard or the settings page
        // replaces the untrusted file, and nothing an attacker put in it survives.
        // Keeping unmanaged keys (issue #550) must not change that: the admin group
        // the attacker planted is exactly the key #489 was about.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        SettingsOverlay.Save(new SettingsOverlay.OverlaySettings("planted\\CA", "https://planted.example"), overlayPath);
        HandEditedOverlay.AddTo(overlayPath);
        FileAcl.GrantEveryoneWrite(overlayPath);

        SettingsOverlay.Mutate(overlayPath, c => c with { ExternalUrl = "https://certus.example.com" });

        Certus.Core.Security.TrustedFile.Check(overlayPath).IsTrusted.Should().BeTrue();
        var loaded = SettingsOverlay.Load(overlayPath);
        loaded.ExternalUrl.Should().Be("https://certus.example.com");
        loaded.CaConnectionString.Should().BeNull();

        using var configuration = new ConfigurationManager();
        ((IConfigurationBuilder)configuration).AddSettingsOverlay(_dataDir).IsTrusted.Should().BeTrue();
        configuration["Auth:AdminGroup"].Should().BeNull();
        configuration["Certus:Alerts:Webhook:Url"].Should().BeNull();
        File.ReadAllText(overlayPath).Should().NotContain(HandEditedOverlay.AdminGroup);
    }

    [Fact]
    public void Save_LeavesAPreCreatedTmpAlone()
    {
        // The staging #489 abused: "settings.json.tmp" was the only name the writer
        // used, so whoever created it first had their file renamed over the target.
        var overlayPath = Path.Combine(_dataDir, "settings.json");
        File.WriteAllText(overlayPath + ".tmp", "planted");

        SettingsOverlay.Save(new SettingsOverlay.OverlaySettings("ca\\CA", null), overlayPath);

        File.ReadAllText(overlayPath + ".tmp").Should().Be("planted");
        SettingsOverlay.Load(overlayPath).CaConnectionString.Should().Be("ca\\CA");
    }
}
