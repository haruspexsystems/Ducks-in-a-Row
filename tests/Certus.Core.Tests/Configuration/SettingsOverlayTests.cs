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
}
