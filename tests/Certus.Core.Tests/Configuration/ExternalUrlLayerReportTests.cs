using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// The layer inspector answers "which configuration layer supplies
/// Certus:ExternalUrl", so the startup log and the settings API can explain
/// why an appsettings.json edit had no effect (issue #93). The load bearing
/// case: appsettings.json ships the key as an explicit JSON null, which lands
/// in configuration data as an empty string and must never read as a real
/// value being overridden.
/// </summary>
public class ExternalUrlLayerReportTests : IDisposable
{
    private readonly string _appDir;
    private readonly string _dataDir;

    public ExternalUrlLayerReportTests()
    {
        var root = Path.Combine(Path.GetTempPath(), $"certus-layers-{Guid.NewGuid():N}");
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

    /// <summary>
    /// Wire appsettings.json and the overlay the way both hosts do, so the
    /// providers carry the file names the inspector classifies by.
    /// </summary>
    private ConfigurationManager BuildConfiguration(
        string? appSettingsJson, string? overlayJson)
    {
        var manager = new ConfigurationManager();
        manager.SetBasePath(_appDir);

        if (appSettingsJson is not null)
        {
            File.WriteAllText(Path.Combine(_appDir, "appsettings.json"), appSettingsJson);
            manager.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
        }

        if (overlayJson is not null)
            File.WriteAllText(Path.Combine(_dataDir, "settings.json"), overlayJson);

        ((IConfigurationBuilder)manager).AddSettingsOverlay(_dataDir);
        return manager;
    }

    [Fact]
    public void Inspect_AppSettingsExplicitNullUnderOverlay_IsNotAnOverride()
    {
        var config = BuildConfiguration(
            """{ "Certus": { "ExternalUrl": null } }""",
            """{ "Certus": { "ExternalUrl": "https://certus.example.com:5001" } }""");

        var report = SettingsOverlay.InspectExternalUrl(config);

        report.EffectiveValue.Should().Be("https://certus.example.com:5001");
        report.EffectiveSource.Should().Be(ExternalUrlLayerReport.SourceOverlay);
        report.AppSettingsValue.Should().BeNull("an explicit JSON null is unset, not a value");
        report.AppSettingsValueOverridden.Should().BeFalse();
    }

    [Fact]
    public void Inspect_RealAppSettingsValueUnderOverlay_ReportsTheOverride()
    {
        var config = BuildConfiguration(
            """{ "Certus": { "ExternalUrl": "https://from-appsettings.example.com" } }""",
            """{ "Certus": { "ExternalUrl": "https://from-overlay.example.com" } }""");

        var report = SettingsOverlay.InspectExternalUrl(config);

        report.EffectiveValue.Should().Be("https://from-overlay.example.com");
        report.EffectiveSource.Should().Be(ExternalUrlLayerReport.SourceOverlay);
        report.AppSettingsValue.Should().Be("https://from-appsettings.example.com");
        report.OverlayValue.Should().Be("https://from-overlay.example.com");
        report.AppSettingsValueOverridden.Should().BeTrue();
    }

    [Fact]
    public void Inspect_AppSettingsOnly_ReportsAppSettingsAsTheSource()
    {
        var config = BuildConfiguration(
            """{ "Certus": { "ExternalUrl": "https://from-appsettings.example.com" } }""",
            overlayJson: null);

        var report = SettingsOverlay.InspectExternalUrl(config);

        report.EffectiveValue.Should().Be("https://from-appsettings.example.com");
        report.EffectiveSource.Should().Be(ExternalUrlLayerReport.SourceAppSettings);
        report.AppSettingsValueOverridden.Should().BeFalse();
    }

    [Fact]
    public void Inspect_SourceAfterTheOverlay_WinsAsOther()
    {
        // Stands in for environment variables and command line, which the
        // overlay is inserted below by design.
        var config = BuildConfiguration(
            """{ "Certus": { "ExternalUrl": null } }""",
            """{ "Certus": { "ExternalUrl": "https://from-overlay.example.com" } }""");
        config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Certus:ExternalUrl"] = "https://from-environment.example.com",
        });

        var report = SettingsOverlay.InspectExternalUrl(config);

        report.EffectiveValue.Should().Be("https://from-environment.example.com");
        report.EffectiveSource.Should().Be(ExternalUrlLayerReport.SourceOther);
        report.OverlayValue.Should().Be("https://from-overlay.example.com");
    }

    [Fact]
    public void Inspect_BlankHigherPrecedenceOverride_ReportsNone()
    {
        // An explicit blank override (command line --Certus:ExternalUrl= or
        // an env var set to empty) really does blank the merged value; the
        // report must not attribute the outranked overlay value as effective.
        var config = BuildConfiguration(
            """{ "Certus": { "ExternalUrl": null } }""",
            """{ "Certus": { "ExternalUrl": "https://from-overlay.example.com" } }""");
        config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Certus:ExternalUrl"] = "",
        });

        var report = SettingsOverlay.InspectExternalUrl(config);

        report.EffectiveValue.Should().BeNull();
        report.EffectiveSource.Should().Be(ExternalUrlLayerReport.SourceNone);
        report.OverlayValue.Should().Be("https://from-overlay.example.com");
    }

    [Fact]
    public void Inspect_NothingSetAnywhere_ReportsNone()
    {
        var config = BuildConfiguration(
            """{ "Certus": { "ExternalUrl": null } }""",
            overlayJson: null);

        var report = SettingsOverlay.InspectExternalUrl(config);

        report.EffectiveValue.Should().BeNull();
        report.EffectiveSource.Should().Be(ExternalUrlLayerReport.SourceNone);
        report.AppSettingsValueOverridden.Should().BeFalse();
    }

    [Fact]
    public void Inspect_NonRootConfiguration_DegradesToTheMergedValue()
    {
        // A configuration section exposes no providers; the inspector still
        // reports the merged value rather than failing.
        var root = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sub:Certus:ExternalUrl"] = "https://from-section.example.com",
            })
            .Build();
        IConfiguration section = root.GetSection("Sub");

        var report = SettingsOverlay.InspectExternalUrl(section);

        report.EffectiveValue.Should().Be("https://from-section.example.com");
        report.EffectiveSource.Should().Be(ExternalUrlLayerReport.SourceOther);
    }
}
