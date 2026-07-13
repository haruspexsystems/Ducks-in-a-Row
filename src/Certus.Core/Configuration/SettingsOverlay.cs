using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.FileProviders;

namespace Certus.Core.Configuration;

/// <summary>
/// Wires the runtime settings overlay into the host configuration. The overlay
/// (settings.json in the data directory) is written by the setup wizard and
/// holds instance configuration such as the CA connection string and external
/// URL. It lives in the data directory, not the install directory, so MSI
/// upgrades can never overwrite it.
/// </summary>
public static class SettingsOverlay
{
    /// <summary>
    /// Insert the overlay source directly after the last appsettings JSON
    /// source. Precedence becomes: appsettings.json &lt; appsettings.{env}.json
    /// &lt; settings.json overlay &lt; environment variables &lt; command line.
    /// A plain Add would land after environment variables and command line,
    /// silently inverting their precedence.
    ///
    /// ReloadOnChange stays off on purpose: a service restart is the apply
    /// mechanism for setup changes, and no file watcher should sit on the data
    /// directory.
    /// </summary>
    public static void AddSettingsOverlay(this IConfigurationBuilder builder, string dataDirectory)
    {
        // The file provider needs an existing root; the data directory is also
        // created by the hosts, but the overlay is inserted first.
        Directory.CreateDirectory(dataDirectory);

        var source = new JsonConfigurationSource
        {
            Path = CertusPaths.SettingsOverlayFileName,
            Optional = true,
            ReloadOnChange = false,
            FileProvider = new PhysicalFileProvider(dataDirectory),
        };

        var index = LastAppSettingsSourceIndex(builder.Sources);
        if (index >= 0)
            builder.Sources.Insert(index + 1, source);
        else
            builder.Add(source);
    }

    private static int LastAppSettingsSourceIndex(IList<IConfigurationSource> sources)
    {
        for (var i = sources.Count - 1; i >= 0; i--)
        {
            if (sources[i] is JsonConfigurationSource json &&
                json.Path?.StartsWith("appsettings", StringComparison.OrdinalIgnoreCase) == true)
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// The instance settings the setup wizard persists. Null values are
    /// omitted from the file so they never mask a lower precedence source.
    /// <see cref="HttpsCertificateThumbprint"/> selects the HTTPS certificate
    /// from the LocalMachine\My store; it is written by the wizard's TLS
    /// certificate provisioning and read by the service host at startup.
    /// <see cref="HttpsCertificateTemplate"/> records which template that
    /// certificate was enrolled with, so the settings page can renew with
    /// the same template later. Informational to the host; never read at
    /// startup.
    /// </summary>
    public sealed record OverlaySettings(
        string? CaConnectionString,
        string? ExternalUrl,
        string? HttpsCertificateThumbprint = null,
        string? HttpsCertificateTemplate = null);

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Read the overlay back from <paramref name="overlayPath"/>. A missing
    /// file, or a file without a Certus section, yields an empty
    /// <see cref="OverlaySettings"/>. Keys outside the Certus section are
    /// tolerated on read (the configuration provider accepts them too) but a
    /// file that is not valid JSON, or whose Certus section is not an object,
    /// throws: the caller must not paper over that, because rewriting the
    /// overlay from an empty record would drop the CA connection string and
    /// unconfigure the CA at the next restart.
    ///
    /// Inside the Certus section only the keys of <see cref="OverlaySettings"/>
    /// survive a <see cref="Load"/> then <see cref="Save"/> round trip; any
    /// other key a hand edit added there is dropped.
    /// </summary>
    public static OverlaySettings Load(string overlayPath)
    {
        if (!File.Exists(overlayPath))
            return new OverlaySettings(null, null);

        using var document = JsonDocument.Parse(File.ReadAllText(overlayPath));
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException(
                $"The settings overlay at {overlayPath} must be a JSON object at the top level.");
        }

        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (string.Equals(property.Name, CertusOptions.SectionName, StringComparison.OrdinalIgnoreCase) &&
                property.Value.ValueKind != JsonValueKind.Null)
            {
                return property.Value.Deserialize<OverlaySettings>(ReadOptions)
                    ?? new OverlaySettings(null, null);
            }
        }

        return new OverlaySettings(null, null);
    }

    /// <summary>
    /// Persist the overlay to <paramref name="overlayPath"/>. Written to a
    /// temporary file first and moved into place, so a crash mid write cannot
    /// leave a torn settings.json that would stop the next start (a malformed
    /// optional JSON source still fails configuration build).
    /// </summary>
    public static void Save(OverlaySettings settings, string overlayPath)
    {
        var directory = Path.GetDirectoryName(overlayPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        var payload = new Dictionary<string, OverlaySettings>
        {
            [CertusOptions.SectionName] = settings,
        };
        var json = JsonSerializer.Serialize(payload, WriteOptions);

        var tempPath = overlayPath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, overlayPath, overwrite: true);
    }

    private const string ExternalUrlKey = CertusOptions.SectionName + ":" + nameof(CertusOptions.ExternalUrl);

    /// <summary>
    /// Report which configuration layer supplies Certus:ExternalUrl. Walks the
    /// configuration providers in precedence order and records the value each
    /// relevant layer contributes, so the startup log and the settings API can
    /// say not just what the effective URL is but where it came from — the
    /// answer to "I edited appsettings.json and nothing changed".
    ///
    /// An empty string counts as unset throughout: appsettings.json ships the
    /// key as an explicit JSON null, which lands in configuration data as an
    /// empty string, and that must never read as a real appsettings value
    /// being overridden.
    /// </summary>
    public static ExternalUrlLayerReport InspectExternalUrl(IConfiguration configuration)
    {
        if (configuration is not IConfigurationRoot root)
        {
            // Without provider access there is nothing to attribute; report
            // the merged value with an unknown source.
            var merged = configuration[ExternalUrlKey];
            return string.IsNullOrEmpty(merged)
                ? new ExternalUrlLayerReport(null, null, null, ExternalUrlLayerReport.SourceNone)
                : new ExternalUrlLayerReport(merged, null, null, ExternalUrlLayerReport.SourceOther);
        }

        string? effective = null;
        string? appSettings = null;
        string? overlay = null;
        var effectiveSource = ExternalUrlLayerReport.SourceNone;

        foreach (var provider in root.Providers)
        {
            if (!provider.TryGet(ExternalUrlKey, out var value))
                continue;

            var layer = ClassifyProvider(provider);
            if (!string.IsNullOrEmpty(value))
            {
                if (layer == ExternalUrlLayerReport.SourceAppSettings)
                    appSettings = value;
                else if (layer == ExternalUrlLayerReport.SourceOverlay)
                    overlay = value;
            }

            // The last provider that carries the key wins, even with an empty
            // value: an explicit blank override (command line or environment
            // variable set to "") really does blank the merged value, and
            // reporting the outranked overlay value as effective would lie.
            effective = string.IsNullOrEmpty(value) ? null : value;
            effectiveSource = string.IsNullOrEmpty(value)
                ? ExternalUrlLayerReport.SourceNone
                : layer;
        }

        return new ExternalUrlLayerReport(effective, appSettings, overlay, effectiveSource);
    }

    private static string ClassifyProvider(IConfigurationProvider provider)
    {
        if (provider is JsonConfigurationProvider json && json.Source.Path is { } path)
        {
            var fileName = Path.GetFileName(path);
            if (fileName.Equals(CertusPaths.SettingsOverlayFileName, StringComparison.OrdinalIgnoreCase))
                return ExternalUrlLayerReport.SourceOverlay;
            if (fileName.StartsWith("appsettings", StringComparison.OrdinalIgnoreCase))
                return ExternalUrlLayerReport.SourceAppSettings;
        }

        return ExternalUrlLayerReport.SourceOther;
    }
}

/// <summary>
/// Where Certus:ExternalUrl comes from, layer by layer. EffectiveValue is the
/// value the merged configuration yields (null when unset everywhere);
/// EffectiveSource is one of the Source constants naming the winning layer.
/// AppSettingsValue and OverlayValue carry what those specific layers
/// contribute, when they contribute anything.
/// </summary>
public sealed record ExternalUrlLayerReport(
    string? EffectiveValue,
    string? AppSettingsValue,
    string? OverlayValue,
    string EffectiveSource)
{
    public const string SourceOverlay = "overlay";
    public const string SourceAppSettings = "appsettings";
    public const string SourceOther = "other";
    public const string SourceNone = "none";

    /// <summary>
    /// True when appsettings.json carries a real value that is not the one in
    /// force — the silent situation issue #93 makes diagnosable.
    /// </summary>
    public bool AppSettingsValueOverridden =>
        AppSettingsValue is not null &&
        !string.Equals(AppSettingsValue, EffectiveValue, StringComparison.Ordinal);
}
