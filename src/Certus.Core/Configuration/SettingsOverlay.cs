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

    /// <summary>
    /// The overlay path in effect for the given options: the configured
    /// override (used by tests) or the data directory default. The single
    /// resolver for every overlay read and write, so a reader can never watch
    /// a different file than the writer wrote. <c>SetupService</c> exposes it
    /// as an instance property; background services that have no scoped
    /// <c>SetupService</c> call this directly.
    /// </summary>
    public static string ResolvePath(CertusOptions options) =>
        options.SettingsOverlayPath ?? CertusPaths.SettingsOverlayPath;

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
        string? HttpsCertificateTemplate = null,
        AlertOverlaySettings? Alerts = null);

    /// <summary>
    /// The parts of <c>Certus:Alerts</c> an administrator may change from the
    /// dashboard (issue #162). Every member is nullable, and null means "not
    /// managed from the dashboard": an install that never saved keeps exactly
    /// the behaviour it had, because <see cref="WriteOptions"/> omits nulls and
    /// <c>AlertOptions.ApplyOverlay</c> skips them.
    ///
    /// <para>
    /// Serialized under the <c>Certus</c> section, this block lands on the same
    /// <c>Certus:Alerts:*</c> configuration keys the section binds from, so the
    /// service host's binder and the apply step agree about what the file says.
    /// The binder result is not what wins, though: see
    /// <c>AlertOptions.ApplyOverlay</c> for why an array has to be replaced
    /// wholesale rather than merged.
    /// </para>
    ///
    /// <para>
    /// What is deliberately absent is the webhook block. It stays file only, so
    /// no dashboard write can point outbound HTTP somewhere new; the webhook
    /// URL routinely embeds a bearer token.
    /// </para>
    /// </summary>
    public sealed record AlertOverlaySettings(
        bool? Enabled = null,
        int? CheckIntervalMinutes = null,
        int[]? ThresholdDays = null,
        AlertSmtpOverlaySettings? Smtp = null);

    /// <summary>
    /// The writable slice of the SMTP block. The host and from address arrived
    /// with issue #162, because without them the feature is inert on a default
    /// install: the shipped appsettings.json carries <c>"Smtp": null</c>, and
    /// the email notifier needs a host, a non blank sender address, and at
    /// least one recipient before it will send (issue #209). The port, TLS
    /// mode, username, password and from name followed once the dashboard
    /// became the primary way to configure the relay: a transport nobody can
    /// finish configuring from the page that owns the rest of it is a support
    /// ticket, not a boundary.
    ///
    /// <para>
    /// <see cref="PasswordProtected"/> is the one credential and it is never
    /// plaintext here: the write path protects it with ISecretProtector before
    /// it reaches this record, and the read path hands the blob to the email
    /// notifier, which unprotects at send time and fails closed when the
    /// keyring cannot decrypt it. <see cref="TlsMode"/> is a canonical
    /// lowercase name from <c>SmtpTlsModes</c>, stored as a string so a hand
    /// edit that misspells a mode is skipped rather than misread.
    /// </para>
    /// </summary>
    public sealed record AlertSmtpOverlaySettings(
        string? Host = null,
        string? FromAddress = null,
        string[]? Recipients = null,
        int? Port = null,
        string? TlsMode = null,
        string? Username = null,
        string? FromName = null,
        string? PasswordProtected = null);

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
        lock (WriteLock)
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
    }

    /// <summary>
    /// Serializes every overlay write in this process, the same role
    /// <c>SetupService.StatusFileWriteLock</c> plays for the wizard status file.
    /// <see cref="Mutate"/> holds it across the whole read, modify, write, so
    /// two writers cannot both load the file, each change their own field, and
    /// have the later save drop the earlier change. It also keeps them off the
    /// single shared ".tmp" path <see cref="Save"/> stages through. Monitor is
    /// reentrant, so <see cref="Mutate"/> calling <see cref="Save"/> is fine.
    /// </summary>
    private static readonly object WriteLock = new();

    /// <summary>
    /// Read the overlay, apply <paramref name="change"/>, and write it back as
    /// one atomic step, returning what was written.
    ///
    /// <para>
    /// This is the shape every overlay write wants. The alternative, a bare
    /// <see cref="Load"/> then <see cref="Save"/>, is a lost update waiting to
    /// happen: <c>HttpsCertificateRenewalService</c> writes the thumbprint from
    /// a background timer, and an administrator saving from the settings page at
    /// the same moment would load the pre-renewal file and save the old
    /// thumbprint back over the new one.
    /// </para>
    ///
    /// <para>
    /// <paramref name="change"/> runs under the lock, so it must not block or
    /// call back into the overlay. A <see cref="JsonException"/> from the read
    /// propagates: the caller has to decide, because rewriting from an empty
    /// record would drop the CA connection string and unconfigure the CA at the
    /// next restart.
    /// </para>
    /// </summary>
    public static OverlaySettings Mutate(
        string overlayPath,
        Func<OverlaySettings, OverlaySettings> change)
    {
        lock (WriteLock)
        {
            var updated = change(Load(overlayPath));
            Save(updated, overlayPath);
            return updated;
        }
    }

    /// <summary>
    /// The saved alert block, reporting a read failure through
    /// <paramref name="failure"/> instead of throwing (issue #162). Mirrors
    /// <c>SetupStatus.TryLoad</c>: a missing file is a legitimate empty state
    /// and yields null with no failure.
    ///
    /// <para>
    /// This is read while options are being built, so it cannot throw the way
    /// <see cref="Load"/> does. Taking the host down over a corrupt overlay
    /// would be worse than the corruption, and returning an empty record would
    /// silently reset alerting rather than leave it as configured. Null keeps
    /// whatever appsettings.json says, which means monitoring stays on with the
    /// standard thresholds: the safe direction to fail for a surface whose job
    /// is to warn.
    /// </para>
    /// </summary>
    public static AlertOverlaySettings? TryLoadAlerts(string overlayPath, out Exception? failure)
    {
        failure = null;
        try
        {
            return Load(overlayPath).Alerts;
        }
        catch (Exception ex)
        {
            failure = ex;
            return null;
        }
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

    /// <summary>
    /// Which of <paramref name="keys"/> a configuration layer above the overlay
    /// supplies: an environment variable or a command line switch. Those outrank
    /// the overlay by design (see <see cref="AddSettingsOverlay"/>), so a value
    /// saved from the dashboard would never come into force, and the settings
    /// surface has to say so rather than appear to have saved something.
    ///
    /// <para>
    /// Only providers positioned after the overlay count. The boundary is the
    /// overlay itself when it is registered, and otherwise the last appsettings
    /// provider, which is exactly where <see cref="AddSettingsOverlay"/> would
    /// have inserted it. Without that, the chained host configuration provider
    /// that <c>WebApplication.CreateBuilder</c> puts at the front, which
    /// classifies as "other" but is the lowest precedence layer there is,
    /// would read as outranking everything.
    /// </para>
    ///
    /// <para>
    /// Scalar keys only. An array is compared by index across providers, which
    /// is the merge behaviour the overlay apply step exists to defeat, so a per
    /// index precedence rule would be incoherent: once saved, an array is owned
    /// by the overlay outright.
    /// </para>
    /// </summary>
    public static HashSet<string> FindOutrankedKeys(
        IConfiguration configuration,
        IEnumerable<string> keys)
    {
        var outranked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (configuration is not IConfigurationRoot root)
            return outranked;

        var providers = root.Providers.ToList();
        var keyList = keys.ToList();

        var boundary = -1;
        for (var i = 0; i < providers.Count; i++)
        {
            var layer = ClassifyProvider(providers[i]);
            if (layer == ExternalUrlLayerReport.SourceOverlay)
            {
                boundary = i;
                break;
            }

            if (layer == ExternalUrlLayerReport.SourceAppSettings)
                boundary = i;
        }

        for (var i = boundary + 1; i < providers.Count; i++)
        {
            foreach (var key in keyList)
            {
                // An empty value counts as unset throughout, the same rule
                // InspectExternalUrl applies: appsettings ships several keys as
                // explicit JSON null, which lands in configuration data as an
                // empty string.
                if (providers[i].TryGet(key, out var value) && !string.IsNullOrEmpty(value))
                    outranked.Add(key);
            }
        }

        return outranked;
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
