using System.Buffers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Certus.Core.Security;
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
    ///
    /// An overlay the service cannot trust (<see cref="TrustedFile"/>) is not
    /// added at all, and the verdict is returned so the host can log it once its
    /// file logger exists (issue #489). The overlay is the administrator's
    /// configuration file, so every key in it is honoured, Auth:AdminGroup
    /// included; what protects it is who may write it. The check and the load
    /// are two separate opens of the file, which matters only if someone could
    /// swap the file in between, and in the protected data folder only SYSTEM
    /// and Administrators can.
    /// </summary>
    public static FileTrust AddSettingsOverlay(this IConfigurationBuilder builder, string dataDirectory)
    {
        // The file provider needs an existing root; the data directory is also
        // created by the hosts, but the overlay is inserted first.
        ProtectedFolder.EnsureExists(dataDirectory);

        var trust = TrustedFile.Check(Path.Combine(dataDirectory, CertusPaths.SettingsOverlayFileName));
        if (!trust.IsTrusted)
            return trust;

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

        return trust;
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
    /// These members, and the members of the alert records nested in them, are
    /// the only keys a save writes; every other key in the file is the
    /// administrator's and is written back as it was read (issue #550).
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

    /// <summary>
    /// The contract a save walks to learn which members it manages. The
    /// resolver is named, and the options locked, so
    /// <see cref="JsonSerializerOptions.GetTypeInfo"/> answers with the same
    /// member names and order the serializer itself uses.
    /// </summary>
    private static readonly JsonSerializerOptions WriteOptions = CreateWriteOptions();

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private static JsonSerializerOptions CreateWriteOptions()
    {
        var options = new JsonSerializerOptions { TypeInfoResolver = new DefaultJsonTypeInfoResolver() };
        options.MakeReadOnly();
        return options;
    }

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
    /// The record carries only the keys the service manages. That is not what a
    /// save keeps: <see cref="Save"/> reads the file again and writes every
    /// other key back as it was, inside the Certus section and outside it
    /// (issue #550). An administrator's own keys, such as Auth:AdminGroup or
    /// the challenge validation block, therefore survive every write.
    ///
    /// An overlay the service cannot trust reads as absent, as it does at
    /// startup (issue #489). So the next <see cref="Mutate"/> writes a fresh,
    /// trusted file holding only what that change sets, and carries nothing
    /// else over from the untrusted file, which is how an administrator
    /// recovers by saving from the wizard or the settings page.
    /// </summary>
    public static OverlaySettings Load(string overlayPath)
    {
        using var document = ReadTrustedDocument(overlayPath);
        return document is null ? new OverlaySettings(null, null) : ReadSection(document.RootElement);
    }

    /// <summary>
    /// Persist the overlay to <paramref name="overlayPath"/> through
    /// <see cref="AtomicFile"/>, so a crash mid write cannot leave a torn
    /// settings.json that would stop the next start (a malformed optional JSON
    /// source still fails configuration build), and no one can stage the write
    /// for the service (issue #489).
    ///
    /// <para>
    /// The save replaces only what <paramref name="settings"/> manages and keeps
    /// the rest of the file (issue #550). The docs make settings.json the
    /// administrator's file for keys well beyond the wizard's, and every write
    /// used to drop them, so the next restart silently put the admin group back
    /// to the built in Administrators, switched private range blocking off and
    /// stopped webhook alerts. A key is kept only from a file the service
    /// trusts; an untrusted one is replaced whole, as before.
    /// </para>
    ///
    /// <para>
    /// A trusted file that is not valid JSON throws <see cref="JsonException"/>
    /// and is left alone, the same answer <see cref="Load"/> gives, because
    /// writing over it would discard whatever it holds. So does a save the
    /// configuration system could not load afterwards (see
    /// <see cref="EnsureLoadsAsConfiguration"/>).
    /// </para>
    /// </summary>
    public static void Save(OverlaySettings settings, string overlayPath)
    {
        lock (WriteLock)
        {
            using var existing = ReadTrustedDocument(overlayPath);
            Write(settings, existing, overlayPath);
        }
    }

    /// <summary>
    /// Serializes every overlay write in this process, the same role
    /// <c>SetupService.StatusFileWriteLock</c> plays for the wizard status file.
    /// <see cref="Mutate"/> holds it across the whole read, modify, write, so
    /// two writers cannot both load the file, each change their own field, and
    /// have the later save drop the earlier change.
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
    /// next restart. The file is read once, and that one read is both what
    /// <paramref name="change"/> sees and what the write keeps the
    /// administrator's keys from, as <see cref="Save"/> describes.
    /// </para>
    /// </summary>
    public static OverlaySettings Mutate(
        string overlayPath,
        Func<OverlaySettings, OverlaySettings> change)
    {
        lock (WriteLock)
        {
            using var existing = ReadTrustedDocument(overlayPath);
            var updated = change(existing is null
                ? new OverlaySettings(null, null)
                : ReadSection(existing.RootElement));
            Write(updated, existing, overlayPath);
            return updated;
        }
    }

    /// <summary>
    /// <see cref="Mutate"/> without the write: read the overlay, apply
    /// <paramref name="change"/>, build the file the save would write, and refuse it
    /// exactly as the save would, but write nothing, not even the folder (issue #553).
    ///
    /// <para>
    /// For a caller whose write comes after work that cannot be undone. Enrolling the
    /// server's HTTPS certificate is the case: the CA issues it and the store installs
    /// it before the thumbprint is recorded, so a record refused afterwards leaves a
    /// live certificate that nothing names, one more on every attempt. Asking first
    /// moves the refusal ahead of the enrolment. It is the same read, the same merge
    /// and the same check as the save, not a second copy of them, so the two cannot
    /// disagree about what the file would hold.
    /// </para>
    ///
    /// <para>
    /// Throws what <see cref="Mutate"/> throws: a <see cref="JsonException"/> for a
    /// trusted file that cannot be read, and a <see cref="SettingsOverlayConflictException"/>
    /// for a change that would set a key twice. Runs under the same lock as the
    /// writers, so it never reads a file half way through another writer's change.
    /// Passing proves only that the file allowed the change when it was read: a hand
    /// edit made between this and the real write is refused by the write, as before.
    /// </para>
    /// </summary>
    public static void EnsureCanMutate(
        string overlayPath,
        Func<OverlaySettings, OverlaySettings> change)
    {
        lock (WriteLock)
        {
            using var existing = ReadTrustedDocument(overlayPath);
            var updated = change(existing is null
                ? new OverlaySettings(null, null)
                : ReadSection(existing.RootElement));
            _ = Build(updated, existing, overlayPath);
        }
    }

    /// <summary>
    /// The overlay parsed, or null when there is nothing the service may read:
    /// no file, or one it does not trust (issue #489). <see cref="Load"/> and
    /// both writers read through this, so a key is carried forward only from a
    /// file the service would itself have honoured at startup.
    /// </summary>
    private static JsonDocument? ReadTrustedDocument(string overlayPath)
    {
        if (!File.Exists(overlayPath) || !TrustedFile.Check(overlayPath).IsTrusted)
            return null;

        var document = JsonDocument.Parse(File.ReadAllText(overlayPath));
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            throw new JsonException(
                $"The settings overlay at {overlayPath} must be a JSON object at the top level.");
        }

        return document;
    }

    private static OverlaySettings ReadSection(JsonElement root)
    {
        var index = FindSection(root);
        if (index < 0)
            return new OverlaySettings(null, null);

        var section = root.EnumerateObject().ElementAt(index).Value;
        return section.ValueKind == JsonValueKind.Null
            ? new OverlaySettings(null, null)
            : section.Deserialize<OverlaySettings>(ReadOptions) ?? new OverlaySettings(null, null);
    }

    /// <summary>
    /// The position of the Certus member at the top level of the file: the
    /// first one, matched ignoring case, whose value is not null, else the first
    /// null one, else -1. The read takes its values from this member and the
    /// write puts them back into the same one, so the two never disagree about
    /// which section the record is.
    /// </summary>
    private static int FindSection(JsonElement root)
    {
        var index = 0;
        var firstNull = -1;
        foreach (var property in root.EnumerateObject())
        {
            if (string.Equals(property.Name, CertusOptions.SectionName, StringComparison.OrdinalIgnoreCase))
            {
                if (property.Value.ValueKind != JsonValueKind.Null)
                    return index;
                if (firstNull < 0)
                    firstNull = index;
            }

            index++;
        }

        return firstNull;
    }

    /// <summary>
    /// Write <paramref name="settings"/> into <paramref name="existing"/>, or into
    /// a new file when there is none, and save the result.
    /// </summary>
    private static void Write(OverlaySettings settings, JsonDocument? existing, string overlayPath)
    {
        var bytes = Build(settings, existing, overlayPath);

        var directory = Path.GetDirectoryName(overlayPath);
        if (!string.IsNullOrEmpty(directory))
            ProtectedFolder.EnsureExists(directory);

        AtomicFile.WriteAllBytes(overlayPath, bytes);
    }

    /// <summary>
    /// The file a save of <paramref name="settings"/> over <paramref name="existing"/>
    /// would write, refused through <see cref="EnsureLoadsAsConfiguration"/> when the
    /// configuration system could not load it. Touches nothing on disk, which is what
    /// lets <see cref="EnsureCanMutate"/> share it with the save. Members outside the
    /// Certus section are written back as they were read; the section itself is
    /// merged by <see cref="WriteManaged"/>, and appended when the file has none.
    /// </summary>
    private static byte[] Build(OverlaySettings settings, JsonDocument? existing, string overlayPath)
    {
        var contract = WriteOptions.GetTypeInfo(typeof(OverlaySettings));
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();

            var section = existing is null ? -1 : FindSection(existing.RootElement);
            if (existing is not null)
            {
                var index = 0;
                foreach (var property in existing.RootElement.EnumerateObject())
                {
                    if (index++ == section)
                    {
                        writer.WritePropertyName(property.Name);
                        WriteManaged(writer, contract, settings, property.Value);
                    }
                    else
                    {
                        WriteVerbatim(writer, property);
                    }
                }
            }

            if (section < 0)
            {
                writer.WritePropertyName(CertusOptions.SectionName);
                WriteManaged(writer, contract, settings, existing: null);
            }

            writer.WriteEndObject();
        }

        var bytes = buffer.WrittenSpan.ToArray();
        EnsureLoadsAsConfiguration(bytes, overlayPath);
        return bytes;
    }

    /// <summary>
    /// Write one object a record manages: <paramref name="value"/>'s members over
    /// <paramref name="existing"/>. A member <paramref name="contract"/> names is
    /// the record's to decide, matched ignoring case as <see cref="Load"/> reads
    /// it: written where the file had it, or appended, and left out when null,
    /// which is the rule that keeps an unset value from masking a lower
    /// precedence source. Every other member is the administrator's and is
    /// written back as it was read.
    ///
    /// <para>
    /// A nested record recurses rather than replacing the block, because a block
    /// the dashboard manages can hold keys it does not: the webhook lives in
    /// Certus:Alerts beside the members the alert card saves. A nested record the
    /// value leaves null is still merged when the file has the block, so its own
    /// members go and the administrator's stay.
    /// </para>
    /// </summary>
    private static void WriteManaged(
        Utf8JsonWriter writer, JsonTypeInfo contract, object? value, JsonElement? existing)
    {
        writer.WriteStartObject();

        var written = new HashSet<JsonPropertyInfo>();
        if (existing is { ValueKind: JsonValueKind.Object } current)
        {
            foreach (var property in current.EnumerateObject())
            {
                // A second spelling of a member already written is not the
                // record's to drop: it goes back as it was, and
                // EnsureLoadsAsConfiguration refuses the save if the two collide.
                var member = FindMember(contract, property.Name);
                if (member is not null && written.Add(member))
                    WriteMember(writer, member, value, property.Value);
                else
                    WriteVerbatim(writer, property);
            }
        }

        foreach (var member in contract.Properties)
        {
            if (written.Add(member))
                WriteMember(writer, member, value, existing: null);
        }

        writer.WriteEndObject();
    }

    private static void WriteMember(
        Utf8JsonWriter writer, JsonPropertyInfo member, object? owner, JsonElement? existing)
    {
        var value = owner is null ? null : member.Get!(owner);
        var contract = WriteOptions.GetTypeInfo(member.PropertyType);

        if (contract.Kind == JsonTypeInfoKind.Object)
        {
            if (value is null && existing is not { ValueKind: JsonValueKind.Object })
                return;

            writer.WritePropertyName(member.Name);
            WriteManaged(writer, contract, value, existing);
        }
        else if (value is not null)
        {
            // Arrays are leaves: once saved, a list is the record's outright,
            // the rule AlertOptions.ApplyOverlay applies when it reads one back.
            writer.WritePropertyName(member.Name);
            JsonSerializer.Serialize(writer, value, member.PropertyType, WriteOptions);
        }
    }

    private static JsonPropertyInfo? FindMember(JsonTypeInfo contract, string name)
    {
        foreach (var member in contract.Properties)
        {
            if (string.Equals(member.Name, name, StringComparison.OrdinalIgnoreCase))
                return member;
        }

        return null;
    }

    /// <summary>
    /// Write a member the service does not manage exactly as the file had it.
    /// The value goes back as its raw text, so its escapes, its number format
    /// and its inner layout are unchanged: a group name carrying a non ASCII
    /// letter is not rewritten as a \u escape the administrator did not type.
    /// </summary>
    private static void WriteVerbatim(Utf8JsonWriter writer, JsonProperty property)
    {
        writer.WritePropertyName(property.Name);
        writer.WriteRawValue(property.Value.GetRawText());
    }

    /// <summary>
    /// Refuse a save the configuration system could not load (issue #550).
    /// Keeping keys the service does not manage means one added by hand can now
    /// meet one the service writes. A top level "Certus:ExternalUrl", the colon
    /// form the docs use for nested keys, is the same configuration key as
    /// ExternalUrl inside the Certus section, and the JSON provider refuses a
    /// file that sets a key twice, so that file would stop the next start. The
    /// writer is told instead, through a <see cref="SettingsOverlayConflictException"/>,
    /// which is the <see cref="JsonException"/> every caller already handles for an
    /// overlay it cannot read, and nothing is written.
    ///
    /// <para>
    /// The message serves the save and its dry run alike (issue #553), so it says the
    /// change was refused rather than that a save failed, and asks for a retry rather
    /// than a save: the change may be a certificate renewal, not a form.
    /// </para>
    /// </summary>
    private static void EnsureLoadsAsConfiguration(byte[] json, string overlayPath)
    {
        try
        {
            using var stream = new MemoryStream(json, writable: false);
            _ = new ConfigurationBuilder().AddJsonStream(stream).Build();
        }
        catch (FormatException ex)
        {
            throw new SettingsOverlayConflictException(
                $"The settings overlay at {overlayPath} cannot take this change, because the result " +
                $"would not load as configuration: {ex.Message} The file would set that key twice, " +
                "usually once inside a section and once in the colon form at the top level. Keep one " +
                "of them and try again.",
                ex);
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
