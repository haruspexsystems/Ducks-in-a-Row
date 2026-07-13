using System.Text.Json;
using System.Text.Json.Serialization;
using Certus.Core.Configuration;

namespace Certus.Core.Setup;

/// <summary>
/// Tracks whether the initial setup wizard has been completed.
/// Persisted to ducks-setup.json next to the database.
/// </summary>
public sealed class SetupStatus
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Whether initial setup has been completed.</summary>
    [JsonPropertyName("setupCompleted")]
    public bool SetupCompleted { get; set; }

    /// <summary>When setup was completed.</summary>
    [JsonPropertyName("completedAt")]
    public DateTime? CompletedAt { get; set; }

    /// <summary>The CA connection string configured during setup.</summary>
    [JsonPropertyName("caConnectionString")]
    public string? CaConnectionString { get; set; }

    /// <summary>Templates that were enabled during setup.</summary>
    [JsonPropertyName("enabledTemplates")]
    public List<string> EnabledTemplates { get; set; } = [];

    /// <summary>The external URL configured during setup.</summary>
    [JsonPropertyName("externalUrl")]
    public string? ExternalUrl { get; set; }

    /// <summary>
    /// The wizard step a saved draft should resume at, by step id ("url",
    /// "review"). Only meaningful while <see cref="SetupCompleted"/> is
    /// false; completion writes a fresh status without it. This is what lets
    /// the wizard continue where it was after the mid wizard restart, even
    /// when the browser has to move to a different origin (where browser
    /// storage cannot follow).
    /// </summary>
    [JsonPropertyName("wizardStep")]
    public string? WizardStep { get; set; }

    /// <summary>The file name of the wizard status file, stored next to the database.</summary>
    public const string FileName = "ducks-setup.json";

    /// <summary>
    /// The path of the wizard status file for the given options: next to the
    /// database when a database path is configured, otherwise in the data
    /// directory. Shared by <c>SetupService</c> (which writes it) and
    /// <c>EnabledTemplatesPolicy</c> (which reads it back at issuance time).
    /// </summary>
    public static string GetStatusPath(CertusOptions options)
    {
        var dir = Path.GetDirectoryName(options.DatabasePath) ?? CertusPaths.DataDirectory;
        return Path.Combine(dir, FileName);
    }

    /// <summary>Load setup status from the given file path.</summary>
    public static SetupStatus Load(string path)
    {
        if (!File.Exists(path))
            return new SetupStatus();

        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<SetupStatus>(json, JsonOptions)
                ?? new SetupStatus();
        }
        catch
        {
            return new SetupStatus();
        }
    }

    /// <summary>
    /// Save setup status to the given file path. Written to a temporary file
    /// and moved into place, like <c>SettingsOverlay.Save</c>: this file is
    /// rewritten during live operation (issue #93 external URL changes), and
    /// a torn write would make <see cref="Load"/> return an empty status,
    /// which drops the enabled template restriction and reopens the wizard.
    /// </summary>
    public void Save(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(this, JsonOptions);
        var tempPath = path + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, path, overwrite: true);
    }
}
