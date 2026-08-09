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

    /// <summary>
    /// Whether certificate issuance is restricted to <see cref="AllowedDomains"/>.
    /// A file written before this field existed deserializes to false, so an
    /// upgraded install stays unrestricted until an administrator opts in.
    /// </summary>
    [JsonPropertyName("allowedDomainsEnabled")]
    public bool AllowedDomainsEnabled { get; set; }

    /// <summary>
    /// The allowed domain list. Each entry covers the domain itself and all
    /// of its subdomains; see <c>AllowedDomainsPolicy</c> for the matching
    /// rules and for how the list is read back at issuance time.
    /// </summary>
    [JsonPropertyName("allowedDomains")]
    public List<string> AllowedDomains { get; set; } = [];

    /// <summary>
    /// External account binding enforcement mode: "off", "optional", or
    /// "required" (RFC 8555 §7.3.4). A file written before this field existed
    /// deserializes to null, which reads as off, so an upgraded install stays
    /// unenforced until an administrator opts in. Read back at ACME time by
    /// <c>EabEnforcementPolicy</c>.
    /// </summary>
    [JsonPropertyName("eabEnforcement")]
    public string? EabEnforcement { get; set; }

    /// <summary>
    /// Dashboard revocation scope mode: "ducks-managed", "custom", or "all".
    /// A file written before this field existed deserializes to null, which
    /// reads as ducks-managed, the safe default. Read back at revocation
    /// time by <c>RevocationScopePolicy</c>; the TLS capability ceiling
    /// applies above every mode.
    /// </summary>
    [JsonPropertyName("revocationScope")]
    public string? RevocationScope { get; set; }

    /// <summary>
    /// The administrator selected template names for the custom revocation
    /// scope. Meaningful only while <see cref="RevocationScope"/> is
    /// "custom", but kept across mode switches so toggling away and back
    /// does not lose the list.
    /// </summary>
    [JsonPropertyName("revocableTemplates")]
    public List<string> RevocableTemplates { get; set; } = [];

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

    /// <summary>
    /// Load setup status from the given file path. Failures read as an empty
    /// status; callers that need to tell a failure from a missing file use
    /// <see cref="TryLoad"/>.
    /// </summary>
    public static SetupStatus Load(string path)
    {
        TryLoad(path, out var status);
        return status;
    }

    /// <summary>
    /// Load the status, reporting failure instead of swallowing it. A
    /// missing file is a legitimate empty state and reads as success; false
    /// means the file exists but could not be read or parsed right now (a
    /// transient lock, a torn write), so the caller can decide whether the
    /// last known state beats an empty one. AllowedDomainsPolicy relies on
    /// this to avoid caching a fail open decision off a momentary read
    /// failure.
    /// </summary>
    public static bool TryLoad(string path, out SetupStatus status)
    {
        status = new SetupStatus();
        if (!File.Exists(path))
            return true;

        try
        {
            var json = File.ReadAllText(path);
            status = JsonSerializer.Deserialize<SetupStatus>(json, JsonOptions)
                ?? new SetupStatus();
            return true;
        }
        catch
        {
            status = new SetupStatus();
            return false;
        }
    }

    /// <summary>
    /// Save setup status to the given file path. Written to a temporary file
    /// and moved into place, like <c>SettingsOverlay.Save</c>: this file is
    /// rewritten during live operation (issue #93 external URL changes), and
    /// a torn write would make <see cref="Load"/> return an empty status,
    /// which reopens the wizard. The ACME template policy reads through
    /// <see cref="TryLoad"/> and fails closed (issue #101), so a torn write
    /// narrows template exposure rather than widening it.
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
