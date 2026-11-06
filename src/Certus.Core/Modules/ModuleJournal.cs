using System.Text.Json;
using System.Text.Json.Serialization;
using Certus.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Certus.Core.Modules;

/// <summary>
/// The core owned record of a module's load attempts, at %DataDirectory%\modules\journal.json
/// (licence design section 6.4, issue #413). It bounds the cost of a module that kills the
/// process: two "attempting" entries for one id and version with no "healthy" one between them
/// quarantine that version, until the version changes or an administrator presses Retry.
///
/// <para>The strike rule is pure and unit tested on its own. The file is written through
/// <see cref="AtomicFile"/> into the protected modules folder. A journal that cannot be read is
/// treated as empty, because it is operational state and a lost history only costs one more
/// attempt before the count rebuilds.</para>
///
/// <para>Whoever can write the journal decides whether the module is quarantined: they could
/// switch paid features off, or keep clearing the strikes and undo the crash bound. So the modules
/// folder and the file are both verified with <see cref="FolderTrust.CheckDataPath"/> before
/// every read, and a journal that is not trusted reads as absent, with the reason logged once
/// (issue #523). Nothing is written into a modules folder that is not trusted, since its owner
/// could rewrite whatever lands there. An untrusted file in a trusted folder is simply replaced
/// at the next write, which is how the journal recovers.</para>
///
/// <para>It assumes a single writer. Each read, add and clear is serialised by this instance's
/// lock, which suffices because the module host owns one instance and makes one module call at a
/// time (section 6.4). The whole file is rewritten on each change, so two writers over the same
/// path, two instances or two hosts, could lose an entry; nothing today creates that, and a
/// cross-process journal would need an external lock.</para>
/// </summary>
public sealed class ModuleJournal
{
    private const string FileName = "journal.json";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
    };

    private readonly string _folder;
    private readonly string _path;
    private readonly ILogger _logger;
    private readonly object _gate = new();

    // The distrust last logged, so one cause is logged once rather than at every read and write.
    private string? _reported;

    public ModuleJournal(string modulesFolder, ILogger<ModuleJournal>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(modulesFolder);
        _folder = Path.GetFullPath(modulesFolder);
        _path = Path.Combine(_folder, FileName);
        _logger = logger ?? NullLogger<ModuleJournal>.Instance;
    }

    /// <summary>The journal file this instance owns.</summary>
    public string JournalPath => _path;

    /// <summary>Records that a load of <paramref name="id"/> at <paramref name="version"/> is being attempted.</summary>
    public void RecordAttempt(string id, string version, DateTimeOffset at) =>
        Append(new ModuleJournalEntry(ModuleJournalEntry.Attempting, Require(id), Require(version), at));

    /// <summary>Records that <paramref name="id"/> at <paramref name="version"/> has run healthily.</summary>
    public void RecordHealthy(string id, string version, DateTimeOffset at) =>
        Append(new ModuleJournalEntry(ModuleJournalEntry.Healthy, Require(id), Require(version), at));

    /// <summary>
    /// Records that <paramref name="id"/> at <paramref name="version"/> was refused before any of
    /// its code ran, with <paramref name="reason"/> (issue #636, a signature that did not verify).
    /// A refusal is a record, not a strike: it neither counts towards a quarantine nor clears one,
    /// so <see cref="IsQuarantined(IReadOnlyList{ModuleJournalEntry}, string, string)"/> ignores it.
    /// </summary>
    public void RecordRefusal(string id, string version, DateTimeOffset at, string reason) =>
        Append(new ModuleJournalEntry(ModuleJournalEntry.Refused, Require(id), Require(version), at) { Reason = Require(reason) });

    /// <summary>
    /// Whether <paramref name="id"/> at <paramref name="version"/> is quarantined: two or more
    /// attempts since its last healthy entry, or since the start if it has never been healthy at
    /// this version. A different version is judged on its own entries, so a new version is never
    /// born quarantined.
    /// </summary>
    public bool IsQuarantined(string id, string version)
    {
        lock (_gate)
            return IsQuarantined(Load(), id, version);
    }

    /// <summary>The pure strike rule, over a list of entries.</summary>
    public static bool IsQuarantined(IReadOnlyList<ModuleJournalEntry> entries, string id, string version)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);

        var attempts = 0;
        foreach (var entry in entries)
        {
            if (!Same(entry.Id, id) || !Same(entry.Version, version))
                continue;

            if (entry.Kind == ModuleJournalEntry.Healthy)
                attempts = 0;
            else if (entry.Kind == ModuleJournalEntry.Attempting)
                attempts++;
        }

        return attempts >= 2;
    }

    /// <summary>Clears every entry for <paramref name="id"/>, which is what Retry does.</summary>
    public void ClearModule(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        lock (_gate)
        {
            var kept = Load().Where(entry => !Same(entry.Id, id)).ToList();
            Save(kept);
        }
    }

    /// <summary>The entries as stored, oldest first. Empty when the journal is absent or unreadable.</summary>
    public IReadOnlyList<ModuleJournalEntry> Entries()
    {
        lock (_gate)
            return Load();
    }

    private void Append(ModuleJournalEntry entry)
    {
        lock (_gate)
        {
            var entries = Load();
            entries.Add(entry);
            Save(entries);
        }
    }

    private List<ModuleJournalEntry> Load()
    {
        if (Distrust(includeFile: true) is { } reason)
        {
            Report(reason);
            return [];
        }

        _reported = null;
        if (!File.Exists(_path))
            return [];

        try
        {
            var bytes = File.ReadAllBytes(_path);
            return JsonSerializer.Deserialize<List<ModuleJournalEntry>>(bytes, Json) ?? [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // A history that is lost, corrupt, or unreadable (a file an attacker planted and locked
            // down, the #489 case) reads as empty, and the count rebuilds from the next attempt.
            // UnauthorizedAccessException is not an IOException, so it has to be named, or an
            // unreadable journal would fault module loading rather than fall back to empty.
            return [];
        }
    }

    private void Save(List<ModuleJournalEntry> entries)
    {
        ProtectedFolder.EnsureExists(_folder);

        // Only the folder decides whether to write. An untrusted file in a trusted folder is
        // replaced by this write, since AtomicFile moves a fresh file over it.
        if (Distrust(includeFile: false) is { } reason)
        {
            Report(reason);
            return;
        }

        AtomicFile.WriteAllText(_path, JsonSerializer.Serialize(entries, Json));
    }

    /// <summary>
    /// Why the journal may not be believed, or null when it may: the modules folder, when it
    /// exists, and with <paramref name="includeFile"/> the journal file, when it exists, must each
    /// pass <see cref="FolderTrust.CheckDataPath"/>. What does not exist holds nothing to believe.
    /// </summary>
    private string? Distrust(bool includeFile)
    {
        if (Directory.Exists(_folder) && FolderTrust.CheckDataPath(_folder) is { IsTrusted: false } folder)
            return $"the modules folder is not trusted: {folder.Reason}";

        if (includeFile && File.Exists(_path) && FolderTrust.CheckDataPath(_path) is { IsTrusted: false } file)
            return $"the journal file is not trusted: {file.Reason}";

        return null;
    }

    private void Report(string reason)
    {
        if (string.Equals(reason, _reported, StringComparison.Ordinal))
            return;

        _reported = reason;
        _logger.LogError("The module load journal {Path} is treated as absent: {Reason}", _path, reason);
    }

    private static string Require(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.Ordinal);
}

/// <summary>One line of the module journal: a kind, the module id and version, when, and for a refusal why.</summary>
public sealed record ModuleJournalEntry(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("at")] DateTimeOffset At)
{
    public const string Attempting = "attempting";
    public const string Healthy = "healthy";
    public const string Refused = "refused";

    /// <summary>Why a <see cref="Refused"/> entry was written; null for the other kinds.</summary>
    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; init; }
}
