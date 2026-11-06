using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Certus.Core.Modules;

/// <summary>
/// A module's manifest, module.json, schema version 1 (licence design section 6.2, step 3). It
/// names the module, its entry assembly and type, the contract minor it was built against, and
/// every file it ships with that file's SHA-256.
/// </summary>
public sealed record ModuleManifest(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("displayName")] string DisplayName,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("entryAssembly")] string EntryAssembly,
    [property: JsonPropertyName("entryType")] string EntryType,
    [property: JsonPropertyName("contract")] string Contract,
    [property: JsonPropertyName("files")] IReadOnlyList<ModuleManifestFile> Files);

/// <summary>One file a module ships: its path, relative to the module folder, and its SHA-256.</summary>
public sealed record ModuleManifestFile(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("sha256")] string Sha256);

/// <summary>
/// The verdict of reading and checking a module.json: the manifest and the absolute entry assembly
/// path when it is sound, or a reason when it is not. A module whose manifest does not check out is
/// marked Failed before any of its code runs (design section 6.2, step 3).
/// </summary>
public sealed record ModuleManifestResult(ModuleManifest? Manifest, string? EntryAssemblyPath, string? Error)
{
    public bool IsValid => Error is null;

    public static ModuleManifestResult Invalid(string error) => new(null, null, error);

    public static ModuleManifestResult Valid(ModuleManifest manifest, string entryAssemblyPath) =>
        new(manifest, entryAssemblyPath, null);
}

/// <summary>
/// Reads and validates a module folder's manifest. It opens no assembly and runs no module code;
/// it only reads json and hashes files. Every check here fails closed: anything it cannot confirm
/// marks the module Failed.
/// </summary>
public static class ModuleManifestReader
{
    private const string FileName = "module.json";

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = false,
    };

    /// <summary>
    /// Reads <c>module.json</c> from <paramref name="moduleFolder"/> and checks it: the id equals
    /// the folder name, the entry assembly is one of the listed files, every listed file exists and
    /// matches its SHA-256, and no unlisted assembly sits in the folder.
    /// </summary>
    public static ModuleManifestResult Read(string moduleFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(moduleFolder);
        var folder = System.IO.Path.GetFullPath(moduleFolder);
        var folderName = new DirectoryInfo(folder).Name;
        var manifestPath = System.IO.Path.Combine(folder, FileName);

        if (!File.Exists(manifestPath))
            return ModuleManifestResult.Invalid($"the module folder '{folderName}' has no {FileName}");

        ModuleManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<ModuleManifest>(File.ReadAllBytes(manifestPath), Json);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return ModuleManifestResult.Invalid($"{FileName} in '{folderName}' could not be read ({ex.Message})");
        }

        if (manifest is null)
            return ModuleManifestResult.Invalid($"{FileName} in '{folderName}' is empty");

        foreach (var (value, name) in new[]
                 {
                     (manifest.Id, "id"), (manifest.Version, "version"),
                     (manifest.EntryAssembly, "entryAssembly"), (manifest.EntryType, "entryType"),
                     (manifest.Contract, "contract"),
                 })
        {
            if (string.IsNullOrWhiteSpace(value))
                return ModuleManifestResult.Invalid($"{FileName} in '{folderName}' is missing '{name}'");
        }

        if (manifest.Files is not { Count: > 0 })
            return ModuleManifestResult.Invalid($"{FileName} in '{folderName}' lists no files");

        // The id is the folder name. Folder names are case insensitive on Windows, so the compare is.
        if (!string.Equals(manifest.Id, folderName, StringComparison.OrdinalIgnoreCase))
            return ModuleManifestResult.Invalid($"the module id '{manifest.Id}' is not its folder name '{folderName}'");

        // A relative path that escapes the folder, or an absolute one, is refused outright.
        foreach (var file in manifest.Files)
        {
            if (file is null)
                return ModuleManifestResult.Invalid($"{FileName} in '{folderName}' has an empty file entry");

            if (string.IsNullOrWhiteSpace(file.Path) || string.IsNullOrWhiteSpace(file.Sha256))
                return ModuleManifestResult.Invalid($"{FileName} in '{folderName}' has a file entry missing its path or hash");

            if (!IsInsideFolder(folder, file.Path, out _))
                return ModuleManifestResult.Invalid($"'{file.Path}' in '{folderName}' is not a path inside the module folder");
        }

        // Every listed file exists and matches its hash. This is a point in time integrity check:
        // the file is read again at load, so the folder trust gate, not this hash, is what guards
        // the bytes at load time.
        foreach (var file in manifest.Files)
        {
            IsInsideFolder(folder, file.Path, out var full);
            if (!File.Exists(full))
                return ModuleManifestResult.Invalid($"'{file.Path}' listed in '{folderName}' is missing");

            string actual;
            try
            {
                actual = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(full)));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return ModuleManifestResult.Invalid($"'{file.Path}' in '{folderName}' could not be read ({ex.Message})");
            }

            if (!string.Equals(actual, file.Sha256.Trim(), StringComparison.OrdinalIgnoreCase))
                return ModuleManifestResult.Invalid($"'{file.Path}' in '{folderName}' does not match its recorded hash");
        }

        // No unlisted assembly may sit in the folder: every .dll and .exe must be listed. The scan
        // is wrapped, so a folder that cannot be read, including a Development junction the reparse
        // refusing gate did not catch under trust all, refuses rather than throwing out of Read.
        var listed = new HashSet<string>(manifest.Files.Select(f => Normalise(folder, f.Path)), StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var onDisk in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
            {
                var extension = System.IO.Path.GetExtension(onDisk);
                if (!(extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)))
                    continue;

                if (!listed.Contains(System.IO.Path.GetFullPath(onDisk)))
                    return ModuleManifestResult.Invalid($"'{System.IO.Path.GetRelativePath(folder, onDisk)}' in '{folderName}' is an assembly the manifest does not list");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ModuleManifestResult.Invalid($"the module folder '{folderName}' could not be scanned ({ex.Message})");
        }

        var entries = manifest.Files
            .Where(f => string.Equals(System.IO.Path.GetFileName(f.Path), manifest.EntryAssembly, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (entries.Count == 0)
            return ModuleManifestResult.Invalid($"the entry assembly '{manifest.EntryAssembly}' in '{folderName}' is not one of the listed files");
        if (entries.Count > 1)
            return ModuleManifestResult.Invalid($"more than one listed file is named '{manifest.EntryAssembly}' in '{folderName}'");

        return ModuleManifestResult.Valid(manifest, Normalise(folder, entries[0].Path));
    }

    private static bool IsInsideFolder(string folder, string relative, out string full)
    {
        full = string.Empty;
        if (System.IO.Path.IsPathRooted(relative))
            return false;

        var combined = System.IO.Path.GetFullPath(System.IO.Path.Combine(folder, relative));
        var root = System.IO.Path.TrimEndingDirectorySeparator(folder);
        if (!combined.StartsWith(root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            return false;

        full = combined;
        return true;
    }

    private static string Normalise(string folder, string relative) =>
        System.IO.Path.GetFullPath(System.IO.Path.Combine(folder, relative));
}
