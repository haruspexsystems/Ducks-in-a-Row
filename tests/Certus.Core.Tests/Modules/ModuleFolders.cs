using System.Security.Cryptography;

namespace Certus.Core.Tests.Modules;

/// <summary>Builds module folders and manifests for the loader tests.</summary>
internal static class ModuleFolders
{
    public static string Sha(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    public static byte[] WriteFile(string folder, string relativePath, byte[] contents)
    {
        var full = Path.Combine(folder, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, contents);
        return contents;
    }

    /// <summary>Writes a module.json by hand, so the test controls every field independently of the reader.</summary>
    public static void WriteManifest(
        string folder,
        string id,
        string entryAssembly,
        string entryType,
        string contract,
        IEnumerable<(string Path, string Sha256)> files)
    {
        var fileEntries = string.Join(",", files.Select(f =>
            $"{{\"path\":\"{f.Path.Replace("\\", "\\\\")}\",\"sha256\":\"{f.Sha256}\"}}"));
        var json =
            $"{{\"id\":\"{id}\",\"displayName\":\"Sample\",\"version\":\"1.0.0\"," +
            $"\"entryAssembly\":\"{entryAssembly}\",\"entryType\":\"{entryType}\"," +
            $"\"contract\":\"{contract}\",\"files\":[{fileEntries}]}}";
        File.WriteAllText(Path.Combine(folder, "module.json"), json);
    }
}
