using System.Security.Cryptography;
using System.Text;

namespace Certus.Core.Security;

/// <summary>
/// Writes a file whole or not at all, through a temporary file no one else can name in
/// advance (issue #489).
///
/// <para>The writers this replaces staged through a fixed name, "settings.json.tmp". A
/// standard user who could create files in the folder pre-created that name and owned it.
/// File.WriteAllText then truncated their file in place, keeping its owner and DACL, and
/// File.Move renamed it over the target, so the service's own configuration file ended up
/// owned and writable by them. Here the temporary name carries 64 random bits and is
/// opened with <see cref="FileMode.CreateNew"/>, so a file that already exists under it is
/// never adopted: the write fails instead.</para>
///
/// <para>The temporary file is moved over the target, never swapped in with File.Replace.
/// A move leaves the target with the new file's own descriptor, which it inherited from
/// the folder. File.Replace keeps the replaced file's DACL and owner, which on a hijacked
/// file are the attacker's.</para>
/// </summary>
public static class AtomicFile
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>Writes <paramref name="contents"/> to <paramref name="path"/> as UTF-8 without a byte order mark.</summary>
    public static void WriteAllText(string path, string contents)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(contents);

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException($"'{path}' has no folder to write into.", nameof(path));
        var tempPath = Path.Combine(
            directory,
            $"{Path.GetFileName(fullPath)}.{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8))}.tmp");

        var created = false;
        try
        {
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                created = true;
                stream.Write(Utf8NoBom.GetBytes(contents));
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, fullPath, overwrite: true);
        }
        catch
        {
            // Only a file this call created is removed: a file that was already there
            // under the name is someone else's, and is left alone.
            if (created)
            {
                try
                {
                    File.Delete(tempPath);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Best effort: the write's own failure is the one worth reporting.
                }
            }

            throw;
        }
    }
}
