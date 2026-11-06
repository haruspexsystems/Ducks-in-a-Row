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
///
/// <para>The move is tried again, a few times, when the target is briefly held open (issue
/// #420). While anything holds the target open the rename fails with access denied, and
/// the product's own readers do hold it: the ACME policies re-read the status file through
/// <c>SetupStatus.TryLoad</c> whenever its write time moves, which is right after a save,
/// so the next save can land in the middle of that read. An antivirus or indexer scanning
/// a file that was just written does the same. Opening the readers with
/// <see cref="FileShare.Delete"/> would not help: measured on Server 2025 on 2026-10-15,
/// the move failed with access denied under every share mode a reader could choose,
/// Delete included. Only the move is retried. The temporary file is created once, and
/// stays where it is between attempts because it is what the move renames.</para>
/// </summary>
public static class AtomicFile
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>
    /// How many times the move is tried in all before its failure is reported. With the
    /// waits from <see cref="MoveRetryDelay"/> that is 750 ms at most for each write, which
    /// matters because several callers wait out the retry holding an in process lock, and
    /// some of them on a request thread (<c>SettingsOverlay.Mutate</c>, <c>SetupService</c>'s
    /// status file lock). A caller making two writes under one lock, as
    /// <c>LicenceFileStore.Save</c> does, can wait twice that.
    /// </summary>
    internal const int MoveAttempts = 5;

    /// <summary>ERROR_SHARING_VIOLATION (32) as the HRESULT .NET puts on the IOException.</summary>
    private const int SharingViolationHResult = unchecked((int)0x80070020);

    /// <summary>Writes <paramref name="contents"/> to <paramref name="path"/> as UTF-8 without a byte order mark.</summary>
    public static void WriteAllText(string path, string contents)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(contents);
        WriteAllBytes(path, Utf8NoBom.GetBytes(contents));
    }

    /// <summary>
    /// Writes <paramref name="contents"/> to <paramref name="path"/> whole or not at all, through
    /// the same unpredictable temporary name and move as <see cref="WriteAllText"/>. The licence
    /// store writes the uploaded licence bytes verbatim through this, so no re-encoding can move a
    /// byte that verification would later weigh (issue #413).
    /// </summary>
    public static void WriteAllBytes(string path, byte[] contents)
        => WriteAllBytes(path, contents, MoveAttempts, static retry => Thread.Sleep(MoveRetryDelay(retry)));

    /// <summary>
    /// The write with its retry spelled out, so a test can hold the target open and let go of it
    /// from <paramref name="waitBeforeRetry"/> rather than racing a clock. The callback receives
    /// the number of the retry about to run, counting from 1, and is never called before the
    /// first attempt or after the last.
    /// </summary>
    internal static void WriteAllBytes(string path, byte[] contents, int moveAttempts, Action<int> waitBeforeRetry)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(contents);
        ArgumentOutOfRangeException.ThrowIfLessThan(moveAttempts, 1);
        ArgumentNullException.ThrowIfNull(waitBeforeRetry);

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
                stream.Write(contents);
                stream.Flush(flushToDisk: true);
            }

            MoveOverTarget(tempPath, fullPath, moveAttempts, waitBeforeRetry);
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

    /// <summary>
    /// Whether a failed move is worth another attempt. Access denied is what a reader holding
    /// the target produces, and a sharing violation is what a scanner holding the temporary file
    /// without sharing delete produces. Anything else is reported at once. A failure that is
    /// lasting, such as a folder standing where the file should be, also reads as access denied,
    /// and costs the full 750 ms before it is reported, which is the price of not being able to
    /// tell the two apart.
    /// </summary>
    internal static bool IsTransientMoveFailure(Exception ex) =>
        ex is UnauthorizedAccessException
        || (ex is IOException && ex.HResult == SharingViolationHResult);

    /// <summary>The wait before retry <paramref name="retry"/>, counting from 1: 50, 100, 200 and 400 ms.</summary>
    internal static TimeSpan MoveRetryDelay(int retry)
    {
        // Guarded because C# masks a shift count to its low five bits, so a number outside the
        // schedule does not fail on its own: retry 0 shifts by 31 and overflows to a wait of
        // 0 ms, a negative retry to a negative wait, and retry 5 adds 800 ms, breaking the one
        // second bound.
        ArgumentOutOfRangeException.ThrowIfLessThan(retry, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(retry, MoveAttempts - 1);
        return TimeSpan.FromMilliseconds(50 << (retry - 1));
    }

    private static void MoveOverTarget(string tempPath, string fullPath, int moveAttempts, Action<int> waitBeforeRetry)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(tempPath, fullPath, overwrite: true);
                return;
            }
            catch (Exception ex) when (attempt < moveAttempts && IsTransientMoveFailure(ex))
            {
                waitBeforeRetry(attempt);
            }
        }
    }
}
