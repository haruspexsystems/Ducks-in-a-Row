using Certus.Core.Security;

namespace Certus.Core.Modules;

/// <summary>
/// The licence file store: one active licence and the previous one, in the protected folder
/// %DataDirectory%\licence\ (licence design section 12, issue #413). The core keeps the bytes and
/// never reads their meaning; the module verifies them.
///
/// <para>The folder path comes from the caller, which resolves it through
/// <see cref="Certus.Core.Configuration.CertusDataDirectory"/>, so a development host or a test
/// keeps the store out of the machine's real data directory.</para>
///
/// <para>Writes go through <see cref="AtomicFile.WriteAllBytes"/>, never File.Replace. The design
/// first wrote File.Replace, but issue #489 showed that keeps a hijacked target's owner and DACL,
/// so a move over the target is the one safe swap. The bytes are stored verbatim, because
/// verification later weighs the exact bytes.</para>
/// </summary>
public sealed class LicenceFileStore
{
    private const string ActiveName = "licence.json";
    private const string PreviousName = "licence.previous.json";

    private readonly string _folder;
    private readonly string _activePath;
    private readonly string _previousPath;
    private readonly object _gate = new();

    private bool _loaded;
    private byte[]? _active;
    private long _activeWriteTicks;
    private long _activeLength;

    public LicenceFileStore(string licenceFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(licenceFolder);
        _folder = Path.GetFullPath(licenceFolder);
        _activePath = Path.Combine(_folder, ActiveName);
        _previousPath = Path.Combine(_folder, PreviousName);
    }

    /// <summary>The licence folder this store owns.</summary>
    public string Folder => _folder;

    /// <summary>Whether an active licence is stored in a folder that may be believed (see <see cref="Verify"/>).</summary>
    public bool HasActive => Verify().IsReady && File.Exists(_activePath);

    /// <summary>Whether a previous licence is kept for undo, in a folder that may be believed (see <see cref="Verify"/>).</summary>
    public bool HasPrevious => Verify().IsReady && File.Exists(_previousPath);

    /// <summary>
    /// Readies the folder. An absent folder is created with the protected DACL (SYSTEM,
    /// Administrators and this process, no one else). The folder is then verified either way, so a
    /// folder that already existed, or one a race planted between the existence check and the
    /// create, is checked rather than trusted blindly. It is verified and never repaired: resetting
    /// a planted junction's DACL would itself be an escalation (section 12.3). A folder that is a
    /// reparse point, is owned by anyone else, or grants write to anyone else is refused, and the
    /// card tells an administrator to delete it so the service can recreate it. A folder that
    /// cannot be created (a file already sits at the path, or access is denied) is refused rather
    /// than thrown out of.
    /// </summary>
    public LicenceStoreState Open()
    {
        try
        {
            ProtectedFolder.EnsureExists(_folder);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return LicenceStoreState.Refused($"the licence folder could not be created ({ex.Message})");
        }

        return Verify();
    }

    /// <summary>
    /// The folder's verdict, without creating anything (licence design section 12.3, issue #523).
    /// An absent folder holds nothing to believe and reads as ready; <see cref="Open"/> creates it
    /// before the first write. An existing folder must pass <see cref="FolderTrust.CheckDataPath"/>.
    /// Every read asks this first, so a licence in a folder that is not trusted reaches neither the
    /// module nor the API: it reads as no licence, whatever files sit in the folder. The licence
    /// file itself is not checked, because section 12.5 lets an administrator drop one in by hand,
    /// and a file copied from their own profile keeps that profile as its owner.
    /// </summary>
    public LicenceStoreState Verify()
    {
        if (!Directory.Exists(_folder))
            return LicenceStoreState.Ready;

        var trust = FolderTrust.CheckDataPath(_folder);
        return trust.IsTrusted
            ? LicenceStoreState.Ready
            : LicenceStoreState.Refused(trust.Reason ?? "the licence folder is not trusted");
    }

    /// <summary>
    /// The active licence bytes, or null when none is stored or the folder is not trusted. Hot: it
    /// re-reads only when the file's last write time or length has changed, the pattern of
    /// EabEnforcementPolicy, so an administrator dropping a file into the folder is picked up. The
    /// file's metadata is sampled inside the lock, so the cached key always describes the cached
    /// bytes, and a transient read failure keeps the last known bytes for the call rather than
    /// caching an absence.
    /// </summary>
    public byte[]? ReadActive()
    {
        lock (_gate)
        {
            // The folder is asked on every read, not once at start, so a folder that stops being
            // trusted stops being read at once. The cache goes too, so bytes read while it was
            // trusted are never served from it afterwards.
            if (!Verify().IsReady)
            {
                Invalidate();
                return null;
            }

            if (!File.Exists(_activePath))
            {
                _loaded = true;
                _active = null;
                _activeWriteTicks = 0;
                _activeLength = 0;
                return null;
            }

            long writeTicks;
            long length;
            try
            {
                writeTicks = File.GetLastWriteTimeUtc(_activePath).Ticks;
                length = new FileInfo(_activePath).Length;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return Copy(_active);
            }

            if (_loaded && _active is not null && writeTicks == _activeWriteTicks && length == _activeLength)
                return Copy(_active);

            try
            {
                var bytes = File.ReadAllBytes(_activePath);
                _active = bytes;
                _activeWriteTicks = writeTicks;
                _activeLength = length;
                _loaded = true;
                return Copy(bytes);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A transient lock or a torn write: keep the last known bytes for this call and
                // retry on the next, rather than caching an absence against the new write time.
                return Copy(_active);
            }
        }
    }

    /// <summary>
    /// Stores <paramref name="bytes"/> as the active licence, keeping the one it replaces, if any,
    /// as the previous licence for undo. The new active is committed first; only once it is on disk
    /// is the old one rolled into the previous slot, so a write that fails never destroys the undo
    /// target without having installed the replacement.
    /// </summary>
    public void Save(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        lock (_gate)
        {
            ProtectedFolder.EnsureExists(_folder);
            var prior = File.Exists(_activePath) ? File.ReadAllBytes(_activePath) : null;

            AtomicFile.WriteAllBytes(_activePath, bytes);
            if (prior is not null)
                AtomicFile.WriteAllBytes(_previousPath, prior);

            Invalidate();
        }
    }

    /// <summary>
    /// Removes the active licence, keeping it as the previous one so the removal can be undone. The
    /// active is removed first; a removal that fails leaves the previous slot untouched. Returns
    /// false when there is no active licence.
    /// </summary>
    public bool DeleteActive()
    {
        lock (_gate)
        {
            if (!File.Exists(_activePath))
                return false;

            var removed = File.ReadAllBytes(_activePath);
            File.Delete(_activePath);
            AtomicFile.WriteAllBytes(_previousPath, removed);
            Invalidate();
            return true;
        }
    }

    /// <summary>
    /// Restores the previous licence as the active one, undoing the last replacement or removal.
    /// Returns false when there is no previous licence to restore.
    /// </summary>
    public bool RestorePrevious()
    {
        lock (_gate)
        {
            if (!File.Exists(_previousPath))
                return false;

            AtomicFile.WriteAllBytes(_activePath, File.ReadAllBytes(_previousPath));
            File.Delete(_previousPath);
            Invalidate();
            return true;
        }
    }

    private void Invalidate()
    {
        _loaded = false;
        _active = null;
        _activeWriteTicks = 0;
        _activeLength = 0;
    }

    private static byte[]? Copy(byte[]? source) => source is null ? null : (byte[])source.Clone();
}

/// <summary>What <see cref="LicenceFileStore.Open"/> decided: ready to use, or refused with why.</summary>
public sealed record LicenceStoreState(bool IsReady, string? RefusalReason)
{
    public static LicenceStoreState Ready { get; } = new(true, null);

    public static LicenceStoreState Refused(string reason) => new(false, reason);
}
