using Certus.Core.Modules;
using Certus.Core.Tests.Security;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The licence file store (licence design section 12, issue #413): a protected folder, verbatim
/// atomic writes, one active licence and the previous one, and a hot read.
/// </summary>
public class LicenceFileStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-licstore-{Guid.NewGuid():N}");

    private static readonly byte[] LicenceA = "licence-A"u8.ToArray();
    private static readonly byte[] LicenceB = "licence-B-two"u8.ToArray();

    public LicenceFileStoreTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private LicenceFileStore NewStore(string? folder = null) => new(folder ?? Path.Combine(_root, "licence"));

    [Fact]
    public void Open_CreatesTheProtectedFolder_WhenAbsent_AndAcceptsItAfterwards()
    {
        var store = NewStore();

        store.Open().IsReady.Should().BeTrue();
        Directory.Exists(store.Folder).Should().BeTrue();

        // The folder it just created must pass its own verification.
        NewStore(store.Folder).Open().IsReady.Should().BeTrue();
    }

    [Fact]
    public void Open_RefusesAFolder_ThatGrantsAnotherAccountWrite()
    {
        var folder = Path.Combine(_root, "licence");
        Directory.CreateDirectory(folder);
        FileAcl.GrantEveryoneWriteToFolder(folder);

        var state = NewStore(folder).Open();

        state.IsReady.Should().BeFalse();
        state.RefusalReason.Should().Contain("write");
    }

    [Fact]
    public void Open_RefusesAReparsePointFolder()
    {
        var target = Path.Combine(_root, "target");
        Directory.CreateDirectory(target);
        var folder = Path.Combine(_root, "licence");
        ReparsePoints.TryCreateJunction(folder, target).Should().BeTrue("the test needs a junction to check");

        var state = NewStore(folder).Open();

        state.IsReady.Should().BeFalse();
        state.RefusalReason.Should().Contain("reparse point");
    }

    [Fact]
    public void Save_ThenReadActive_ReturnsTheBytes()
    {
        var store = NewStore();
        store.Open();

        store.Save(LicenceA);

        store.HasActive.Should().BeTrue();
        store.ReadActive().Should().Equal(LicenceA);
    }

    [Fact]
    public void Save_StoresBytesVerbatim_WithNoReEncoding()
    {
        var store = NewStore();
        store.Open();
        // A lone 0xFF and a lone 0x80 are not valid UTF-8, so a store that routed the bytes through
        // a string would turn them into U+FFFD and fail this. A verbatim byte write keeps them, as
        // verification of the exact bytes requires.
        var bytes = new byte[] { 0xEF, 0xBB, 0xBF, 0x00, 0xFF, 0x7B, 0x0A, 0xC3, 0xA9, 0x80, 0x7D };

        store.Save(bytes);

        store.ReadActive().Should().Equal(bytes);
    }

    [Fact]
    public void Save_KeepsThePrevious_AndRestoreBringsItBack()
    {
        var store = NewStore();
        store.Open();

        store.Save(LicenceA);
        store.Save(LicenceB);

        store.ReadActive().Should().Equal(LicenceB);
        store.HasPrevious.Should().BeTrue();

        store.RestorePrevious().Should().BeTrue();
        store.ReadActive().Should().Equal(LicenceA);
        store.HasPrevious.Should().BeFalse();
    }

    [Fact]
    public void DeleteActive_RemovesIt_ButKeepsItForUndo()
    {
        var store = NewStore();
        store.Open();
        store.Save(LicenceA);

        store.DeleteActive().Should().BeTrue();

        store.HasActive.Should().BeFalse();
        store.ReadActive().Should().BeNull();

        store.RestorePrevious().Should().BeTrue();
        store.ReadActive().Should().Equal(LicenceA);
    }

    [Fact]
    public void ReadActive_IsNull_WhenNoneStored_AndTheUndoVerbsDoNothing()
    {
        var store = NewStore();
        store.Open();

        store.ReadActive().Should().BeNull();
        store.RestorePrevious().Should().BeFalse();
        store.DeleteActive().Should().BeFalse();
    }

    [Fact]
    public void ReadActive_PicksUpAFileDroppedIntoTheFolder()
    {
        var store = NewStore();
        store.Open();
        store.Save(LicenceA);
        store.ReadActive().Should().Equal(LicenceA);

        // An administrator drops a different licence in by hand (group policy, a script). The
        // lengths differ, so the change is seen whatever the timestamp resolution.
        File.WriteAllBytes(Path.Combine(store.Folder, "licence.json"), LicenceB);

        store.ReadActive().Should().Equal(LicenceB);
    }

    [Fact]
    public void ReadActive_ReturnsACopy_SoACallerCannotMutateTheCache()
    {
        var store = NewStore();
        store.Open();
        store.Save(LicenceA);

        var first = store.ReadActive()!;
        first[0] ^= 0xFF;

        store.ReadActive().Should().Equal(LicenceA);
    }

    [Fact]
    public void Open_RefusesWhenAFileSitsAtTheFolderPath()
    {
        var folderPath = Path.Combine(_root, "licence");
        File.WriteAllText(folderPath, "not a folder");

        var state = NewStore(folderPath).Open();

        state.IsReady.Should().BeFalse();
        state.RefusalReason.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Save_OverAHijackedActiveFile_DropsTheForeignDacl()
    {
        var store = NewStore();
        store.Open();
        var active = Path.Combine(store.Folder, "licence.json");

        // A file a standard user planted inside the folder and made world writable (issue #489).
        File.WriteAllBytes(active, LicenceA);
        FileAcl.GrantEveryoneWrite(active);
        FileAcl.EveryoneCanWrite(active).Should().BeTrue("the fixture must start hijacked");

        store.Save(LicenceB);

        FileAcl.EveryoneCanWrite(active).Should().BeFalse();
        store.ReadActive().Should().Equal(LicenceB);
    }

    // ---- reads verify the folder (issue #523) ----

    [Fact]
    public void AnUntrustedFolder_HoldsNoLicence_ForEveryReader()
    {
        // Open verified the folder only for the API's writes; the module host read licence.json
        // through ReadActive with no check at all. Every read now asks the folder first.
        var store = NewStore();
        store.Open();
        store.Save(LicenceA);
        store.Save(LicenceB);
        FileAcl.GrantEveryoneWriteToFolder(store.Folder);

        store.ReadActive().Should().BeNull();
        store.HasActive.Should().BeFalse();
        store.HasPrevious.Should().BeFalse();
        var verdict = store.Verify();
        verdict.IsReady.Should().BeFalse();
        verdict.RefusalReason.Should().Contain("write");
    }

    [Fact]
    public void ReadActive_DoesNotServeTheCache_OnceTheFolderIsUntrusted()
    {
        var store = NewStore();
        store.Open();
        store.Save(LicenceA);
        store.ReadActive().Should().Equal(LicenceA); // cached against the file's write time and length

        FileAcl.GrantEveryoneWriteToFolder(store.Folder);

        store.ReadActive().Should().BeNull();
    }

    [Fact]
    public void AReparsePointFolder_HoldsNoLicence()
    {
        var target = Path.Combine(_root, "target");
        Directory.CreateDirectory(target);
        File.WriteAllBytes(Path.Combine(target, "licence.json"), LicenceA);
        var folder = Path.Combine(_root, "licence");
        ReparsePoints.TryCreateJunction(folder, target).Should().BeTrue("the test needs a junction to check");

        var store = NewStore(folder);

        store.ReadActive().Should().BeNull();
        store.HasActive.Should().BeFalse();
        store.Verify().RefusalReason.Should().Contain("reparse point");
    }

    [Fact]
    public void Verify_ReadsAnAbsentFolderAsReady_AndCreatesNothing()
    {
        var store = NewStore();

        store.Verify().IsReady.Should().BeTrue("there is nothing in it to believe");
        Directory.Exists(store.Folder).Should().BeFalse("only Open creates the folder");
        store.ReadActive().Should().BeNull();
    }
}
