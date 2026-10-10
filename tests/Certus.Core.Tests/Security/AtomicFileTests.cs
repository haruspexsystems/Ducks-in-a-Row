using Certus.Core.Security;

namespace Certus.Core.Tests.Security;

/// <summary>
/// The write path that replaced the fixed ".tmp" staging (issue #489).
/// </summary>
public class AtomicFileTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"certus-atomic-{Guid.NewGuid():N}");

    public AtomicFileTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void WritesTheContent_AsUtf8WithoutAMark_AndLeavesNothingBehind()
    {
        var path = Path.Combine(_dir, "settings.json");

        AtomicFile.WriteAllText(path, "{ \"é\": 1 }");

        File.ReadAllBytes(path).Should().Equal("{ \"é\": 1 }"u8.ToArray());
        Directory.GetFiles(_dir).Should().ContainSingle();
    }

    [Fact]
    public void ReplacesAnExistingFile()
    {
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, "old");

        AtomicFile.WriteAllText(path, "new");

        File.ReadAllText(path).Should().Be("new");
    }

    [Fact]
    public void APreCreatedFileUnderTheOldTemporaryName_IsNeitherUsedNorTouched()
    {
        // The hijack: the old writers staged through "<file>.tmp", truncating a file a
        // standard user had already created there and renaming it over the target.
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path + ".tmp", "planted");

        AtomicFile.WriteAllText(path, "written");

        File.ReadAllText(path).Should().Be("written");
        File.ReadAllText(path + ".tmp").Should().Be("planted");
    }

    [Fact]
    public void TheTargetDoesNotKeepTheDaclOfTheFileItReplaces()
    {
        // A hijacked target carries an entry that lets someone else write it. File.Move
        // gives the target the new file's own descriptor; File.Replace would keep the old
        // one, entry and all, and this test would fail.
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, "hijacked");
        FileAcl.GrantEveryoneWrite(path);
        TrustedFile.Check(path).IsTrusted.Should().BeFalse("the fixture must start untrusted");

        AtomicFile.WriteAllText(path, "written");

        FileAcl.EveryoneCanWrite(path).Should().BeFalse();
        TrustedFile.Check(path).IsTrusted.Should().BeTrue();
    }

    [Fact]
    public void AFailedMove_RemovesItsTemporaryFile()
    {
        // A folder where the file should be: the move fails, and the staged file must not
        // be left lying beside it.
        var path = Path.Combine(_dir, "settings.json");
        Directory.CreateDirectory(path);

        var write = () => AtomicFile.WriteAllText(path, "content");

        write.Should().Throw<Exception>().Which.Should().Match<Exception>(e => e is IOException || e is UnauthorizedAccessException);
        Directory.GetFiles(_dir).Should().BeEmpty();
    }
}
