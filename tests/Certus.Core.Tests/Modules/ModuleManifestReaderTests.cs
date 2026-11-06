using Certus.Core.Modules;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The manifest check (licence design section 6.2, step 3): the id is the folder name, every listed
/// file exists and matches its SHA-256, no unlisted assembly sits in the folder, and the entry
/// assembly is one of the listed files. Anything it cannot confirm marks the module Failed.
/// </summary>
public class ModuleManifestReaderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-manifest-{Guid.NewGuid():N}");

    public ModuleManifestReaderTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private string MakeModule(string id)
    {
        var folder = Path.Combine(_root, id);
        Directory.CreateDirectory(folder);
        return folder;
    }

    [Fact]
    public void AWellFormedManifest_IsValid()
    {
        var folder = MakeModule("paid");
        var dll = ModuleFolders.WriteFile(folder, "Haruspex.Ducks.Paid.dll", [1, 2, 3, 4]);
        ModuleFolders.WriteManifest(folder, "paid", "Haruspex.Ducks.Paid.dll", "Haruspex.Ducks.Paid.Module", "1.0",
            [("Haruspex.Ducks.Paid.dll", ModuleFolders.Sha(dll))]);

        var result = ModuleManifestReader.Read(folder);

        result.IsValid.Should().BeTrue(result.Error);
        result.Manifest!.Id.Should().Be("paid");
        result.EntryAssemblyPath.Should().Be(Path.Combine(folder, "Haruspex.Ducks.Paid.dll"));
    }

    [Fact]
    public void AnIdThatIsNotTheFolderName_IsRefused()
    {
        var folder = MakeModule("paid");
        var dll = ModuleFolders.WriteFile(folder, "entry.dll", [1]);
        ModuleFolders.WriteManifest(folder, "other", "entry.dll", "T", "1.0", [("entry.dll", ModuleFolders.Sha(dll))]);

        ModuleManifestReader.Read(folder).IsValid.Should().BeFalse();
    }

    [Fact]
    public void AMissingListedFile_IsRefused()
    {
        var folder = MakeModule("paid");
        ModuleFolders.WriteManifest(folder, "paid", "entry.dll", "T", "1.0", [("entry.dll", new string('a', 64))]);

        ModuleManifestReader.Read(folder).IsValid.Should().BeFalse();
    }

    [Fact]
    public void AFileWhoseHashDoesNotMatch_IsRefused()
    {
        var folder = MakeModule("paid");
        ModuleFolders.WriteFile(folder, "entry.dll", [1, 2, 3]);
        ModuleFolders.WriteManifest(folder, "paid", "entry.dll", "T", "1.0",
            [("entry.dll", ModuleFolders.Sha([9, 9, 9]))]); // the wrong hash

        ModuleManifestReader.Read(folder).IsValid.Should().BeFalse();
    }

    [Fact]
    public void AnUnlistedAssemblyInTheFolder_IsRefused()
    {
        var folder = MakeModule("paid");
        var dll = ModuleFolders.WriteFile(folder, "entry.dll", [1]);
        ModuleFolders.WriteFile(folder, "sneaky.dll", [2]); // present but not listed
        ModuleFolders.WriteManifest(folder, "paid", "entry.dll", "T", "1.0", [("entry.dll", ModuleFolders.Sha(dll))]);

        ModuleManifestReader.Read(folder).IsValid.Should().BeFalse();
    }

    [Fact]
    public void AnEntryAssemblyThatIsNotListed_IsRefused()
    {
        var folder = MakeModule("paid");
        var dll = ModuleFolders.WriteFile(folder, "lib.dll", [1]);
        ModuleFolders.WriteManifest(folder, "paid", "entry.dll", "T", "1.0", [("lib.dll", ModuleFolders.Sha(dll))]);

        ModuleManifestReader.Read(folder).IsValid.Should().BeFalse();
    }

    [Fact]
    public void NoManifest_IsRefused()
    {
        var folder = MakeModule("paid");

        ModuleManifestReader.Read(folder).IsValid.Should().BeFalse();
    }
}
