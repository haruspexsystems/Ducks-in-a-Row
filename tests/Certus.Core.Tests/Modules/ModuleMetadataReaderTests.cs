using Certus.Core.Modules;
using Certus.Modules;
using Certus.Tests.Shared;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The metadata reference gate (licence design section 6.2, step 4): the entry assembly must
/// reference the contract at a version the core can satisfy, and every assembly the module ships may
/// reference only the contract, its own listed assemblies and the shared framework (issue #538). It
/// reads metadata and executes nothing. Most fixtures are emitted by <see cref="ModuleAssemblyBuilder"/>
/// with exactly the references a case needs; a few real assemblies serve where the real shape is the
/// point: the contract references no contract, this test assembly references Certus.Core, and
/// Certus.Core references the service's own dependencies.
/// </summary>
public class ModuleMetadataReaderTests : IDisposable
{
    private static readonly Version CoreContract =
        typeof(ICertusModule).Assembly.GetName().Version!;

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-meta-{Guid.NewGuid():N}");

    public ModuleMetadataReaderTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private string Write(string fileName, byte[] image)
    {
        var path = Path.Combine(_root, fileName);
        File.WriteAllBytes(path, image);
        return path;
    }

    [Fact]
    public void AnAssemblyThatReferencesOnlyTheContractAndTheFramework_Passes()
    {
        var path = Write("paid.dll", ModuleAssemblyBuilder.Module());

        var result = ModuleMetadataReader.Check(path, CoreContract);

        result.IsOk.Should().BeTrue(result.Error);
        result.ContractVersion!.Major.Should().Be(CoreContract.Major);
    }

    [Fact]
    public void AnAssemblyThatDoesNotReferenceTheContract_IsRefused()
    {
        var path = typeof(ICertusModule).Assembly.Location; // the contract itself references no contract

        var result = ModuleMetadataReader.Check(path, CoreContract);

        result.IsOk.Should().BeFalse();
        result.IsIncompatible.Should().BeFalse("an assembly that is no module at all is Failed, not built for another contract");
        result.Error.Should().Contain("does not reference");
    }

    [Fact]
    public void AnAssemblyThatReferencesACoreAssembly_IsRefused()
    {
        var path = typeof(ModuleMetadataReaderTests).Assembly.Location; // the test assembly references Certus.Core

        var result = ModuleMetadataReader.Check(path, CoreContract);

        result.IsOk.Should().BeFalse();
        result.IsIncompatible.Should().BeFalse();
        result.Error.Should().Contain("Certus.Core").And.Contain("only the contract may do");
    }

    [Fact]
    public void AModuleThatNeedsANewerContractMajor_IsRefused_AsIncompatible_KeepingItsVersion()
    {
        var path = Write("paid.dll", ModuleAssemblyBuilder.Module(contract: new Version(2, 0, 0, 0)));

        var result = ModuleMetadataReader.Check(path, CoreContract);

        result.IsOk.Should().BeFalse();
        result.Error.Should().Contain("major");

        // Issue #493: the Settings card names the version the module was built for.
        result.IsIncompatible.Should().BeTrue();
        result.ContractVersion.Should().Be(new Version(2, 0, 0, 0));
    }

    [Fact]
    public void AModuleThatNeedsANewerContractMinor_IsRefused_AsIncompatible_KeepingItsVersion()
    {
        var newerMinor = new Version(CoreContract.Major, CoreContract.Minor + 3, 0, 0);
        var path = Write("paid.dll", ModuleAssemblyBuilder.Module(contract: newerMinor));

        var result = ModuleMetadataReader.Check(path, CoreContract);

        result.IsOk.Should().BeFalse();
        result.Error.Should().Contain("newer than the core's");
        result.IsIncompatible.Should().BeTrue();
        result.ContractVersion.Should().Be(newerMinor);
    }

    [Fact]
    public void AModuleThatReferencesAnAssemblyItDoesNotShip_IsRefused_ThoughTheCoreCarriesIt()
    {
        // Issue #538: the default context holds the service's own BouncyCastle, so a module whose
        // publish missed its own copy would once have verified with the core's. The core really does
        // carry it, which is what makes the case worth refusing.
        typeof(Org.BouncyCastle.Asn1.Asn1Object).Assembly.GetName().Name.Should().Be("BouncyCastle.Cryptography");
        var path = Write("paid.dll", ModuleAssemblyBuilder.Module(alsoReferences: ["BouncyCastle.Cryptography"]));

        var result = ModuleMetadataReader.Check(path, CoreContract);

        result.IsOk.Should().BeFalse();
        result.IsIncompatible.Should().BeFalse();
        result.Error.Should().Contain("BouncyCastle.Cryptography")
            .And.Contain("neither one of its own listed files nor part of the shared framework");
    }

    [Fact]
    public void TheCoresOwnAssembly_IsRefused_ForReferencingTheServicesDependencies()
    {
        // Certus.Core references the contract and none of the four forbidden names, which is why the
        // tests once used it as a stand in module. It does reference EF Core, Serilog and the rest of
        // the service's dependencies, and those are what the allow list exists to keep out.
        var result = ModuleMetadataReader.Check(typeof(ModuleLoader).Assembly.Location, CoreContract);

        result.IsOk.Should().BeFalse();
        result.Error.Should().Contain("neither one of its own listed files nor part of the shared framework");
    }

    [Fact]
    public void AnAssemblyTheModuleShips_IsAllowed_AndItsOwnReferencesAreChecked()
    {
        var entry = Write("paid.dll", ModuleAssemblyBuilder.Module(alsoReferences: ["BouncyCastle.Cryptography"]));
        var shipped = Write("bc.dll", ModuleAssemblyBuilder.Build("BouncyCastle.Cryptography", [ModuleAssemblyBuilder.SystemRuntime]));

        var result = ModuleMetadataReader.CheckModule(entry, [entry, shipped], CoreContract);

        result.IsOk.Should().BeTrue(result.Error);
    }

    [Fact]
    public void AShippedAssemblyThatReferencesSomethingNotShipped_IsRefused_ByItsFileName()
    {
        var entry = Write("paid.dll", ModuleAssemblyBuilder.Module(alsoReferences: ["Helper"]));
        var helper = Write("helper.dll", ModuleAssemblyBuilder.Build("Helper", [ModuleAssemblyBuilder.SystemRuntime, ("Serilog", new Version(4, 0, 0, 0))]));

        var result = ModuleMetadataReader.CheckModule(entry, [entry, helper], CoreContract);

        result.IsOk.Should().BeFalse();
        result.Error.Should().Contain("'helper.dll' references Serilog");
    }

    [Fact]
    public void AShippedAssemblyThatReferencesCore_IsRefused()
    {
        var entry = Write("paid.dll", ModuleAssemblyBuilder.Module());
        var helper = Write("helper.dll", File.ReadAllBytes(typeof(ModuleMetadataReaderTests).Assembly.Location)); // references Certus.Core

        var result = ModuleMetadataReader.CheckModule(entry, [entry, helper], CoreContract);

        result.IsOk.Should().BeFalse();
        result.Error.Should().Contain("'helper.dll' references Certus.Core");
    }

    [Fact]
    public void AListedDataFileThatIsNotAPeImage_Passes()
    {
        // Every published module lists its deps.json and runtimeconfig.json. Before the fix the PE
        // reader threw on them, outside any catch, and no real module could load.
        var entry = Write("paid.dll", ModuleAssemblyBuilder.Module());
        var deps = Path.Combine(_root, "paid.deps.json");
        File.WriteAllText(deps, "{\"runtimeTarget\":{\"name\":\".NETCoreApp,Version=v10.0\"}}");

        var result = ModuleMetadataReader.CheckModule(entry, [entry, deps], CoreContract);

        result.IsOk.Should().BeTrue(result.Error);
    }

    [Fact]
    public void Check_RefusesAnEntryThatIsNotAPeImage_RatherThanThrowing()
    {
        var path = Path.Combine(_root, "paid.dll");
        File.WriteAllText(path, "not an assembly");

        var result = ModuleMetadataReader.Check(path, CoreContract);

        result.IsOk.Should().BeFalse();
        result.Error.Should().Contain("no managed metadata");
    }
}
