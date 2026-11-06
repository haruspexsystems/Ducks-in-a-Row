using Certus.Core.Modules;
using Certus.Modules;
using Certus.Tests.Shared;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// Discovery and validation, the load-path steps that open no module and run no module code
/// (licence design section 6.2, steps 1 to 4). The entry assembly is emitted by
/// <see cref="ModuleAssemblyBuilder"/>: it is not a real module, but it references the contract and
/// the framework and nothing else, which is all the metadata gate reads. The signature tests sign
/// it with the suite's own chain (<see cref="SignatureFixture"/>) under a policy that trusts that
/// chain; the production policy stays pinned to the Haruspex publisher (issue #636).
/// </summary>
public class ModuleLoaderTests : IDisposable
{
    private static readonly Version CoreContract = typeof(ICertusModule).Assembly.GetName().Version!;
    private static readonly byte[] EntryImage = ModuleAssemblyBuilder.Module();

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-loader-{Guid.NewGuid():N}");

    public ModuleLoaderTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public void Discover_FindsNothing_WhenThereIsNoModulesFolder()
    {
        ModuleLoader.Discover(Path.Combine(_root, "modules")).Outcome.Should().Be(ModuleDiscoveryOutcome.None);
    }

    [Fact]
    public void Discover_FindsNothing_WhenTheFolderIsEmpty()
    {
        var modules = Path.Combine(_root, "modules");
        Directory.CreateDirectory(modules);

        ModuleLoader.Discover(modules).Outcome.Should().Be(ModuleDiscoveryOutcome.None);
    }

    [Fact]
    public void Discover_RefusesMoreThanOneModule()
    {
        var modules = Path.Combine(_root, "modules");
        Directory.CreateDirectory(Path.Combine(modules, "a"));
        Directory.CreateDirectory(Path.Combine(modules, "b"));

        ModuleLoader.Discover(modules).Outcome.Should().Be(ModuleDiscoveryOutcome.Multiple);
    }

    [Fact]
    public void Discover_FindsTheOneModule()
    {
        var modules = Path.Combine(_root, "modules");
        var only = Path.Combine(modules, "paid");
        Directory.CreateDirectory(only);

        var discovery = ModuleLoader.Discover(modules);

        discovery.Outcome.Should().Be(ModuleDiscoveryOutcome.One);
        discovery.FolderPath.Should().Be(Path.GetFullPath(only));
    }

    [Fact]
    public void Validate_RefusesAnUntrustedFolder_WhenNotTrustingAll()
    {
        var folder = MakeValidModule("paid");

        // The temp folder is not a trusted module tree, so the gate refuses it.
        var validation = ModuleLoader.Validate(_root, folder, trustAll: false, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeFalse();
        validation.Reason.Should().Contain("not trusted");

        // Issue #493: the gate's refusal is its own outcome, and nothing in the folder was read.
        validation.Outcome.Should().Be(ModuleValidationOutcome.Refused);
        validation.ModuleId.Should().BeNull();
        validation.ModuleVersion.Should().BeNull();
    }

    [Fact]
    public void Validate_RefusesAFolderOutsideTheInstallFolder_RatherThanThrowing()
    {
        // A Development path can name a module folder outside the install folder. The gate has no
        // chain to walk for it, so validation refuses it instead of letting the gate throw.
        var folder = MakeValidModule("paid");
        var installBase = Path.Combine(_root, "install");
        Directory.CreateDirectory(installBase);

        var validation = ModuleLoader.Validate(installBase, folder, trustAll: false, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeFalse();
        validation.Reason.Should().Contain("not trusted").And.Contain("not inside the install folder");
        validation.Outcome.Should().Be(ModuleValidationOutcome.Refused);
    }

    [Fact]
    public void Validate_Passes_WhenTrustingAll_AndTheManifestAndMetadataAreSound()
    {
        var folder = MakeValidModule("paid");

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeTrue(validation.Reason);
        validation.Outcome.Should().Be(ModuleValidationOutcome.Ready);
        validation.Manifest!.Id.Should().Be("paid");
    }

    [Theory]
    [InlineData(2, 0)] // another major
    [InlineData(1, 4)] // a newer minor than the core carries
    public void Validate_ReportsAModuleBuiltForAnotherContract_AsIncompatible_WithItsVersions(int major, int minor)
    {
        // Issue #493: the card's Incompatible text names the module's version and both contract
        // numbers, so validation keeps them, but still hands back no manifest to load.
        var folder = WriteModule(("paid.dll", ModuleAssemblyBuilder.Module(contract: new Version(major, minor, 0, 0))));

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeFalse();
        validation.Outcome.Should().Be(ModuleValidationOutcome.Incompatible);
        validation.ModuleId.Should().Be("paid");
        validation.ModuleVersion.Should().Be("1.0.0");
        validation.ModuleContract.Should().Be(new Version(major, minor, 0, 0));
        validation.Manifest.Should().BeNull("an incompatible module must never be activated");
        validation.EntryAssemblyPath.Should().BeNull();
    }

    [Fact]
    public void Validate_Passes_AModuleThatListsItsDepsAndRuntimeConfig()
    {
        // The shape Certus-Commercial's Publish-TestModule.ps1 writes: the entry, its own
        // dependencies, and the two JSON files dotnet publish emits, every one listed.
        var folder = Path.Combine(_root, "paid");
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "paid.dll"), EntryImage);
        File.WriteAllText(Path.Combine(folder, "paid.deps.json"), "{\"runtimeTarget\":{}}");
        File.WriteAllText(Path.Combine(folder, "paid.runtimeconfig.json"), "{\"runtimeOptions\":{}}");
        ModuleFolders.WriteManifest(folder, "paid", "paid.dll", "T", "1.0",
            new[] { "paid.dll", "paid.deps.json", "paid.runtimeconfig.json" }
                .Select(f => (f, ModuleFolders.Sha(File.ReadAllBytes(Path.Combine(folder, f))))));

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeTrue(validation.Reason);
    }

    [Fact]
    public void Validate_Refuses_WhenAFileHashIsWrong()
    {
        var folder = Path.Combine(_root, "paid");
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "paid.dll"), EntryImage);
        ModuleFolders.WriteManifest(folder, "paid", "paid.dll", "T", "1.0",
            [("paid.dll", new string('0', 64))]); // deliberately wrong hash

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeFalse();
        validation.Outcome.Should().Be(ModuleValidationOutcome.Failed);
    }

    [Fact]
    public void Validate_Refuses_WhenABundledAssemblyReferencesCore()
    {
        // The entry references only the contract and passes, but a bundled helper references the
        // core, which the stated boundary forbids. Both are hash-verified, so only the reference
        // screen of the non-entry assembly catches it.
        var folder = Path.Combine(_root, "paid");
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "paid.dll"), EntryImage);
        File.Copy(typeof(ModuleLoaderTests).Assembly.Location, Path.Combine(folder, "helper.dll")); // references Certus.Core
        ModuleFolders.WriteManifest(folder, "paid", "paid.dll", "T", "1.0",
        [
            ("paid.dll", ModuleFolders.Sha(File.ReadAllBytes(Path.Combine(folder, "paid.dll")))),
            ("helper.dll", ModuleFolders.Sha(File.ReadAllBytes(Path.Combine(folder, "helper.dll")))),
        ]);

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeFalse();
        validation.Outcome.Should().Be(ModuleValidationOutcome.Failed);
        validation.ModuleId.Should().BeNull();
    }

    [Fact]
    public void Validate_Refuses_AModuleThatNeedsAnAssemblyOnlyTheCoreCarries()
    {
        // Issue #538, the version coupling case: the module's own verifier references BouncyCastle,
        // and its publish left BouncyCastle out. The core carries a BouncyCastle of its own, which the
        // load context's old fallback would have handed over. The refusal names the missing assembly,
        // before any module code runs.
        var folder = WriteModule(("paid.dll", ModuleAssemblyBuilder.Module(alsoReferences: ["BouncyCastle.Cryptography"])));

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeFalse();
        validation.Outcome.Should().Be(ModuleValidationOutcome.Failed);
        validation.Reason.Should().Contain("BouncyCastle.Cryptography")
            .And.Contain("neither one of its own listed files nor part of the shared framework");
    }

    [Fact]
    public void Validate_Passes_TheSameModule_WhenItShipsThatAssemblyItself()
    {
        var folder = WriteModule(
            ("paid.dll", ModuleAssemblyBuilder.Module(alsoReferences: ["BouncyCastle.Cryptography"])),
            ("BouncyCastle.Cryptography.dll", ModuleAssemblyBuilder.Build("BouncyCastle.Cryptography", [ModuleAssemblyBuilder.SystemRuntime])));

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, ModuleSignaturePolicy.Unchecked);

        validation.IsReady.Should().BeTrue(validation.Reason);
    }

    [Fact]
    public void Validate_RefusesAnUnsignedModule_UnderAnEnforcedPolicy_NamingTheFile()
    {
        // The manifest is signed, so the refusal falls on the entry assembly, the way an operator
        // would see it for a build whose signing step was skipped.
        using var chain = new SignatureFixture();
        var folder = WriteModule(("paid.dll", EntryImage));
        SignManifest(folder, chain);

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, chain.Policy);

        validation.IsReady.Should().BeFalse();
        validation.Outcome.Should().Be(ModuleValidationOutcome.SignatureRefused);
        validation.Reason.Should().Be("the paid module's signature could not be verified: 'paid.dll' is not signed");
        validation.Signature!.FileName.Should().Be("paid.dll");
        validation.Signature.FoundPublisher.Should().BeNull();
        validation.ModuleId.Should().Be("paid", "the manifest passed, so the card can name the module");
        validation.ModuleVersion.Should().Be("1.0.0");
        validation.Manifest.Should().BeNull("a refused module must never be activated");
        validation.EntryAssemblyPath.Should().BeNull();
    }

    [Fact]
    public void Validate_RefusesAModuleWithAnUnsignedManifest_BeforeLookingAtItsFiles()
    {
        using var chain = new SignatureFixture();
        var folder = WriteModule(("paid.dll", chain.SignedModule(EntryImage)));

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, chain.Policy);

        validation.Outcome.Should().Be(ModuleValidationOutcome.SignatureRefused);
        validation.Reason.Should().Be(
            "the paid module's signature could not be verified: 'module.json' has no signature file (module.json.p7 is missing)");
    }

    [Fact]
    public void Validate_RefusesAModuleSignedByAnotherPublisher_NamingBothPublishers()
    {
        using var chain = new SignatureFixture();
        var signed = AuthenticodeTestSigner.SignPortableExecutable(EntryImage, chain.OtherPublisher, chain.TimeStamper, SignatureFixture.TimestampedAt);
        var folder = WriteModule(("paid.dll", signed));
        SignManifest(folder, chain);

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, chain.Policy);

        validation.Outcome.Should().Be(ModuleValidationOutcome.SignatureRefused);
        validation.Reason.Should().Be(
            $"the paid module's signature could not be verified: 'paid.dll' is signed by 'Other Co', not by '{SignatureFixture.Publisher}'");
        validation.Signature!.FoundPublisher.Should().Be("Other Co");
    }

    [Fact]
    public void Validate_Passes_AModuleWhoseManifestAndAssembliesTheExpectedPublisherSigned()
    {
        using var chain = new SignatureFixture();
        var folder = WriteModule(
            ("paid.dll", chain.SignedModule(ModuleAssemblyBuilder.Module(alsoReferences: ["BouncyCastle.Cryptography"]))),
            ("BouncyCastle.Cryptography.dll", chain.SignedModule(ModuleAssemblyBuilder.Build("BouncyCastle.Cryptography", [ModuleAssemblyBuilder.SystemRuntime]))));
        File.WriteAllText(Path.Combine(folder, "paid.deps.json"), "{}");
        ModuleFolders.WriteManifest(folder, "paid", "paid.dll", "T", "1.0",
            new[] { "paid.dll", "BouncyCastle.Cryptography.dll", "paid.deps.json" }
                .Select(f => (f, ModuleFolders.Sha(File.ReadAllBytes(Path.Combine(folder, f))))));
        SignManifest(folder, chain);

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, chain.Policy);

        validation.IsReady.Should().BeTrue(validation.Reason);
        validation.Outcome.Should().Be(ModuleValidationOutcome.Ready);
    }

    [Fact]
    public void Validate_RefusesTheSameModule_WhenAnAssemblyChangedAfterTheManifestWasSigned()
    {
        // The hash in the signed manifest catches a swapped file even when the swap is itself a
        // signed assembly, so a mix of Haruspex signed files from two releases is refused too.
        using var chain = new SignatureFixture();
        var folder = WriteModule(("paid.dll", chain.SignedModule(EntryImage)));
        SignManifest(folder, chain);
        File.WriteAllBytes(Path.Combine(folder, "paid.dll"), chain.SignedModule(ModuleAssemblyBuilder.Module("Fixture.Other")));

        var validation = ModuleLoader.Validate(_root, folder, trustAll: true, CoreContract, chain.Policy);

        validation.IsReady.Should().BeFalse();
        validation.Outcome.Should().Be(ModuleValidationOutcome.Failed);
        validation.Reason.Should().Contain("does not match its recorded hash");
    }

    /// <summary>Writes module.json.p7 for the manifest in <paramref name="folder"/>, signed by the fixture's expected publisher.</summary>
    private static void SignManifest(string folder, SignatureFixture chain) =>
        File.WriteAllBytes(
            Path.Combine(folder, ModuleSignatureVerifier.ManifestSignatureFileName),
            chain.SignedDetached(File.ReadAllBytes(Path.Combine(folder, "module.json"))));

    /// <summary>Writes a module folder named "paid" holding <paramref name="files"/>, the first of which is the entry, with a manifest listing every one.</summary>
    private string WriteModule(params (string Name, byte[] Contents)[] files)
    {
        var folder = Path.Combine(_root, "paid");
        Directory.CreateDirectory(folder);
        foreach (var (name, contents) in files)
            File.WriteAllBytes(Path.Combine(folder, name), contents);
        ModuleFolders.WriteManifest(folder, "paid", files[0].Name, "T", "1.0",
            files.Select(f => (f.Name, ModuleFolders.Sha(f.Contents))));
        return folder;
    }

    private string MakeValidModule(string id)
    {
        var folder = Path.Combine(_root, id);
        Directory.CreateDirectory(folder);
        var entry = Path.Combine(folder, $"{id}.dll");
        File.WriteAllBytes(entry, EntryImage);
        ModuleFolders.WriteManifest(folder, id, $"{id}.dll", "T", "1.0",
            [($"{id}.dll", ModuleFolders.Sha(File.ReadAllBytes(entry)))]);
        return folder;
    }
}
