using System.Reflection;
using System.Runtime.Loader;
using Certus.Core.Modules;
using Certus.Modules;
using Certus.Tests.Shared;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// What a module's load context shares from the default context at run time (licence design section
/// 6.2, step 6; issue #538): the contract and the shared framework, nothing else. Each test makes a
/// real context over an emitted entry assembly in a temporary folder and asks it for one name. The
/// contexts are not collectible, as in production, so each one stays loaded until the test process
/// ends; they hold only metadata, so that costs nothing.
///
/// <para>A refusal surfaces as the runtime's own <see cref="FileLoadException"/>, carrying the one
/// <see cref="ModuleLoadContext"/> threw as its inner exception, so the reason is read from there.</para>
/// </summary>
public class ModuleLoadContextTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), $"certus-alc-{Guid.NewGuid():N}");
    private readonly string _entry;

    public ModuleLoadContextTests()
    {
        Directory.CreateDirectory(_folder);
        _entry = Path.Combine(_folder, "Fixture.Module.dll");
        File.WriteAllBytes(_entry, ModuleAssemblyBuilder.Module(alsoReferences: ["Fixture.Helper"]));
    }

    public void Dispose()
    {
        // A file the context loaded stays mapped, so the folder may outlive the test.
        try { Directory.Delete(_folder, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private ModuleLoadContext NewContext() => new($"test:{Guid.NewGuid():N}", _entry);

    [Fact]
    public void TheContract_IsTheDefaultContextsOwnCopy()
    {
        var loaded = NewContext().LoadFromAssemblyName(new AssemblyName(ModuleMetadataReader.ContractAssembly));

        loaded.Should().BeSameAs(typeof(ICertusModule).Assembly);
    }

    [Fact]
    public void AFrameworkAssembly_ComesFromTheDefaultContext()
    {
        var loaded = NewContext().LoadFromAssemblyName(new AssemblyName("System.Runtime"));

        AssemblyLoadContext.GetLoadContext(loaded).Should().BeSameAs(AssemblyLoadContext.Default);
    }

    [Fact]
    public void ADependencyOfTheCore_TheModuleDoesNotShip_IsRefused()
    {
        // The default context holds EF Core, so deferring to it would have handed the module the
        // core's own copy. The first assertion proves that copy is there to be handed out.
        var efCore = typeof(Microsoft.EntityFrameworkCore.DbContext).Assembly;
        AssemblyLoadContext.GetLoadContext(efCore).Should().BeSameAs(AssemblyLoadContext.Default);

        var act = () => NewContext().LoadFromAssemblyName(new AssemblyName(efCore.GetName().Name!));

        act.Should().Throw<FileLoadException>()
            .WithInnerException<FileLoadException>()
            .WithMessage("*neither one of the module's own files nor part of the shared framework*");
    }

    [Fact]
    public void ACoreAssembly_IsRefused()
    {
        var act = () => NewContext().LoadFromAssemblyName(new AssemblyName("Certus.Core"));

        act.Should().Throw<FileLoadException>()
            .WithInnerException<FileLoadException>()
            .WithMessage("*may not load 'Certus.Core'*");
    }

    [Fact]
    public void AnAssemblyTheModuleShips_LoadsIntoTheModulesOwnContext()
    {
        File.WriteAllBytes(
            Path.Combine(_folder, "Fixture.Helper.dll"),
            ModuleAssemblyBuilder.Build("Fixture.Helper", [ModuleAssemblyBuilder.SystemRuntime]));
        var context = NewContext();

        var loaded = context.LoadFromAssemblyName(new AssemblyName("Fixture.Helper"));

        AssemblyLoadContext.GetLoadContext(loaded).Should().BeSameAs(context);
    }
}
