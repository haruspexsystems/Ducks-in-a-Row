using System.Reflection;
using System.Runtime.Loader;

namespace Certus.Core.Modules;

/// <summary>
/// The load context for one module (licence design section 6.2, step 6). It is not collectible,
/// because the module runs for the life of the process.
///
/// <para>Two things are shared from the default context, and nothing else. The contract assembly,
/// so <c>ICertusModule</c> is the same type on both sides of the boundary rather than two unrelated
/// types. And the shared framework: the module is built with a framework reference and carries no
/// framework copies, and the dependency resolver returns null for a framework assembly.</para>
///
/// <para>Everything else, BouncyCastle included, is private to the module and loaded from its own
/// folder with <see cref="AssemblyLoadContext.LoadFromAssemblyPath"/>, which keeps the loaded image
/// tied to the signed file that WDAC and AppLocker publisher rules evaluate. Returning null defers
/// to the default context, which also holds the core and the service's own dependencies, so null
/// is returned only for the contract and a <see cref="SharedFramework"/> assembly. Any other name
/// the module's own files cannot provide is refused (issue #538), the run time half of the allow
/// list <see cref="ModuleMetadataReader"/> applies at validation.</para>
/// </summary>
internal sealed class ModuleLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;

    public ModuleLoadContext(string name, string entryAssemblyPath)
        : base(name, isCollectible: false)
    {
        _resolver = new AssemblyDependencyResolver(entryAssemblyPath);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        // Share the contract from the default context. Returning null defers to the default context,
        // which already holds the one loaded Certus.Modules.Abstractions. The compare is case
        // insensitive, like assembly identity itself.
        if (string.Equals(assemblyName.Name, ModuleMetadataReader.ContractAssembly, StringComparison.OrdinalIgnoreCase))
            return null;

        // A core assembly is refused outright, before the resolver, so a module cannot ship a copy
        // of one either.
        if (ModuleMetadataReader.IsForbidden(assemblyName.Name))
            throw new FileLoadException($"a module may not load '{assemblyName.Name}'.");

        var path = _resolver.ResolveAssemblyToPath(assemblyName);
        if (path is not null)
            return LoadFromAssemblyPath(path);

        // Not one of the module's own files. Only the framework may come from the default context:
        // deferring anything else would hand the module the core's own copy of it.
        if (SharedFramework.Contains(assemblyName.Name))
            return null;

        throw new FileLoadException(
            $"a module may not load '{assemblyName.Name}': it is neither one of the module's own files nor part of the shared framework.");
    }

    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        var path = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        return path is null ? IntPtr.Zero : LoadUnmanagedDllFromPath(path);
    }
}
