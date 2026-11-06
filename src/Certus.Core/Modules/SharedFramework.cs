using System.Runtime.InteropServices;

namespace Certus.Core.Modules;

/// <summary>
/// The assemblies the shared framework provides, which a module may take from the default load
/// context (licence design section 6.2, steps 4 and 6; issue #538). The design shares the contract
/// and the framework with a module and nothing else. The default context also holds the service's
/// own dependencies (Serilog, EF Core, Microsoft.Data.Sqlite, BouncyCastle), so "anything the
/// module's own files do not provide" is the wrong test: a module whose publish forgot BouncyCastle
/// would verify silently with the core's copy, and a module could reach the core's static state,
/// such as Serilog's Log.Logger, and log around <c>IModuleLog</c>.
///
/// <para>An assembly is part of the framework when the runtime's trusted platform assembly list
/// places it under the Microsoft.NETCore.App or Microsoft.AspNetCore.App folder of the shared
/// framework this process runs on. That list is what the default context binds from, keyed by
/// file name, so the test asks the same question the binder does. The two folders are found from
/// the runtime directory rather than by name alone, so a folder that merely happens to be called
/// Microsoft.NETCore.App elsewhere counts for nothing.</para>
///
/// <para>The service is framework dependent, so its framework lives in the shared folders. A self
/// contained or single file build has no shared framework, this set is then empty, and every
/// module is refused at validation: the check fails closed rather than guessing. The same holds
/// for one name if the service ever ships a newer copy of a framework assembly of its own: the
/// list then points at the install folder, and a module referencing that name must ship its own
/// copy or be refused, naming it. No such copy ships today.</para>
/// </summary>
internal static class SharedFramework
{
    private const string NetCoreApp = "Microsoft.NETCore.App";
    private const string AspNetCoreApp = "Microsoft.AspNetCore.App";

    private static readonly Lazy<IReadOnlySet<string>> Names = new(() => FromTrustedPlatformAssemblies(
        AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string,
        RuntimeEnvironment.GetRuntimeDirectory()));

    /// <summary>Whether <paramref name="assemblyName"/> is an assembly the shared framework provides.</summary>
    public static bool Contains(string? assemblyName) =>
        assemblyName is not null && Names.Value.Contains(assemblyName);

    /// <summary>
    /// The simple names of the assemblies in <paramref name="trustedPlatformAssemblies"/> (the
    /// runtime's path separated list) that sit under the shared framework folders next to
    /// <paramref name="runtimeDirectory"/>. Compared without regard to case, like assembly names.
    /// </summary>
    internal static IReadOnlySet<string> FromTrustedPlatformAssemblies(string? trustedPlatformAssemblies, string? runtimeDirectory)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(trustedPlatformAssemblies) || string.IsNullOrWhiteSpace(runtimeDirectory))
            return names;

        // A framework dependent process runs from <dotnet>\shared\Microsoft.NETCore.App\<version>\.
        // Anything else has no shared framework to share.
        var netCoreApp = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(runtimeDirectory)));
        if (netCoreApp is null || !string.Equals(Path.GetFileName(netCoreApp), NetCoreApp, StringComparison.OrdinalIgnoreCase))
            return names;

        var shared = Path.GetDirectoryName(netCoreApp);
        if (shared is null)
            return names;

        string[] frameworks = [Path.Combine(shared, NetCoreApp), Path.Combine(shared, AspNetCoreApp)];

        foreach (var entry in trustedPlatformAssemblies.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            // An entry that is not a usable path counts for nothing. Letting it throw would make the
            // cached set an exception, and every later validation a host failure, not a refusal.
            string path;
            try
            {
                path = Path.GetFullPath(entry);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                continue;
            }

            if (frameworks.Any(framework => FolderTrust.IsAtOrUnder(framework, path)))
                names.Add(Path.GetFileNameWithoutExtension(path));
        }

        return names;
    }
}
