using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace Certus.Core.Modules;

/// <summary>
/// Checks a module's assemblies by reading their metadata, which executes nothing (licence design
/// section 6.2, step 4). The entry assembly must reference the module contract at a version the core
/// can satisfy. The contract version comes from the actual assembly reference, not the manifest, so a
/// manifest cannot misreport it, and a reference to a newer contract major, or a newer minor than the
/// core carries, is refused here (the runtime would otherwise let a newer major satisfy an older
/// reference, design section 5).
///
/// <para>Every reference, from the entry and from each assembly the module ships, must be on an allow
/// list: the contract, an assembly one of the module's own listed files defines, or the shared
/// framework (<see cref="SharedFramework"/>). That mirrors what <see cref="ModuleLoadContext"/> will
/// share at run time, so a module that would be refused there is refused here first, before any of
/// its code runs (issue #538). A reference to one of the core's own assemblies has a message of its
/// own, because that is the boundary the design names.</para>
/// </summary>
public static class ModuleMetadataReader
{
    /// <summary>The module contract assembly, the one reference a module is allowed to share with the core.</summary>
    public const string ContractAssembly = "Certus.Modules.Abstractions";

    /// <summary>Core assemblies a module must never reference, nor load at runtime: its surface is the contract alone.</summary>
    private static readonly HashSet<string> ForbiddenAssemblies = new(StringComparer.OrdinalIgnoreCase)
    {
        "Certus.Core",
        "Certus.Adcs",
        "Certus.Web",
        "DucksInARow.Service",
    };

    /// <summary>Whether <paramref name="assemblyName"/> is one of the core assemblies a module may not bind.</summary>
    public static bool IsForbidden(string? assemblyName) =>
        assemblyName is not null && ForbiddenAssemblies.Contains(assemblyName);

    /// <summary>The check for a module whose entry assembly is the only file it ships.</summary>
    public static MetadataCheckResult Check(string entryAssemblyPath, Version coreContractVersion) =>
        CheckModule(entryAssemblyPath, [entryAssemblyPath], coreContractVersion);

    /// <summary>
    /// The full check over a module's listed files: the entry references the contract at a
    /// satisfiable version, and no assembly the module ships references anything outside the allow
    /// list. A listed file with no managed metadata (the deps.json, the runtimeconfig.json, a native
    /// library) is neither checked nor counted as one of the module's own assemblies.
    /// </summary>
    public static MetadataCheckResult CheckModule(string entryAssemblyPath, IEnumerable<string> listedFiles, Version coreContractVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(entryAssemblyPath);
        ArgumentNullException.ThrowIfNull(listedFiles);
        ArgumentNullException.ThrowIfNull(coreContractVersion);

        var entryPath = System.IO.Path.GetFullPath(entryAssemblyPath);
        var (entry, entryError) = Read(entryPath);
        if (entryError is not null)
            return MetadataCheckResult.Refused(entryError);

        if (entry is null)
            return MetadataCheckResult.Refused("the entry assembly carries no managed metadata");

        // The module's own assemblies are the ones its listed files define, read off their metadata
        // rather than guessed from a file name.
        var own = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (entry.Name is not null)
            own.Add(entry.Name);

        var bundled = new List<(string FileName, AssemblyMetadata Metadata)>();
        foreach (var file in listedFiles)
        {
            var path = System.IO.Path.GetFullPath(file);
            if (string.Equals(path, entryPath, StringComparison.OrdinalIgnoreCase))
                continue;

            var (metadata, error) = Read(path);
            if (error is not null)
                return MetadataCheckResult.Refused(error);

            if (metadata is null)
                continue;

            if (metadata.Name is not null)
                own.Add(metadata.Name);
            bundled.Add((System.IO.Path.GetFileName(path), metadata));
        }

        if (FirstDisallowed(entry.References, own) is { } entryRefusal)
            return MetadataCheckResult.Refused($"the module references {entryRefusal}");

        Version? contract = null;
        foreach (var (name, version) in entry.References)
        {
            if (string.Equals(name, ContractAssembly, StringComparison.OrdinalIgnoreCase))
                contract = version;
        }

        if (contract is null)
            return MetadataCheckResult.Refused($"the module does not reference {ContractAssembly}, so it is not a module");

        // The two contract refusals keep the version they refused, because the Settings card names
        // both numbers (design section 13.3, Incompatible) and a matching module is the only fix.
        if (contract.Major != coreContractVersion.Major)
        {
            return MetadataCheckResult.Incompatible(contract,
                $"the module needs contract major {contract.Major}, and the core carries {coreContractVersion.Major}");
        }

        if (contract.Minor > coreContractVersion.Minor)
        {
            return MetadataCheckResult.Incompatible(contract,
                $"the module needs contract {contract.Major}.{contract.Minor}, newer than the core's {coreContractVersion.Major}.{coreContractVersion.Minor}");
        }

        // The contract version is the entry's to declare, but every bundled assembly is held to the
        // same allow list: a helper's reference would otherwise reach the default context through the
        // load context just as surely as the entry's would.
        foreach (var (fileName, metadata) in bundled)
        {
            if (FirstDisallowed(metadata.References, own) is { } refusal)
                return MetadataCheckResult.Refused($"'{fileName}' references {refusal}");
        }

        return MetadataCheckResult.Ok(contract);
    }

    /// <summary>
    /// The first reference in <paramref name="references"/> that is not allowed, with why, or null
    /// when all are: the contract, one of <paramref name="own"/>, or the shared framework. An allow
    /// list, so an assembly the core happens to carry is refused unless the module ships its own
    /// copy. A core assembly is looked for first, so it is the one named wherever it sits in the
    /// list: it is the boundary the design names, and the more telling refusal.
    /// </summary>
    private static string? FirstDisallowed(IReadOnlyList<(string Name, Version Version)> references, IReadOnlySet<string> own)
    {
        foreach (var (name, _) in references)
        {
            if (IsForbidden(name))
                return $"{name}, which only the contract may do";
        }

        foreach (var (name, _) in references)
        {
            if (!string.Equals(name, ContractAssembly, StringComparison.OrdinalIgnoreCase)
                && !own.Contains(name)
                && !SharedFramework.Contains(name))
            {
                return $"{name}, which is neither one of its own listed files nor part of the shared framework";
            }
        }

        return null;
    }

    /// <summary>
    /// Reads the assembly name and the assembly references of a PE file. Returns null metadata, with
    /// no error, for a file that carries no managed metadata (a native dependency or a data file).
    /// </summary>
    private static (AssemblyMetadata? Metadata, string? Error) Read(string path)
    {
        PEReader pe;
        try
        {
            pe = new PEReader(File.OpenRead(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException)
        {
            return (null, $"'{System.IO.Path.GetFileName(path)}' could not be opened ({ex.Message})");
        }

        using (pe)
        {
            // The constructor reads nothing; HasMetadata is what parses the headers, so a file that is
            // not a PE image at all throws here. That is a data file, such as the deps.json and
            // runtimeconfig.json every published module carries, and it passes like a native one.
            // Letting it throw took the whole host down to "the module host failed" for every real
            // module, found by the #413 end to end run with the Test module.
            bool hasMetadata;
            try
            {
                hasMetadata = pe.HasMetadata;
            }
            catch (BadImageFormatException)
            {
                return (null, null);
            }

            if (!hasMetadata)
                return (null, null);

            try
            {
                var reader = pe.GetMetadataReader();
                var name = reader.IsAssembly ? reader.GetString(reader.GetAssemblyDefinition().Name) : null;

                var references = new List<(string, Version)>();
                foreach (var handle in reader.AssemblyReferences)
                {
                    var reference = reader.GetAssemblyReference(handle);
                    references.Add((reader.GetString(reference.Name), reference.Version));
                }

                return (new AssemblyMetadata(name, references), null);
            }
            catch (BadImageFormatException ex)
            {
                return (null, $"the metadata of '{System.IO.Path.GetFileName(path)}' could not be read ({ex.Message})");
            }
        }
    }

    /// <summary>What one assembly's metadata says: its own name (null for a module that is not an assembly) and its references.</summary>
    private sealed record AssemblyMetadata(string? Name, IReadOnlyList<(string Name, Version Version)> References);
}

/// <summary>
/// The verdict of a metadata check: the contract version referenced (for the entry), or a reason to
/// refuse. A refusal over the contract version alone is <see cref="IsIncompatible"/> and keeps the
/// version it refused; every other refusal carries none.
/// </summary>
public sealed record MetadataCheckResult(bool IsOk, Version? ContractVersion, string? Error)
{
    /// <summary>Whether the only thing wrong is the contract version the entry references (issue #493).</summary>
    public bool IsIncompatible { get; init; }

    public static MetadataCheckResult Ok(Version contractVersion) => new(true, contractVersion, null);

    public static MetadataCheckResult Refused(string error) => new(false, null, error);

    public static MetadataCheckResult Incompatible(Version contractVersion, string error) =>
        new(false, contractVersion, error) { IsIncompatible = true };
}
