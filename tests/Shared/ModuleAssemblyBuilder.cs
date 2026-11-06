using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

namespace Certus.Tests.Shared;

/// <summary>
/// Emits a small assembly that carries metadata and no code: a name and exactly the assembly
/// references a test asks for. The module host's metadata check reads nothing else, so this stands
/// in for a module's entry assembly or for a file it ships, with every reference chosen by the test
/// (issue #538). Before that issue the tests copied Certus.Core.dll in as the module, which
/// references the core's own dependencies and is exactly what the reference allow list refuses.
///
/// <para>Linked into the test projects that need it as a source file, like <c>PoolAwareWait</c>.</para>
/// </summary>
internal static class ModuleAssemblyBuilder
{
    /// <summary>The module contract, by name, so the builder carries no reference to any Certus type.</summary>
    public const string Contract = "Certus.Modules.Abstractions";

    /// <summary>The contract version a sound fixture references: the one the core carries today.</summary>
    public static readonly Version ContractVersion = new(1, 0, 0, 0);

    /// <summary>A framework assembly every real module references.</summary>
    public static readonly (string Name, Version Version) SystemRuntime = ("System.Runtime", new Version(10, 0, 0, 0));

    /// <summary>
    /// A stand in module entry assembly: it references the contract at <paramref name="contract"/>
    /// (the current contract when null), System.Runtime, and each of <paramref name="alsoReferences"/>
    /// at version 1.0.
    /// </summary>
    public static byte[] Module(string name = "Fixture.Module", Version? contract = null, params string[] alsoReferences) =>
        Build(name, [(Contract, contract ?? ContractVersion), SystemRuntime, .. alsoReferences.Select(r => (r, new Version(1, 0, 0, 0)))]);

    /// <summary>An assembly named <paramref name="name"/> that references exactly <paramref name="references"/>.</summary>
    public static byte[] Build(string name, IEnumerable<(string Name, Version Version)> references)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            0,
            metadata.GetOrAddString(name + ".dll"),
            metadata.GetOrAddGuid(new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(name)).AsSpan(0, 16))),
            default,
            default);
        metadata.AddAssembly(
            metadata.GetOrAddString(name),
            new Version(1, 0, 0, 0),
            default,
            default,
            default,
            AssemblyHashAlgorithm.Sha1);

        foreach (var (reference, version) in references)
            metadata.AddAssemblyReference(metadata.GetOrAddString(reference), version, default, default, default, default);

        // Every module has the <Module> type, even one with no code.
        metadata.AddTypeDefinition(
            default,
            default,
            metadata.GetOrAddString("<Module>"),
            default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var image = new BlobBuilder();
        new ManagedPEBuilder(
            PEHeaderBuilder.CreateLibraryHeader(),
            new MetadataRootBuilder(metadata),
            new BlobBuilder()).Serialize(image);
        return image.ToArray();
    }
}
