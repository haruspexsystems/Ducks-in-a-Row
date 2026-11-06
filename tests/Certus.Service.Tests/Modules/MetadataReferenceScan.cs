using System.Collections.Immutable;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace Certus.Service.Tests.Modules;

/// <summary>A type an assembly refers to: the assembly it lives in, its namespace and its name.</summary>
internal readonly record struct TypeName(string Assembly, string Namespace, string Name);

/// <summary>One type definition and whether anything it declares or runs matched the scan.</summary>
internal sealed record ScannedType(string FullName, string OwnerNamespace, bool Matched);

/// <summary>
/// Reads an assembly's metadata with System.Reflection.Metadata, never loading it, and reports for
/// every type definition whether its base type, interfaces, field and method signatures, local
/// variables or method bodies refer to a type or a member the caller forbids (licence design section
/// 18.2). Method bodies are read instruction by instruction through <see cref="IlTokens"/>, so a
/// reference only a method body makes, a call into the contract that no signature shows, is found.
///
/// <para>Compiler generated types (closures, async state machines) are attributed to the namespace
/// of the outermost type they are nested in, which is the type a person wrote, so a lambda inside
/// the module host counts as the module host.</para>
/// </summary>
internal sealed class MetadataReferenceScan
{
    private readonly MetadataReader _md;
    private readonly PEReader _pe;
    private readonly string _assemblyName;
    private readonly Func<TypeName, bool> _forbiddenType;
    private readonly Func<string, bool> _forbiddenMember;
    private readonly Provider _provider;

    private MetadataReferenceScan(PEReader pe, Func<TypeName, bool> forbiddenType, Func<string, bool> forbiddenMember)
    {
        _pe = pe;
        _md = pe.GetMetadataReader();
        _assemblyName = _md.GetString(_md.GetAssemblyDefinition().Name);
        _forbiddenType = forbiddenType;
        _forbiddenMember = forbiddenMember;
        _provider = new Provider(this);
    }

    /// <summary>Scans every type definition in the assembly at <paramref name="path"/>.</summary>
    public static IReadOnlyList<ScannedType> Scan(
        string path,
        Func<TypeName, bool> forbiddenType,
        Func<string, bool>? forbiddenMember = null)
    {
        using var stream = File.OpenRead(path);
        using var pe = new PEReader(stream);
        var scan = new MetadataReferenceScan(pe, forbiddenType, forbiddenMember ?? (_ => false));
        return scan.Run();
    }

    /// <summary>The names of the assemblies <paramref name="path"/> references.</summary>
    public static IReadOnlyList<string> AssemblyReferences(string path)
    {
        using var stream = File.OpenRead(path);
        using var pe = new PEReader(stream);
        var md = pe.GetMetadataReader();
        return md.AssemblyReferences.Select(h => md.GetString(md.GetAssemblyReference(h).Name)).ToList();
    }

    private List<ScannedType> Run()
    {
        var result = new List<ScannedType>();
        foreach (var handle in _md.TypeDefinitions)
        {
            var type = _md.GetTypeDefinition(handle);
            var name = _md.GetString(type.Name);
            if (name == "<Module>")
                continue;

            result.Add(new ScannedType(FullName(handle), OwnerNamespace(handle), Matches(type)));
        }

        return result;
    }

    private bool Matches(TypeDefinition type)
    {
        if (!type.BaseType.IsNil && Refers(type.BaseType))
            return true;

        foreach (var implementation in type.GetInterfaceImplementations())
        {
            if (Refers(_md.GetInterfaceImplementation(implementation).Interface))
                return true;
        }

        foreach (var fieldHandle in type.GetFields())
        {
            if (_md.GetFieldDefinition(fieldHandle).DecodeSignature(_provider, null))
                return true;
        }

        foreach (var methodHandle in type.GetMethods())
        {
            if (MethodMatches(_md.GetMethodDefinition(methodHandle)))
                return true;
        }

        return false;
    }

    private bool MethodMatches(MethodDefinition method)
    {
        var signature = method.DecodeSignature(_provider, null);
        if (signature.ReturnType || signature.ParameterTypes.Any(t => t))
            return true;

        if (method.RelativeVirtualAddress == 0)
            return false;

        var body = _pe.GetMethodBody(method.RelativeVirtualAddress);
        if (!body.LocalSignature.IsNil
            && _md.GetStandaloneSignature(body.LocalSignature).DecodeLocalSignature(_provider, null).Any(t => t))
        {
            return true;
        }

        foreach (var (kind, token) in IlTokens.Enumerate(body.GetILBytes()!))
        {
            if (kind == OperandType.InlineSig)
                continue;
            if (Refers(MetadataTokens.EntityHandle(token)))
                return true;
        }

        return false;
    }

    /// <summary>Whether a token, of any kind an instruction or a signature can carry, reaches a forbidden type or member.</summary>
    private bool Refers(EntityHandle handle)
    {
        switch (handle.Kind)
        {
            case HandleKind.TypeReference:
                return _forbiddenType(Describe((TypeReferenceHandle)handle));

            case HandleKind.TypeDefinition:
                return _forbiddenType(Describe((TypeDefinitionHandle)handle));

            case HandleKind.TypeSpecification:
                return _md.GetTypeSpecification((TypeSpecificationHandle)handle).DecodeSignature(_provider, null);

            case HandleKind.MemberReference:
            {
                var member = _md.GetMemberReference((MemberReferenceHandle)handle);
                if (_forbiddenMember(_md.GetString(member.Name)))
                    return true;
                if (Refers(member.Parent))
                    return true;
                if (member.GetKind() == MemberReferenceKind.Method)
                {
                    var signature = member.DecodeMethodSignature(_provider, null);
                    return signature.ReturnType || signature.ParameterTypes.Any(t => t);
                }

                return member.DecodeFieldSignature(_provider, null);
            }

            case HandleKind.MethodSpecification:
            {
                var specification = _md.GetMethodSpecification((MethodSpecificationHandle)handle);
                return Refers(specification.Method) || specification.DecodeSignature(_provider, null).Any(t => t);
            }

            case HandleKind.MethodDefinition:
            {
                var method = _md.GetMethodDefinition((MethodDefinitionHandle)handle);
                return _forbiddenMember(_md.GetString(method.Name))
                    || _forbiddenType(Describe(method.GetDeclaringType()));
            }

            case HandleKind.FieldDefinition:
                return _forbiddenType(Describe(_md.GetFieldDefinition((FieldDefinitionHandle)handle).GetDeclaringType()));

            default:
                return false;
        }
    }

    private TypeName Describe(TypeReferenceHandle handle)
    {
        var reference = _md.GetTypeReference(handle);
        var name = _md.GetString(reference.Name);
        var ns = _md.GetString(reference.Namespace);

        // A nested type's reference is scoped to its enclosing type's reference; the assembly and the
        // namespace belong to the outermost one.
        var scope = reference.ResolutionScope;
        while (scope.Kind == HandleKind.TypeReference)
        {
            var outer = _md.GetTypeReference((TypeReferenceHandle)scope);
            ns = _md.GetString(outer.Namespace);
            scope = outer.ResolutionScope;
        }

        var assembly = scope.Kind == HandleKind.AssemblyReference
            ? _md.GetString(_md.GetAssemblyReference((AssemblyReferenceHandle)scope).Name)
            : _assemblyName;
        return new TypeName(assembly, ns, name);
    }

    private TypeName Describe(TypeDefinitionHandle handle) =>
        new(_assemblyName, OwnerNamespace(handle), _md.GetString(_md.GetTypeDefinition(handle).Name));

    private string OwnerNamespace(TypeDefinitionHandle handle)
    {
        var type = _md.GetTypeDefinition(handle);
        while (!type.GetDeclaringType().IsNil)
            type = _md.GetTypeDefinition(type.GetDeclaringType());
        return _md.GetString(type.Namespace);
    }

    private string FullName(TypeDefinitionHandle handle)
    {
        var type = _md.GetTypeDefinition(handle);
        var name = _md.GetString(type.Name);
        var declaring = type.GetDeclaringType();
        return declaring.IsNil
            ? $"{_md.GetString(type.Namespace)}.{name}"
            : $"{FullName(declaring)}+{name}";
    }

    /// <summary>Decodes a signature into "does any type in it match the scan".</summary>
    private sealed class Provider(MetadataReferenceScan scan) : ISignatureTypeProvider<bool, object?>
    {
        public bool GetArrayType(bool elementType, ArrayShape shape) => elementType;
        public bool GetByReferenceType(bool elementType) => elementType;
        public bool GetFunctionPointerType(MethodSignature<bool> signature) =>
            signature.ReturnType || signature.ParameterTypes.Any(t => t);
        public bool GetGenericInstantiation(bool genericType, ImmutableArray<bool> typeArguments) =>
            genericType || typeArguments.Any(t => t);
        public bool GetGenericMethodParameter(object? genericContext, int index) => false;
        public bool GetGenericTypeParameter(object? genericContext, int index) => false;
        public bool GetModifiedType(bool modifier, bool unmodifiedType, bool isRequired) => modifier || unmodifiedType;
        public bool GetPinnedType(bool elementType) => elementType;
        public bool GetPointerType(bool elementType) => elementType;
        public bool GetPrimitiveType(PrimitiveTypeCode typeCode) => false;
        public bool GetSZArrayType(bool elementType) => elementType;
        public bool GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) =>
            scan._forbiddenType(scan.Describe(handle));
        public bool GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) =>
            scan._forbiddenType(scan.Describe(handle));
        public bool GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) =>
            reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
    }
}
