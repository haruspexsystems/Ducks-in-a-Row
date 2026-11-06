using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using Certus.Modules;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The module contract, Certus.Modules.Abstractions (licence design section 5;
/// lethe377/Certus#413), is the one assembly the core and a paid module share. These
/// tests hold the three things about it that a careless change would break silently.
/// <list type="bullet">
/// <item><b>The surface</b> changes only as a deliberate diff of its baseline,
/// <c>src/Certus.Modules.Abstractions/PublicApi.txt</c>. The private repository
/// vendors the same baseline, so a module built against one surface can never meet
/// another unnoticed.</item>
/// <item><b>It reaches no framework or container type.</b> Licence design rule 2 (section
/// 2.4) gives modules no access to the core's machinery, and the contract is the only way
/// in.</item>
/// <item><b>Its version is the contract's</b>, not the product's (deviation Dv10 on #413).
/// The loader compares a module's reference by major and minor, so a product release must
/// not move it.</item>
/// </list>
/// </summary>
public class ModuleContractTests
{
    private static readonly Assembly Contract = typeof(ICertusModule).Assembly;

    /// <summary>
    /// Set this to 1 to rewrite the baseline from the current surface, then review the diff
    /// of PublicApi.txt. A contract change is a new contract minor or major version with its
    /// own review (design section 5), never a side effect.
    /// </summary>
    private const string UpdateVariable = "CERTUS_UPDATE_CONTRACT_BASELINE";

    [Fact]
    public void ContractVersionIsPinned() =>
        Contract.GetName().Version.Should().Be(new Version(1, 0, 0, 0),
            "the contract version moves only with the contract, never with VersionPrefix");

    /// <summary>
    /// The MSI records the contract the core carries as ModuleContractVersion, and the paid
    /// module's installer requires the same major (issue #495). build.ps1 passes it from this
    /// assembly's project and checks the published DLL agrees, but Certus.wxs keeps fallback
    /// defines for a direct wix build, and a stale fallback would record a contract this
    /// service does not carry.
    /// </summary>
    [Fact]
    public void TheInstallerFallbackRecordsThisContract()
    {
        var version = Contract.GetName().Version!;

        InstallerSource.Define("ModuleContractVersion").Should().Be($"{version.Major}.{version.Minor}",
            "the MSI records the contract as major.minor, and its upgrade check compares by a major prefix");
        InstallerSource.Define("ModuleContractMajor").Should().Be($"{version.Major}");
    }

    [Fact]
    public void ContractExposesNoContainerOrFrameworkTypes()
    {
        // The base class library alone: each reference is an assembly of the runtime's own
        // shared framework, the same test the module loader applies to a module's references
        // (design section 6.2, step 4). Records bring System.Collections for EqualityComparer.
        var runtimeDirectory = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
        foreach (var reference in Contract.GetReferencedAssemblies())
        {
            File.Exists(Path.Combine(runtimeDirectory, reference.Name + ".dll")).Should().BeTrue(
                $"{reference.Name} must be part of the base runtime, not ASP.NET Core, Microsoft.Extensions, Serilog or Certus");
            reference.Name.Should().NotStartWith("Microsoft.").And.NotStartWith("Serilog").And.NotStartWith("Certus");
        }

        var namespaces = Contract.GetExportedTypes()
            .SelectMany(SignatureTypes)
            .Select(t => t.Namespace ?? string.Empty)
            .Distinct()
            .ToArray();
        namespaces.Should().BeSubsetOf(new[] { "System", "Certus.Modules" },
            "no public signature may name IServiceProvider, IConfiguration, ILogger, HttpContext, a Serilog type, a System.Text.Json type or a Certus.Core type");
    }

    [Fact]
    public void ContractSurfaceMatchesBaseline()
    {
        var path = Path.Combine(RepositoryRoot(), "src", "Certus.Modules.Abstractions", "PublicApi.txt");
        var actual = Render();

        if (Environment.GetEnvironmentVariable(UpdateVariable) == "1")
        {
            File.WriteAllText(path, actual, new UTF8Encoding(false));
            return;
        }

        File.Exists(path).Should().BeTrue($"the baseline {path} must exist; create it with {UpdateVariable}=1");
        var expected = File.ReadAllText(path).Replace("\r\n", "\n");
        actual.Should().Be(expected,
            $"the contract's public surface changed. If that is deliberate, rerun with {UpdateVariable}=1, " +
            "review the diff of PublicApi.txt, and bump the contract version and the vendored copy in " +
            "lethe377/Certus-Commercial to match");
    }

    /// <summary>
    /// The public and protected surface, one line per member, sorted, with nullable
    /// annotations, so any change to a name, a type, a parameter or nullability shows.
    /// </summary>
    internal static string Render()
    {
        var nullability = new NullabilityInfoContext();
        var lines = new List<string>();
        foreach (var type in Contract.GetExportedTypes().OrderBy(t => t.FullName, StringComparer.Ordinal))
        {
            lines.Add($"{Kind(type)} {type.FullName}{BaseList(type)}");
            if (type.IsEnum)
            {
                foreach (var name in Enum.GetNames(type))
                    lines.Add($"  {name} = {Convert.ToInt64(Enum.Parse(type, name), System.Globalization.CultureInfo.InvariantCulture)}");
                continue;
            }

            var members = new List<string>();
            const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
            foreach (var ctor in type.GetConstructors(all).Where(Visible))
                members.Add($"  ctor({Parameters(ctor, nullability)})");
            foreach (var method in type.GetMethods(all).Where(Visible).Where(m => !IsAccessor(m)))
                members.Add($"  method{(method.IsStatic ? " static" : "")} {TypeName(method.ReturnType, nullability.Create(method.ReturnParameter))} {method.Name}({Parameters(method, nullability)})");
            foreach (var property in type.GetProperties(all).Where(p => p.GetMethod is { } g && Visible(g)))
                members.Add($"  property {TypeName(property.PropertyType, nullability.Create(property))} {property.Name} {{ get;{Setter(property)} }}");
            foreach (var field in type.GetFields(all).Where(f => f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly))
                members.Add($"  field {TypeName(field.FieldType, nullability.Create(field))} {field.Name}");
            lines.AddRange(members.OrderBy(m => m, StringComparer.Ordinal));
        }
        return string.Join("\n", lines) + "\n";
    }

    private static string Kind(Type t) =>
        t.IsEnum ? "enum" : t.IsInterface ? "interface" : t.IsValueType ? "struct" : t.IsSealed ? "sealed class" : "class";

    private static string BaseList(Type t)
    {
        if (t.IsEnum) return $" : {Enum.GetUnderlyingType(t).FullName}";
        var bases = new List<string>();
        if (t.BaseType is { } b && b != typeof(object) && b != typeof(ValueType)) bases.Add(TypeName(b, null));
        bases.AddRange(t.GetInterfaces().Select(i => TypeName(i, null)).OrderBy(x => x, StringComparer.Ordinal));
        return bases.Count == 0 ? "" : " : " + string.Join(", ", bases);
    }

    private static bool Visible(MethodBase m) => m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly;

    private static bool IsAccessor(MethodInfo m) =>
        m.IsSpecialName && (m.Name.StartsWith("get_", StringComparison.Ordinal) || m.Name.StartsWith("set_", StringComparison.Ordinal)
                            || m.Name.StartsWith("add_", StringComparison.Ordinal) || m.Name.StartsWith("remove_", StringComparison.Ordinal));

    private static string Setter(PropertyInfo p)
    {
        if (p.SetMethod is not { } set || !Visible(set)) return "";
        var init = set.ReturnParameter.GetRequiredCustomModifiers().Contains(typeof(IsExternalInit));
        return init ? " init;" : " set;";
    }

    private static string Parameters(MethodBase m, NullabilityInfoContext nullability) =>
        string.Join(", ", m.GetParameters().Select(p =>
            $"{(p.IsOut ? "out " : p.ParameterType.IsByRef ? "ref " : "")}{TypeName(p.ParameterType, nullability.Create(p))} {p.Name}"));

    private static string TypeName(Type t, NullabilityInfo? n)
    {
        if (t.IsByRef) return TypeName(t.GetElementType()!, n?.ElementType ?? n);
        if (Nullable.GetUnderlyingType(t) is { } underlying) return TypeName(underlying, null) + "?";
        string name;
        if (t.IsArray) name = TypeName(t.GetElementType()!, n?.ElementType) + "[]";
        else if (t.IsGenericType)
        {
            var args = t.GetGenericArguments();
            name = $"{t.Namespace}.{t.Name[..t.Name.IndexOf('`')]}<" +
                   string.Join(", ", args.Select((a, i) => TypeName(a, n is not null && i < n.GenericTypeArguments.Length ? n.GenericTypeArguments[i] : null))) + ">";
        }
        else name = t.FullName ?? t.Name;
        if (!t.IsValueType && n?.ReadState == NullabilityState.Nullable) name += "?";
        return name;
    }

    /// <summary>Every type a public signature of <paramref name="type"/> mentions, generics unwrapped.</summary>
    private static IEnumerable<Type> SignatureTypes(Type type)
    {
        const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        var direct = new List<Type>();
        if (type.BaseType is { } b) direct.Add(b);
        direct.AddRange(type.GetInterfaces());
        foreach (var m in type.GetMethods(flags))
        {
            direct.Add(m.ReturnType);
            direct.AddRange(m.GetParameters().Select(p => p.ParameterType));
        }
        foreach (var c in type.GetConstructors(flags)) direct.AddRange(c.GetParameters().Select(p => p.ParameterType));
        foreach (var p in type.GetProperties(flags)) direct.Add(p.PropertyType);
        foreach (var f in type.GetFields(flags)) direct.Add(f.FieldType);
        return direct.SelectMany(Unwrap);
    }

    private static IEnumerable<Type> Unwrap(Type t)
    {
        if (t.HasElementType) return Unwrap(t.GetElementType()!);
        if (t.IsGenericType) return new[] { t.GetGenericTypeDefinition() }.Concat(t.GetGenericArguments().SelectMany(Unwrap));
        return [t];
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
            directory = directory.Parent;
        return directory?.FullName
            ?? throw new InvalidOperationException($"Could not find Certus.sln walking up from {AppContext.BaseDirectory}.");
    }
}
