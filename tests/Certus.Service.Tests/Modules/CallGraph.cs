using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;

namespace Certus.Service.Tests.Modules;

/// <summary>
/// The first party call graph (licence design section 18.2): from a set of entry methods, every
/// first party method a body can reach, followed through calls, constructions, delegates (ldftn),
/// async and iterator state machines, and virtual and interface dispatch to every first party
/// implementation. It over approximates on purpose: a reach it reports may not happen at run time,
/// but a reach that can happen is never missed through a call, a lambda or an interface.
///
/// <para>Dispatch fans out only through first party interfaces and first party virtual methods. A
/// call through a framework interface such as <see cref="IDisposable"/> is not followed into every
/// first party implementation, or every <c>using</c> would reach everything that is disposable,
/// the module host included.</para>
///
/// <para>Dependency injection is not a call, so the graph also reports a reachable type whose
/// constructor asks for a forbidden type: the container would build the module host to satisfy it.</para>
/// </summary>
internal sealed class CallGraph
{
    private const BindingFlags Declared =
        BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    private readonly HashSet<Assembly> _firstParty;
    private readonly Func<Type, bool> _forbidden;
    private readonly Dictionary<MethodBase, List<MethodBase>> _implementations = new();

    public CallGraph(IEnumerable<Assembly> firstParty, Func<Type, bool> forbidden)
    {
        _firstParty = firstParty.ToHashSet();
        _forbidden = forbidden;
        IndexDispatch();
    }

    /// <summary>
    /// What a walk found: every method visited, every reach into a forbidden type with the path to
    /// it, and how many tokens could not be resolved, which a caller asserts on, since a token the
    /// walker cannot read hides whatever that instruction calls.
    /// </summary>
    public sealed record Walk(IReadOnlySet<MethodBase> Visited, IReadOnlyList<string> Reaches, int Unresolved);

    private int _unresolved;

    public Walk From(IEnumerable<MethodBase> entries)
    {
        var visited = new HashSet<MethodBase>();
        var parent = new Dictionary<MethodBase, MethodBase?>();
        var reaches = new List<string>();
        var queue = new Queue<MethodBase>();

        foreach (var entry in entries.Select(Definition).Where(IsFirstParty))
        {
            if (visited.Add(entry))
            {
                parent[entry] = null;
                queue.Enqueue(entry);
            }
        }

        var typesChecked = new HashSet<Type>();
        while (queue.Count > 0)
        {
            var method = queue.Dequeue();

            if (method.DeclaringType is { } owner && typesChecked.Add(owner))
            {
                foreach (var forbidden in ConstructorDependencies(owner).Where(_forbidden))
                    reaches.Add($"{Path(parent, method)} -> constructor of {owner} asks for {forbidden}");
            }

            foreach (var target in Targets(method))
            {
                if (target is Type type)
                {
                    if (Flatten(type).FirstOrDefault(_forbidden) is { } named)
                        reaches.Add($"{Path(parent, method)} -> {named}");
                    continue;
                }

                // The type arguments count as much as the declaring type: a service locator call such
                // as GetRequiredService<ModuleHost>() is a framework method, and only its type
                // argument says what it reaches.
                var resolved = (MethodBase)target;
                if (ForbiddenIn(resolved) is { } forbidden)
                {
                    reaches.Add($"{Path(parent, method)} -> {resolved.DeclaringType}.{resolved.Name} names {forbidden}");
                    continue;
                }

                var callee = Definition(resolved);

                if (!IsFirstParty(callee))
                    continue;

                foreach (var next in Expand(callee))
                {
                    if (visited.Add(next))
                    {
                        parent[next] = method;
                        queue.Enqueue(next);
                    }
                }
            }
        }

        return new Walk(visited, reaches, _unresolved);
    }

    /// <summary>The first forbidden type a method names: its declaring type, or a type argument of either.</summary>
    private Type? ForbiddenIn(MethodBase method)
    {
        IEnumerable<Type> named = method.DeclaringType is { } declaring ? Flatten(declaring) : [];
        if (method is MethodInfo { IsGenericMethod: true } generic)
            named = named.Concat(generic.GetGenericArguments().SelectMany(Flatten));
        return named.FirstOrDefault(_forbidden);
    }

    /// <summary>A method and, when it is abstract, virtual or an interface member, every first party implementation of it.</summary>
    private IEnumerable<MethodBase> Expand(MethodBase method)
    {
        yield return method;
        if (_implementations.TryGetValue(method, out var implementations))
        {
            foreach (var implementation in implementations)
                yield return implementation;
        }
    }

    /// <summary>The methods and types a body names, plus the state machine an async or iterator method runs.</summary>
    private IEnumerable<object> Targets(MethodBase method)
    {
        if (method.GetCustomAttribute<StateMachineAttribute>() is { } machine
            && machine.StateMachineType.GetMethod("MoveNext", Declared) is { } moveNext)
        {
            yield return moveNext;
        }

        byte[]? il;
        try
        {
            il = method.GetMethodBody()?.GetILAsByteArray();
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            il = null;
        }

        if (il is null)
            yield break;

        var typeArguments = method.DeclaringType is { IsGenericType: true } generic ? generic.GetGenericArguments() : null;
        var methodArguments = method is MethodInfo { IsGenericMethod: true } info ? info.GetGenericArguments() : null;

        foreach (var (kind, token) in IlTokens.Enumerate(il))
        {
            if (kind is not (OperandType.InlineMethod or OperandType.InlineTok or OperandType.InlineType))
                continue;

            MemberInfo? member;
            try
            {
                member = method.Module.ResolveMember(token, typeArguments, methodArguments);
            }
            catch (Exception ex) when (ex is ArgumentException or BadImageFormatException or TypeLoadException or MissingMemberException)
            {
                _unresolved++;
                continue;
            }

            switch (member)
            {
                case MethodBase callee:
                    yield return callee;
                    break;
                case Type type:
                    yield return type;
                    break;
            }
        }
    }

    private IEnumerable<Type> ConstructorDependencies(Type type)
    {
        foreach (var constructor in type.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
        {
            foreach (var parameter in constructor.GetParameters())
            {
                foreach (var named in Flatten(parameter.ParameterType))
                    yield return named;
            }
        }
    }

    /// <summary>A type and every type argument inside it, so <c>Lazy&lt;ModuleHost&gt;</c> counts as asking for the host.</summary>
    private static IEnumerable<Type> Flatten(Type type)
    {
        if (type.HasElementType && type.GetElementType() is { } element)
        {
            foreach (var inner in Flatten(element))
                yield return inner;
            yield break;
        }

        yield return type;
        if (type.IsGenericType)
        {
            foreach (var argument in type.GetGenericArguments())
            {
                foreach (var inner in Flatten(argument))
                    yield return inner;
            }
        }
    }

    private void IndexDispatch()
    {
        foreach (var type in _firstParty.SelectMany(LoadableTypes))
        {
            if (type.IsInterface)
                continue;

            foreach (var contract in type.GetInterfaces().Where(i => _firstParty.Contains(i.Assembly)))
            {
                InterfaceMapping map;
                try
                {
                    map = type.GetInterfaceMap(contract);
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException)
                {
                    continue;
                }

                for (var i = 0; i < map.InterfaceMethods.Length; i++)
                    Add(map.InterfaceMethods[i], map.TargetMethods[i]);
            }

            foreach (var method in type.GetMethods(Declared))
            {
                if (!method.IsVirtual)
                    continue;
                var baseDefinition = method.GetBaseDefinition();
                if (baseDefinition != method && _firstParty.Contains(baseDefinition.Module.Assembly))
                    Add(baseDefinition, method);
            }
        }

        void Add(MethodBase declared, MethodBase implementation)
        {
            var key = Definition(declared);
            if (!_implementations.TryGetValue(key, out var list))
                _implementations[key] = list = [];
            list.Add(Definition(implementation));
        }
    }

    private bool IsFirstParty(MethodBase method) => _firstParty.Contains(method.Module.Assembly);

    /// <summary>
    /// The definition behind a method of a constructed generic type or a generic method instance, so
    /// each body is walked once.
    /// </summary>
    private static MethodBase Definition(MethodBase method)
    {
        if (method is MethodInfo { IsGenericMethod: true, IsGenericMethodDefinition: false } instance)
            method = instance.GetGenericMethodDefinition();

        if (method.DeclaringType is { IsGenericType: true, IsGenericTypeDefinition: false })
        {
            try
            {
                return method.Module.ResolveMethod(method.MetadataToken)!;
            }
            catch (ArgumentException)
            {
                return method;
            }
        }

        return method;
    }

    private static IEnumerable<Type> LoadableTypes(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            return ex.Types.Where(t => t is not null)!;
        }
    }

    private static string Path(Dictionary<MethodBase, MethodBase?> parent, MethodBase method)
    {
        var steps = new List<string>();
        for (MethodBase? at = method; at is not null && steps.Count < 12; at = parent.GetValueOrDefault(at))
            steps.Add($"{at.DeclaringType?.Name}.{at.Name}");
        steps.Reverse();
        return string.Join(" -> ", steps);
    }
}
