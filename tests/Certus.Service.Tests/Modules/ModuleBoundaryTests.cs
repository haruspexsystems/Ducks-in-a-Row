using System.Reflection;
using Certus.Core.Acme.Services;
using Certus.Core.Alerts;
using Certus.Core.Crl;
using Certus.Core.Modules;
using Certus.Core.Services;
using Certus.Core.Setup;
using Certus.Web.Controllers.Settings;
using Certus.Web.Controllers.Setup;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Certus.Service.Tests.Modules;

/// <summary>
/// The structural half of the licence invariant (licence design section 18.2, issue #413): the
/// module contract is touched by the module host alone, nothing on the issuance path can reach the
/// module host, and the module host carries no signature code. Each scan reads all four product
/// assemblies, carries a positive control that proves it can see what it looks for, and a floor on
/// what it scanned, so a scan that sees nothing cannot pass.
/// </summary>
public class ModuleBoundaryTests
{
    private const string ContractAssembly = "Certus.Modules.Abstractions";
    private const string ModulesNamespace = "Certus.Core.Modules";

    private static readonly Assembly Core = typeof(ModuleHost).Assembly;
    private static readonly Assembly Adcs = Assembly.Load("Certus.Adcs");
    private static readonly Assembly Web = typeof(LicenceController).Assembly;
    private static readonly Assembly Service = typeof(ServiceHostEntryPoint).Assembly;
    private static readonly Assembly[] Product = [Core, Adcs, Web, Service];

    // ---- OnlyTheModuleHostTouchesTheContract ----

    [Fact]
    public void OnlyTheModuleHostTouchesTheContract()
    {
        var scanned = 0;
        var hostSeen = false;
        var violations = new List<string>();

        foreach (var assembly in Product)
        {
            foreach (var type in MetadataReferenceScan.Scan(assembly.Location, t => t.Assembly == ContractAssembly))
            {
                scanned++;
                if (!type.Matched)
                    continue;

                // Deviation Dv15: the licence controller is not on this list. It works from the core's
                // own views, so the module host's namespace is the only place the contract appears.
                if (assembly == Core && type.OwnerNamespace == ModulesNamespace)
                {
                    hostSeen |= type.FullName == typeof(ModuleHost).FullName;
                    continue;
                }

                violations.Add($"{assembly.GetName().Name}: {type.FullName}");
            }
        }

        hostSeen.Should().BeTrue("the module host refers to the contract, and a scan that cannot see that sees nothing");
        scanned.Should().BeGreaterThan(500, "all four product assemblies were scanned");
        violations.Should().BeEmpty("only the Certus.Core.Modules namespace may refer to the module contract");
    }

    [Fact]
    public void NoProductAssemblyButTheCore_ReferencesTheContractAssembly()
    {
        // The compiler emits an assembly reference only when a type from that assembly is used, so
        // this is the same rule read off the manifest, and it cannot be fooled by a body the IL scan
        // misreads.
        MetadataReferenceScan.AssemblyReferences(Core.Location).Should().Contain(ContractAssembly);
        foreach (var assembly in new[] { Adcs, Web, Service })
            MetadataReferenceScan.AssemblyReferences(assembly.Location).Should().NotContain(ContractAssembly, assembly.GetName().Name);
    }

    // ---- OnlyTheLicenceApiReadsTheLicenceStatus ----

    [Fact]
    public void OnlyTheLicenceApiReadsTheLicenceStatus()
    {
        // The free product boundary (issue #652, issue #655): the core never branches on a tier.
        // The licence status reaches the operator through the licence API alone, and the dashboard's
        // banner and licence card read that API, never the source itself. The module host's own
        // namespace defines, implements and registers the source, and its licence alert pass reads it
        // there (#494), so the rule is that namespace plus the licence controller and nothing else.
        var violations = new List<string>();
        var controllerSeen = false;
        var hostSeen = false;

        foreach (var assembly in Product)
        {
            foreach (var type in MetadataReferenceScan.Scan(assembly.Location, IsLicenceStatusSource))
            {
                if (!type.Matched)
                    continue;

                if (assembly == Core && type.OwnerNamespace == ModulesNamespace)
                {
                    hostSeen |= type.FullName == typeof(ModuleHost).FullName;
                    continue;
                }

                // Its async state machines are nested types of their own (LicenceController+<Inspect>d__9),
                // and they are the controller's code.
                var controller = typeof(LicenceController).FullName!;
                if (assembly == Web && (type.FullName == controller || type.FullName.StartsWith(controller + "+", StringComparison.Ordinal)))
                {
                    controllerSeen = true;
                    continue;
                }

                violations.Add($"{assembly.GetName().Name}: {type.FullName}");
            }
        }

        // Positive controls: both allowed readers are seen, so a scan that sees nothing cannot pass.
        hostSeen.Should().BeTrue("the module host implements the licence status source");
        controllerSeen.Should().BeTrue("the licence controller reads the licence status source");
        violations.Should().BeEmpty(
            "only the licence controller and the module host's namespace may read ILicenceStatusSource, so no free feature can branch on a tier");
    }

    private static bool IsLicenceStatusSource(TypeName type) =>
        type.Namespace == ModulesNamespace && type.Name == nameof(ILicenceStatusSource);

    // ---- IssuancePathNeverReachesTheModuleHost ----

    [Fact]
    public void IssuancePathNeverReachesTheModuleHost()
    {
        var graph = new CallGraph(Product, IsModuleHostSide);

        var walk = graph.From(IssuanceEntryPoints());

        walk.Reaches.Should().BeEmpty("nothing on the protected surface (design section 2.2) may reach the module host");
        walk.Unresolved.Should().Be(0, "a token the walker cannot resolve hides whatever that instruction calls");

        // Anti vacuity: the walk went deep, through the order service into the CA client behind its
        // interface, and on through the server certificate enrolment (W2).
        walk.Visited.Count.Should().BeGreaterThan(300);
        walk.Visited.Should().Contain(m => m.DeclaringType == typeof(OrderService) && m.Name == nameof(OrderService.FinalizeOrderAsync));
        walk.Visited.Should().Contain(m => m.DeclaringType!.FullName == "Certus.Adcs.AdcsClient");
        walk.Visited.Should().Contain(m => m.DeclaringType == typeof(TlsCertificateEnroller));

        // And through the licence alert the notifiers build (issue #494): its builder is reached from
        // a notifier, so it is on the protected side and must stay clear of the module host.
        walk.Visited.Should().Contain(m => m.DeclaringType == typeof(EmailAlertNotifier) && m.Name == "BuildLicenceMessage");
    }

    [Fact]
    public void TheCallGraph_SeesAReachWhenThereIsOne()
    {
        // The positive control: the licence API does reach the module host, through the interfaces
        // the container hands it, so a walker that missed this would miss a regression too.
        var graph = new CallGraph(Product, IsModuleHostSide);

        var walk = graph.From(typeof(LicenceController).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly));

        walk.Reaches.Should().NotBeEmpty();
        walk.Reaches.Should().Contain(r => r.Contains(nameof(IModuleHostControl)));
    }

    /// <summary>
    /// Every entry point of the protected surface (design section 2.2), plus every middleware and
    /// health check, because those run on every request including the ACME ones.
    /// </summary>
    private static IEnumerable<MethodBase> IssuanceEntryPoints()
    {
        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance
            | BindingFlags.Static | BindingFlags.DeclaredOnly;

        var whole = new List<Type>
        {
            typeof(OrderService),                       // W1, W3, W5
            typeof(TlsCertificateEnroller),             // W2
            typeof(HttpsCertificateRenewalService),     // W2, the renew button
            typeof(HttpsCertificateAutoRenewalService), // W2, unattended
            typeof(CertificateRevocationService),       // W4
            typeof(ChallengeValidationService),         // F1
            typeof(PendingIssuanceService),             // F2
            typeof(CertificateSyncService),             // F4
            typeof(ExpiryMonitorService),               // F4
            typeof(CrlMonitorService),                  // F4
        };

        var productTypes = Product.SelectMany(a => a.GetTypes()).ToList();

        // F3: every ACME controller, revoke-cert (W3) among them.
        whole.AddRange(productTypes.Where(t => t.Namespace == "Certus.Web.Controllers.Acme" && !t.IsAbstract));

        // F4: every alert notifier.
        whole.AddRange(productTypes.Where(t => !t.IsInterface && !t.IsAbstract && typeof(IAlertNotifier).IsAssignableFrom(t)));

        // Every middleware and health check.
        whole.AddRange(productTypes.Where(t => !t.IsAbstract && t.GetMethods(all).Any(IsMiddlewareInvoke)));
        whole.AddRange(productTypes.Where(t => !t.IsInterface && !t.IsAbstract && typeof(IHealthCheck).IsAssignableFrom(t)));

        whole.Should().Contain(t => t.Name == "RevokeCertController");
        whole.Should().Contain(t => t.Name == "CsrfHeaderMiddleware");

        foreach (var type in whole.Distinct())
        {
            foreach (var method in type.GetMethods(all))
                yield return method;
            foreach (var constructor in type.GetConstructors(all))
                yield return constructor;
        }

        // W2 from the dashboard and the wizard: those two actions only, since the rest of their
        // controllers are not on the protected surface.
        yield return Action(typeof(SettingsController), "https-certificate/renew");
        yield return Action(typeof(SetupController), "tls-certificate");
    }

    private static bool IsMiddlewareInvoke(MethodInfo method) =>
        method.Name is "Invoke" or "InvokeAsync"
        && method.GetParameters() is [{ ParameterType: var first }, ..]
        && first == typeof(HttpContext);

    private static MethodInfo Action(Type controller, string template) =>
        controller.GetMethods().Single(m => m.GetCustomAttributes<HttpMethodAttribute>().Any(a => a.Template == template));

    /// <summary>The module host's side of the boundary: its namespace and the contract assembly.</summary>
    private static bool IsModuleHostSide(Type type)
    {
        // A generic parameter's DeclaringType is the generic that declares it, which says nothing
        // about what the parameter will be bound to.
        if (type.IsGenericParameter)
            return false;

        var outer = type;
        while (outer.DeclaringType is { } declaring)
            outer = declaring;
        return outer.Namespace == ModulesNamespace || type.Assembly.GetName().Name == ContractAssembly;
    }

    // ---- CoreModulesUseNoSignatureCrypto ----

    private static readonly HashSet<string> SignatureTypes =
    [
        "AsymmetricAlgorithm", "AsymmetricSignatureDeformatter", "AsymmetricSignatureFormatter",
        "RSA", "RSACng", "RSACryptoServiceProvider", "RSAOpenSsl",
        "RSAPKCS1SignatureDeformatter", "RSAPKCS1SignatureFormatter",
        "DSA", "DSACng", "DSACryptoServiceProvider", "DSAOpenSsl",
        "DSASignatureDeformatter", "DSASignatureFormatter",
        "ECAlgorithm", "ECDsa", "ECDsaCng", "ECDsaOpenSsl", "ECDiffieHellman",
        "KeyedHashAlgorithm", "HMAC", "HMACMD5", "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512",
        "HMACSHA3_256", "HMACSHA3_384", "HMACSHA3_512",
        "MLDsa", "SlhDsa", "CompositeMLDsa",
    ];

    private static bool IsSignatureCrypto(TypeName type) =>
        type.Namespace.StartsWith("Org.BouncyCastle", StringComparison.Ordinal)
        || (type.Namespace == "System.Security.Cryptography" && SignatureTypes.Contains(type.Name))
        || type.Name.Contains("Ed25519", StringComparison.OrdinalIgnoreCase)
        || type.Name.Contains("EdDsa", StringComparison.OrdinalIgnoreCase)
        || type.Namespace == "Certus.Core.Acme.Crypto"; // the core's own JWS verification

    private static bool IsSignatureMember(string name) =>
        name is "SignData" or "SignHash" or "VerifyData" or "VerifyHash" or "TrySignData" or "TrySignHash";

    [Fact]
    public void CoreModulesUseNoSignatureCrypto()
    {
        var scan = MetadataReferenceScan.Scan(Core.Location, IsSignatureCrypto, IsSignatureMember);
        var modules = scan.Where(t => t.OwnerNamespace == ModulesNamespace).ToList();

        // The positive control: the CRL signature check elsewhere in the core is exactly what this
        // scan exists to find, so the scan must flag it.
        scan.Should().Contain(t => t.FullName == typeof(CrlSignatureVerifier).FullName && t.Matched);
        modules.Count.Should().BeGreaterThan(15, "the module host's namespace was scanned");
        modules.Where(t => t.Matched).Select(t => t.FullName).Should().BeEmpty(
            "the core never verifies a licence (design section 2.4, rule 4), so the module host holds no signature code");
    }
}
