using Certus.Core.Modules;
using Certus.Modules;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// What counts as the shared framework a module may take from the default load context (licence
/// design section 6.2, steps 4 and 6; issue #538): an assembly the trusted platform assembly list
/// places under the Microsoft.NETCore.App or Microsoft.AspNetCore.App folder of the framework this
/// process runs on, and nothing the application carries for itself.
/// </summary>
public class SharedFrameworkTests
{
    private const string Runtime = @"C:\dotnet\shared\Microsoft.NETCore.App\10.0.1\";

    private static string List(params string[] paths) => string.Join(Path.PathSeparator, paths);

    [Fact]
    public void BothSharedFrameworks_Count_AndTheApplicationsOwnAssembliesDoNot()
    {
        var names = SharedFramework.FromTrustedPlatformAssemblies(List(
            @"C:\dotnet\shared\Microsoft.NETCore.App\10.0.1\System.Runtime.dll",
            @"C:\dotnet\shared\Microsoft.AspNetCore.App\10.0.1\Microsoft.AspNetCore.Http.dll",
            @"C:\Program Files\Ducks in a Row\Serilog.dll",
            @"C:\Program Files\Ducks in a Row\Certus.Modules.Abstractions.dll"), Runtime);

        names.Should().BeEquivalentTo(["System.Runtime", "Microsoft.AspNetCore.Http"]);
    }

    [Fact]
    public void AnotherSharedFramework_DoesNotCount()
    {
        // Windows Desktop is a shared framework too, but not one the service runs on or shares.
        var names = SharedFramework.FromTrustedPlatformAssemblies(List(
            @"C:\dotnet\shared\Microsoft.WindowsDesktop.App\10.0.1\System.Windows.Forms.dll"), Runtime);

        names.Should().BeEmpty();
    }

    [Fact]
    public void AFolderThatIsOnlyNamedLikeTheFramework_DoesNotCount()
    {
        // The folders are found from the runtime directory, not by their name alone.
        var names = SharedFramework.FromTrustedPlatformAssemblies(List(
            @"C:\Program Files\Ducks in a Row\shared\Microsoft.NETCore.App\10.0.1\Planted.dll"), Runtime);

        names.Should().BeEmpty();
    }

    [Fact]
    public void ASelfContainedProcess_HasNoSharedFramework_SoNothingCounts()
    {
        // A self contained build runs its framework from its own folder. There is no shared
        // framework to share, and the check fails closed rather than guessing.
        var names = SharedFramework.FromTrustedPlatformAssemblies(List(
            @"C:\Program Files\Ducks in a Row\System.Runtime.dll"), @"C:\Program Files\Ducks in a Row\");

        names.Should().BeEmpty();
    }

    [Fact]
    public void NoList_MeansNoFramework()
    {
        SharedFramework.FromTrustedPlatformAssemblies(null, Runtime).Should().BeEmpty();
        SharedFramework.FromTrustedPlatformAssemblies(List(@"C:\dotnet\shared\Microsoft.NETCore.App\10.0.1\System.Runtime.dll"), null)
            .Should().BeEmpty();
    }

    [Fact]
    public void InThisProcess_TheFrameworkCounts_AndTheContractAndTheCoresDependenciesDoNot()
    {
        // The positive control: the test host is framework dependent, like the service, so the real
        // list must place System.Runtime in the framework. Without it every other assertion here
        // would pass on an empty set.
        SharedFramework.Contains("System.Runtime").Should().BeTrue();
        SharedFramework.Contains("system.runtime").Should().BeTrue("assembly names compare without regard to case");

        SharedFramework.Contains(typeof(ICertusModule).Assembly.GetName().Name).Should().BeFalse();
        SharedFramework.Contains(typeof(ModuleLoader).Assembly.GetName().Name).Should().BeFalse();
        SharedFramework.Contains(typeof(Microsoft.EntityFrameworkCore.DbContext).Assembly.GetName().Name).Should().BeFalse();
        SharedFramework.Contains(typeof(Org.BouncyCastle.Asn1.Asn1Object).Assembly.GetName().Name).Should().BeFalse();
        SharedFramework.Contains(null).Should().BeFalse();
    }
}
