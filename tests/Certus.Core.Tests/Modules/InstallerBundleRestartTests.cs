using System.Xml.Linq;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// Holds the setup bundle to never restarting the server because of the runtime it installs
/// (decided 2026-11-07). WixStdBA takes its restart policy from its command line alone, and under
/// <c>/quiet</c> or <c>/passive</c> with no <c>/norestart</c> it restarts the server by itself as
/// soon as any package reports a restart. No bundle setting changes that, so the only lever is the
/// Hosting Bundle package's exit code mapping: 3010 and 1641 must both read as plain success.
/// Burn treats either code as a restart when it is left unmapped, so an absent mapping fails too.
/// tests/build/Test-BuildScripts.ps1 checks the same with planted defects, but it runs by hand
/// only, so the rule is held here as well, where CI runs it.
/// </summary>
public class InstallerBundleRestartTests
{
    private static readonly XNamespace Wix = "http://wixtoolset.org/schemas/v4/wxs";

    private const string Because =
        "WixStdBA restarts the server by itself under /quiet or /passive when a package reports a " +
        "restart, and the setup must never do that; read the comment above the package in Bundle.wxs";

    private static XDocument Bundle() => XDocument.Parse(InstallerSource.InstallerFile("Bundle.wxs"));

    [Theory]
    [InlineData("3010")]
    [InlineData("1641")]
    public void TheRuntimePackage_MapsARestartCode_ToPlainSuccess(string code)
    {
        var package = Bundle().Descendants(Wix + "ExePackage")
            .Single(p => (string?)p.Attribute("Id") == "AspNetCoreHostingBundle");

        package.Elements(Wix + "ExitCode")
            .Where(e => (string?)e.Attribute("Value") == code)
            .Select(e => (string?)e.Attribute("Behavior"))
            .Should().ContainSingle(Because).Which.Should().Be("success", Because);
    }

    [Fact]
    public void NoPackageInTheChain_AsksBurnForARestart()
    {
        Bundle().Descendants(Wix + "Chain").Descendants(Wix + "ExitCode")
            .Select(e => (string?)e.Attribute("Behavior") ?? "")
            .Should().NotContain(b => b.Contains("Reboot", StringComparison.Ordinal), Because);
    }
}
