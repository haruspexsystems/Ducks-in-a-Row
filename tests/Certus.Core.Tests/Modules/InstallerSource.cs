using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// Reads <c>installer/Certus.wxs</c> for the tests that hold the MSI to the code it installs
/// (issue #495). tests/build/Test-BuildScripts.ps1 checks the installer authoring far more
/// closely, but it runs by hand only, so the two facts the module host itself depends on are
/// held here as well, where CI runs them. The installer sources ship in the public source
/// snapshot, so these tests run there too.
/// </summary>
internal static class InstallerSource
{
    private static readonly XNamespace Wix = "http://wixtoolset.org/schemas/v4/wxs";

    private static readonly Lazy<string> Text = new(() =>
        File.ReadAllText(Path.Combine(FindRepositoryRoot(), "installer", "Certus.wxs")));

    /// <summary>The value of a <c>&lt;?define Name = "value" ?&gt;</c> fallback, or null.</summary>
    public static string? Define(string name)
    {
        var match = Regex.Match(Text.Value, $"<\\?define {Regex.Escape(name)} = \"([^\"]*)\" \\?>");
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>The SDDL the named component's CreateFolder locks its folder with.</summary>
    public static string FolderSddl(string componentId) =>
        XDocument.Parse(Text.Value)
            .Descendants(Wix + "Component")
            .Single(c => (string?)c.Attribute("Id") == componentId)
            .Element(Wix + "CreateFolder")!
            .Element(Wix + "PermissionEx")!
            .Attribute("Sddl")!.Value;

    /// <summary>
    /// The account the named ServiceInstall element registers the service as. WiX registers a
    /// service with no Account attribute as LocalSystem, so an absent attribute reads that way.
    /// </summary>
    public static string ServiceAccount(string serviceInstallId) =>
        (string?)XDocument.Parse(Text.Value)
            .Descendants(Wix + "ServiceInstall")
            .Single(s => (string?)s.Attribute("Id") == serviceInstallId)
            .Attribute("Account") ?? "LocalSystem";

    /// <summary>The text of another file in the installer folder, such as install-service.ps1.</summary>
    public static string InstallerFile(string name) =>
        File.ReadAllText(Path.Combine(FindRepositoryRoot(), "installer", name));

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Certus.sln")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new InvalidOperationException(
            $"Could not find Certus.sln walking up from {AppContext.BaseDirectory}.");
    }
}
