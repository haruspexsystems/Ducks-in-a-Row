using System.Text.RegularExpressions;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// Holds the service on LocalSystem in both places that register it (issue #638). Running it as
/// the virtual service account NT SERVICE\DucksInARow was measured on a lab: the ADCS path works,
/// but on an upgrade the Data Protection keyring, DPAPI protected in the service account's own
/// scope, can no longer be decrypted, so every stored EAB secret and the saved SMTP password are
/// lost; and the data folder DACL, the HTTPS certificate's key, the machine certificate store, the
/// service's own DACL and the rights check's identity each need a change first. A one word edit
/// to either installer file would ship all of that silently, so the reason sits in the assertion.
/// </summary>
public class InstallerServiceAccountTests
{
    private const string Because =
        "a switch away from LocalSystem loses the DPAPI keyring on upgrade and needs the changes " +
        "measured in #638; read the 2026-10-25 entry in the installer design note first";

    [Fact]
    public void TheMsiRegistersTheService_AsLocalSystem()
    {
        InstallerSource.ServiceAccount("DucksService").Should().Be("LocalSystem", Because);
    }

    [Fact]
    public void TheDevelopmentInstallScript_RegistersTheService_AsLocalSystem()
    {
        var script = InstallerSource.InstallerFile("install-service.ps1");

        // sc.exe takes the value quoted or bare; either way it is the next token after obj=.
        var accounts = Regex.Matches(script, "obj=\\s*(?:\"([^\"]*)\"|([^\\s`\"]+))")
            .Select(m => m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value)
            .ToList();

        accounts.Should().ContainSingle(because: "install-service.ps1 registers the service once")
            .Which.Should().Be("LocalSystem", Because);
    }
}
