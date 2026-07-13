using Certus.Core.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// Normalization of the installer written data directory registry value. MSI
/// directory properties resolve with a trailing backslash; blank values must
/// fall back to the default directory.
/// </summary>
public class CertusPathsTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\\")]
    public void NormalizeDataDirectory_BlankValues_ReturnNull(string? value)
    {
        CertusPaths.NormalizeDataDirectory(value).Should().BeNull();
    }

    [Theory]
    [InlineData(@"D:\DucksData\", @"D:\DucksData")]
    [InlineData(@"D:\DucksData", @"D:\DucksData")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\", @"C:\ProgramData\Ducks in a Row")]
    public void NormalizeDataDirectory_TrimsTrailingSeparators(string value, string expected)
    {
        CertusPaths.NormalizeDataDirectory(value).Should().Be(expected);
    }

    [Fact]
    public void SettingsOverlayPath_IsInsideTheDataDirectory()
    {
        CertusPaths.SettingsOverlayPath.Should().Be(
            Path.Combine(CertusPaths.DataDirectory, "settings.json"));
    }
}
