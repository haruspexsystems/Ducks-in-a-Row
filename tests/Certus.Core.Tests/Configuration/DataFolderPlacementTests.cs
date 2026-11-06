using Certus.Core.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// The database and the settings overlay belong in the data folder (issue #506). Every
/// other place is refused, including ones that look close: a subfolder, a folder whose
/// name starts the same way, and a path that is not fully qualified.
/// </summary>
public class DataFolderPlacementTests
{
    private const string DataFolder = @"C:\ProgramData\Ducks in a Row";

    [Theory]
    [InlineData(@"C:\ProgramData\Ducks in a Row\ducks.db")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\another-name.db")]
    [InlineData(@"c:\programdata\ducks in a row\ducks.db")]
    [InlineData(@"C:/ProgramData/Ducks in a Row/ducks.db")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\sub\..\ducks.db")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\.\ducks.db")]
    public void ADatabaseInTheDataFolder_IsAllowed(string databasePath)
    {
        DataFolderPlacement.RefuseDatabase(databasePath, DataFolder).Should().BeNull();
    }

    [Fact]
    public void TheDataFolderMayCarryATrailingSeparator()
    {
        DataFolderPlacement.RefuseDatabase(@"C:\ProgramData\Ducks in a Row\ducks.db", DataFolder + @"\")
            .Should().BeNull();
    }

    [Fact]
    public void TheDefaultDatabasePath_IsAllowed()
    {
        DataFolderPlacement.RefuseDatabase(CertusPaths.DefaultDatabasePath, CertusPaths.DataDirectory)
            .Should().BeNull();
    }

    [Fact]
    public void TheInMemoryDatabase_IsAllowed()
    {
        DataFolderPlacement.RefuseDatabase(CertusPaths.InMemoryDatabase, DataFolder).Should().BeNull();
    }

    [Theory]
    [InlineData(@"D:\DucksData\ducks.db")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\db\ducks.db")]
    [InlineData(@"C:\ProgramData\ducks.db")]
    [InlineData(@"C:\ducks.db")]
    [InlineData(@"C:\ProgramData\Ducks in a Row2\ducks.db")]
    [InlineData(@"\\fileserver\share\Ducks in a Row\ducks.db")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\..\Ducks in a Row2\ducks.db")]
    public void ADatabaseAnywhereElse_IsRefused(string databasePath)
    {
        var refusal = DataFolderPlacement.RefuseDatabase(databasePath, DataFolder);

        refusal.Should().NotBeNull()
            .And.Contain("Certus:DatabasePath")
            .And.Contain($"'{databasePath}'")
            .And.Contain($"'{DataFolder}'")
            .And.Contain("outside the data folder")
            .And.Contain(DataFolderPlacement.TroubleshootingHeading);
    }

    [Theory]
    [InlineData("ducks.db")]
    [InlineData(@"..\ducks.db")]
    [InlineData(@"\ducks.db")]
    [InlineData(@"C:ducks.db")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\")]
    public void APathThatIsNotAFullPathToAFile_IsRefused(string databasePath)
    {
        var refusal = DataFolderPlacement.RefuseDatabase(databasePath, DataFolder);

        refusal.Should().NotBeNull()
            .And.Contain("not a full path to a file")
            .And.Contain($"'{DataFolder}'");
    }

    [Fact]
    public void TheRefusal_SaysWhatToMoveAndWhere()
    {
        var refusal = DataFolderPlacement.RefuseDatabase(@"D:\DucksData\ducks.db", DataFolder);

        refusal.Should().Contain("ducks.db-wal")
            .And.Contain("ducks-setup.json")
            .And.Contain("keys folder")
            .And.Contain("move the whole data folder");
    }

    [Fact]
    public void TheRefusal_CannotBreakTheLogLine()
    {
        var refusal = DataFolderPlacement.RefuseDatabase("D:\\Ducks\r\nForged line\\ducks.db", DataFolder);

        refusal.Should().NotBeNull();
        refusal!.Should().NotContainAny("\r", "\n");
    }

    [Fact]
    public void AnUnsetOverlayPath_IsAllowed()
    {
        DataFolderPlacement.RefuseSettingsOverlay(null, DataFolder).Should().BeNull();
    }

    [Theory]
    [InlineData(@"C:\ProgramData\Ducks in a Row\settings.json")]
    [InlineData(@"c:\programdata\ducks in a row\SETTINGS.JSON")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\sub\..\settings.json")]
    public void TheDataFoldersOwnSettingsFile_IsAllowed(string overlayPath)
    {
        DataFolderPlacement.RefuseSettingsOverlay(overlayPath, DataFolder).Should().BeNull();
    }

    [Theory]
    [InlineData(@"D:\DucksData\settings.json")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\other.json")]
    [InlineData(@"C:\ProgramData\Ducks in a Row\sub\settings.json")]
    [InlineData("settings.json")]
    [InlineData("")]
    public void AnyOtherOverlayPath_IsRefused(string overlayPath)
    {
        var refusal = DataFolderPlacement.RefuseSettingsOverlay(overlayPath, DataFolder);

        refusal.Should().NotBeNull()
            .And.Contain("Certus:SettingsOverlayPath")
            .And.Contain($@"'{DataFolder}\settings.json'")
            .And.Contain(DataFolderPlacement.TroubleshootingHeading);
    }
}
