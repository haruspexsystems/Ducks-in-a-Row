using Certus.Core.Configuration;

namespace Certus.Service.Tests;

/// <summary>
/// The service host refuses a database or a settings overlay outside the data folder
/// (issue #506), and refuses before it creates or writes anything there: a refusal that
/// came after the migration would already have put a database in the folder it refuses.
/// </summary>
public class DataFolderPlacementStartupTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ADatabaseOutsideTheDataFolder_StopsTheHost_BeforeAnythingIsWrittenThere(bool folderExists)
    {
        var elsewhere = Path.Combine(Path.GetTempPath(), "ducks-service-tests-db-" + Guid.NewGuid().ToString("N"));
        if (folderExists)
            Directory.CreateDirectory(elsewhere);

        var factory = new DatabaseElsewhere(elsewhere);
        try
        {
            var log = await BootAndReadLog(factory);
            log.Should().Contain("Certus:DatabasePath")
                .And.Contain(factory.DatabasePath)
                .And.Contain(DataFolderPlacement.TroubleshootingHeading);

            if (folderExists)
                Directory.EnumerateFileSystemEntries(elsewhere).Should().BeEmpty();
            else
                Directory.Exists(elsewhere).Should().BeFalse();
        }
        finally
        {
            // Disposed first: a host that did not refuse would hold the database open in there.
            factory.Dispose();
            if (Directory.Exists(elsewhere))
                Directory.Delete(elsewhere, recursive: true);
        }
    }

    [Fact]
    public async Task ASettingsOverlayOutsideTheDataFolder_StopsTheHost()
    {
        var elsewhere = Path.Combine(Path.GetTempPath(), "ducks-service-tests-overlay-" + Guid.NewGuid().ToString("N"));
        using var factory = new OverlayElsewhere(elsewhere);

        var log = await BootAndReadLog(factory);

        log.Should().Contain("Certus:SettingsOverlayPath")
            .And.Contain(factory.SettingsOverlayPath)
            .And.Contain(DataFolderPlacement.TroubleshootingHeading);
        Directory.Exists(elsewhere).Should().BeFalse();
    }

    // Bounded, so a host that hung instead of stopping fails here rather than holding the
    // run; a timeout is not the refusal, so it is not accepted as one.
    private static async Task<string> BootAndReadLog(ServiceHostFactory factory)
    {
        var boot = Task.Run(() => factory.CreateClient());
        var thrown = await FluentActions.Awaiting(() => boot.WaitAsync(TimeSpan.FromSeconds(60)))
            .Should().ThrowAsync<Exception>();
        thrown.Which.Should().NotBeOfType<TimeoutException>();

        return Directory.EnumerateFiles(Path.Combine(factory.DataDirectory, "logs"), "ducks-*.log")
            .Select(ReadShared)
            .Should().ContainSingle().Subject;
    }

    private static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private sealed class DatabaseElsewhere(string folder) : ServiceHostFactory
    {
        public override string DatabasePath => Path.Combine(folder, "ducks.db");
    }

    private sealed class OverlayElsewhere(string folder) : ServiceHostFactory
    {
        public override string SettingsOverlayPath => Path.Combine(folder, CertusPaths.SettingsOverlayFileName);
    }
}
