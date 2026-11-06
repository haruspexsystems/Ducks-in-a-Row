using System.Text.Json;
using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Certus.Service.Tests;

/// <summary>
/// The settings overlay lives in the data directory, and anyone who can write that folder
/// can write the overlay (issue #489). So the overlay must never be able to say where the
/// data directory is: the service resolves it before the overlay is added (deviation Dv12).
/// </summary>
public class DataDirectoryOverlayTests
{
    // The host reads DOTNET_ prefixed variables as host configuration, which ranks below
    // appsettings.json and so below the overlay. The factory's usual UseSetting would not
    // do: it arrives as a command line argument, which outranks the overlay, so the
    // overlay's value could never win whatever order the host resolved in, and the first
    // version of this test passed with the order broken for exactly that reason.
    private const string WeakSource = "DOTNET_Certus__Development__DataDirectory";

    [Fact]
    public void TheOverlayCannotMoveTheDataDirectory()
    {
        var elsewhere = Path.Combine(Path.GetTempPath(), "ducks-service-tests-elsewhere-" + Guid.NewGuid().ToString("N"));
        var factory = new OverlayNamingAnotherDirectory(elsewhere);
        Environment.SetEnvironmentVariable(WeakSource, factory.DataDirectory);
        try
        {
            var services = factory.Services;
            var certus = services.GetRequiredService<IOptions<CertusOptions>>().Value;
            var configuration = services.GetRequiredService<IConfiguration>();

            // The positive controls. The overlay was read, and in configuration its value
            // for the key wins over the source that named the real folder. So a host that
            // resolved the folder after adding the overlay would have moved.
            certus.ExternalUrl.Should().Be(OverlayNamingAnotherDirectory.ExternalUrl);
            configuration[CertusDataDirectory.DevelopmentKey].Should().Be(elsewhere);

            Directory.Exists(elsewhere).Should().BeFalse("the host must not have written anything there");
            Directory.EnumerateFiles(Path.Combine(factory.DataDirectory, "logs"), "ducks-*.log")
                .Should().NotBeEmpty("the host wrote to the folder it was given");
        }
        finally
        {
            Environment.SetEnvironmentVariable(WeakSource, null);
            // Disposed first: a host that did move would hold its log file open in there.
            factory.Dispose();
            if (Directory.Exists(elsewhere))
                Directory.Delete(elsewhere, recursive: true);
        }
    }

    private sealed class OverlayNamingAnotherDirectory(string elsewhere) : ServiceHostFactory
    {
        public const string ExternalUrl = "https://overlay-was-read.example";

        protected override bool NamesDataDirectoryAsSetting => false;

        protected override void SeedDataDirectory(string dataDirectory)
        {
            // Nested the way the configuration provider reads it: Certus:Development:DataDirectory.
            var overlay = new { Certus = new { ExternalUrl, Development = new { DataDirectory = elsewhere } } };
            File.WriteAllText(
                Path.Combine(dataDirectory, CertusPaths.SettingsOverlayFileName),
                JsonSerializer.Serialize(overlay));
        }
    }
}
