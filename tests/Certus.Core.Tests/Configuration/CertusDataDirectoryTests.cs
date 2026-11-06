using Certus.Core.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// The Development data directory override (issue #413, deviation Dv12). It must move a
/// Development host, and nothing else: no other environment, and no relative path that
/// would land wherever the process started.
/// </summary>
public class CertusDataDirectoryTests
{
    private static readonly string Elsewhere = Path.Combine(Path.GetTempPath(), "ducks-dev-data");

    [Fact]
    public void Development_UsesTheConfiguredFolder()
    {
        CertusDataDirectory.Resolve(Config(Elsewhere), Env(Environments.Development))
            .Should().Be(Elsewhere);
    }

    [Fact]
    public void Development_TrimsTheTrailingSeparator()
    {
        CertusDataDirectory.Resolve(Config(Elsewhere + Path.DirectorySeparatorChar), Env(Environments.Development))
            .Should().Be(Elsewhere);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Development_WithNothingConfigured_UsesTheMachineDataDirectory(string? value)
    {
        CertusDataDirectory.Resolve(Config(value), Env(Environments.Development))
            .Should().Be(CertusPaths.DataDirectory);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("development-ish")]
    public void AnyOtherEnvironment_IgnoresTheKey(string environment)
    {
        CertusDataDirectory.Resolve(Config(Elsewhere), Env(environment))
            .Should().Be(CertusPaths.DataDirectory);
    }

    [Theory]
    [InlineData("ducks-data")]
    [InlineData(@"..\ducks-data")]
    [InlineData(@"\ducks-data")]
    public void Development_RefusesAPathThatIsNotAbsolute(string value)
    {
        var resolve = () => CertusDataDirectory.Resolve(Config(value), Env(Environments.Development));

        resolve.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{CertusDataDirectory.DevelopmentKey}*absolute*");
    }

    private static IConfiguration Config(string? value) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [CertusDataDirectory.DevelopmentKey] = value })
            .Build();

    private static IHostEnvironment Env(string name) => new TestEnvironment { EnvironmentName = name };

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;

        public string ApplicationName { get; set; } = "Certus.Core.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
