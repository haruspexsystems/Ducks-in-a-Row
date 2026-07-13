using System.IO;
using Certus.Core.Configuration;

namespace Certus.Core.Tests.Configuration;

/// <summary>
/// Regression coverage for the database path resolution. appsettings ships
/// "DatabasePath": null and the configuration binder applies that null over the
/// property initializer, so at runtime the service was left with an empty Data
/// Source. That opens a throwaway temporary database per connection and the
/// startup migration crashed with "no such table: __EFMigrationsHistory".
/// NormalizeDatabasePath resolves the unset value back to the default.
/// </summary>
public class CertusOptionsTests
{
    [Fact]
    public void NormalizeDatabasePath_Null_ResolvesToDefault()
    {
        var options = new CertusOptions { DatabasePath = null! };

        options.NormalizeDatabasePath();

        options.DatabasePath.Should().Be(CertusPaths.DefaultDatabasePath);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void NormalizeDatabasePath_Blank_ResolvesToDefault(string blank)
    {
        var options = new CertusOptions { DatabasePath = blank };

        options.NormalizeDatabasePath();

        options.DatabasePath.Should().Be(CertusPaths.DefaultDatabasePath);
    }

    [Fact]
    public void NormalizeDatabasePath_ConfiguredPath_IsPreserved()
    {
        var path = Path.Combine(Path.GetTempPath(), "ducks-test", "ducks.db");
        var options = new CertusOptions { DatabasePath = path };

        options.NormalizeDatabasePath();

        options.DatabasePath.Should().Be(path);
    }

    [Fact]
    public void NormalizeDatabasePath_InMemorySentinel_IsPreserved()
    {
        var options = new CertusOptions { DatabasePath = CertusPaths.InMemoryDatabase };

        options.NormalizeDatabasePath();

        options.DatabasePath.Should().Be(CertusPaths.InMemoryDatabase);
    }
}
