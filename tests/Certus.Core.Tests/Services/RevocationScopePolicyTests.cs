using Certus.Core.Configuration;
using Certus.Core.Services;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Services;

/// <summary>
/// Tests for RevocationScopePolicy, the three mode hot read twin of
/// EabEnforcementPolicy. A missing wizard status file, a file written before
/// the fields existed, or an unrecognized value all read as ducks-managed,
/// the safe default; recognized values parse case insensitively; edits hot
/// reload on the file's write time; and the snapshot carries the custom list
/// and the enabled template set from the same read.
/// </summary>
public class RevocationScopePolicyTests : IDisposable
{
    private readonly string _tempDir;
    private readonly CertusOptions _options;

    public RevocationScopePolicyTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _options = new CertusOptions { DatabasePath = Path.Combine(_tempDir, "certus.db") };
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: a stray temp folder is harmless.
        }
    }

    private RevocationScopePolicy BuildPolicy()
    {
        return new RevocationScopePolicy(
            Options.Create(_options), NullLogger<RevocationScopePolicy>.Instance);
    }

    private void WriteStatus(
        string? revocationScope,
        List<string>? revocableTemplates = null,
        List<string>? enabledTemplates = null)
    {
        var status = new SetupStatus
        {
            SetupCompleted = true,
            EnabledTemplates = enabledTemplates ?? ["WebServer"],
            RevocationScope = revocationScope,
            RevocableTemplates = revocableTemplates ?? [],
        };
        status.Save(SetupStatus.GetStatusPath(_options));
    }

    private void BumpWriteTime()
    {
        var path = SetupStatus.GetStatusPath(_options);
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddSeconds(1));
    }

    [Fact]
    public void Snapshot_NoStatusFile_IsDucksManagedWithEmptySets()
    {
        var snapshot = BuildPolicy().GetSnapshot();

        snapshot.Mode.Should().Be(RevocationScopeMode.DucksManaged);
        snapshot.CustomTemplates.Should().BeEmpty();
        snapshot.EnabledTemplates.Should().BeEmpty();
    }

    [Fact]
    public void Snapshot_FileWithoutTheFields_IsDucksManaged()
    {
        // A status file written before the scope existed: the upgrade path.
        WriteStatus(null);

        BuildPolicy().GetSnapshot().Mode.Should().Be(RevocationScopeMode.DucksManaged);
    }

    [Fact]
    public void Snapshot_UnrecognizedValue_IsDucksManaged()
    {
        WriteStatus("banana");

        BuildPolicy().GetSnapshot().Mode.Should().Be(RevocationScopeMode.DucksManaged);
    }

    [Theory]
    [InlineData("ducks-managed", RevocationScopeMode.DucksManaged)]
    [InlineData("custom", RevocationScopeMode.Custom)]
    [InlineData("all", RevocationScopeMode.All)]
    [InlineData("All", RevocationScopeMode.All)]
    [InlineData(" Custom ", RevocationScopeMode.Custom)]
    public void Snapshot_RecognizedValue_ParsesCaseInsensitively(
        string value, RevocationScopeMode expected)
    {
        WriteStatus(value);

        BuildPolicy().GetSnapshot().Mode.Should().Be(expected);
    }

    [Fact]
    public void Snapshot_CarriesTheListsFromTheSameRead()
    {
        WriteStatus("custom",
            revocableTemplates: ["WebServer", "DevicesTemplate"],
            enabledTemplates: ["WebServer", "AcmeClient"]);

        var snapshot = BuildPolicy().GetSnapshot();

        snapshot.CustomTemplates.Should().Equal("WebServer", "DevicesTemplate");
        snapshot.EnabledTemplates.Should().Equal("WebServer", "AcmeClient");
    }

    [Fact]
    public void Snapshot_HotReloadsOnWriteTimeChange()
    {
        WriteStatus("ducks-managed");
        var policy = BuildPolicy();
        policy.GetSnapshot().Mode.Should().Be(RevocationScopeMode.DucksManaged);

        WriteStatus("all");
        BumpWriteTime();

        policy.GetSnapshot().Mode.Should().Be(RevocationScopeMode.All);
    }

    [Fact]
    public void Snapshot_UnchangedWriteTime_ServesTheCache()
    {
        WriteStatus("custom", revocableTemplates: ["WebServer"]);
        var policy = BuildPolicy();
        var first = policy.GetSnapshot();

        // Same write time: the second read must serve the cached snapshot
        // rather than re-reading the file.
        policy.GetSnapshot().Should().BeSameAs(first);
    }

    [Theory]
    [InlineData("ducks-managed", true, RevocationScopeMode.DucksManaged)]
    [InlineData("custom", true, RevocationScopeMode.Custom)]
    [InlineData("ALL", true, RevocationScopeMode.All)]
    [InlineData("banana", false, RevocationScopeMode.DucksManaged)]
    [InlineData("", false, RevocationScopeMode.DucksManaged)]
    [InlineData(null, false, RevocationScopeMode.DucksManaged)]
    public void TryParseMode_IsStrict(string? value, bool expectedOk, RevocationScopeMode expectedMode)
    {
        var ok = RevocationScopePolicy.TryParseMode(value, out var mode);

        ok.Should().Be(expectedOk);
        mode.Should().Be(expectedMode);
    }

    [Theory]
    [InlineData(RevocationScopeMode.DucksManaged, "ducks-managed")]
    [InlineData(RevocationScopeMode.Custom, "custom")]
    [InlineData(RevocationScopeMode.All, "all")]
    public void ModeName_IsTheCanonicalLowercaseForm(RevocationScopeMode mode, string expected)
    {
        RevocationScopePolicy.ModeName(mode).Should().Be(expected);
    }
}
