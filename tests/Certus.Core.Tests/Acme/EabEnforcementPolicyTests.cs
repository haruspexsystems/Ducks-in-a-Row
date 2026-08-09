using Certus.Core.Acme.Services;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for EabEnforcementPolicy. A missing wizard status file, a file
/// written before the field existed, or an unrecognized value all read as
/// Off, so an upgraded install stays unenforced; recognized values parse
/// case insensitively; and edits hot reload the same way the allowed domain
/// policy does, keeping the last known mode across a transient read failure.
/// </summary>
public class EabEnforcementPolicyTests : IDisposable
{
    private readonly string _tempDir;
    private readonly CertusOptions _options;

    public EabEnforcementPolicyTests()
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

    private EabEnforcementPolicy BuildPolicy()
    {
        return new EabEnforcementPolicy(
            Options.Create(_options), NullLogger<EabEnforcementPolicy>.Instance);
    }

    private void WriteStatus(string? eabEnforcement)
    {
        var status = new SetupStatus
        {
            SetupCompleted = true,
            EnabledTemplates = ["WebServer"],
            EabEnforcement = eabEnforcement,
        };
        status.Save(SetupStatus.GetStatusPath(_options));
    }

    private void BumpWriteTime()
    {
        var path = SetupStatus.GetStatusPath(_options);
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddSeconds(1));
    }

    [Fact]
    public void Mode_NoStatusFile_IsOff()
    {
        BuildPolicy().Mode.Should().Be(EabEnforcementMode.Off);
    }

    [Fact]
    public void Mode_FileWithoutTheField_IsOff()
    {
        // A status file written before EAB existed: the upgrade path.
        WriteStatus(null);

        BuildPolicy().Mode.Should().Be(EabEnforcementMode.Off);
    }

    [Fact]
    public void Mode_UnrecognizedValue_IsOff()
    {
        WriteStatus("banana");

        BuildPolicy().Mode.Should().Be(EabEnforcementMode.Off);
    }

    [Theory]
    [InlineData("off", EabEnforcementMode.Off)]
    [InlineData("optional", EabEnforcementMode.Optional)]
    [InlineData("required", EabEnforcementMode.Required)]
    [InlineData("Required", EabEnforcementMode.Required)]
    [InlineData("  OPTIONAL  ", EabEnforcementMode.Optional)]
    public void Mode_RecognizedValues_ParseCaseInsensitively(
        string value, EabEnforcementMode expected)
    {
        WriteStatus(value);

        BuildPolicy().Mode.Should().Be(expected);
    }

    [Fact]
    public void Mode_ReloadsWhenTheFileChanges()
    {
        WriteStatus("optional");
        var sut = BuildPolicy();
        sut.Mode.Should().Be(EabEnforcementMode.Optional);

        // A settings page save rewrites the file; the policy must pick up the
        // new mode without a restart. Bump the write time explicitly so the
        // test does not depend on file system timestamp resolution.
        WriteStatus("required");
        BumpWriteTime();

        sut.Mode.Should().Be(EabEnforcementMode.Required);
    }

    [Fact]
    public void Mode_TransientReadFailure_KeepsTheLastKnownMode()
    {
        WriteStatus("required");
        var sut = BuildPolicy();
        sut.Mode.Should().Be(EabEnforcementMode.Required);

        // Bump the write time so the cache would reload, then hold the file
        // open exclusively (an antivirus scanner or backup does the same).
        // The reload fails; the policy must keep the last known mode instead
        // of caching a fail open decision.
        var path = SetupStatus.GetStatusPath(_options);
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddSeconds(1));
        using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            sut.Mode.Should().Be(EabEnforcementMode.Required);
        }

        // Lock released: the next request reloads normally.
        sut.Mode.Should().Be(EabEnforcementMode.Required);
    }

    [Fact]
    public void Mode_FileAppearsAfterFirstCheck_IsPickedUp()
    {
        var sut = BuildPolicy();
        sut.Mode.Should().Be(EabEnforcementMode.Off, "no file means off");

        WriteStatus("required");

        sut.Mode.Should().Be(EabEnforcementMode.Required);
    }

    [Theory]
    [InlineData("off", true, EabEnforcementMode.Off)]
    [InlineData("Optional", true, EabEnforcementMode.Optional)]
    [InlineData("REQUIRED", true, EabEnforcementMode.Required)]
    [InlineData("banana", false, EabEnforcementMode.Off)]
    [InlineData("", false, EabEnforcementMode.Off)]
    [InlineData(null, false, EabEnforcementMode.Off)]
    public void TryParseMode_IsStrict(string? value, bool expectedOk, EabEnforcementMode expectedMode)
    {
        var ok = EabEnforcementPolicy.TryParseMode(value, out var mode);

        ok.Should().Be(expectedOk);
        mode.Should().Be(expectedMode);
    }

    [Theory]
    [InlineData(EabEnforcementMode.Off, "off")]
    [InlineData(EabEnforcementMode.Optional, "optional")]
    [InlineData(EabEnforcementMode.Required, "required")]
    public void ModeName_IsTheCanonicalLowercaseForm(EabEnforcementMode mode, string expected)
    {
        EabEnforcementPolicy.ModeName(mode).Should().Be(expected);
    }
}
