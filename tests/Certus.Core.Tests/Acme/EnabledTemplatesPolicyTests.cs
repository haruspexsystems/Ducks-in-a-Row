using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for EnabledTemplatesPolicy (issues #85 and #101). The policy fails
/// closed: a missing wizard status file, an empty enabled list, and an
/// unreadable file all expose nothing. A non empty list restricts ACME to the
/// listed templates, matched by programmatic name or display name, case
/// insensitive. Certus:Acme:ExposeAllTemplates is the explicit break-glass
/// override and wins over a recorded set.
/// </summary>
public class EnabledTemplatesPolicyTests : IDisposable
{
    private static readonly TemplateInfo WebServer =
        new("WebServerACME", "Web Server ACME", "1.2.3");
    private static readonly TemplateInfo Machine =
        new("Machine", "Computer", "1.2.4");

    private readonly string _tempDir;
    private readonly CertusOptions _options;

    public EnabledTemplatesPolicyTests()
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

    private EnabledTemplatesPolicy BuildPolicy(bool exposeAll = false)
    {
        return new EnabledTemplatesPolicy(
            Options.Create(_options),
            Options.Create(new AcmeOptions { ExposeAllTemplates = exposeAll }),
            NullLogger<EnabledTemplatesPolicy>.Instance);
    }

    private void WriteStatus(params string[] enabledTemplates)
    {
        var status = new SetupStatus
        {
            SetupCompleted = true,
            EnabledTemplates = enabledTemplates.ToList(),
        };
        status.Save(SetupStatus.GetStatusPath(_options));
    }

    /// <summary>
    /// Advances the status file's write time so the policy's write time cache
    /// sees a change without the test depending on file system timestamp
    /// resolution.
    /// </summary>
    private void BumpWriteTime()
    {
        var path = SetupStatus.GetStatusPath(_options);
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddSeconds(1));
    }

    [Fact]
    public void IsEnabled_NoStatusFile_ExposesNothing()
    {
        var sut = BuildPolicy();

        sut.IsEnabled(WebServer).Should().BeFalse();
        sut.IsEnabled(Machine).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_EmptyList_ExposesNothing()
    {
        // The wizard requires at least one template at completion, so an empty
        // list is a pre completion draft or a hand edited file. Either way it
        // must expose nothing (issue #101).
        WriteStatus();
        var sut = BuildPolicy();

        sut.IsEnabled(WebServer).Should().BeFalse();
        sut.IsEnabled(Machine).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_UnparseableFile_ExposesNothing()
    {
        // A corrupt status file must fail closed, not fall through to the old
        // allow all (issue #101).
        File.WriteAllText(SetupStatus.GetStatusPath(_options), "{this is not json");
        var sut = BuildPolicy();

        sut.IsEnabled(WebServer).Should().BeFalse();
        sut.IsEnabled(Machine).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_MatchesProgrammaticName()
    {
        WriteStatus("WebServerACME");
        var sut = BuildPolicy();

        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_MatchesDisplayName()
    {
        WriteStatus("Web Server ACME");
        var sut = BuildPolicy();

        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_CaseInsensitive()
    {
        WriteStatus("webserveracme");
        var sut = BuildPolicy();

        sut.IsEnabled(WebServer).Should().BeTrue();
    }

    [Fact]
    public void IsEnabled_ReloadsWhenFileChanges()
    {
        WriteStatus("Machine");
        var sut = BuildPolicy();
        sut.IsEnabled(WebServer).Should().BeFalse();

        // A wizard re run rewrites the file; the policy must pick up the new
        // set without a restart.
        WriteStatus("WebServerACME");
        BumpWriteTime();

        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_FileAppearsAfterFirstCheck_Restricts()
    {
        var sut = BuildPolicy();
        sut.IsEnabled(Machine).Should().BeFalse("no file means nothing is exposed");

        WriteStatus("WebServerACME");

        sut.IsEnabled(Machine).Should().BeFalse();
        sut.IsEnabled(WebServer).Should().BeTrue();
    }

    [Fact]
    public void IsEnabled_UnparseableFileAfterGoodLoad_KeepsLastKnownSetWithoutCaching()
    {
        WriteStatus("WebServerACME");
        var sut = BuildPolicy();
        sut.IsEnabled(WebServer).Should().BeTrue();

        var path = SetupStatus.GetStatusPath(_options);
        File.WriteAllText(path, "{this is not json");
        BumpWriteTime();
        var unreadableTime = File.GetLastWriteTimeUtc(path);

        sut.IsEnabled(WebServer).Should().BeTrue(
            "the last known set answers while the file is unreadable");
        sut.IsEnabled(Machine).Should().BeFalse(
            "a read failure must never widen exposure");

        // Fix the file but pin its write time to the unreadable file's time.
        // A policy that had cached the failed read against that time would
        // skip the reload and keep serving the stale set.
        WriteStatus("Machine");
        File.SetLastWriteTimeUtc(path, unreadableTime);

        sut.IsEnabled(Machine).Should().BeTrue(
            "a failed read must not be cached, so the fixed file is reloaded");
        sut.IsEnabled(WebServer).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_TransientReadFailureAfterGoodLoad_KeepsLastKnownSet()
    {
        WriteStatus("WebServerACME");
        var sut = BuildPolicy();
        sut.IsEnabled(WebServer).Should().BeTrue();

        BumpWriteTime();
        var path = SetupStatus.GetStatusPath(_options);
        using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            sut.IsEnabled(WebServer).Should().BeTrue(
                "the last known set answers during a transient read failure");
            sut.IsEnabled(Machine).Should().BeFalse();
        }

        // After the lock is released the next request reloads and enforcement
        // continues.
        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_ExposeAllTemplatesFlag_NoStatusFile_AllowsEverything()
    {
        var sut = BuildPolicy(exposeAll: true);

        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeTrue();
    }

    [Fact]
    public void IsEnabled_ExposeAllTemplatesFlag_OverridesWizardSet()
    {
        // The break-glass override wins over a recorded set: config alone
        // tells you the posture.
        WriteStatus("Machine");
        var sut = BuildPolicy(exposeAll: true);

        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeTrue();
    }
}
