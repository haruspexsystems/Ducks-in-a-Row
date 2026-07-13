using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for EnabledTemplatesPolicy (issue #85). A missing wizard status file
/// or an empty enabled list means no restriction (pre wizard compatibility);
/// a non empty list restricts ACME to the listed templates, matched by
/// programmatic name or display name, case insensitive.
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

    private EnabledTemplatesPolicy BuildPolicy()
    {
        return new EnabledTemplatesPolicy(
            Options.Create(_options), NullLogger<EnabledTemplatesPolicy>.Instance);
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

    [Fact]
    public void IsEnabled_NoStatusFile_AllowsEverything()
    {
        var sut = BuildPolicy();

        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeTrue();
    }

    [Fact]
    public void IsEnabled_EmptyList_AllowsEverything()
    {
        // The wizard requires at least one template, so an empty list only
        // occurs on pre wizard state and must not restrict.
        WriteStatus();
        var sut = BuildPolicy();

        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeTrue();
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
        // set without a restart. Bump the write time explicitly so the test
        // does not depend on file system timestamp resolution.
        WriteStatus("WebServerACME");
        var path = SetupStatus.GetStatusPath(_options);
        File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddSeconds(1));

        sut.IsEnabled(WebServer).Should().BeTrue();
        sut.IsEnabled(Machine).Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_FileAppearsAfterFirstCheck_Restricts()
    {
        var sut = BuildPolicy();
        sut.IsEnabled(Machine).Should().BeTrue("no file means no restriction");

        WriteStatus("WebServerACME");

        sut.IsEnabled(Machine).Should().BeFalse();
        sut.IsEnabled(WebServer).Should().BeTrue();
    }
}
