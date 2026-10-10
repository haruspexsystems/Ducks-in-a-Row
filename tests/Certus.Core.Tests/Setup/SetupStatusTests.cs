using Certus.Core.Setup;
using Certus.Core.Tests.Security;

namespace Certus.Core.Tests.Setup;

public class SetupStatusTests : IDisposable
{
    private readonly string _tempDir;

    public SetupStatusTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void Load_FileNotExists_ReturnsDefault()
    {
        var status = SetupStatus.Load(Path.Combine(_tempDir, "nope.json"));

        status.SetupCompleted.Should().BeFalse();
        status.EnabledTemplates.Should().BeEmpty();
    }

    [Fact]
    public void SaveAndLoad_RoundTrips()
    {
        var path = Path.Combine(_tempDir, "setup.json");
        var original = new SetupStatus
        {
            SetupCompleted = true,
            CompletedAt = new DateTime(2026, 4, 10, 12, 0, 0, DateTimeKind.Utc),
            CaConnectionString = "ca\\TestCA",
            EnabledTemplates = new List<string> { "WebServer", "CodeSigning" },
            ExternalUrl = "https://certus.example.com",
        };

        original.Save(path);
        var loaded = SetupStatus.Load(path);

        loaded.SetupCompleted.Should().BeTrue();
        loaded.CompletedAt.Should().Be(original.CompletedAt);
        loaded.CaConnectionString.Should().Be("ca\\TestCA");
        loaded.EnabledTemplates.Should().BeEquivalentTo(new[] { "WebServer", "CodeSigning" });
        loaded.ExternalUrl.Should().Be("https://certus.example.com");
    }

    [Fact]
    public void SaveAndLoad_RoundTripsTheWizardStep()
    {
        var path = Path.Combine(_tempDir, "draft.json");
        var original = new SetupStatus
        {
            SetupCompleted = false,
            CaConnectionString = "ca\\TestCA",
            WizardStep = "url",
        };

        original.Save(path);
        var loaded = SetupStatus.Load(path);

        loaded.WizardStep.Should().Be("url");
    }

    [Fact]
    public void Load_FileWithoutWizardStep_ReadsNull()
    {
        // Status files written before the resume feature carry no wizardStep;
        // they must load as "no resume point", not fail.
        var path = Path.Combine(_tempDir, "old.json");
        File.WriteAllText(path, """{ "setupCompleted": false, "caConnectionString": "ca\\TestCA" }""");

        var status = SetupStatus.Load(path);

        status.WizardStep.Should().BeNull();
        status.CaConnectionString.Should().Be("ca\\TestCA");
    }

    [Fact]
    public void Load_CorruptFile_ReturnsDefault()
    {
        var path = Path.Combine(_tempDir, "corrupt.json");
        File.WriteAllText(path, "this is not json {{{");

        var status = SetupStatus.Load(path);

        status.SetupCompleted.Should().BeFalse();
    }

    [Fact]
    public void Save_CreatesDirectoryIfNeeded()
    {
        var path = Path.Combine(_tempDir, "nested", "deep", "setup.json");

        var status = new SetupStatus { SetupCompleted = true };
        status.Save(path);

        File.Exists(path).Should().BeTrue();
    }

    [Fact]
    public void TryLoad_Untrusted_ReadsAsAbsent_SoNoTemplateIsExposed()
    {
        // The ACME policy half of #489: a standard user who could write this file could
        // widen the templates, the allowed domains and the EAB mode, unauthenticated.
        var path = Path.Combine(_tempDir, SetupStatus.FileName);
        new SetupStatus { SetupCompleted = true, EnabledTemplates = ["WebServer"] }.Save(path);
        FileAcl.GrantEveryoneWrite(path);

        var ok = SetupStatus.TryLoad(path, out var status);

        ok.Should().BeTrue("an untrusted file reads as absent, which is not a read failure");
        status.SetupCompleted.Should().BeFalse();
        status.EnabledTemplates.Should().BeEmpty();
    }

    [Fact]
    public void Save_LeavesAPreCreatedTmpAlone()
    {
        var path = Path.Combine(_tempDir, SetupStatus.FileName);
        File.WriteAllText(path + ".tmp", "planted");

        new SetupStatus { SetupCompleted = true }.Save(path);

        File.ReadAllText(path + ".tmp").Should().Be("planted");
        SetupStatus.Load(path).SetupCompleted.Should().BeTrue();
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); }
        catch { /* cleanup best effort */ }
    }
}
