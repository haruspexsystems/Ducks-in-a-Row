using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Acme;

/// <summary>
/// Tests for TemplateService — confirms that ACME callers can address an
/// ADCS template by either its programmatic name (AD <c>cn</c>, no spaces)
/// or its display name (AD <c>displayName</c>, may contain spaces), and that
/// the administrator's enabled set gates the outcome. Issue #17 motivates
/// the dual form match; issue #85 motivates the enabled set gate.
/// </summary>
public class TemplateServiceTests : IDisposable
{
    private readonly string _tempDir;

    public TemplateServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certus-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
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

    private TemplateService BuildService(params TemplateInfo[] templates)
    {
        // The policy fails closed (issue #101), so this overload enables every
        // template it registers: these tests exercise name resolution, not the
        // enabled set gate.
        return BuildService(templates.Select(t => t.Name).ToArray(), templates);
    }

    /// <summary>
    /// Builds the service against a temp data directory. When
    /// <paramref name="enabledTemplates"/> is set, a wizard status file carrying
    /// that list is written where the policy reads it; null means no file,
    /// which exposes nothing (issue #101).
    /// </summary>
    private TemplateService BuildService(string[]? enabledTemplates, params TemplateInfo[] templates)
    {
        var options = new CertusOptions { DatabasePath = Path.Combine(_tempDir, "certus.db") };

        if (enabledTemplates != null)
        {
            var status = new SetupStatus
            {
                SetupCompleted = true,
                EnabledTemplates = enabledTemplates.ToList(),
            };
            status.Save(SetupStatus.GetStatusPath(options));
        }

        var policy = new EnabledTemplatesPolicy(
            Options.Create(options),
            Options.Create(new AcmeOptions()),
            NullLogger<EnabledTemplatesPolicy>.Instance);
        var mock = new MockAdcsClient(templates: templates);
        return new TemplateService(mock, policy, NullLogger<TemplateService>.Instance);
    }

    [Fact]
    public async Task ResolveAsync_ByProgrammaticName_ReturnsEnabledTemplate()
    {
        var sut = BuildService(new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"));

        var resolution = await sut.ResolveAsync("WebServerACME");

        resolution.Access.Should().Be(TemplateAccess.Enabled);
        resolution.Template!.Name.Should().Be("WebServerACME");
        resolution.Template.DisplayName.Should().Be("Web Server ACME");
    }

    [Fact]
    public async Task ResolveAsync_ByDisplayName_ReturnsEnabledTemplate()
    {
        // Issue #17 regression: ACME directory at /acme/Web%20Server%20ACME/directory
        // must resolve when CR_PROP_TEMPLATES exposes only the programmatic name.
        var sut = BuildService(new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"));

        var resolution = await sut.ResolveAsync("Web Server ACME");

        resolution.Access.Should().Be(TemplateAccess.Enabled);
        resolution.Template!.Name.Should().Be("WebServerACME");
        resolution.Template.DisplayName.Should().Be("Web Server ACME");
    }

    [Fact]
    public async Task ResolveAsync_CaseInsensitive_Matches()
    {
        var sut = BuildService(new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"));

        (await sut.ResolveAsync("webserveracme")).Access.Should().Be(TemplateAccess.Enabled);
        (await sut.ResolveAsync("WEB SERVER ACME")).Access.Should().Be(TemplateAccess.Enabled);
    }

    [Fact]
    public async Task ResolveAsync_Unknown_ReturnsUnknown()
    {
        var sut = BuildService(new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"));

        var resolution = await sut.ResolveAsync("NotATemplate");

        resolution.Access.Should().Be(TemplateAccess.Unknown);
        resolution.Template.Should().BeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public async Task ResolveAsync_EmptyOrNull_ReturnsUnknown(string? input)
    {
        var sut = BuildService(new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"));

        (await sut.ResolveAsync(input!)).Access.Should().Be(TemplateAccess.Unknown);
    }

    [Fact]
    public async Task ResolveAsync_PrefersProgrammaticOnAmbiguity()
    {
        // If two templates collide such that one's display name equals
        // another's programmatic name, the programmatic match wins because
        // it appears first in the FirstOrDefault scan order. Regression
        // guard against silent reordering of the predicate.
        var sut = BuildService(
            new TemplateInfo("Alpha", "Alpha Display", "1.1"),
            new TemplateInfo("Alpha Display", "Alpha Display Other", "1.2"));

        var resolution = await sut.ResolveAsync("Alpha Display");

        resolution.Access.Should().Be(TemplateAccess.Enabled);
        resolution.Template!.Name.Should().Be("Alpha");
    }

    [Fact]
    public async Task ResolveAsync_NoStatusFile_ReturnsDisabled()
    {
        // Issue #101: with no wizard status file nothing is exposed. The
        // template still resolves so the caller reports a clear 403 disabled
        // response, not a 404.
        var sut = BuildService(
            enabledTemplates: null,
            new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"));

        var resolution = await sut.ResolveAsync("WebServerACME");

        resolution.Access.Should().Be(TemplateAccess.Disabled);
        resolution.Template!.Name.Should().Be("WebServerACME");
    }

    [Fact]
    public async Task ResolveAsync_TemplateOutsideEnabledSet_ReturnsDisabledWithTemplate()
    {
        // Issue #85: the CA publishes both templates but only one was enabled
        // in the wizard. The other still resolves, so the caller can report a
        // clear disabled response, but is not Enabled.
        var sut = BuildService(
            enabledTemplates: ["WebServerACME"],
            new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"),
            new TemplateInfo("Machine", "Computer", "1.2.4"));

        var resolution = await sut.ResolveAsync("Machine");

        resolution.Access.Should().Be(TemplateAccess.Disabled);
        resolution.Template!.Name.Should().Be("Machine");
    }

    [Fact]
    public async Task ResolveAsync_TemplateInEnabledSet_ReturnsEnabled()
    {
        var sut = BuildService(
            enabledTemplates: ["WebServerACME"],
            new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"),
            new TemplateInfo("Machine", "Computer", "1.2.4"));

        (await sut.ResolveAsync("WebServerACME")).Access.Should().Be(TemplateAccess.Enabled);
        // Dual form: the enabled set stores the programmatic name, but the
        // client may still address the template by display name.
        (await sut.ResolveAsync("Web Server ACME")).Access.Should().Be(TemplateAccess.Enabled);
    }

    [Fact]
    public async Task ResolveAsync_EnabledSetByDisplayName_StillEnables()
    {
        // The wizard writes programmatic names, but a hand edited file may
        // carry the display form; the policy accepts either.
        var sut = BuildService(
            enabledTemplates: ["Web Server ACME"],
            new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"),
            new TemplateInfo("Machine", "Computer", "1.2.4"));

        (await sut.ResolveAsync("WebServerACME")).Access.Should().Be(TemplateAccess.Enabled);
        (await sut.ResolveAsync("Machine")).Access.Should().Be(TemplateAccess.Disabled);
    }

    [Fact]
    public async Task ResolveAsync_UnknownWithEnabledSet_ReturnsUnknownNotDisabled()
    {
        var sut = BuildService(
            enabledTemplates: ["WebServerACME"],
            new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3"));

        (await sut.ResolveAsync("NotATemplate")).Access.Should().Be(TemplateAccess.Unknown);
    }

    [Fact]
    public async Task ResolveAsync_EnabledTemplateWithVerifiedDangerousEku_IsBlockedByCeiling()
    {
        // The template is in the enabled set, but its verified AD metadata
        // carries code signing next to server auth: the ceiling refuses it
        // before an order can exist, with the template attached so the
        // caller can log the match.
        var sut = BuildService(
            enabledTemplates: ["Sneaky"],
            new TemplateInfo("Sneaky", "Sneaky Template", "1.2.5",
                ExtendedKeyUsages: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.3"]));

        var resolution = await sut.ResolveAsync("Sneaky");

        resolution.Access.Should().Be(TemplateAccess.BlockedByCeiling);
        resolution.Template!.Name.Should().Be("Sneaky");
    }

    [Fact]
    public async Task ResolveAsync_EnabledTemplateWithUnverifiedMetadata_StaysEnabled()
    {
        // Null EKU metadata means the AD lookup could not verify, which is a
        // routine condition (not domain joined, no read rights) and must not
        // block issuance; the finalize leaf check is the guarantee behind it.
        var sut = BuildService(
            enabledTemplates: ["WebServerACME"],
            new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3",
                ExtendedKeyUsages: null));

        (await sut.ResolveAsync("WebServerACME")).Access.Should().Be(TemplateAccess.Enabled);
    }

    [Fact]
    public async Task ResolveAsync_EnabledTemplateInsideTheCeiling_StaysEnabled()
    {
        // Verified metadata inside the ceiling changes nothing.
        var sut = BuildService(
            enabledTemplates: ["WebServerACME"],
            new TemplateInfo("WebServerACME", "Web Server ACME", "1.2.3",
                ExtendedKeyUsages: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]));

        (await sut.ResolveAsync("WebServerACME")).Access.Should().Be(TemplateAccess.Enabled);
    }
}
