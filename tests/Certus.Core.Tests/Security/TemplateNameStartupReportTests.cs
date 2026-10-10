using Certus.Core.Acme.Services;
using Certus.Core.Adcs;
using Certus.Core.Configuration;
using Certus.Core.Security;
using Certus.Core.Setup;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Certus.Core.Tests.Security;

/// <summary>
/// The boot line for issues #235 and #292. Two things about it are load bearing
/// and both are easy to lose in a later edit: it says nothing at all on a
/// healthy install, and it never prints a template name or OID, because
/// printing one would write into the log exactly the characters the refusal
/// exists to keep out of it.
///
/// A third became load bearing when the OID joined it. The three counts have to
/// be counted, not derived: for as long as the last one was "everything else",
/// a template whose OID alone was dirty was reported as a display name fault
/// and described as a 400 nobody was getting.
/// </summary>
public class TemplateNameStartupReportTests : IDisposable
{
    private readonly string _tempDir;

    public TemplateNameStartupReportTests()
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

    /// <summary>Records level and rendered message for every entry.</summary>
    private sealed class RecordingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public List<string> Warnings =>
            Entries.Where(e => e.Level == LogLevel.Warning).Select(e => e.Message).ToList();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    // Built from numeric code points rather than written literally: a soft
    // hyphen pasted into source is invisible to the next reader of this file.
    private const int SoftHyphen = 0x00AD;
    private const int LineSeparator = 0x2028;

    private static string With(int codePoint, string before, string after) =>
        before + char.ConvertFromUtf32(codePoint) + after;

    private (TemplateService Templates, EnabledTemplatesPolicy Enabled) Build(
        string[]? enabledTemplates,
        IAdcsClient client,
        AcmeOptions? acmeOptions = null)
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
            Options.Create(acmeOptions ?? new AcmeOptions()),
            NullLogger<EnabledTemplatesPolicy>.Instance);

        return (new TemplateService(client, policy, NullLogger<TemplateService>.Instance), policy);
    }

    private async Task<RecordingLogger> RunAsync(
        string[]? enabledTemplates,
        IAdcsClient client,
        AcmeOptions? acmeOptions = null)
    {
        var (templates, enabled) = Build(enabledTemplates, client, acmeOptions);
        var logger = new RecordingLogger();

        await TemplateNameStartupReport.LogAsync(templates, enabled, logger);
        return logger;
    }

    [Fact]
    public async Task CleanExposedTemplates_SayNothing()
    {
        // The whole install base sees this path. A line here on every healthy
        // boot would train an operator to skip the one that matters.
        var logger = await RunAsync(
            new[] { "WebServer" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServer", "Web Server", "1.2.3"),
            }));

        logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task AnExposedDirtyDisplayName_WarnsWithTheCodePointAndPosition()
    {
        var logger = await RunAsync(
            new[] { "WebServer" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServer", With(SoftHyphen, "Web", " Server"), "1.2.3"),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().Contain("U+00AD");
        warning.Should().Contain("position 3");
        warning.Should().Contain("display name");
    }

    [Fact]
    public async Task TheWarningNeverPrintsTheName()
    {
        var displayName = With(SoftHyphen, "Contoso", " Web Server");
        var logger = await RunAsync(
            new[] { "WebServer" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServer", displayName, "1.2.3"),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().NotContain(displayName);
        warning.Should().NotContain("Contoso");
        warning.Should().NotContainAny("\n", "\r");
    }

    [Fact]
    public async Task AnExposedDirtyProgrammaticName_IsReportedAsUnenrollable()
    {
        var name = With(SoftHyphen, "Web", "Server");

        // The enabled set matches on either form, so naming the dirty value is
        // how this template gets exposed at all: setup completion would have
        // refused to record it, which leaves a hand edited file as the way in.
        var logger = await RunAsync(
            new[] { name },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo(name, "Web Server", "1.2.3"),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().Contain("cannot be enrolled at all");
        warning.Should().Contain("programmatic name");
        warning.Should().NotContain(name);
    }

    [Fact]
    public async Task TheExampleNamesTheWorstFaultNotTheFirstPublished()
    {
        // An operator anchors on the example rather than on the counts, so a
        // recoverable display name fault must not be the one named while an
        // unenrollable template sits in the same line. The dirty display name
        // is published first here on purpose.
        var badName = With(0x0A, "Legacy", "Template");
        var logger = await RunAsync(
            new[] { "WebServerPasted", badName },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServerPasted", With(SoftHyphen, "Web", " Server"), "1.2.3"),
                new TemplateInfo(badName, "Legacy Template", "1.2.4"),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().Contain("U+000A");
        warning.Should().Contain("of a programmatic name");
        warning.Should().NotContain("U+00AD");
    }

    [Fact]
    public async Task AnExposedDirtyOid_WarnsAndSaysItRefusesNothing()
    {
        var logger = await RunAsync(
            new[] { "WebServer" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServer", "Web Server", With(SoftHyphen, "1.3.6", ".1")),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().Contain("U+00AD");
        warning.Should().Contain("position 5");
        warning.Should().Contain("of a template OID");
        warning.Should().Contain(
            "refuses nothing",
            "an operator who reads this must not go looking for a client that is being turned away");
    }

    [Fact]
    public async Task AnOidOnlyFault_IsCountedAsOneAndNotAsADisplayNameFault()
    {
        // The regression the three counts exist for. While the last bucket was
        // computed as the remainder, this template landed in the display name
        // one and the line told the operator that clients addressing it were
        // getting a 400.
        var logger = await RunAsync(
            new[] { "WebServer" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServer", "Web Server", With(SoftHyphen, "1.3.6", ".1")),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().Contain("0 carry one in the display name");
        warning.Should().Contain("1 carry one in the template OID alone");
    }

    [Fact]
    public async Task TheThreeCountsAddUpToTheTemplatesReported()
    {
        var badName = With(0x0A, "Legacy", "Template");
        var logger = await RunAsync(
            new[] { badName, "WebServerPasted", "WebServerOid" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo(badName, "Legacy Template", "1.2.3"),
                new TemplateInfo("WebServerPasted", With(SoftHyphen, "Web", " Server"), "1.2.4"),
                new TemplateInfo("WebServerOid", "Web Server Oid", With(SoftHyphen, "1.3.6", ".1")),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().StartWith("3 certificate template(s)");
        warning.Should().Contain("1 carry one in the programmatic name");
        warning.Should().Contain("1 carry one in the display name");
        warning.Should().Contain("1 carry one in the template OID alone");
    }

    [Fact]
    public async Task TheExampleNamesAnOidOnlyWhenNothingCostlierIsPresent()
    {
        // Same reasoning as the programmatic name tier above it, one step down.
        // An OID fault costs nobody anything, so sending an operator to look at
        // one while a client is being refused a directory URL is the wrong
        // template to point at. The OID fault is published first on purpose.
        var logger = await RunAsync(
            new[] { "WebServerOid", "WebServerPasted" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServerOid", "Web Server Oid", With(LineSeparator, "1.3.6", ".1")),
                new TemplateInfo("WebServerPasted", With(SoftHyphen, "Web", " Server"), "1.2.4"),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().Contain("U+00AD");
        warning.Should().Contain("of a display name");
        warning.Should().NotContain("U+2028");
    }

    [Fact]
    public async Task TheWarningNeverPrintsTheOid()
    {
        var oid = With(SoftHyphen, "1.3.6.1.4.1.311", ".21.8.99999");
        var logger = await RunAsync(
            new[] { "WebServer" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServer", "Web Server", oid),
            }));

        var warning = logger.Warnings.Should().ContainSingle().Subject;
        warning.Should().NotContain(oid);
        warning.Should().NotContain("21.8.99999");
        warning.Should().NotContainAny("\n", "\r");
    }

    [Fact]
    public async Task ADirtyTemplateThatIsNotExposed_SaysNothing()
    {
        // The wizard's template step is where a published but unexposed
        // template gets flagged, at the moment someone might choose it.
        var logger = await RunAsync(
            new[] { "WebServer" },
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("WebServer", "Web Server", "1.2.3"),
                new TemplateInfo("Legacy", With(SoftHyphen, "Leg", "acy"), "1.2.4"),
            }));

        logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task ExposeAllTemplates_WidensTheCheckToEverythingPublished()
    {
        // Correct rather than incidental: with the break glass on, everything
        // published is exposed, so everything published is in scope.
        var logger = await RunAsync(
            enabledTemplates: null,
            new MockAdcsClient(templates: new[]
            {
                new TemplateInfo("Legacy", With(SoftHyphen, "Leg", "acy"), "1.2.4"),
            }),
            new AcmeOptions { ExposeAllTemplates = true });

        logger.Warnings.Should().ContainSingle();
    }

    [Fact]
    public async Task AnUnconfiguredCa_IsSilentAndDoesNotThrow()
    {
        // A fresh install before the wizard runs. Every reason to fail here is
        // a reason not to say anything, and none of them may take boot down.
        var logger = await RunAsync(new[] { "WebServer" }, new UnconfiguredAdcsClient());

        logger.Warnings.Should().BeEmpty();
    }
}
