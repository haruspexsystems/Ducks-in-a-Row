using Certus.Core.Modules;
using Certus.Core.Tests.Security;
using Microsoft.Extensions.Logging;

namespace Certus.Core.Tests.Modules;

/// <summary>
/// The module load journal and its strike rule (licence design section 6.4, issue #413): two
/// attempts at one version with no healthy one between them quarantine that version, until the
/// version changes or an administrator presses Retry.
/// </summary>
public class ModuleJournalTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"certus-journal-{Guid.NewGuid():N}");

    public ModuleJournalTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private ModuleJournal NewJournal() => new(Path.Combine(_root, "modules"));

    private static ModuleJournalEntry Attempt(string version) => new(ModuleJournalEntry.Attempting, "paid", version, T0);

    private static ModuleJournalEntry Healthy(string version) => new(ModuleJournalEntry.Healthy, "paid", version, T0);

    [Fact]
    public void ARefusal_IsRecordedWithItsReason_AndNeverCountsAsAStrike()
    {
        // Issue #636: a module whose signature did not verify is journaled, so the refusal is on
        // disk beside the attempts, but it is not a failed start. Two refusals do not quarantine,
        // and a refusal between two attempts does not reset them either.
        var journal = NewJournal();
        journal.RecordRefusal("paid", "1.0", T0, "the paid module's signature could not be verified: 'paid.dll' is not signed");
        journal.RecordRefusal("paid", "1.0", T0.AddMinutes(1), "the paid module's signature could not be verified: 'paid.dll' is not signed");

        journal.IsQuarantined("paid", "1.0").Should().BeFalse("a refusal is a record, not a strike");
        var entries = journal.Entries();
        entries.Should().HaveCount(2);
        entries[0].Kind.Should().Be(ModuleJournalEntry.Refused);
        entries[0].Reason.Should().Contain("'paid.dll' is not signed");

        ModuleJournal.IsQuarantined([Attempt("1.0"), Refused("1.0"), Attempt("1.0")], "paid", "1.0").Should().BeTrue();
        ModuleJournal.IsQuarantined([Attempt("1.0"), Refused("1.0")], "paid", "1.0").Should().BeFalse();

        // An attempt and a healthy entry carry no reason, and the file says nothing about one.
        journal.RecordAttempt("paid", "1.0", T0.AddMinutes(2));
        journal.Entries()[2].Reason.Should().BeNull();
        File.ReadAllText(journal.JournalPath).Should().Contain("\"reason\"").And.NotContain("\"reason\": null");
    }

    private static ModuleJournalEntry Refused(string version) =>
        new(ModuleJournalEntry.Refused, "paid", version, T0) { Reason = "refused" };

    [Fact]
    public void TwoAttemptsWithNoHealthy_Quarantine()
    {
        ModuleJournal.IsQuarantined([Attempt("1.0"), Attempt("1.0")], "paid", "1.0").Should().BeTrue();
    }

    [Fact]
    public void OneAttempt_DoesNotQuarantine()
    {
        ModuleJournal.IsQuarantined([Attempt("1.0")], "paid", "1.0").Should().BeFalse();
    }

    [Fact]
    public void AHealthyEntry_ResetsTheCount()
    {
        ModuleJournal.IsQuarantined(
            [Attempt("1.0"), Attempt("1.0"), Healthy("1.0"), Attempt("1.0")], "paid", "1.0")
            .Should().BeFalse();
    }

    [Fact]
    public void ANewVersion_IsJudgedOnItsOwnEntries()
    {
        var entries = new[] { Attempt("1.0"), Attempt("1.0") };

        ModuleJournal.IsQuarantined(entries, "paid", "1.0").Should().BeTrue();
        ModuleJournal.IsQuarantined(entries, "paid", "2.0").Should().BeFalse();
    }

    [Fact]
    public void AnEmptyJournal_DoesNotQuarantine()
    {
        ModuleJournal.IsQuarantined([], "paid", "1.0").Should().BeFalse();
    }

    [Fact]
    public void RecordedAttempts_Persist_AndQuarantineAcrossInstances()
    {
        var journal = NewJournal();
        journal.RecordAttempt("paid", "1.0", T0);
        journal.RecordAttempt("paid", "1.0", T0.AddSeconds(1));

        journal.IsQuarantined("paid", "1.0").Should().BeTrue();
        NewJournal().IsQuarantined("paid", "1.0").Should().BeTrue("the journal is persisted to disk");
    }

    [Fact]
    public void RecordingHealthy_ClearsTheStrikes()
    {
        var journal = NewJournal();
        journal.RecordAttempt("paid", "1.0", T0);
        journal.RecordAttempt("paid", "1.0", T0.AddSeconds(1));
        journal.RecordHealthy("paid", "1.0", T0.AddSeconds(2));

        journal.IsQuarantined("paid", "1.0").Should().BeFalse();
    }

    [Fact]
    public void ClearModule_LiftsTheQuarantine_ForRetry()
    {
        var journal = NewJournal();
        journal.RecordAttempt("paid", "1.0", T0);
        journal.RecordAttempt("paid", "1.0", T0.AddSeconds(1));
        journal.IsQuarantined("paid", "1.0").Should().BeTrue();

        journal.ClearModule("paid");

        journal.IsQuarantined("paid", "1.0").Should().BeFalse();
    }

    [Fact]
    public void AnotherModulesAttempts_DoNotQuarantineThisOne()
    {
        var journal = NewJournal();
        journal.RecordAttempt("other", "1.0", T0);
        journal.RecordAttempt("other", "1.0", T0.AddSeconds(1));

        journal.IsQuarantined("paid", "1.0").Should().BeFalse();
    }

    [Fact]
    public void ACorruptJournal_ReadsAsEmpty()
    {
        var journal = NewJournal();
        journal.RecordAttempt("paid", "1.0", T0); // creates the folder and a valid file first
        File.WriteAllText(journal.JournalPath, "this is not json");

        journal.Entries().Should().BeEmpty();
        journal.IsQuarantined("paid", "1.0").Should().BeFalse();
    }

    // ---- trust (issue #523) ----

    [Fact]
    public void AJournalAnotherAccountCanWrite_ReadsAsEmpty_AndSaysWhy()
    {
        // The #523 comment: a standard user who can write the journal can quarantine the module, or
        // keep clearing its strikes. Such a journal is treated as absent, and the log says why.
        var log = new RecordingLogger();
        var journal = new ModuleJournal(Path.Combine(_root, "modules"), log);
        journal.RecordAttempt("paid", "1.0", T0);
        journal.RecordAttempt("paid", "1.0", T0.AddSeconds(1));
        journal.IsQuarantined("paid", "1.0").Should().BeTrue("the fixture starts quarantined");

        FileAcl.GrantEveryoneWrite(journal.JournalPath);

        journal.Entries().Should().BeEmpty();
        journal.IsQuarantined("paid", "1.0").Should().BeFalse();
        log.Errors.Should().ContainSingle().Which.Should().Contain("not trusted").And.Contain("write");
    }

    [Fact]
    public void AnUntrustedJournal_IsReplacedByATrustedOne_OnTheNextWrite()
    {
        // In a trusted folder the recovery is the next write: AtomicFile moves a fresh file over the
        // planted one, the #489 pattern, so the foreign entry is gone with it.
        var journal = NewJournal();
        journal.RecordAttempt("paid", "1.0", T0);
        FileAcl.GrantEveryoneWrite(journal.JournalPath);

        journal.RecordAttempt("paid", "1.0", T0.AddSeconds(1));

        FileAcl.EveryoneCanWrite(journal.JournalPath).Should().BeFalse();
        journal.Entries().Should().ContainSingle("the untrusted history was dropped, not carried forward");
    }

    [Fact]
    public void AnUntrustedModulesFolder_ReadsAsEmpty_AndIsNeverWritten()
    {
        var log = new RecordingLogger();
        var journal = new ModuleJournal(Path.Combine(_root, "modules"), log);
        journal.RecordAttempt("paid", "1.0", T0);
        journal.RecordAttempt("paid", "1.0", T0.AddSeconds(1));
        var before = File.ReadAllBytes(journal.JournalPath);

        FileAcl.GrantEveryoneWriteToFolder(Path.Combine(_root, "modules"));

        journal.IsQuarantined("paid", "1.0").Should().BeFalse();
        journal.ClearModule("paid");
        journal.RecordAttempt("paid", "1.0", T0.AddSeconds(2));

        File.ReadAllBytes(journal.JournalPath).Should().Equal(before, "nothing is written into a folder its owner could rewrite");
        log.Errors.Should().ContainSingle("one cause is logged once").Which.Should().Contain("modules folder");
    }

    private sealed class RecordingLogger : ILogger<ModuleJournal>
    {
        public List<string> Errors { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Error)
                Errors.Add(formatter(state, exception));
        }
    }
}
