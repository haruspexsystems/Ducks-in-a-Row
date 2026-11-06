using Certus.Core.Security;

namespace Certus.Core.Tests.Security;

/// <summary>
/// The write path that replaced the fixed ".tmp" staging (issue #489).
/// </summary>
public class AtomicFileTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"certus-atomic-{Guid.NewGuid():N}");

    public AtomicFileTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void WritesTheContent_AsUtf8WithoutAMark_AndLeavesNothingBehind()
    {
        var path = Path.Combine(_dir, "settings.json");

        AtomicFile.WriteAllText(path, "{ \"é\": 1 }");

        File.ReadAllBytes(path).Should().Equal("{ \"é\": 1 }"u8.ToArray());
        Directory.GetFiles(_dir).Should().ContainSingle();
    }

    [Fact]
    public void ReplacesAnExistingFile()
    {
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, "old");

        AtomicFile.WriteAllText(path, "new");

        File.ReadAllText(path).Should().Be("new");
    }

    [Fact]
    public void APreCreatedFileUnderTheOldTemporaryName_IsNeitherUsedNorTouched()
    {
        // The hijack: the old writers staged through "<file>.tmp", truncating a file a
        // standard user had already created there and renaming it over the target.
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path + ".tmp", "planted");

        AtomicFile.WriteAllText(path, "written");

        File.ReadAllText(path).Should().Be("written");
        File.ReadAllText(path + ".tmp").Should().Be("planted");
    }

    [Fact]
    public void TheTargetDoesNotKeepTheDaclOfTheFileItReplaces()
    {
        // A hijacked target carries an entry that lets someone else write it. File.Move
        // gives the target the new file's own descriptor; File.Replace would keep the old
        // one, entry and all, and this test would fail.
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, "hijacked");
        FileAcl.GrantEveryoneWrite(path);
        TrustedFile.Check(path).IsTrusted.Should().BeFalse("the fixture must start untrusted");

        AtomicFile.WriteAllText(path, "written");

        FileAcl.EveryoneCanWrite(path).Should().BeFalse();
        TrustedFile.Check(path).IsTrusted.Should().BeTrue();
    }

    [Fact]
    public void AFailedMove_RemovesItsTemporaryFile()
    {
        // A folder where the file should be: the move fails, and the staged file must not
        // be left lying beside it. The folder reads as access denied, the same answer a
        // reader holding the file gives, so this goes through every retry first (issue #420).
        var path = Path.Combine(_dir, "settings.json");
        Directory.CreateDirectory(path);

        var write = () => AtomicFile.WriteAllText(path, "content");

        write.Should().Throw<Exception>().Which.Should().Match<Exception>(e => e is IOException || e is UnauthorizedAccessException);
        Directory.GetFiles(_dir).Should().BeEmpty();
    }

    [Fact]
    public void WriteAllBytes_WritesTheExactBytes_AndLeavesNothingBehind()
    {
        var path = Path.Combine(_dir, "licence.json");
        // Includes a lone 0xFF and a lone 0x80, which are not valid UTF-8, so a writer that routed
        // the bytes through a string (decode then re-encode) would turn them into U+FFFD and fail
        // this assertion. A verbatim byte write keeps them.
        var bytes = new byte[] { 0xEF, 0xBB, 0xBF, 0x00, 0xFF, 0x7B, 0x0A, 0xC3, 0xA9, 0x80, 0x7D };

        AtomicFile.WriteAllBytes(path, bytes);

        File.ReadAllBytes(path).Should().Equal(bytes);
        Directory.GetFiles(_dir).Should().ContainSingle();
    }

    [Fact]
    public void WriteAllBytes_ReplacesAnExistingFile_WithoutKeepingItsDacl()
    {
        // The same guarantee as the text writer, since that now delegates here: a hijacked
        // target's entry letting someone else write does not survive the move.
        var path = Path.Combine(_dir, "licence.json");
        File.WriteAllText(path, "hijacked");
        FileAcl.GrantEveryoneWrite(path);
        TrustedFile.Check(path).IsTrusted.Should().BeFalse("the fixture must start untrusted");

        AtomicFile.WriteAllBytes(path, "written"u8.ToArray());

        File.ReadAllBytes(path).Should().Equal("written"u8.ToArray());
        FileAcl.EveryoneCanWrite(path).Should().BeFalse();
        TrustedFile.Check(path).IsTrusted.Should().BeTrue();
    }

    [Fact]
    public void AMoveBlockedByAReader_IsTriedAgain_AndLandsOnceTheReaderLetsGo()
    {
        // Issue #420. SetupStatus.TryLoad reads the status file through File.ReadAllText on every
        // ACME policy check, and a save landing in the middle of that read used to fail outright
        // with access denied. The reader here lets go from the wait before the first retry, so
        // the test needs no clock at all.
        var path = Path.Combine(_dir, "ducks-setup.json");
        File.WriteAllText(path, "old");
        using var reader = HoldOpenLikeFileReadAllText(path);
        var retries = new List<int>();

        AtomicFile.WriteAllBytes(path, "new"u8.ToArray(), moveAttempts: 5, waitBeforeRetry: retry =>
        {
            retries.Add(retry);
            reader.Dispose();
        });

        retries.Should().Equal(1);
        File.ReadAllText(path).Should().Be("new");
        Directory.GetFiles(_dir).Should().ContainSingle();
    }

    [Fact]
    public void AReaderThatNeverLetsGo_FailsWithTheMoveError_AfterEveryAttempt_AndLeavesNoTemporaryFile()
    {
        var path = Path.Combine(_dir, "ducks-setup.json");
        File.WriteAllText(path, "old");
        using var reader = HoldOpenLikeFileReadAllText(path);
        var retries = new List<int>();

        var write = () => AtomicFile.WriteAllBytes(path, "new"u8.ToArray(), moveAttempts: 5, waitBeforeRetry: retries.Add);

        // The caller sees the error the move itself raised, not a wrapper, so every arm that
        // already catches UnauthorizedAccessException keeps working unchanged.
        write.Should().Throw<UnauthorizedAccessException>();
        retries.Should().Equal(1, 2, 3, 4);
        reader.Dispose();
        File.ReadAllText(path).Should().Be("old");
        Directory.GetFiles(_dir).Should().Equal(path);
    }

    [Fact]
    public void AFailureThatIsNotTransient_StopsTheRetryAtOnce()
    {
        // The first attempt fails on the reader; the wait then removes the staged file, so the
        // second attempt fails with file not found, which no amount of waiting will cure.
        var path = Path.Combine(_dir, "ducks-setup.json");
        File.WriteAllText(path, "old");
        using var reader = HoldOpenLikeFileReadAllText(path);
        var retries = new List<int>();

        var write = () => AtomicFile.WriteAllBytes(path, "new"u8.ToArray(), moveAttempts: 5, waitBeforeRetry: retry =>
        {
            retries.Add(retry);
            foreach (var staged in Directory.GetFiles(_dir, "*.tmp"))
                File.Delete(staged);
        });

        write.Should().Throw<FileNotFoundException>();
        retries.Should().Equal(1);
    }

    [Fact]
    public void OnlyAccessDeniedAndASharingViolation_AreTransient()
    {
        AtomicFile.IsTransientMoveFailure(new UnauthorizedAccessException()).Should().BeTrue();
        AtomicFile.IsTransientMoveFailure(new IOException("in use", unchecked((int)0x80070020))).Should().BeTrue();

        AtomicFile.IsTransientMoveFailure(new IOException("exists", unchecked((int)0x80070050))).Should().BeFalse();
        AtomicFile.IsTransientMoveFailure(new IOException()).Should().BeFalse();
        AtomicFile.IsTransientMoveFailure(new FileNotFoundException()).Should().BeFalse();
        AtomicFile.IsTransientMoveFailure(new DirectoryNotFoundException()).Should().BeFalse();
        AtomicFile.IsTransientMoveFailure(new InvalidOperationException()).Should().BeFalse();
    }

    [Fact]
    public void TheRetryWaitsLessThanASecondInAll()
    {
        // Callers wait the retry out holding an in process lock, some on a request thread, so
        // the bound is part of the contract and not a tuning detail.
        var total = Enumerable.Range(1, AtomicFile.MoveAttempts - 1)
            .Select(AtomicFile.MoveRetryDelay)
            .Aggregate(TimeSpan.Zero, (sum, wait) => sum + wait);

        total.Should().BePositive().And.BeLessThan(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void TheRetryScheduleIsFourWaitsDoubling()
    {
        // The deterministic pin on the attempt count. The public write test below can only assert
        // a lower bound on wall clock time, and a timer tick of slack either way means it cannot
        // tell four attempts (350 ms of waits) from five reliably.
        Enumerable.Range(1, AtomicFile.MoveAttempts - 1)
            .Select(AtomicFile.MoveRetryDelay)
            .Should().Equal(
                TimeSpan.FromMilliseconds(50),
                TimeSpan.FromMilliseconds(100),
                TimeSpan.FromMilliseconds(200),
                TimeSpan.FromMilliseconds(400));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(AtomicFile.MoveAttempts)]
    public void ARetryNumberOutsideTheSchedule_IsRefused(int retry)
    {
        // A shift count is masked to its low five bits, so retry 0 would otherwise come back as
        // a wait of 0 ms (50 << 31 overflows to 0) and retry MoveAttempts as 800 ms.
        var delay = () => AtomicFile.MoveRetryDelay(retry);

        delay.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void ThePublicWrite_WaitsOutAReader_BeforeReportingIt()
    {
        // The public overload is the one the product calls, so this pins that it carries the
        // retry at all. Only a lower bound is asserted: a loaded machine can make the write slower
        // but never faster. Half of the planned 750 ms leaves room for each of the four sleeps
        // to return a timer tick early. It does not reliably fail a write that makes four attempts
        // instead of five (350 ms of waits, which a slow timer stretches past 375 ms);
        // TheRetryScheduleIsFourWaitsDoubling is the deterministic pin on the count.
        var path = Path.Combine(_dir, "ducks-setup.json");
        File.WriteAllText(path, "old");
        using var reader = HoldOpenLikeFileReadAllText(path);

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var write = () => AtomicFile.WriteAllText(path, "new");

        write.Should().Throw<UnauthorizedAccessException>();
        clock.Elapsed.Should().BeGreaterThanOrEqualTo(TimeSpan.FromMilliseconds(375));
        Directory.GetFiles(_dir).Should().Equal(path);
    }

    /// <summary>The share mode File.ReadAllText opens with, which is what SetupStatus.TryLoad uses.</summary>
    private static FileStream HoldOpenLikeFileReadAllText(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
}
