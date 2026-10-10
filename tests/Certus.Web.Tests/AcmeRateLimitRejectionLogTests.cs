using Certus.Core.Security;
using Certus.Web.Security;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Certus.Web.Tests;

/// <summary>
/// Nothing logged a rate limit refusal before issue #263, so an operator could
/// not tell which of the four policies had refused a client. These cover the two
/// halves of the fix: the line has to name the policy, and it has to be throttled,
/// because a Warning per refused request would let a flood fill the log file
/// using the very traffic the limiter exists to shed cheaply.
/// </summary>
public class AcmeRateLimitRejectionLogTests
{
    private readonly FakeTimeProvider _time = new();
    private readonly CapturingLogger _logger = new();

    private AcmeRateLimitRejectionLog CreateLog() => new(_logger, _time);

    private bool Record(AcmeRateLimitRejectionLog log, string policy = AcmeRateLimitPolicies.NewOrder) =>
        log.Record(policy, "POST", "/acme/WebServer/new-order", "203.0.113.7", 10);

    [Fact]
    public void Record_FirstRefusal_LogsAWarningNamingThePolicyAndTheSettingToRaise()
    {
        var log = CreateLog();

        Record(log).Should().BeTrue();

        _logger.Entries.Should().ContainSingle();
        var entry = _logger.Entries[0];
        entry.Level.Should().Be(LogLevel.Warning);
        entry.Message.Should().Contain(AcmeRateLimitPolicies.NewOrder);
        entry.Message.Should().Contain("Certus:RateLimiting:NewOrderLimit",
            "the line has to name the knob, or the operator is left to find it");
        entry.Message.Should().Contain("203.0.113.7").And.Contain("/acme/WebServer/new-order");
    }

    [Fact]
    public void Record_WithinTheCooldown_LogsOnceHoweverManyRefusalsArrive()
    {
        var log = CreateLog();

        Record(log).Should().BeTrue();
        for (var i = 0; i < 500; i++)
        {
            _time.Advance(TimeSpan.FromMilliseconds(50));
            Record(log).Should().BeFalse();
        }

        _logger.Entries.Should().ContainSingle(
            "a flood must not be able to write a log line per refused request");
    }

    [Fact]
    public void Record_AfterTheCooldown_LogsAgainAndReportsWhatItSuppressed()
    {
        var log = CreateLog();

        Record(log);
        Record(log);
        Record(log);
        Record(log);

        _time.Advance(AcmeRateLimitRejectionLog.Cooldown + TimeSpan.FromSeconds(1));
        Record(log).Should().BeTrue();

        _logger.Entries.Should().HaveCount(2);
        _logger.Entries[1].Message.Should().Contain("3",
            "the three refusals that were not logged still have to be accounted for");
    }

    [Fact]
    public void Record_DifferentPolicies_EachGetTheirOwnCooldown()
    {
        var log = CreateLog();

        Record(log, AcmeRateLimitPolicies.NewOrder).Should().BeTrue();
        Record(log, AcmeRateLimitPolicies.NewAccount).Should().BeTrue();
        Record(log, AcmeRateLimitPolicies.Poll).Should().BeTrue();
        Record(log, AcmeRateLimitPolicies.General).Should().BeTrue();

        // A busy policy must not silence a quiet one: attributing the refusal is
        // the whole point, so the first sighting of each policy has to get through.
        Record(log, AcmeRateLimitPolicies.NewOrder).Should().BeFalse();
        _logger.Entries.Should().HaveCount(4);
    }

    [Fact]
    public void Record_WithNoPolicyOnTheEndpoint_StillLogsRatherThanDroppingTheLine()
    {
        var log = CreateLog();

        log.Record(null, "POST", "/acme/WebServer/new-order", null, null).Should().BeTrue();

        _logger.Entries[0].Message.Should().Contain("(unattributed)");
        _logger.Entries[0].Message.Should().Contain("(unknown)");
    }

    private sealed class CapturingLogger : ILogger<AcmeRateLimitRejectionLog>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }
}
