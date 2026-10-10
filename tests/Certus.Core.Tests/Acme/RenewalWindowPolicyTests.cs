using Certus.Core.Acme.Services;

namespace Certus.Core.Tests.Acme;

public class RenewalWindowPolicyTests
{
    private static readonly DateTimeOffset NotBefore =
        new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly byte[] Serial = { 0x00, 0x12, 0x34, 0x56, 0x78 };

    [Theory]
    [InlineData(1)]            // exercises the width clamps on a tiny lifetime
    [InlineData(90 * 24)]
    [InlineData(365 * 24)]
    public void Window_SitsInsideTheValidity_AndEndsAfterItStarts(int lifetimeHours)
    {
        // Inside the validity is also what makes an expired certificate renew
        // immediately with no special case: its whole validity is in the past,
        // so its window is too.
        var notAfter = NotBefore.AddHours(lifetimeHours);

        var (start, end) = RenewalWindowPolicy.GetWindow(
            NotBefore, notAfter, revokedAt: null, Serial);

        end.Should().BeAfter(start, "RFC 9773 §4.2: servers MUST NOT serve end <= start");
        start.Should().BeOnOrAfter(NotBefore);
        end.Should().BeOnOrBefore(notAfter);
    }

    [Fact]
    public void Window_SitsInTheFinalThirdOfTheLifetime_AtTwoPercentWidth()
    {
        var notAfter = NotBefore.AddDays(365);
        var lifetime = notAfter - NotBefore;

        var (start, end) = RenewalWindowPolicy.GetWindow(
            NotBefore, notAfter, revokedAt: null, Serial);

        start.Should().BeOnOrAfter(NotBefore + TimeSpan.FromTicks(lifetime.Ticks * 2 / 3));
        // 2/3 position + 2% width + at most one width of jitter is about 71%
        // of the lifetime.
        end.Should().BeBefore(NotBefore + TimeSpan.FromTicks((long)(lifetime.Ticks * 0.75)));
        (end - start).Should().Be(TimeSpan.FromTicks(lifetime.Ticks / 50));
    }

    [Fact]
    public void Window_IsDeterministicAcrossCalls()
    {
        // A window that moved between polls would make the client re-roll its
        // chosen renewal instant every Retry-After, defeating the spread.
        // Every arm anchors on facts about the certificate, never the clock.
        var notAfter = NotBefore.AddDays(365);

        var first = RenewalWindowPolicy.GetWindow(NotBefore, notAfter, null, Serial);
        var second = RenewalWindowPolicy.GetWindow(NotBefore, notAfter, null, Serial);

        second.Should().Be(first);
    }

    [Fact]
    public void Window_SpreadsAcrossSerials()
    {
        // The point of the per certificate jitter: a fleet issued in one batch
        // shares notBefore/notAfter, so only the serial separates their windows.
        var notAfter = NotBefore.AddDays(365);

        var starts = Enumerable.Range(0, 16)
            .Select(i => RenewalWindowPolicy.GetWindow(
                NotBefore, notAfter, null, new byte[] { (byte)i, 0x55, 0xAA }).Start)
            .Distinct()
            .ToList();

        starts.Count.Should().BeGreaterThan(1);
    }

    [Fact]
    public void Revoked_WindowIsEntirelyBeforeTheRevocationInstant_AndStable()
    {
        // The "renew immediately" signal: whatever instant the client picks
        // inside the window precedes the revocation, so it has already gone
        // by (RFC 9773 §4.2 step 3). Anchored on the revocation instant, not
        // the clock, so it does not slide between polls.
        var notAfter = NotBefore.AddDays(365);
        var revokedAt = new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

        var first = RenewalWindowPolicy.GetWindow(NotBefore, notAfter, revokedAt, Serial);
        var second = RenewalWindowPolicy.GetWindow(NotBefore, notAfter, revokedAt, Serial);

        first.End.Should().BeAfter(first.Start);
        first.End.Should().BeBefore(revokedAt);
        second.Should().Be(first);
    }

    [Fact]
    public void DegenerateValidity_AnswersRenewNow()
    {
        // notAfter at or before notBefore leaves no lifetime to schedule
        // against; the answer is a past window anchored on the expiry, never
        // end <= start.
        var (start, end) = RenewalWindowPolicy.GetWindow(
            NotBefore, NotBefore, revokedAt: null, Serial);

        end.Should().BeAfter(start);
        end.Should().BeBefore(NotBefore);
    }

    [Fact]
    public void TinyLifetime_AnswersRenewNow()
    {
        // Below the minimum lifetime the fraction arithmetic degenerates: a
        // width under a couple of seconds could serialize as start == end once
        // the wire form truncates to whole seconds, which the RFC forbids.
        var notAfter = NotBefore.AddSeconds(5);

        var (start, end) = RenewalWindowPolicy.GetWindow(
            NotBefore, notAfter, revokedAt: null, Serial);

        end.Should().BeAfter(start);
        end.Should().BeBefore(notAfter);
        (end - start).Should().BeGreaterThan(TimeSpan.FromSeconds(1),
            "whole second truncation on the wire must never collapse the window");
    }

    [Fact]
    public void OrdinaryWindow_IsWiderThanTheWireTruncation()
    {
        var notAfter = NotBefore.AddHours(1);

        var (start, end) = RenewalWindowPolicy.GetWindow(
            NotBefore, notAfter, revokedAt: null, Serial);

        (end - start).Should().BeGreaterThan(TimeSpan.FromSeconds(1));
    }
}
