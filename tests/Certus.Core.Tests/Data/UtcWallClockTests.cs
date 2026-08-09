using System.Text.Json;
using Certus.Core.Data;

namespace Certus.Core.Tests.Data;

/// <summary>
/// Unit tests for the UTC normalization every date arriving from outside is put
/// through before it is stored or compared (issue #257).
///
/// The rule is stated here in a form that holds in any timezone, because the
/// integration tests cannot show it on both paths. Over a query string MVC's
/// DateTimeModelBinder already hands the controller Kind=Utc, so there the
/// normalization is identity and invisible. Over a JSON body it is not: the
/// deserializer resolves an offset qualified instant to Kind=Local, and the
/// round trip below pins that, because it is the reason this helper exists
/// rather than a framework detail we are free to assume.
/// </summary>
public class UtcWallClockTests
{
    // Midday in mid August, so no zone puts a daylight saving transition on it.
    // An ambiguous or non existent local time would make the offset the test
    // computes and the offset ToUniversalTime picks disagree.
    private static readonly DateTime SettledLocalNoon = new(2026, 8, 8, 12, 0, 0, DateTimeKind.Local);

    [Fact]
    public void Normalize_LocalKind_KeepsTheInstantAndTakesOffTheOffset()
    {
        var result = UtcWallClock.Normalize(SettledLocalNoon);

        result.Kind.Should().Be(DateTimeKind.Utc);
        (SettledLocalNoon - result).Should().Be(
            TimeZoneInfo.Local.GetUtcOffset(SettledLocalNoon),
            "the wall clock moves by exactly the host's UTC offset, which is what " +
            "a stored or compared value would otherwise be wrong by");
    }

    [Fact]
    public void Normalize_UtcKind_PassesThroughUntouched()
    {
        var utc = new DateTime(2026, 8, 8, 12, 0, 0, DateTimeKind.Utc);

        var result = UtcWallClock.Normalize(utc);

        result.Should().Be(utc);
        result.Kind.Should().Be(DateTimeKind.Utc);
    }

    [Fact]
    public void Normalize_UnspecifiedKind_IsTakenAtItsWordAsAlreadyUtc()
    {
        // A caller who sends no offset means the wall clock they typed. Shifting
        // it would move a value the caller never asked to move.
        var unspecified = new DateTime(2026, 8, 8, 12, 0, 0, DateTimeKind.Unspecified);

        var result = UtcWallClock.Normalize(unspecified);

        result.Should().Be(DateTime.SpecifyKind(unspecified, DateTimeKind.Utc));
        result.Kind.Should().Be(DateTimeKind.Utc);
    }

    [Fact]
    public void Normalize_NoValue_StaysNull()
    {
        // "Never expires", and "no filter" on the query string paths, both have
        // to survive normalization rather than becoming a value at the epoch.
        UtcWallClock.Normalize((DateTime?)null).Should().BeNull();
    }

    [Fact]
    public void Normalize_NullableInput_MatchesTheNonNullableOverload()
    {
        UtcWallClock.Normalize((DateTime?)SettledLocalNoon)
            .Should().Be(UtcWallClock.Normalize(SettledLocalNoon));
    }

    [Theory]
    [InlineData("2026-08-08T12:00:00Z")]
    [InlineData("2026-08-08T17:00:00+05:00")]
    [InlineData("2026-08-08T07:00:00-05:00")]
    public void Normalize_JsonBodyInstant_ResolvesToTheInstantThatWasSent(string wireValue)
    {
        // The load-bearing path. System.Text.Json hands back Kind=Local for the
        // two offset qualified forms, so without this the stored expiry would be
        // that instant rendered on the host's clock. All three name the same
        // moment, so all three must normalize to it.
        var deserialized = JsonSerializer.Deserialize<DateTime>($"\"{wireValue}\"");

        var result = UtcWallClock.Normalize(deserialized);

        result.Kind.Should().Be(DateTimeKind.Utc);
        result.Should().Be(new DateTime(2026, 8, 8, 12, 0, 0, DateTimeKind.Utc));
    }
}
