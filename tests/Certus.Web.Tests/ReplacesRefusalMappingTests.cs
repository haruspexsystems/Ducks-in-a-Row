using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Web.Controllers.Acme;
using FluentAssertions;

namespace Certus.Web.Tests;

/// <summary>
/// The wire half of RFC 9773 §5: every refusal
/// <see cref="OrderService.ResolveReplacesAsync"/> can return reaches the
/// client as a definite ACME error, the
/// <see cref="FinalizeRefusalMappingTests"/> pattern. The service side is
/// proved in Certus.Core.Tests; this file proves what each outcome becomes on
/// the wire, and that an outcome added later cannot ship without an answer.
/// </summary>
public class ReplacesRefusalMappingTests
{
    [Theory]
    [InlineData(ReplacesOutcome.Malformed, 400, "urn:ietf:params:acme:error:malformed")]
    // A certificate that does not exist and one that belongs to another
    // account share one answer on purpose: serials are enumerable, so the
    // difference must not be observable to an authenticated stranger.
    [InlineData(ReplacesOutcome.UnknownCertificate, 400, "urn:ietf:params:acme:error:malformed")]
    [InlineData(ReplacesOutcome.NotOwned, 400, "urn:ietf:params:acme:error:malformed")]
    [InlineData(ReplacesOutcome.NoSharedIdentifier, 400, "urn:ietf:params:acme:error:malformed")]
    // The one answer §5 prescribes: HTTP 409 with alreadyReplaced.
    [InlineData(ReplacesOutcome.AlreadyReplaced, 409, "urn:ietf:params:acme:error:alreadyReplaced")]
    public void EachRefusal_MapsToItsAcmeError(
        ReplacesOutcome outcome, int expectedStatus, string expectedType)
    {
        var (status, errorType, detail) = OrderController.MapReplacesRefusal(outcome);

        status.Should().Be(expectedStatus);
        errorType.Should().Be(expectedType);
        detail.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void UnknownAndNotOwned_AreIndistinguishableOnTheWire()
    {
        var unknown = OrderController.MapReplacesRefusal(ReplacesOutcome.UnknownCertificate);
        var notOwned = OrderController.MapReplacesRefusal(ReplacesOutcome.NotOwned);

        notOwned.Should().Be(unknown,
            "an account holder probing serials must not learn which certificates exist");
    }

    [Theory]
    [InlineData(ReplacesOutcome.NotPresent)]
    [InlineData(ReplacesOutcome.Resolved)]
    public void AdmittingOutcomes_AreNotRefusals(ReplacesOutcome outcome)
    {
        var map = () => OrderController.MapReplacesRefusal(outcome);

        map.Should().Throw<ArgumentOutOfRangeException>(
            "an admitted replaces has no error to answer with");
    }

    [Fact]
    public void EveryRefusal_IsMapped()
    {
        // The guard: a ReplacesOutcome added later with no mapping fails here
        // instead of shipping behind a catch-all answer.
        var refusals = Enum.GetValues<ReplacesOutcome>()
            .Where(o => o is not (ReplacesOutcome.NotPresent or ReplacesOutcome.Resolved));

        foreach (var outcome in refusals)
        {
            var map = () => OrderController.MapReplacesRefusal(outcome);

            map.Should().NotThrow(
                "every replaces refusal needs an ACME answer, and {0} has none", outcome);
        }
    }
}
