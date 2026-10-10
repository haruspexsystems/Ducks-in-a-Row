using Certus.Core.Acme.Models;
using Certus.Core.Acme.Services;
using Certus.Web.Controllers.Acme;
using FluentAssertions;

namespace Certus.Web.Tests;

/// <summary>
/// The controller half of issue #313: every refusal
/// <see cref="OrderService.FinalizeOrderAsync"/> can return reaches the client as
/// the ACME error RFC 8555 section 6.7 defines for it, rather than as one
/// catch-all badCSR.
///
/// A mapping test rather than an integration test, because there is no seam to
/// drive these arms through the pipeline with. The controller pre-checks the same
/// conditions on the same tracked entity the service then reads, so the ready and
/// expiry arms inside the service can never fire behind a real request; the two
/// that can (a concurrent deactivation, and losing the claim) only fire on a
/// genuine race. <see cref="OrderService"/> is sealed and injected concretely, so
/// there is nothing to substitute either. The service side is proved in
/// Certus.Core.Tests, which asserts the outcome each condition produces; this file
/// proves what each outcome then becomes on the wire.
/// </summary>
public class FinalizeRefusalMappingTests
{
    [Theory]
    // An order state refusal, not a CSR refusal. This is the mis-mapping issue
    // #313 was filed for: the controller's own pre-checks already answer these two
    // conditions with 403 orderNotReady, so the service arms must agree.
    [InlineData(FinalizeOutcome.OrderNotReady, 403, "urn:ietf:params:acme:error:orderNotReady")]
    // Matches the controller's order lookup.
    [InlineData(FinalizeOutcome.NotFound, 404, "urn:ietf:params:acme:error:malformed")]
    // Matches the controller's expiry pre-check.
    [InlineData(FinalizeOutcome.Expired, 403, "urn:ietf:params:acme:error:malformed")]
    // The CSR really is unacceptable. Unchanged, and the reason badCSR exists.
    [InlineData(FinalizeOutcome.BadCsr, 400, "urn:ietf:params:acme:error:badCSR")]
    // The CA decided against the request. 500 serverInternal is the type the order's
    // own error field already records for it, and the type the pending issuance
    // sweep writes for the same refusal arriving later, so one refusal now reads the
    // same wherever it is discovered (issue #324).
    [InlineData(FinalizeOutcome.CaRefused, 500, "urn:ietf:params:acme:error:serverInternal")]
    // The CA could not be reached. 503 serviceUnavailable, word for word what
    // template resolution and revoke-cert already answer for an outage, and the
    // order is still there to retry because the finalize released its claim.
    [InlineData(FinalizeOutcome.CaUnavailable, 503, "urn:ietf:params:acme:error:serviceUnavailable")]
    // The CA refused this service's own credentials. Deliberately the same answer as
    // the outage above rather than a distinct one (issue #336): the two differ in
    // cause and in what an operator must do, but not in anything a client can act on.
    // Not 403 unauthorized, which RFC 8555 section 6.7 gives to a client lacking
    // authorization; the client here is authorized and would go off to re-register
    // over a permission missing on our side of the CA.
    [InlineData(FinalizeOutcome.CaAccessDenied, 503, "urn:ietf:params:acme:error:serviceUnavailable")]
    // The template's device attestation profile is gone or disabled. Must equal what
    // this controller's own finalize-device gate answers, because which of the two
    // fires is only a matter of an administrator's timing (issue #323). The finalize
    // body answers it with the gate's whole response; this is the floor.
    [InlineData(FinalizeOutcome.DeviceNotOffered, 400, "urn:ietf:params:acme:error:rejectedIdentifier")]
    // The template still takes device orders but this device was delisted
    // (issue #335). The same answer on the wire as the outcome above, because the
    // controller's gate refuses both the same way; what separates them is the
    // detail the gate writes, which the finalize body gets from re-running it.
    [InlineData(FinalizeOutcome.DeviceNotOnAllowlist, 400, "urn:ietf:params:acme:error:rejectedIdentifier")]
    public void EachRefusal_MapsToItsAcmeError(
        FinalizeOutcome outcome, int expectedStatus, string expectedType)
    {
        var (status, errorType) = OrderController.MapFinalizeRefusal(outcome);

        status.Should().Be(expectedStatus);
        errorType.Should().Be(expectedType);
    }

    [Fact]
    public void Submitted_IsNotARefusal()
    {
        var map = () => OrderController.MapFinalizeRefusal(FinalizeOutcome.Submitted);

        map.Should().Throw<ArgumentOutOfRangeException>(
            "a successful finalize has no error to answer with");
    }

    [Fact]
    public void EveryOutcome_IsMapped()
    {
        // The guard that keeps issue #313 fixed. An outcome added later with no
        // mapping fails here, where before there was a catch-all that would have
        // answered badCSR for it and shipped quietly.
        var refusals = Enum.GetValues<FinalizeOutcome>()
            .Where(o => o != FinalizeOutcome.Submitted);

        foreach (var outcome in refusals)
        {
            var map = () => OrderController.MapFinalizeRefusal(outcome);

            map.Should().NotThrow(
                "every refusal needs an ACME answer, and {0} has none", outcome);
        }
    }

    [Fact]
    public void NoRefusalIsMappedToAnUnknownErrorType()
    {
        // Cheap cross check that the table above names real RFC 8555 constants
        // rather than hand typed URNs that happen to match.
        var known = new[]
        {
            AcmeErrorType.Malformed,
            AcmeErrorType.OrderNotReady,
            AcmeErrorType.BadCsr,
            AcmeErrorType.ServerInternal,
            AcmeErrorType.ServiceUnavailable,
            AcmeErrorType.RejectedIdentifier,
        };

        foreach (var outcome in Enum.GetValues<FinalizeOutcome>()
                     .Where(o => o != FinalizeOutcome.Submitted))
        {
            var (_, errorType) = OrderController.MapFinalizeRefusal(outcome);

            known.Should().Contain(errorType, $"{outcome} answers with a known error type");
        }
    }
}
